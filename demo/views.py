import traceback
import requests
import json
import pdb
import threading
import time
import re
import logging
import urllib.parse
import json
import requests

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.conf import settings
from  django.http import HttpResponse

from demo.settings import IRODS

import urllib.parse

from irods.session import iRODSSession
from irods.manager.collection_manager import CollectionManager
from irods.exception import CollectionDoesNotExist
from irods.models import DataObject, DataObjectMeta, Collection, CollectionMeta
from irods.column import Criterion

from irods.connection import ExceptionOpenIDAuthUrl

# Create your views here.

@login_required
def getToken(request):
    return render(request, 'demo/getToken.html', {'token':request.session.get('oidc_access_token', None)})

@login_required
def validateToken(request):
    req = requests.get ('https://irods-auth.lexis.lrz.de/validate_token', 
             params = {'provider': 'keycloak_openid', 'access_token': request.session.get('oidc_access_token', None)})
    if req.status_code == 200:
       return render(request, 'demo/validateToken.html', {'response': req.status_code, 'json': req.json()})
    else:
       return render(request, 'demo/validateToken.html', {'response': req.status_code, 'json': "{}"}, status=req.status_code)


def index(request):
    return render(request, 'demo/index.html')

def datasetMeta(d, metadata):
    for x in ['identifier', 'title', 'publicationYear', 'resourceType', 'relatedIdentifier']:
        try:
           d[x]=metadata.get_one(x).value
        except:
           print('Irods metadata for ' + x + ' does not conform to standard, ignoring')
    for x in ['creator', 'publisher', 'owner', 'contributor' ]:
           d[x]=[]
           for y in metadata.get_all(x):
               d[x].append (y.value)


#https://github.com/theferrit32/python-irodsclient/blob/openid/examples/pyils.py
def ls_coll_public(coll):
        i=[]
#        pdb.set_trace()
        for group in coll.subcollections:
            g={}
            g['name']=group.name
            for proj in group.subcollections:
                p={}
                p['name']=proj.name
                for dataset in proj.subcollections:
                    d={}
                    d['name']=dataset.name
                    d['project']=p['name']
                    d['group']=g['name']
                    #now metadata
                    datasetMeta(d, dataset.metadata)
                    # now origin
                    d['access_permission']='public'
                    i.append(d)
        return i

def ls_coll (coll_manager):
   coll=coll_manager.get('/'+IRODS['zone']+'/public')
   public=ls_coll_public (coll)
#add search through project and user
   return public

#https://github.com/RubenGarcia/python-irodsclient/blob/openid/examples/pyiget.py
@login_required
def irods(request):
    with iRODSSession(host=IRODS['host'], port=IRODS['port'], authentication_scheme='openid', 
        openid_provider='keycloak_openid', user=request.user.irods_username, 
        zone=IRODS['zone'], access_token=request.session.get('oidc_access_token', None),
        block_on_authURL=False
        ) as session:
#        pdb.set_trace()
        coll_manager = CollectionManager(session)
        try:
          d=ls_coll(coll_manager.get('/'+IRODS['zone']))
        except CollectionDoesNotExist:
          return render (request, "demo/irods.html", {"info": "503 irods.exception.CollectionDoesNotExist", "data":{}}, status=503)
        except ExceptionOpenIDAuthUrl:
          return render (request, "demo/irods.html", {"info":"401 OpenID Auth URL received; token not valid or not validated by broker. Or user unknown to iRODS.", "data":{}}, status=401)
        except:
          return render (request, "demo/irods.html", {"info": "503 Irods service or authentification backend down", "data":{}}, status=503)
        return render (request, "demo/irods.html", {"info":"200", "data":json.dumps(d, sort_keys=True, indent=4)})

@login_required
def listDatasets(request):
    with iRODSSession(host=IRODS['host'], port=IRODS['port'], authentication_scheme='openid',
        openid_provider='keycloak_openid', user=request.user.irods_username,
        zone=IRODS['zone'], access_token=request.session.get('oidc_access_token', None),
        block_on_authURL=False
        ) as session:
        coll_manager = CollectionManager(session)
        try:
          d=ls_coll(coll_manager)
        except CollectionDoesNotExist:
          return HttpResponse ('{"status": "503", "errorString": "Irods files not in expected format"}', content_type='application/json', status=503)
        except ExceptionOpenIDAuthUrl:
          return HttpResponse ('{"status": "401", "errorString": "Token not accepted by irods, Auth URL sent by irods"}', content_type='application/json', status=401)
        except:
          return HttpResponse ('{"status": "503", "errorString": "Error connecting to irods backend"}', content_type='application/json', status=503)
        return HttpResponse (json.dumps(d, sort_keys=True, indent=4), content_type='application/json')


def Dataset(request, doi):
    with iRODSSession(host=IRODS['host'], port=IRODS['port'], authentication_scheme='openid',
         openid_provider='keycloak_openid', user=request.user.irods_username,
        zone=IRODS['zone'], access_token=request.session.get('oidc_access_token', None),
        block_on_authURL=False
        ) as session:
        try:
          results = session.query(Collection, CollectionMeta).filter(
                         Criterion('=', CollectionMeta.name, 'identifier')).filter( 
                         Criterion('=', CollectionMeta.value, doi)
                         ).execute()
        except ExceptionOpenIDAuthUrl:
          return HttpResponse ('{"status": "401", "errorString": "Token not accepted by irods, Auth URL sent by irods"}', content_type='application/json', status=401)
        except:
          return HttpResponse ('{"status": "503", "errorString": "Error connecting to irods backend"}', content_type='application/json', status=503)
        if len(results)==0:
          return HttpResponse ('{}',  content_type='application/json')
        result=results[0]
        coll=session.collections.get(result[Collection.name])
        d={}
        d['name']=coll.name
        datasetMeta(d, coll.metadata)

        return HttpResponse (json.dumps(d, sort_keys=True, indent=4), content_type='application/json')

def gatherData(session, results):
        i=[]
        for r in results:
           d={}
           coll=session.collections.get(r[Collection.name])
           d['name']=coll.name
           datasetMeta(d, coll.metadata)
           i.append(d)
        return i

           
def Year(request, year):
    with iRODSSession(host=IRODS['host'], port=IRODS['port'], authentication_scheme='openid',
         openid_provider='keycloak_openid', user=request.user.irods_username,
        zone=IRODS['zone'], access_token=request.session.get('oidc_access_token', None),
        block_on_authURL=False
        ) as session:
        try:
           results = session.query(Collection, CollectionMeta).filter(
                        Criterion('=', CollectionMeta.name, 'publicationYear')).filter(
                        Criterion('=', CollectionMeta.value, year)
                        ).execute()
        except ExceptionOpenIDAuthUrl:
          return HttpResponse ('{"status": "401", "errorString": "Token not accepted by irods, Auth URL sent by irods"}', content_type='application/json', status=401)
        except:
          return HttpResponse ('{"status": "503", "errorString": "Error connecting to irods backend"}', content_type='application/json', status=503)
        if len(results)==0:
          return HttpResponse ('{}',  content_type='application/json')
        
        i=gatherData(session, results)
        return HttpResponse (json.dumps(i, sort_keys=True, indent=4), content_type='application/json') 

def Meta(request, meta, value):
    with iRODSSession(host=IRODS['host'], port=IRODS['port'], authentication_scheme='openid',
         openid_provider='keycloak_openid', user=request.user.irods_username,
        zone=IRODS['zone'], access_token=request.session.get('oidc_access_token', None),
        block_on_authURL=False
        ) as session:
        try:
           results = session.query(Collection, CollectionMeta).filter(
                        Criterion('=', CollectionMeta.name, meta)).filter(
                        Criterion('=', CollectionMeta.value, value)
                        ).execute()
        except ExceptionOpenIDAuthUrl:
          return HttpResponse ('{"status": "401", "errorString": "Token not accepted by irods, Auth URL sent by irods"}', content_type='application/json', status=401)
        except:
          return HttpResponse ('{"status": "503", "errorString": "Error connecting to irods backend"}', content_type='application/json', status=503)
        i=gatherData(session, results)
        return HttpResponse (json.dumps(i, sort_keys=True, indent=4), content_type='application/json')
 

def provider_logout(request):
    # See your provider's documentation for details on if and how this is
    # supported
    #https://stackoverflow.com/questions/37108782/keycloak-logout-request
    back_url=request.build_absolute_uri('/')
    encoded=urllib.parse.quote(back_url)
    redirect_url = settings.KEYCLOAK_LOGOUT_ENDPOINT + '?redirect_uri='+encoded
    return redirect_url
