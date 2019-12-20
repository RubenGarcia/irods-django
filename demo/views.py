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
import os.path

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.urls import reverse
from django.conf import settings
from django.http import HttpResponse
from django.views.static import serve

from django.views.decorators.csrf import csrf_exempt

from demo.settings import IRODS, GLOBUS

import urllib.parse

from irods.session import iRODSSession
from irods.manager.collection_manager import CollectionManager
from irods.exception import CollectionDoesNotExist, CAT_NO_ACCESS_PERMISSION
from irods.models import DataObject, DataObjectMeta, Collection, CollectionMeta
from irods.column import Criterion

from irods.connection import ExceptionOpenIDAuthUrl

logger = logging.getLogger('django')

# Create your views here.

@login_required
def getToken(request):
    return render(request, 'demo/getToken.html', {'token':request.session.get('oidc_access_token', None)})

def requestValidateToken(token):
    return requests.get (IRODS['openid_microservice']+'/validate_token',
             params = {'provider': 'keycloak_openid', 'access_token': token})


@login_required
def validateToken(request):
    req = requestValidateToken (request.session.get('oidc_access_token', None))
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
        openid_provider='keycloak_openid', user=request.user.irods_name, 
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

def _listDatasets(token, user):
    with iRODSSession(host=IRODS['host'], port=IRODS['port'], authentication_scheme='openid',
        openid_provider='keycloak_openid', user=user,
        zone=IRODS['zone'], access_token=token,
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

def _cert(request):
    filepath = GLOBUS["cert"]
    return serve(request, os.path.basename(filepath), os.path.dirname(filepath))

@csrf_exempt
def certAPI(request):
    (token, user, resp)=GetUserAndTokenAPI(request)
    if resp!=None:
       return resp
    return _cert(request)

@login_required
def certWeb(request):
    return _cert(request)

def cert(request):
    if request.content_type=='application/json' or request.content_type=='text/json':
      return certAPI(request)
    else:
      return certWeb(request)

@login_required
def GetUserAndTokenWeb(request):
    token=request.session.get('oidc_access_token', None)
    user=request.user.irods_name
    return (token, user)

@csrf_exempt
def GetUserAndTokenAPI(request):
    try:
      token=request.headers.get('Authorization').split(" ")[1]
    except:
      return (None, None, HttpResponse ('{"status": "401", "errorString": "Invalid Authorization"}', content_type='application/json'))
    req = requestValidateToken (token)
    if req.status_code == 200:
       j=req.json()
       if j['active']==False:
         return (None, None, HttpResponse ('{"status": "401", "errorString": "Invalid Token"}', content_type='application/json'))
       else:
         user=j['username']
         return (token, user, None)
    else:
       return (None, None, HttpResponse ('{"status": "%d", "errorString": "Error connecting to token validator service"}'%req.status_code))
    

def listDatasetsWeb(request):
    (token, user) = GetUserAndTokenWeb(request)
    return _listDatasets(token, user)

@csrf_exempt
def listDatasetsAPI(request):
    #token=request.session.get('token', None)
    (token, user, err)=GetUserAndTokenAPI(request)
    if err==None:
       return _listDatasets(token, user)
    return err

def listDatasets(request):
    if request.content_type=='application/json' or request.content_type=='text/json':
      return listDatasetsAPI(request)
    else:
      return listDatasetsWeb(request)

def _Dataset(doi, token, user):
    with iRODSSession(host=IRODS['host'], port=IRODS['port'], authentication_scheme='openid',
         openid_provider='keycloak_openid', user=user,
        zone=IRODS['zone'], access_token=token,
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

@csrf_exempt
def DatasetAPI(request, doi):
    (token, user, err)=GetUserAndTokenAPI(request)
    if err==None:
       return _Dataset(doi, token, user)
    return err

@login_required
def DatasetWeb(request, doi):
    (token, user) = GetUserAndTokenWeb(request)
    return _Dataset (doi, token, user)

def Dataset(request, doi):
    if request.content_type=='application/json' or request.content_type=='text/json':
      return DatasetAPI(request, doi)
    else:
      return DatasetWeb(request, doi)


def gatherData(session, results):
        i=[]
        for r in results:
           d={}
           coll=session.collections.get(r[Collection.name])
           d['name']=coll.name
           datasetMeta(d, coll.metadata)
           i.append(d)
        return i

def gatherDataC(session, colls):
        i=[]
        for r in colls:
           d={}
           d['name']=r.name
           datasetMeta(d, r.metadata)
           i.append(d)
        return i
    
           
def Year(request, year):
    with iRODSSession(host=IRODS['host'], port=IRODS['port'], authentication_scheme='openid',
         openid_provider='keycloak_openid', user=request.user.irods_name,
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

def CollChecks(coll, checks):
    for key in checks:
        found = False
        for y in coll.metadata.get_all(key):
            if y.value == str(checks[key]):
               found= True
               break
        if found == False:
           return False
    return True

def findCols(coll, checks):
    cols=[]
    res= CollChecks (coll, checks)
    if res == True:
       cols.append(coll)
    for col in coll.subcollections:
           l=findCols(col, checks)
           cols+=l
    return cols

@csrf_exempt
def SearchMeta(request):
#API, pass as json an array with the query terms: e.g. ["Year": "1900", "Author": "1"]
    (token, user, err)=GetUserAndTokenAPI(request)
    if err!=None:
       return err
    with iRODSSession(host=IRODS['host'], port=IRODS['port'], authentication_scheme='openid',
        openid_provider='keycloak_openid', user=user,
        zone=IRODS['zone'], access_token=token,
        block_on_authURL=False
        ) as session:
#Multiple filters on the same column overwrite, so 
#imeta qu -C publicationYear = 1900 and relatedIdentifier = "doi://lexis-datasets/wp5/datasetpublicx1"
#does not work. Doing the set-intersection ourselves is one possibility, or going through all collections recursively.
#https://github.com/irods/python-irodsclient/issues/135#issuecomment-564554609

#https://github.com/irods/python-irodsclient/issues/135
        try:
          q=json.loads(request.body.decode('utf-8'))
          logger.info('/'+IRODS['zone'])
          root=session.collections.get('/'+IRODS['zone'])
#          pdb.set_trace()
          results = findCols(root, q)
        except ExceptionOpenIDAuthUrl:
          return HttpResponse ('{"status": "401", "errorString": "Token not accepted by irods, Auth URL sent by irods"}', content_type='application/json', status=401)
        except CollectionDoesNotExist:
          return HttpResponse ('{"status": "503", "errorString": "Irods permissions too restrictive for this user"}', content_type='application/json', status=503)
        except:
          return HttpResponse ('{"status": "503", "errorString": "Error connecting to irods backend"}', content_type='application/json', status=503)
        if request.method=='GET':
          i=gatherDataC(session, results)
          return HttpResponse (json.dumps(i, sort_keys=True, indent=4), content_type='application/json')
        elif request.method=='DELETE':
          logger.info("deleting")
          noPerm=[]
          for r in results:
            try:
              r.remove()
            except CAT_NO_ACCESS_PERMISSION:
              noPerm.append(r)
              logger.info("not deleted: %s"%r.name)
          if noPerm==[]:
            logger.info("204")
            return HttpResponse ('{"status": "204", "errorString": "Collections successfully deleted"}', content_type='application/json', status=204)
          else:
            logger.info("401")
            resp={"status": "401", "errorString": "Some collections were not deleted due to insufficient permissions by user"}
            res=[]
            for c in noPerm:
                 res.append({"name":c.name})
            resp["permission_error"]=res
            return HttpResponse (json.dumps(resp), content_type='application/json', status=401)


def Meta(request, meta, value):
    with iRODSSession(host=IRODS['host'], port=IRODS['port'], authentication_scheme='openid',
        openid_provider='keycloak_openid', user=request.user.irods_name,
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
