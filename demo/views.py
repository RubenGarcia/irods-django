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

from demo.settings import IRODS

import urllib.parse

from irods.session import iRODSSession
from irods.manager.collection_manager import CollectionManager

# Create your views here.

@login_required
def getToken(request):
    return render(request, 'demo/getToken.html', {'token':request.session.get('oidc_access_token', None)})

@login_required
def validateToken(request):
    req = requests.get ('https://irods-auth.lexis.lrz.de/validate_token', 
             params = {'provider': 'keycloak_openid', 'access_token': request.session.get('oidc_access_token', None)})

    return render(request, 'demo/validateToken.html', {'response': req.status_code, 'json': req.json()})


def index(request):
    return render(request, 'demo/index.html')

#https://github.com/theferrit32/python-irodsclient/blob/openid/examples/pyils.py
def ls_coll(coll):
        info = '<p>Content of public:</p><p>'
        i=[]
#        pdb.set_trace()
        for group in coll.subcollections:
            g={}
            g['name']=group.name
            info = info + 'C- ' + group.name + '<br/>'
            for proj in group.subcollections:
                p={}
                p['name']=proj.name
                info = info + 'C- ' + proj.name +'<br/>'
                for dataset in proj.subcollections:
                    d={}
                    d['name']=dataset.name
                    d['project']=p['name']
                    d['group']=g['name']
                    info = info + 'C-  ' + dataset.name+'<br/>'
                    #now metadata
                    info = info + 'metadata:<br/>'
                    for x in ['identifier', 'title', 'publicationYear', 'resourceType', 'relatedIdentifier']:
                        try:
                          d[x]=dataset.metadata.get_one(x).value
                          info = info + x +': ' +d[x]+'<br/>'
                        except:
                          info = info + 'Irods metadata for ' + x + ' does not conform to standard <br/>'
                    for x in ['creator', 'publisher', 'owner', 'contributor' ]:
                             d[x]=[]
                             for y in dataset.metadata.get_all(x):
                                 d[x].append (y.value)
                    i.append(d)
                info = info + '</p><p>'
            info = info + '</p><p>'
        info = info + '</p>'
        return info, i

class irodsthread:
  nonce=None
  def __init__(self, coll_manager):
     threading.Thread(target=self.mythread, args=(coll_manager,)).start()
     
  def mythread(self, coll_manager):
    global myresults
    global inProcess
#    pdb.set_trace()
    logger = logging.getLogger('django')
    logger.info("from thread, before blocking")
    print ("from thread, before blocking")
    try:
       (data,d)=ls_coll(coll_manager.get('/'+IRODS['zone']+'/public'))
       while (self.nonce == None):
            time.sleep(0.1)
       for i in range (0, len(myresults)):
            if myresults[i][0]==self.nonce:
               myresults[i][1]=data
               myresults[i][2]=d      
#       myresults.insert (0,  (self.nonce,data,d))
    except Exception as e:
       print ("in thread, auth failed, aborting" + str(e))
       for i in range (0, len(myresults)):
            if myresults[i][0]==self.nonce:
               myresults[i][1]='Authentification failed' + str(e)
               myresults[i][2]={}
    logger.info("from thread, after blocking")


#https://github.com/RubenGarcia/python-irodsclient/blob/openid/examples/pyiget.py
@login_required
def irods(request):

    with iRODSSession(host=IRODS['host'], port=IRODS['port'], authentication_scheme='openid', 
        openid_provider='keycloak_openid', user=IRODS['user'], 
        zone=IRODS['zone'], access_token=request.session.get('oidc_access_token', None)
        ) as session:
        pdb.set_trace()
        coll_manager = CollectionManager(session)
        (data,d)=ls_coll(coll_manager.get('/'+IRODS['zone']+'/public'))
        return render (request, {info:data, json:d})

@login_required
def listDatasets(request):
    with iRODSSession(host=IRODS['host'], port=IRODS['port'], authentication_scheme='openid',
        openid_provider='keycloak_openid', user=IRODS['user'],
        zone=IRODS['zone'], access_token=at
        ) as session:
        coll_manager = CollectionManager(session)
        x = irodsthread (coll_manager)
        while (session.pool.currentAuth==None):
            time.sleep(0.1)

        info = session.pool.currentAuth
        print ("info is <"+info+">")
        nonce=re.search ("nonce=(.*?)&", info).group(1)
        print ("nonce is <"+str(nonce)+">")
        myresults.insert (0,  [nonce,None,None])
        x.nonce=nonce
        info = re.sub('\&prompt\=login\%20consent$', '', info)

#do redirect ourselves
        response = requests.get (info, verify=False, 
            headers={#'Accept': 'application/json',
#                     'Authorization' : 'Bearer ' + request.session.get('oidc_access_token', None)})
                     'Authorization' : 'Bearer ' + request.session.get('oidc_id_token', None)})
        pdb.set_trace()
        print (response)
    return render(request, 'demo/X.html', {'body':response.content})
#    return redirect (info)


def provider_logout(request):
    # See your provider's documentation for details on if and how this is
    # supported
    #https://stackoverflow.com/questions/37108782/keycloak-logout-request
    back_url=request.build_absolute_uri('/')
    encoded=urllib.parse.quote(back_url)
    redirect_url = settings.KEYCLOAK_LOGOUT_ENDPOINT + '?redirect_uri='+encoded
    return redirect_url
