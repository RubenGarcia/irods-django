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

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.urls import reverse

from demo.settings import IRODS

import urllib.parse

from irods.session import iRODSSession
from irods.manager.collection_manager import CollectionManager

myresults = [] 
calls = 0
inProcess=False

# Create your views here.

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

@login_required
def irods(request):
    global myresults
    global calls
    global inProcess

    while inProcess:
         time.sleep (0.1)

    nonce=request.GET.get('nonce')
   
    if nonce != None:
      for i in range (0, len(myresults)):
        if myresults[i][0]==nonce:
#confirm that thread finished
           while(myresults[i][1]==None):
              time.sleep(0.1)
           info="<h2>" + "irods results:</h2><br/>" + myresults[i][1]
           data=myresults[i][2]
           del myresults[i]
           print ("array of json is")
           print (data)
           return render(request, 'demo/irods.html', {'info':info, 'data':json.dumps(data, sort_keys=True, indent=4)})
      #old request
      return redirect (request.build_absolute_uri('/'))

    with iRODSSession(host=IRODS['host'], port=IRODS['port'], authentication_scheme='openid', 
        openid_provider='keycloak_openid', user=IRODS['user'], 
        zone=IRODS['zone'], 
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

    return redirect (info)

@login_required
def listDatasets(request):
    with iRODSSession(host=IRODS['host'], port=IRODS['port'], authentication_scheme='openid',
        openid_provider='keycloak_openid', user=IRODS['user'],
        zone=IRODS['zone'],
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

    return redirect (info)


def provider_logout(request):
    # See your provider's documentation for details on if and how this is
    # supported
    #https://stackoverflow.com/questions/37108782/keycloak-logout-request
    back_url=request.build_absolute_uri('/')
    encoded=urllib.parse.quote(back_url)
    redirect_url = 'https://keycloak.it4i.cz/auth/realms/LEXIS/protocol/openid-connect/logout?redirect_uri='+encoded
    return redirect_url
