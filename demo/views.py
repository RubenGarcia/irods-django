import traceback
import requests
import json
import pdb
import threading
import time
import re
import logging
import urllib.parse

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.urls import reverse

import urllib.parse
from moz_test.settings import OIDC_OP_USER_ENDPOINT

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
        info = 'Content of collection:<br/>'
        for data_obj in coll.data_objects:
            info = info + '   ' + data_obj.name +'<br/>'
        for coll_obj in coll.subcollections:
            info = 'C- ' + coll_obj.name + '<br/>'
        return info

def mythread(coll_manager, token):
    global myresults
    global inProcess
    logger = logging.getLogger('django')
    logger.info("from thread, before blocking")
    inProcess=True
    print ("from thread, before blocking")
    try:
       myresults.insert (0,  (token,ls_coll(coll_manager.get('/tempZone/home/rods'))))
    except:
       print ("in thread, auth failed, aborting")
    inProcess=False
    logger.info("from thread, after blocking")

@login_required
def irods(request):
    global myresults
    global calls
    global inProcess

    while inProcess:
         time.sleep (0.1)

    id=request.session.get('oidc_id_token', None)
   
    for i in range (0, len(myresults)):
        if myresults[i][0]==id:
           info=myresults[i][1]
           del myresults[i]
           return render(request, 'demo/irods.html', {'info':info})

    with iRODSSession(host='172.17.0.4', port=1247, authentication_scheme='openid', 
        openid_provider='keycloak_openid', user="rods", 
        zone='tempZone', 
        ) as session:
        coll_manager = CollectionManager(session)
        x = threading.Thread(target=mythread, args=(coll_manager,id,))
        x.start()
        while (session.pool.currentAuth==None):
            time.sleep(0.1)

        info = session.pool.currentAuth

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
