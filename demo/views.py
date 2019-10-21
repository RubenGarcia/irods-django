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

def mythread(coll_manager):
    global myresults
    global inProcess
    logger = logging.getLogger('django')
    logger.info("from thread, before blocking")
    inProcess=True
    print ("from thread, before blocking")
    myresults.insert (0,  ls_coll(coll_manager.get('/tempZone/home/rods')))
    inProcess=False
    logger.info("from thread, after blocking")
    print("from thread, after blocking")
    logger.info("from thread, " + myresults[0])
    print ("from thread, len(myresults):" + str(len(myresults)))
    print ("my thread ended")
#    i=0
#    while True:
#      i=i+1
#      print ("from thread, "+str(i))  

#code is a random number which corresponds to the previous request
@login_required
def irods(request, code=0):
    global myresults
    global calls
    global inProcess

    calls = calls + 1
    print ("calls "+str(calls))
    print ("myresults has elements:")
    print (len(myresults))
    if (inProcess):
      while inProcess:
         print ("in irods, inProcess is true, waiting")
         time.sleep (10)
      print ("process ended")
    if len(myresults)==1:
       info=myresults[0]
       myresults=[]
       return render(request, 'demo/irods.html', {'info':info})       

    at=request.session.get('oidc_access_token', None)
#rgh: these tokens (at, id) are too large and provide a USER_PACKSTRUCT_INPUT_ERR. Probably this is not the token we want.
#rgh: most of the information is good, see https://code.it4i.cz/lexis/wp8/dataset-management-interface/issues/6#note_13967

#rgh: testing session id: session_state does not work here.
#but on manual login, I get: 
#Received session information: act=eyJhbGciOiJSUzI1NiIsInR5cC...;sid=016aefe1214ac9ab4fac6ec186d106c5a9fbc19b81799fd719,
#so this may be the way to go
#the act seems to be the at token. 
    id=request.session.get('oidc_id_token', None)
#    print ("at is")
#    print (at)
#    print ("len of at: "+str(len(at)))
#    print ("len of id: "+str(len(id)))
#    print (id)
    info = 'information +'

    r = requests.get('https://172.17.0.3:8080/token', 
     headers={
        'Authorization':'Basic 37789fde4bb12a17818d7a4161448a5176285ac793c216b5724391040bd2dd2c'
     }, 
     params={
        'uid':"ab28fabf-2ccb-4a19-be38-42af549b5d77",
        'provider':'keycloak_openid',
        'scope':'openid'},
     verify=False)

    print (r.status_code)
    print (r.content)


    if (r.status_code==200):
       obj=json.loads(r.text)
       #id=obj["access_token"]
       print ("extracted access token from response, passing to irods")
       print ("new id:")
       #print (id)

    #pdb.set_trace()
    if (id == None):
       info = 'no access token'
    else:
      with iRODSSession(host='172.17.0.4', port=1247, authentication_scheme='openid', 
        openid_provider='keycloak_openid', user="rods", 
        zone='tempZone', 
        access_token=id,
        ) as session:
        coll_manager = CollectionManager(session)
        x = threading.Thread(target=mythread, args=(coll_manager,))
        x.start()
        while (session.pool.currentAuth==None):
#            print ("Waiting")
            time.sleep(0.1)
        print (session.pool.currentAuth)
        info = session.pool.currentAuth
#        coll = coll_manager.get('/tempZone/home/rods')
#        info = info + ls_coll(coll)

        info = re.sub('\&prompt\=login\%20consent$', '', info)
        print (info)
        thisview=request.build_absolute_uri(reverse('irods'))
        print ("this view: "+thisview)
        thisview=urllib.parse.quote(thisview)
        print ("urlencoded: "+thisview)
#triple somersault
#keycloak -> https://irods1.it4i.cz:8080/authcallback -> https://irods1.it4i.cz/demo/irods
#        info = re.sub('https://irods1.it4i.cz:8080/authcallback', "https://irods1.it4i.cz:8080/authcallback%3F%0Aredirect%3D" +thisview+"&", info)
        print (info)

    #return render(request, 'demo/irods.html', {'info':info})
    return redirect (info)

def provider_logout(request):
    # See your provider's documentation for details on if and how this is
    # supported
    #https://stackoverflow.com/questions/37108782/keycloak-logout-request
    back_url=request.build_absolute_uri('/')
    encoded=urllib.parse.quote(back_url)
    redirect_url = 'https://keycloak.it4i.cz/auth/realms/LEXIS/protocol/openid-connect/logout?redirect_uri='+encoded
    return redirect_url
