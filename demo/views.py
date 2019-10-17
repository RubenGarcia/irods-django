import traceback
import requests
import json

from django.shortcuts import render
from django.contrib.auth.decorators import login_required

import urllib.parse
from moz_test.settings import OIDC_OP_USER_ENDPOINT

from irods.session import iRODSSession
from irods.manager.collection_manager import CollectionManager

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

@login_required
def irods(request):
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
    print ("len of at: "+str(len(at)))
    print ("len of id: "+str(len(id)))
    print (id)
    info = 'information +'

#try to get a smaller token using
#https://github.com/heliumdatacommons/auth_microservice/wiki/API-and-Use

#sub of id is the uid

#to get the authorization, use
#https://github.com/irods-contrib/irods_auth_plugin_openid

#auth: 1a91e10eb3cda3d404a383f49c04d3cc13acbee5cb680c8769414e4343b9482e
#with service: webportal

#auth: 37789fde4bb12a17818d7a4161448a5176285ac793c216b5724391040bd2dd2c
#with service: irods-auth-plugin

#since we are in a container, use https://172.17.0.3:8080

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
       id=obj["access_token"]
       print ("extracted access token from response, passing to irods")
#
    if (id == None):
       info = 'no access token'
    else:
      with iRODSSession(host='172.17.0.4', port=1247, authentication_scheme='openid', 
        openid_provider='keycloak_openid', user="rods", 
        zone='tempZone', 
        access_token=id,
        ) as session:
        coll_manager = CollectionManager(session)
        try:
          coll = coll_manager.get('/tempZone/home/rods')
          info = info + ls_coll(coll)
        except Exception as e: 
           traceback.print_exc()
           print (e)
           info = info + 'error on first irods session '+str(e)
           with iRODSSession(host='172.17.0.4', port=1247, authentication_scheme='openid',
           openid_provider='keycloak_openid', user="rods", zone='tempZone') as s2:
              coll_manager = CollectionManager(s2)
              coll = coll_manager.get('/tempZone/home/rods')
              info = info + ls_coll(coll)



    return render(request, 'demo/irods.html', {'info':info})

def provider_logout(request):
    # See your provider's documentation for details on if and how this is
    # supported
    #https://stackoverflow.com/questions/37108782/keycloak-logout-request
    back_url=request.build_absolute_uri('/')
    encoded=urllib.parse.quote(back_url)
    redirect_url = 'https://keycloak.it4i.cz/auth/realms/LEXIS/protocol/openid-connect/logout?redirect_uri='+encoded
    return redirect_url
