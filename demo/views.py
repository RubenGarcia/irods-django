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
Ã#the act seems to be the at token. 
    id=request.session.get('oidc_id_token', None)
    print ("id is")
    print (id)
    info = 'information +'
    if (id == None):
       info = 'no access token'
    else:
      with iRODSSession(host='172.17.0.4', port=1247, authentication_scheme='openid', 
        openid_provider='keycloak_openid', user="rods", 
        zone='tempZone', 
        access_token=at,
        ) as session:
        coll_manager = CollectionManager(session)
        try:
          coll = coll_manager.get('/tempZone/home/rods')
          info = info + ls_coll(coll)
        except:
           info = info + 'error on first irods session'
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
    redirect_url = 'https://138.246.232.245:8443/auth/realms/rgh-test/protocol/openid-connect/logout?redirect_uri='+encoded
    return redirect_url
