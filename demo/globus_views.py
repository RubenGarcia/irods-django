from demo.settings import GLOBUS
from demo.views import GetUserAndTokenAPI

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt

import random
import string
import globus_sdk

import pdb 

#https://globus-sdk-python.readthedocs.io/en/latest/tutorial/

def _globusTransfer(request, code, verifier, token, transfer_token, endpoint):
#    pdb.set_trace()
    if token == None:
      client = globus_sdk.NativeAppAuthClient(GLOBUS["client-id"])
      client.oauth2_start_flow(redirect_uri="https://irods-api.lexis.lrz.de/demo/globus", verifier=verifier, state=verifier)
      try: 
        token_response = client.oauth2_exchange_code_for_tokens(code)
      except:
        return "token exchange failed"

      globus_auth_data = token_response.by_resource_server['auth.globus.org']
      globus_transfer_data = token_response.by_resource_server['transfer.api.globus.org']

      token = globus_auth_data['access_token']
      transfer_token = globus_transfer_data['access_token']


    authorizer = globus_sdk.AccessTokenAuthorizer(transfer_token)
    tc = globus_sdk.TransferClient(authorizer=authorizer)

    if endpoint != None:
        resp = "endpoind received: "+endpoint
        return resp


    resp="Your endpoints<br/>"
    for ep in tc.endpoint_search(filter_scope="my-endpoints"):
        resp+='[<a href="globus?endpoint={}&token={}&transfer_token={}">{}</a>] {}<br/>'.format(ep["id"], token, transfer_token, ep["id"], ep["display_name"])

    resp+="<br/>All LRZ endpoints<br/>"
    list= tc.endpoint_search("LRZ")  
    for ep in list:
        resp+="[<a href="globus?endpoint={}&token={}&transfer_token={}">{}</a>] {}<br/>".format(ep["id"], token, transfer_token, ep["display_name"])
#        print (ep["display_name"])
        list=tc.endpoint_server_list(ep["id"])
#        for srv in list["DATA"]:
#             print(srv)
#            resp+=srv["uri"]
#            resp+="<br/>"
        
    return resp

@login_required
def globusTransferWeb(request):
    print (request.GET)
    code = request.GET.get ("code", None)
    verifier = request.GET.get ("state", None)
    endpoint = request.GET.get ("endpoint", None)
    token = request.GET.get ("token", None)
    transfer_token = request.GET.get ("transfer_token", None)
    if code == None and token == None:
        verifier = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(128)])
        client = globus_sdk.NativeAppAuthClient(GLOBUS["client-id"])
        client.oauth2_start_flow(redirect_uri="https://irods-api.lexis.lrz.de/demo/globus", 
                  verifier=verifier, state=verifier)
        authorize_url = client.oauth2_get_authorize_url()
        return redirect (authorize_url)
    result=_globusTransfer(request, code, verifier, token, transfer_token, endpoint)

    return render(request, 'demo/globus.html', {'info':result})

@csrf_exempt
def globusTransferAPI(request):
    (token, user, resp)=GetUserAndTokenAPI(request)
    if resp!=None:
       return resp
    q=json.loads(request.body.decode('utf-8'))
    code=q["code"]
    verifier=q["verifier"]
    if code==None:
       return HttpResponse ('{"status": "401", "errorString": "code parameter missing"}', 
                  content_type='application/json', status=401)
    if verifier==None:
       return HttpResponse ('{"status": "401", "errorString": "verifier parameter missing"}', 
                  content_type='application/json', status=401)

    result=_globusTransfer(code, verifier)
    return HttpResponse ('{"status": "200", "answer": "%s"}'%result)

def globusTransfer(request):
#    pdb.set_trace()
    if request.content_type=='application/json' or request.content_type=='text/json':
      return globusTransferAPI(request)
    else:
      return globusTransferWeb(request)


