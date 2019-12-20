from demo.settings import GLOBUS
from demo.views import GetUserAndTokenAPI

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt

import random
import string
import globus_sdk

#https://globus-sdk-python.readthedocs.io/en/latest/tutorial/

def _globusTransfer(code, verifier):
    client = globus_sdk.NativeAppAuthClient(GLOBUS["client-id"])
    client.oauth2_start_flow(redirect_uri="https://irods-api.lexis.lrz.de/demo/globus", verifier=verifier)
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

    resp="Your endpoints<br/>"
    for ep in tc.endpoint_search(filter_scope="my-endpoints"):
        resp+="[{}] {}<br/>".format(ep["id"], ep["display_name"])
    return resp

@login_required
def globusTransferWeb(request):
    print (request.GET)
    code = request.GET.get ("code", None)
    verifier = request.GET.get ("state", None)
    if code == None:
        verifier = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(128)])
        client = globus_sdk.NativeAppAuthClient(GLOBUS["client-id"])
        client.oauth2_start_flow(redirect_uri="https://irods-api.lexis.lrz.de/demo/globus", 
                  verifier=verifier, state=verifier)
        authorize_url = client.oauth2_get_authorize_url()
        return redirect (authorize_url)
    result=_globusTransfer(code, verifier)

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
    if request.content_type=='application/json' or request.content_type=='text/json':
      return globusTransferAPI(request)
    else:
      return globusTransferWeb(request)


