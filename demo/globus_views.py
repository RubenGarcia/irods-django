from demo.settings import GLOBUS
from demo.views import GetUserAndTokenAPI

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt

import globus_sdk

from demo.utils import randomString

import pdb 

#https://globus-sdk-python.readthedocs.io/en/latest/tutorial/

def _globusTransfer(request, code, verifier, token, transfer_token, endpoint, path, dataset):
    client = None
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
#        pdb.set_trace()
        resp = "Endpoind received: {} <br/>".format(endpoint) 
        if path != None:
           resp+='Path: {} <br/>'.format(path)
           if dataset == None:
              resp += '<a href="globus?endpoint={}&path={}&token={}&transfer_token={}&dataset=Y">Transfer this dataset</a><br/><br/>'.format(endpoint, path, 
                         token, transfer_token)

        if dataset=='Y':
           resp += 'Requesting transfer to DDI'
           basepath=randomString(20)
           dest = GLOBUS["path"]+"/"+basepath

           if client==None:
              client = globus_sdk.NativeAppAuthClient(GLOBUS["client-id"])

           WP3authorizer = globus_sdk.RefreshTokenAuthorizer(
              GLOBUS["transfer_refresh_token"], client) 

           WP3tc=globus_sdk.TransferClient(authorizer=WP3authorizer)
           WP3tc.operation_mkdir (GLOBUS["endpoint"], path=dest)

#rgh: no way to use both tokens together to permit the transfer.
#rgh: give user writing permission at the newly created dest
           ac = globus_sdk.AuthClient(authorizer=globus_sdk.AccessTokenAuthorizer(token))
           identity_id=ac.oauth2_userinfo()['sub']

           resp += 'Your identity code: ' +identity_id+'<br/>'

           rule_data = {
             "DATA_TYPE": "access",
             "principal_type": "identity",
             "principal": identity_id,
             "path": dest+"/",
             "permissions": "rw",
           }
           result = WP3tc.add_endpoint_acl_rule(GLOBUS["endpoint"], rule_data)
           rule_id = result["access_id"]

           tdata = globus_sdk.TransferData(tc, endpoint,
                                 GLOBUS["endpoint"],
                                 label="Dataset Ingest for Lexis, "+path,
                                 sync_level="exists")
           tdata.add_item(path, dest, recursive=True)
           transfer_result = tc.submit_transfer(tdata)
#           pdb.set_trace()
           resp += "task_id ="+ str(transfer_result["task_id"])+"; you will receive an email after transfer is complete.<br/>"
           return resp

        try:
          for entry in tc.operation_ls(endpoint, path=path):
            name=entry["name"]
            if path == None:
                fullpath=name
            else:
                fullpath=path+'/'+name
            if entry["type"] == "dir":
                resp+='Name: [<a href="globus?endpoint={}&path={}&token={}&transfer_token={}">{}]</a>, Type: {}<br/>'.format(endpoint, fullpath, 
                     token, transfer_token, name, entry["type"])
            else:
                resp+='Name: [{}], Type: {}<br/>'.format(name, entry["type"])
        except globus_sdk.exc.TransferAPIError as e:
               return ("Error when listing directory, message: "+e.message )
        return resp


    resp="Your endpoints<br/>"
    for ep in tc.endpoint_search(filter_scope="my-endpoints"):
        resp+='[<a href="globus?endpoint={}&token={}&transfer_token={}">{}</a>] {}<br/>'.format(ep["id"], token, transfer_token, ep["id"], ep["display_name"])

    resp+="<br/>All LRZ endpoints<br/>"
    list= tc.endpoint_search("LRZ")  
    for ep in list:
        resp+='[<a href="globus?endpoint={}&token={}&transfer_token={}">{}</a>] {}<br/>'.format(ep["id"], token, transfer_token, ep["id"], ep["display_name"])
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
    path = request.GET.get ("path", None)
    token = request.GET.get ("token", None)
    transfer_token = request.GET.get ("transfer_token", None)
    dataset = request.GET.get ("dataset", None)
    if code == None and token == None:
        verifier = randomString(128)
        client = globus_sdk.NativeAppAuthClient(GLOBUS["client-id"])
        client.oauth2_start_flow(redirect_uri="https://irods-api.lexis.lrz.de/demo/globus", 
                  verifier=verifier, state=verifier)
        authorize_url = client.oauth2_get_authorize_url()
        return redirect (authorize_url)
    result=_globusTransfer(request, code, verifier, token, transfer_token, endpoint, path, dataset)

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


