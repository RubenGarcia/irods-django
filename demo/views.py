from django.shortcuts import render
import urllib.parse
from moz_test.settings import OIDC_OP_USER_ENDPOINT

# Create your views here.

def index(request):
    return render(request, 'demo/index.html')

def provider_logout(request):
    # See your provider's documentation for details on if and how this is
    # supported
    #https://stackoverflow.com/questions/37108782/keycloak-logout-request
    back_url=request.build_absolute_uri('/')
    encoded=urllib.parse.quote(back_url)
    redirect_url = 'https://138.246.232.245:8443/auth/realms/rgh-test/protocol/openid-connect/logout?redirect_uri='+encoded
    return redirect_url
