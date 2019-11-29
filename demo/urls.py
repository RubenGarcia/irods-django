from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^irods$', views.irods, name='irods'),
    url(r'^dataset$', views.listDatasets, name='listDatasets'),
    url(r'^token$', views.getToken, name='getToken'),
    url(r'^validate_token$', views.validateToken, name='validateToken'),
#    url(r'^validated_token$', views.getValidatedToken, name='validatedToken'),
]

