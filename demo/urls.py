from django.urls import path

from . import views

urlpatterns = [
    path(r'', views.index, name='index'),
    path(r'irods', views.irods, name='irods'),
    path(r'dataset', views.listDatasets, name='listDatasets'),
    path(r'token', views.getToken, name='getToken'),
    path(r'validate_token', views.validateToken, name='validateToken'),
]

