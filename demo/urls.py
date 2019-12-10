from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('irods', views.irods, name='irods'),
    path('dataset', views.listDatasets, name='listDatasets'),
    path('dataset/<path:doi>/', views.Dataset),
    path('token', views.getToken, name='getToken'),
    path('validate_token', views.validateToken, name='validateToken'),
]

