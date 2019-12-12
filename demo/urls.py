from django.urls import path

from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('irods', views.irods, name='irods'),
    path('dataset', views.listDatasets, name='listDatasets'),
    path('dataset/doi/<path:doi>', views.Dataset),
    path('dataset/search/year/<int:year>', views.Year),
    path('dataset/search/metadata/<str:meta>/<str:value>', views.Meta),
    path('dataset/search/metadata/', views.SearchMeta),
    path('token', views.getToken, name='getToken'),
    path('validate_token', views.validateToken, name='validateToken'),
]

