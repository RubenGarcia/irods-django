from django.urls import path

from . import views, globus_views

urlpatterns = [
    path('', views.index, name='index'),
    path('irods', views.irods, name='irods'),
    path('dataset', views.Datasets, name='listDatasets'),
#GET lists
#PUT creates a new dataset
#{push_methods"ssh", "grid", "globus", "directupload",
#file="file contents", used in directupload
#compress_method='file' 'tar' 'targz', ...
#URL="url", used in others
#name="dataset name",
#access="user", "group", "project", "public"
#project=""
#group=""
#metadata=[]
#}
#receive an identifier back (collectionid), which can be low-level queried to see if complete/obsolete (error in transfer)/in progress

    path('dataset/status', views.DatasetStatus, name='datasetStatus'),
#get  success/failure/in progress
#parameter identifier back (collectionid) from 'dataset'
#internally metadata read.

    path('dataset/doi/<path:doi>', views.Dataset),
    path('dataset/search/year/<int:year>', views.Year),
    path('dataset/search/metadata/<str:meta>/<str:value>', views.Meta),
    path('dataset/search/metadata/', views.SearchMeta),
    path('token', views.getToken, name='getToken'),
    path('validate_token', views.validateToken, name='validateToken'),
#This gives the public key of the server
#Internally, call to low-level routines
    path('cert', views.cert, name='cert'),
#User creation. Inputs: irods username, keycloak code (aua), irods usertype, irods zone
#User is added to public group so he can access public data.
#In the view, replication can be requested. Call low-level on both irods servers as-needed.
#    path('user/create', view.CreateUser, name='createUser'),
#User deletion. Cascade delete all his data
#    path('user/delete', view.DeleteUser, name='deleteUser'),

#Admin requests that user joins a project
#inputs: irods username, irods zone, array of (group, project)
#User is added to group if needed
#project directories are created, access rights are applied to these directories
#     path('user/addToProjects', views.addToProjects, name='userAddToProjects')



    path('globus', globus_views.globusTransfer, name='globus'),
]

