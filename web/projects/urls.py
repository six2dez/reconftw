from django.urls import path
from . import views

# Namespace name
app_name = 'projects'

# Be careful setting the name to just /login use userlogin instead!
urlpatterns=[
    path('', views.index, name='index'),
    path('<int:id>/delete/', views.delete_project,name='delete'),
    path('<int:id>/cancel/', views.cancel_scan,name='cancel'),
    path('<int:id>/backup/', views.DownloadBackup, name='backup'),
]
