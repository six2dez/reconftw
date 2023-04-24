from django.urls import path
from . import views

# Namespace name
app_name = 'edit_profile'

# Be careful setting the name to just /login use userlogin instead!
urlpatterns=[
    path('', views.index, name='index'),
]
