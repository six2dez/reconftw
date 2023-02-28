from django.urls import path
from . import views

# Namespace name
app_name = 'schedules'

# Be careful setting the name to just /login use userlogin instead!
urlpatterns=[
    path('timezone', views.define_timezone, name='timezone'),
    path('new', views.schedule_scan, name='new'),
    path('get', views.getSchedules, name='get'),
    path('delete', views.deleteSchedule, name='delete'),
]
