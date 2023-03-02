from django.urls import path,include
from django.contrib.auth import views as auth_views
from django.conf.urls.static import static
from django.conf import settings

from projects import views
from scans import views
from apikeys import views
from editprofile import views

urlpatterns = [
    path('', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path('logout/', auth_views.LogoutView.as_view(template_name='logged_out.html'), name='logout'),
    path('projects/', include('projects.urls')),
    path('scans/', include('scans.urls')),
    path('schedules/', include('schedules.urls')),
    path('apikeys_settings/', include('apikeys.urls')),
    path('edit_profile/', include('editprofile.urls')),

] 
