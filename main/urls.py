from django.urls import path
from main.views import auth_views


app_name = 'main'


urlpatterns = [
    path('auth-login', auth_views.login, name='login'),
    path('auth-logout', auth_views.logout, name='logout'),
    path('auth-refresh', auth_views.refresh_token, name='refresh_token'),
    path('auth-me', auth_views.me, name='me'),
    path('auth-permissions', auth_views.permissions, name='permissions')
]