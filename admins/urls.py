from django.urls import path
from admins.views import user_views



app_name = 'admins'

urlpatterns = [
    path('users', user_views.user_list, name='user-list'),
    path('users/<int:user_id>', user_views.user_detail, name='user-detail'),
    path('users/create', user_views.user_create, name='user-create'),
    path('users/<int:user_id>/update', user_views.user_update, name='user-update'),
    path('users/<int:user_id>/password', user_views.user_update_password, name='user-update-password'),
    path('users/<int:user_id>/roles', user_views.user_update_roles, name='user-update-roles'),
    path('users/<int:user_id>/groups', user_views.user_update_groups, name='user-update-groups'),
    path('users/<int:user_id>/delete', user_views.user_delete, name='user-delete'),
    path('users/<int:user_id>/restore', user_views.user_restore, name='user-restore'),
]