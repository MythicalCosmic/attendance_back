from django.urls import path
from admins.views import user_views, role_views, student_views, group_views



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

    path('roles', role_views.role_list, name='role-list'),
    path('roles/permissions', role_views.permission_list, name='permission-list'),
    path('roles/<int:role_id>', role_views.role_detail, name='role-detail'),
    path('roles/create', role_views.role_create, name='role-create'),
    path('roles/<int:role_id>/update', role_views.role_update, name='role-update'),
    path('roles/<int:role_id>/permissions', role_views.role_update_permissions, name='role-update-permissions'),
    path('roles/<int:role_id>/permissions/add', role_views.role_add_permissions, name='role-add-permissions'),
    path('roles/<int:role_id>/permissions/remove', role_views.role_remove_permissions, name='role-remove-permissions'),
    path('roles/<int:role_id>/delete', role_views.role_delete, name='role-delete'),

    path('students', student_views.student_list, name='student-list'),
    path('students/<int:student_id>', student_views.student_detail, name='student-detail'),
    path('students/create', student_views.student_create, name='student-create'),
    path('students/bulk-create', student_views.student_bulk_create, name='student-bulk-create'),
    path('students/<int:student_id>/update', student_views.student_update, name='student-update'),
    path('students/<int:student_id>/transfer', student_views.student_transfer, name='student-transfer'),
    path('students/bulk-transfer', student_views.student_bulk_transfer, name='student-bulk-transfer'),
    path('students/<int:student_id>/delete', student_views.student_delete, name='student-delete'),
    path('students/bulk-delete', student_views.student_bulk_delete, name='student-bulk-delete'),
    path('students/<int:student_id>/restore', student_views.student_restore, name='student-restore'),
    path('groups/<int:group_id>/students', student_views.students_by_group, name='students-by-group'),

    path('groups', group_views.group_list, name='group-list'),
    path('groups/active', group_views.group_active_list, name='group-active-list'),
    path('groups/stats', group_views.group_stats, name='group-stats'),
    path('groups/<int:group_id>', group_views.group_detail, name='group-detail'),
    path('groups/create', group_views.group_create, name='group-create'),
    path('groups/<int:group_id>/update', group_views.group_update, name='group-update'),
    path('groups/<int:group_id>/finish', group_views.group_finish, name='group-finish'),
    path('groups/<int:group_id>/cancel', group_views.group_cancel, name='group-cancel'),
    path('groups/<int:group_id>/reactivate', group_views.group_reactivate, name='group-reactivate'),
    path('groups/<int:group_id>/users', group_views.group_update_users, name='group-update-users'),
    path('groups/<int:group_id>/users/add', group_views.group_add_users, name='group-add-users'),
    path('groups/<int:group_id>/users/remove', group_views.group_remove_users, name='group-remove-users'),
    path('groups/<int:group_id>/delete', group_views.group_delete, name='group-delete'),
    path('groups/<int:group_id>/students', student_views.students_by_group, name='students-by-group'),
]