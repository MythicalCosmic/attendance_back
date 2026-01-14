# admin_panel/views/user_views.py

from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from base.helpers.response import APIResponse
from base.helpers.request import parse_body, validate_required
from base.decorators.auth import permission_required
from admins.services.user_service import UserService


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('user.view')
def user_list(request):
    page = int(request.GET.get('page', 1))
    per_page = int(request.GET.get('per_page', 20))
    search = request.GET.get('search')
    role_id = request.GET.get('role_id')
    is_active = request.GET.get('is_active')
    order_by = request.GET.get('order_by', '-created_at')
    if is_active is not None:
        is_active = is_active.lower() in ('true', '1', 'yes')
    
    if role_id:
        try:
            role_id = int(role_id)
        except ValueError:
            role_id = None
    
    result = UserService.get_list(
        page=page,
        per_page=per_page,
        search=search,
        role_id=role_id,
        is_active=is_active,
        order_by=order_by
    )
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(
        data=result['users'],
        meta=result['meta']
    )


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('user.view')
def user_detail(request, user_id):
    result = UserService.get_by_id(user_id)
    
    if not result['success']:
        return APIResponse.not_found(message=result['message'])
    
    return APIResponse.success(data=result['user'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('user.create')
def user_create(request):
    data, error = parse_body(request)
    if error:
        return error
    errors = validate_required(data, ['email', 'password', 'first_name', 'last_name'])
    if errors:
        return APIResponse.validation_error(errors=errors)
    if len(data['password']) < 6:
        return APIResponse.validation_error(
            errors={'password': 'Password must be at least 6 characters'}
        )
    
    result = UserService.create(
        email=data['email'],
        password=data['password'],
        first_name=data['first_name'],
        last_name=data['last_name'],
        middle_name=data.get('middle_name'),
        role_ids=data.get('role_ids', []),
        group_ids=data.get('group_ids', []),
        is_active=data.get('is_active', True)
    )
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.created(data=result['user'])


@csrf_exempt
@require_http_methods(["PUT", "PATCH"])
@permission_required('user.edit')
def user_update(request, user_id):
    data, error = parse_body(request)
    if error:
        return error
    
    result = UserService.update(
        user_id=user_id,
        email=data.get('email'),
        first_name=data.get('first_name'),
        last_name=data.get('last_name'),
        middle_name=data.get('middle_name'),
        is_active=data.get('is_active')
    )
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['user'])


@csrf_exempt
@require_http_methods(["PUT"])
@permission_required('user.edit')
def user_update_password(request, user_id):
    data, error = parse_body(request)
    if error:
        return error
    
    errors = validate_required(data, ['password'])
    if errors:
        return APIResponse.validation_error(errors=errors)
    
    if len(data['password']) < 6:
        return APIResponse.validation_error(
            errors={'password': 'Password must be at least 6 characters'}
        )
    
    result = UserService.update_password(user_id, data['password'])
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(message=result['message'])


@csrf_exempt
@require_http_methods(["PUT"])
@permission_required('user.edit')
def user_update_roles(request, user_id):
    data, error = parse_body(request)
    if error:
        return error
    
    role_ids = data.get('role_ids', [])
    
    if not isinstance(role_ids, list):
        return APIResponse.validation_error(
            errors={'role_ids': 'role_ids must be a list'}
        )
    
    result = UserService.update_roles(user_id, role_ids)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['user'])


@csrf_exempt
@require_http_methods(["PUT"])
@permission_required('user.edit')
def user_update_groups(request, user_id):
    data, error = parse_body(request)
    if error:
        return error
    
    group_ids = data.get('group_ids', [])
    
    if not isinstance(group_ids, list):
        return APIResponse.validation_error(
            errors={'group_ids': 'group_ids must be a list'}
        )
    
    result = UserService.update_group_access(user_id, group_ids)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['user'])


@csrf_exempt
@require_http_methods(["DELETE"])
@permission_required('user.delete')
def user_delete(request, user_id):
    if request.user.id == user_id:
        return APIResponse.error(message='Cannot delete your own account')
    
    result = UserService.delete(user_id)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(message=result['message'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('user.edit')
def user_restore(request, user_id):
    result = UserService.restore(user_id)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['user'])