from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from base.helpers.response import APIResponse
from base.helpers.request import parse_body, validate_required
from base.decorators.auth import permission_required
from admins.services.role_service import RoleService


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('role.view')
def role_list(request):
    page = int(request.GET.get('page', 1))
    per_page = int(request.GET.get('per_page', 20))
    search = request.GET.get('search')
    order_by = request.GET.get('order_by', 'name')
    
    result = RoleService.get_list(
        page=page,
        per_page=per_page,
        search=search,
        order_by=order_by
    )
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(
        data=result['roles'],
        meta=result['meta']
    )


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('role.view')
def role_detail(request, role_id):
    result = RoleService.get_by_id(role_id)
    
    if not result['success']:
        return APIResponse.not_found(message=result['message'])
    
    return APIResponse.success(data=result['role'])


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('role.view')
def permission_list(request):
    result = RoleService.get_all_permissions()
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['permissions'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('role.create')
def role_create(request):
    data, error = parse_body(request)
    if error:
        return error
    
    errors = validate_required(data, ['name'])
    if errors:
        return APIResponse.validation_error(errors=errors)
    
    result = RoleService.create(
        name=data['name'],
        description=data.get('description'),
        permission_ids=data.get('permission_ids', [])
    )
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.created(data=result['role'])


@csrf_exempt
@require_http_methods(["PUT", "PATCH"])
@permission_required('role.edit')
def role_update(request, role_id):
    data, error = parse_body(request)
    if error:
        return error
    
    result = RoleService.update(
        role_id=role_id,
        name=data.get('name'),
        description=data.get('description')
    )
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['role'])


@csrf_exempt
@require_http_methods(["PUT"])
@permission_required('role.edit')
def role_update_permissions(request, role_id):
    data, error = parse_body(request)
    if error:
        return error
    
    permission_ids = data.get('permission_ids', [])
    
    if not isinstance(permission_ids, list):
        return APIResponse.validation_error(
            errors={'permission_ids': 'permission_ids must be a list'}
        )
    
    result = RoleService.update_permissions(role_id, permission_ids)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['role'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('role.edit')
def role_add_permissions(request, role_id):
    data, error = parse_body(request)
    if error:
        return error
    
    permission_ids = data.get('permission_ids', [])
    
    if not isinstance(permission_ids, list):
        return APIResponse.validation_error(
            errors={'permission_ids': 'permission_ids must be a list'}
        )
    
    result = RoleService.add_permissions(role_id, permission_ids)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['role'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('role.edit')
def role_remove_permissions(request, role_id):
    data, error = parse_body(request)
    if error:
        return error
    
    permission_ids = data.get('permission_ids', [])
    
    if not isinstance(permission_ids, list):
        return APIResponse.validation_error(
            errors={'permission_ids': 'permission_ids must be a list'}
        )
    
    result = RoleService.remove_permissions(role_id, permission_ids)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['role'])


@csrf_exempt
@require_http_methods(["DELETE"])
@permission_required('role.delete')
def role_delete(request, role_id):
    result = RoleService.delete(role_id)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(message=result['message'])