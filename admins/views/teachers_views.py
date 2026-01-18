from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from base.helpers.response import APIResponse
from base.helpers.request import parse_body, validate_required
from base.decorators.auth import permission_required
from admins.services.teacher_service import TeacherService


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('user.view')
def teacher_list(request):
    page = int(request.GET.get('page', 1))
    per_page = int(request.GET.get('per_page', 20))
    search = request.GET.get('search')
    is_active = request.GET.get('is_active')
    group_id = request.GET.get('group_id')
    order_by = request.GET.get('order_by', 'first_name')

    if is_active is not None:
        is_active = is_active.lower() in ('true', '1', 'yes')
    
    if group_id:
        try:
            group_id = int(group_id)
        except ValueError:
            group_id = None
    
    result = TeacherService.get_list(
        page=page,
        per_page=per_page,
        search=search,
        is_active=is_active,
        group_id=group_id,
        order_by=order_by
    )
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(
        data=result['teachers'],
        meta=result['meta']
    )


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('user.view')
def teacher_detail(request, teacher_id):
    result = TeacherService.get_by_id(teacher_id)
    
    if not result['success']:
        return APIResponse.not_found(message=result['message'])
    
    return APIResponse.success(data=result['teacher'])


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('user.view')
def teacher_active_list(request):
    result = TeacherService.get_all_active()
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['teachers'])


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('user.view')
def teacher_available_for_group(request, group_id):
    result = TeacherService.get_available_for_group(group_id)
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['teachers'])


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('user.view')
def teacher_stats(request):
    result = TeacherService.get_stats()
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['stats'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('user.create')
def teacher_create(request):
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
    
    result = TeacherService.create(
        email=data['email'],
        password=data['password'],
        first_name=data['first_name'],
        last_name=data['last_name'],
        middle_name=data.get('middle_name'),
        group_ids=data.get('group_ids', []),
        is_active=data.get('is_active', True)
    )
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.created(data=result['teacher'])


@csrf_exempt
@require_http_methods(["PUT", "PATCH"])
@permission_required('user.edit')
def teacher_update(request, teacher_id):
    data, error = parse_body(request)
    if error:
        return error
    
    result = TeacherService.update(
        teacher_id=teacher_id,
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
    
    return APIResponse.success(data=result['teacher'])


@csrf_exempt
@require_http_methods(["PUT"])
@permission_required('user.edit')
def teacher_update_password(request, teacher_id):
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
    
    result = TeacherService.update_password(teacher_id, data['password'])
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(message=result['message'])


@csrf_exempt
@require_http_methods(["PUT"])
@permission_required('user.edit')
def teacher_update_groups(request, teacher_id):
    data, error = parse_body(request)
    if error:
        return error
    
    group_ids = data.get('group_ids', [])
    
    if not isinstance(group_ids, list):
        return APIResponse.validation_error(
            errors={'group_ids': 'group_ids must be a list'}
        )
    
    result = TeacherService.update_groups(teacher_id, group_ids)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['teacher'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('user.edit')
def teacher_add_to_group(request, teacher_id, group_id):
    result = TeacherService.add_to_group(teacher_id, group_id)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['teacher'])


@csrf_exempt
@require_http_methods(["DELETE"])
@permission_required('user.edit')
def teacher_remove_from_group(request, teacher_id, group_id):
    result = TeacherService.remove_from_group(teacher_id, group_id)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['teacher'])


@csrf_exempt
@require_http_methods(["DELETE"])
@permission_required('user.delete')
def teacher_delete(request, teacher_id):
    result = TeacherService.delete(teacher_id)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(message=result['message'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('user.edit')
def teacher_restore(request, teacher_id):
    result = TeacherService.restore(teacher_id)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['teacher'])