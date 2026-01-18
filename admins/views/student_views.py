from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from base.helpers.response import APIResponse
from base.helpers.request import parse_body, validate_required
from base.decorators.auth import permission_required
from admins.services.student_service import StudentService


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('student.view')
def student_list(request):
    page = int(request.GET.get('page', 1))
    per_page = int(request.GET.get('per_page', 20))
    search = request.GET.get('search')
    group_id = request.GET.get('group_id')
    is_active = request.GET.get('is_active')
    order_by = request.GET.get('order_by', 'first_name')
    
    if group_id:
        try:
            group_id = int(group_id)
        except ValueError:
            group_id = None
    
    if is_active is not None:
        is_active = is_active.lower() in ('true', '1', 'yes')
    
    result = StudentService.get_list(
        page=page,
        per_page=per_page,
        search=search,
        group_id=group_id,
        is_active=is_active,
        order_by=order_by
    )
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(
        data=result['students'],
        meta=result['meta']
    )


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('student.view')
def student_detail(request, student_id):
    result = StudentService.get_by_id(student_id)
    
    if not result['success']:
        return APIResponse.not_found(message=result['message'])
    
    return APIResponse.success(data=result['student'])


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('student.view')
def students_by_group(request, group_id):
    is_active = request.GET.get('is_active')
    
    if is_active is not None:
        is_active = is_active.lower() in ('true', '1', 'yes')
    
    result = StudentService.get_by_group(group_id, is_active=is_active)
    
    if not result['success']:
        return APIResponse.not_found(message=result['message'])
    
    return APIResponse.success(
        data={
            'group': result['group'],
            'students': result['students']
        }
    )


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('student.create')
def student_create(request):
    data, error = parse_body(request)
    if error:
        return error
    
    errors = validate_required(data, ['group_id', 'first_name', 'last_name'])
    if errors:
        return APIResponse.validation_error(errors=errors)
    
    result = StudentService.create(
        group_id=data['group_id'],
        first_name=data['first_name'],
        last_name=data['last_name'],
        middle_name=data.get('middle_name'),
        identifier=data.get('identifier'),
        phone=data.get('phone'),
        is_active=data.get('is_active', True)
    )
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.created(data=result['student'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('student.create')
def student_bulk_create(request):
    data, error = parse_body(request)
    if error:
        return error
    
    errors = validate_required(data, ['group_id', 'students'])
    if errors:
        return APIResponse.validation_error(errors=errors)
    
    if not isinstance(data['students'], list):
        return APIResponse.validation_error(
            errors={'students': 'students must be a list'}
        )
    
    if len(data['students']) == 0:
        return APIResponse.validation_error(
            errors={'students': 'students list cannot be empty'}
        )
    
    if len(data['students']) > 100:
        return APIResponse.validation_error(
            errors={'students': 'Cannot create more than 100 students at once'}
        )
    
    result = StudentService.bulk_create(
        group_id=data['group_id'],
        students_data=data['students']
    )
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.created(
        data={
            'students': result['students'],
            'created_count': result['created_count'],
            'errors': result.get('errors', [])
        }
    )


@csrf_exempt
@require_http_methods(["PUT", "PATCH"])
@permission_required('student.edit')
def student_update(request, student_id):
    data, error = parse_body(request)
    if error:
        return error
    
    result = StudentService.update(
        student_id=student_id,
        first_name=data.get('first_name'),
        last_name=data.get('last_name'),
        middle_name=data.get('middle_name'),
        identifier=data.get('identifier'),
        phone=data.get('phone'),
        is_active=data.get('is_active')
    )
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['student'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('student.edit')
def student_transfer(request, student_id):
    data, error = parse_body(request)
    if error:
        return error
    
    errors = validate_required(data, ['group_id'])
    if errors:
        return APIResponse.validation_error(errors=errors)
    
    result = StudentService.transfer_to_group(student_id, data['group_id'])
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['student'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('student.edit')
def student_bulk_transfer(request):
    data, error = parse_body(request)
    if error:
        return error
    
    errors = validate_required(data, ['student_ids', 'group_id'])
    if errors:
        return APIResponse.validation_error(errors=errors)
    
    if not isinstance(data['student_ids'], list):
        return APIResponse.validation_error(
            errors={'student_ids': 'student_ids must be a list'}
        )
    
    result = StudentService.bulk_transfer(
        student_ids=data['student_ids'],
        new_group_id=data['group_id']
    )
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(
        data={'transferred_count': result['transferred_count']},
        message=result['message']
    )


@csrf_exempt
@require_http_methods(["DELETE"])
@permission_required('student.delete')
def student_delete(request, student_id):
    result = StudentService.delete(student_id)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(message=result['message'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('student.delete')
def student_bulk_delete(request):
    data, error = parse_body(request)
    if error:
        return error
    
    errors = validate_required(data, ['student_ids'])
    if errors:
        return APIResponse.validation_error(errors=errors)
    
    if not isinstance(data['student_ids'], list):
        return APIResponse.validation_error(
            errors={'student_ids': 'student_ids must be a list'}
        )
    
    result = StudentService.bulk_delete(data['student_ids'])
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(
        data={'deleted_count': result['deleted_count']},
        message=result['message']
    )


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('student.edit')
def student_restore(request, student_id):
    result = StudentService.restore(student_id)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['student'])