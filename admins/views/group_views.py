# admin_panel/views/group_views.py

from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from base.helpers.response import APIResponse
from base.helpers.request import parse_body, validate_required
from base.decorators.auth import permission_required
from admins.services.group_service import GroupService
from datetime import datetime


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('group.view')
def group_list(request):
    page = int(request.GET.get('page', 1))
    per_page = int(request.GET.get('per_page', 20))
    search = request.GET.get('search')
    is_active = request.GET.get('is_active')
    is_finished = request.GET.get('is_finished')
    is_cancelled = request.GET.get('is_cancelled')
    order_by = request.GET.get('order_by', '-created_at')
    def to_bool(val):
        if val is None:
            return None
        return val.lower() in ('true', '1', 'yes')
    
    result = GroupService.get_list(
        page=page,
        per_page=per_page,
        search=search,
        is_active=to_bool(is_active),
        is_finished=to_bool(is_finished),
        is_cancelled=to_bool(is_cancelled),
        order_by=order_by
    )
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(
        data=result['groups'],
        meta=result['meta']
    )


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('group.view')
def group_detail(request, group_id):
    result = GroupService.get_by_id(group_id)
    
    if not result['success']:
        return APIResponse.not_found(message=result['message'])
    
    return APIResponse.success(data=result['group'])


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('group.view')
def group_active_list(request):
    result = GroupService.get_active_groups()
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['groups'])


@csrf_exempt
@require_http_methods(["GET"])
@permission_required('group.view')
def group_stats(request):
    result = GroupService.get_stats()
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['stats'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('group.create')
def group_create(request):
    data, error = parse_body(request)
    if error:
        return error
    
    errors = validate_required(data, ['name'])
    if errors:
        return APIResponse.validation_error(errors=errors)
    
    start_date = None
    end_date = None
    
    if data.get('start_date'):
        try:
            start_date = datetime.strptime(data['start_date'], '%Y-%m-%d').date()
        except ValueError:
            return APIResponse.validation_error(
                errors={'start_date': 'Invalid date format. Use YYYY-MM-DD'}
            )
    
    if data.get('end_date'):
        try:
            end_date = datetime.strptime(data['end_date'], '%Y-%m-%d').date()
        except ValueError:
            return APIResponse.validation_error(
                errors={'end_date': 'Invalid date format. Use YYYY-MM-DD'}
            )
    
    result = GroupService.create(
        name=data['name'],
        description=data.get('description'),
        start_date=start_date,
        end_date=end_date,
        assigned_user_ids=data.get('assigned_user_ids', [])
    )
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.created(data=result['group'])


@csrf_exempt
@require_http_methods(["PUT", "PATCH"])
@permission_required('group.edit')
def group_update(request, group_id):
    data, error = parse_body(request)
    if error:
        return error

    start_date = None
    end_date = None
    
    if 'start_date' in data:
        if data['start_date']:
            try:
                start_date = datetime.strptime(data['start_date'], '%Y-%m-%d').date()
            except ValueError:
                return APIResponse.validation_error(
                    errors={'start_date': 'Invalid date format. Use YYYY-MM-DD'}
                )
    
    if 'end_date' in data:
        if data['end_date']:
            try:
                end_date = datetime.strptime(data['end_date'], '%Y-%m-%d').date()
            except ValueError:
                return APIResponse.validation_error(
                    errors={'end_date': 'Invalid date format. Use YYYY-MM-DD'}
                )
    
    result = GroupService.update(
        group_id=group_id,
        name=data.get('name'),
        description=data.get('description'),
        start_date=start_date if 'start_date' in data else None,
        end_date=end_date if 'end_date' in data else None
    )
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['group'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('group.edit')
def group_finish(request, group_id):
    result = GroupService.finish_group(group_id)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['group'], message='Group marked as finished')


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('group.edit')
def group_cancel(request, group_id):
    result = GroupService.cancel_group(group_id)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['group'], message='Group cancelled')


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('group.edit')
def group_reactivate(request, group_id):
    result = GroupService.reactivate_group(group_id)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['group'], message='Group reactivated')


@csrf_exempt
@require_http_methods(["PUT"])
@permission_required('group.edit')
def group_update_users(request, group_id):
    data, error = parse_body(request)
    if error:
        return error
    
    user_ids = data.get('user_ids', [])
    
    if not isinstance(user_ids, list):
        return APIResponse.validation_error(
            errors={'user_ids': 'user_ids must be a list'}
        )
    
    result = GroupService.update_assigned_users(group_id, user_ids)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['group'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('group.edit')
def group_add_users(request, group_id):
    data, error = parse_body(request)
    if error:
        return error
    
    user_ids = data.get('user_ids', [])
    
    if not isinstance(user_ids, list):
        return APIResponse.validation_error(
            errors={'user_ids': 'user_ids must be a list'}
        )
    
    result = GroupService.add_assigned_users(group_id, user_ids)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['group'])


@csrf_exempt
@require_http_methods(["POST"])
@permission_required('group.edit')
def group_remove_users(request, group_id):
    data, error = parse_body(request)
    if error:
        return error
    
    user_ids = data.get('user_ids', [])
    
    if not isinstance(user_ids, list):
        return APIResponse.validation_error(
            errors={'user_ids': 'user_ids must be a list'}
        )
    
    result = GroupService.remove_assigned_users(group_id, user_ids)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(data=result['group'])


@csrf_exempt
@require_http_methods(["DELETE"])
@permission_required('group.delete')
def group_delete(request, group_id):
    force = request.GET.get('force', 'false').lower() in ('true', '1', 'yes')
    
    result = GroupService.delete(group_id, force=force)
    
    if not result['success']:
        if 'not found' in result['message'].lower():
            return APIResponse.not_found(message=result['message'])
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(message=result['message'])