from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from base.helpers.response import APIResponse
from base.helpers.request import get_client_ip, get_user_agent, get_token, parse_body, validate_required
from base.decorators.auth import login_required
from main.services.auth_service import AuthService


@csrf_exempt
@require_http_methods(["POST"])
def login(request):
    data, error = parse_body(request)
    if error:
        return error
    
    errors = validate_required(data, ['email', 'password'])
    if errors:
        return APIResponse.validation_error(errors=errors)
    
    result = AuthService.login(
        email=data['email'].strip().lower(),
        password=data['password'],
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request)
    )
    
    if not result['success']:
        return APIResponse.unauthorized(message=result['message'])
    
    return APIResponse.success(
        data={
            'token': result['token'],
            'user': result['user']  
        },
        message=result['message']
    )


@csrf_exempt
@require_http_methods(["POST"])
@login_required
def logout(request):
    result = AuthService.logout(request.token)
    
    if not result['success']:
        return APIResponse.error(message=result['message'])
    
    return APIResponse.success(message=result['message'])


@csrf_exempt
@require_http_methods(["POST"])
@login_required
def refresh_token(request):
    result = AuthService.refresh_token(
        old_token=request.token,
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request)
    )
    
    if not result['success']:
        return APIResponse.unauthorized(message=result['message'])
    
    return APIResponse.success(
        data={'token': result['token']},
        message=result['message']
    )


@csrf_exempt
@require_http_methods(["GET"])
@login_required
def me(request):
    user = request.user
    
    return APIResponse.success(
        data={
            'id': user.id,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'middle_name': user.middle_name,
            'full_name': user.full_name,
            'permissions': request.permissions
        }
    )


@csrf_exempt
@require_http_methods(["GET"])
@login_required
def permissions(request):
    return APIResponse.success(
        data={'permissions': request.permissions}
    )