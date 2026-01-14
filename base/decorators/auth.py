from functools import wraps
from typing import Callable
from django.http import HttpRequest
from base.helpers.request import get_token
from base.helpers.response import APIResponse
from main.services.auth_service import AuthService


def login_required(view_func: Callable) -> Callable:
    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs):
        token = get_token(request)
        if not token:
            return APIResponse.unauthorized(message='Authentication required')
        
        user, permissions = AuthService.validate_token(token)
        if not user:
            return APIResponse.unauthorized(message='Invalid or expired token')
        request.user = user
        request.permissions = permissions
        request.token = token
        
        return view_func(request, *args, **kwargs)
    
    return wrapper


def permission_required(*required_permissions: str, require_all: bool = True) -> Callable:
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs):
            token = get_token(request)
            if not token:
                return APIResponse.unauthorized(message='Authentication required')
            
            user, permissions = AuthService.validate_token(token)
            if not user:
                return APIResponse.unauthorized(message='Invalid or expired token')
            
            if require_all:
                has_permission = all(p in permissions for p in required_permissions)
            else:
                has_permission = any(p in permissions for p in required_permissions)
            
            if not has_permission:
                return APIResponse.forbidden(
                    message=f'Missing required permission(s): {", ".join(required_permissions)}'
                )
            
            request.user = user
            request.permissions = permissions
            request.token = token
            
            return view_func(request, *args, **kwargs)
        
        return wrapper
    return decorator


def group_access_required(view_func: Callable) -> Callable:
    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs):
        token = get_token(request)
        if not token:
            return APIResponse.unauthorized(message='Authentication required')
        
        user, permissions = AuthService.validate_token(token)
        if not user:
            return APIResponse.unauthorized(message='Invalid or expired token')
        
        group_id = kwargs.get('group_id')
        if not group_id:
            return APIResponse.bad_request(message='Group ID required')
        
        if 'group.access_all' not in permissions:
            has_access = AuthService.check_group_access(user.id, group_id)
            if not has_access:
                return APIResponse.forbidden(message='No access to this group')
        
        request.user = user
        request.permissions = permissions
        request.token = token
        
        return view_func(request, *args, **kwargs)
    
    return wrapper