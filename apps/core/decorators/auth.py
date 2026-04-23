from functools import wraps
from typing import Callable

from django.http import HttpRequest

from apps.core.helpers.request import get_token
from apps.core.helpers.response import APIResponse


def _authenticate(request: HttpRequest):
    """Shared authentication logic. Returns (user, permissions) or raises."""
    # Import here to avoid circular imports — auth service registered in Phase 1
    from main.services.auth_service import AuthService

    token = get_token(request)
    if not token:
        return None, None, None

    user, permissions = AuthService.validate_token(token)
    return user, permissions, token


def login_required(view_func: Callable) -> Callable:
    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs):
        user, permissions, token = _authenticate(request)
        if not token:
            return APIResponse.unauthorized(message='Authentication required')
        if not user:
            return APIResponse.unauthorized(message='Invalid or expired token')

        request.user = user
        request.permissions = permissions
        request.token = token
        request.organization_id = getattr(user, 'organization_id', None)

        return view_func(request, *args, **kwargs)

    return wrapper


def permission_required(*required_permissions: str, require_all: bool = True) -> Callable:
    def decorator(view_func: Callable) -> Callable:
        @wraps(view_func)
        def wrapper(request: HttpRequest, *args, **kwargs):
            user, permissions, token = _authenticate(request)
            if not token:
                return APIResponse.unauthorized(message='Authentication required')
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
            request.organization_id = getattr(user, 'organization_id', None)

            return view_func(request, *args, **kwargs)

        return wrapper
    return decorator


def group_access_required(view_func: Callable) -> Callable:
    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs):
        from main.services.auth_service import AuthService

        user, permissions, token = _authenticate(request)
        if not token:
            return APIResponse.unauthorized(message='Authentication required')
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
        request.organization_id = getattr(user, 'organization_id', None)

        return view_func(request, *args, **kwargs)

    return wrapper
