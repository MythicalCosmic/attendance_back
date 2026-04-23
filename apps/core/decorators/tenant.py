from functools import wraps
from typing import Callable

from django.http import HttpRequest

from apps.core.helpers.response import APIResponse


def tenant_required(view_func: Callable) -> Callable:
    """Ensures request has organization_id set (by auth decorator or middleware)."""
    @wraps(view_func)
    def wrapper(request: HttpRequest, *args, **kwargs):
        if not getattr(request, 'organization_id', None):
            return APIResponse.bad_request(message='Organization context required')
        return view_func(request, *args, **kwargs)

    return wrapper
