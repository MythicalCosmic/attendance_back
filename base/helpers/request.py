import json
from typing import Any
from django.http import HttpRequest
from .response import APIResponse


def get_client_ip(request: HttpRequest) -> str:
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR', '0.0.0.0')


def get_user_agent(request: HttpRequest) -> str:
    return request.META.get('HTTP_USER_AGENT', 'Unknown')[:200]


def get_token(request: HttpRequest) -> str | None:
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]
    return None


def parse_body(request: HttpRequest) -> tuple[dict | None, Any]:
    if not request.body:
        return {}, None
    
    try:
        return json.loads(request.body), None
    except json.JSONDecodeError:
        return None, APIResponse.bad_request(message='Invalid JSON body')


def validate_required(data: dict, fields: list[str]) -> dict[str, str] | None:
    errors = {}
    for field in fields:
        value = data.get(field)
        if value is None or (isinstance(value, str) and not value.strip()):
            errors[field] = f'{field} is required'
    return errors if errors else None