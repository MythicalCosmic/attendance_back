import json
from datetime import datetime, timezone

from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin


class JSONOnlyMiddleware(MiddlewareMixin):
    def process_request(self, request):
        if 'application/json' not in request.META.get('HTTP_ACCEPT', ''):
            request.META['HTTP_ACCEPT'] = 'application/json'
        return None

    def process_response(self, request, response):
        if isinstance(response, JsonResponse):
            return response

        status_code = response.status_code

        if 200 <= status_code < 400:
            return response

        try:
            json_data = {
                "status_code": status_code,
                "success": False,
                "message": self._get_status_message(status_code),
                "meta": {
                    "path": request.path,
                    "method": request.method,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            }

            return JsonResponse(json_data, status=status_code)

        except Exception:
            return JsonResponse({
                "status_code": 500,
                "success": False,
                "message": "Internal server error",
            }, status=500)

    def process_exception(self, request, exception):
        return JsonResponse({
            "status_code": 500,
            "success": False,
            "message": "Internal server error",
            "meta": {
                "path": request.path,
                "method": request.method,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        }, status=500)

    @staticmethod
    def _get_status_message(status_code):
        messages = {
            400: "Bad request",
            401: "Authentication required",
            403: "Access forbidden",
            404: "Not found",
            405: "Method not allowed",
            408: "Request timeout",
            409: "Conflict",
            422: "Unprocessable entity",
            429: "Too many requests",
            500: "Internal server error",
            502: "Bad gateway",
            503: "Service unavailable",
            504: "Gateway timeout",
        }
        return messages.get(status_code, f"Error ({status_code})")
