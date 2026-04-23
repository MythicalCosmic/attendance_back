from django.utils.deprecation import MiddlewareMixin


class TenantMiddleware(MiddlewareMixin):
    """Sets request.organization and request.organization_id from the authenticated user."""

    def process_request(self, request):
        request.organization = None
        request.organization_id = None

        user = getattr(request, 'user', None)
        if user and hasattr(user, 'organization_id') and user.organization_id:
            request.organization_id = user.organization_id
            request.organization = getattr(user, 'organization', None)

        return None
