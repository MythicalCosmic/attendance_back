class ServiceError(Exception):
    """Base for all service-layer errors."""
    pass


class NotFoundError(ServiceError):
    """Entity not found."""
    pass


class ConflictError(ServiceError):
    """Duplicate or conflicting data (e.g., email already exists)."""
    pass


class BusinessRuleError(ServiceError):
    """Business rule violation (e.g., cannot add student to finished group)."""
    pass


class AuthenticationError(ServiceError):
    """Invalid credentials or expired token."""
    pass


class AuthorizationError(ServiceError):
    """Insufficient permissions."""
    pass
