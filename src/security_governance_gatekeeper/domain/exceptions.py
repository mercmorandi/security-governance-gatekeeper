"""
Domain exceptions for the Security Gatekeeper.

Custom exceptions for domain-specific error handling.
"""

from typing import Optional


class DomainException(Exception):
    """Base exception for all domain errors."""

    def __init__(self, message: str, details: Optional[dict] = None):
        super().__init__(message)
        self.message = message
        self.details = details or {}


class RateLimitExceededError(DomainException):
    """Raised when a user exceeds their rate limit quota."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after_seconds: int = 0,
        limit: int = 0,
        remaining: int = 0,
    ):
        super().__init__(
            message,
            details={
                "retry_after_seconds": retry_after_seconds,
                "limit": limit,
                "remaining": remaining,
            },
        )
        self.retry_after_seconds = retry_after_seconds
        self.limit = limit
        self.remaining = remaining


class UnauthorizedAccessError(DomainException):
    """Raised when user attempts to access a resource without proper authorization."""

    def __init__(self, message: str = "Unauthorized access", required_role: Optional[str] = None):
        super().__init__(
            message,
            details={"required_role": required_role} if required_role else {},
        )
        self.required_role = required_role


class PolicyNotFoundError(DomainException):
    """Raised when a role policy cannot be found."""

    def __init__(self, role: str):
        super().__init__(
            f"Policy not found for role: {role}",
            details={"role": role},
        )
        self.role = role


class ConfigurationError(DomainException):
    """Raised when there's an error in configuration."""

    def __init__(self, message: str, config_key: Optional[str] = None):
        super().__init__(
            message,
            details={"config_key": config_key} if config_key else {},
        )
        self.config_key = config_key
