"""
Mock Authentication Middleware.

Extracts user info from HTTP headers for testing/demo purposes.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Mock authentication middleware that extracts user info from headers.
    
    Headers:
        X-User-ID: User identifier
        X-User-Role: User role (admin, junior_intern)
        X-Department: Department name
    """

    async def dispatch(self, request: Request, call_next):
        # Extract auth info from headers (mock authentication)
        request.state.user_id = request.headers.get("X-User-ID")
        request.state.user_role = request.headers.get("X-User-Role")
        request.state.department = request.headers.get("X-Department")
        
        return await call_next(request)
