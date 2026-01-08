"""
Centralized Security Gatekeeper Middleware.

Handles PII redaction, rate limiting, and audit logging in a single middleware.
"""

import json
import time
from typing import Callable, Set

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from security_governance_gatekeeper.domain.models import (
    AuditEntry,
    SupportedLanguage,
    UserRole,
    ViolationType,
)
from security_governance_gatekeeper.domain.policies import RolePolicyRegistry
from security_governance_gatekeeper.interfaces.pii_redactor import PIIRedactorPort
from security_governance_gatekeeper.interfaces.rate_limiter import RateLimiterPort
from security_governance_gatekeeper.interfaces.audit.audit import AuditLoggerPort



class SecurityGatekeeperMiddleware(BaseHTTPMiddleware):
    """
    Middleware that centralizes all security governance concerns:
    - Rate limiting based on user role
    - PII redaction from responses
    - Comprehensive audit logging
    """

    # Paths to exclude from security processing (health checks, docs, etc.)
    EXCLUDED_PATHS: Set[str] = {
        "/health",
        "/health/ready",
        "/health/live",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/favicon.ico",
    }
    
    # Path prefixes to exclude (e.g., admin audit endpoints)
    EXCLUDED_PREFIXES: tuple[str, ...] = (
        "/admin/audit",
    )

    def __init__(
        self,
        app,
        pii_redactor: PIIRedactorPort,
        rate_limiter: RateLimiterPort,
        audit_logger: AuditLoggerPort,
        policy_registry: RolePolicyRegistry,
    ):
        super().__init__(app)
        self.pii_redactor = pii_redactor
        self.rate_limiter = rate_limiter
        self.audit_logger = audit_logger
        self.policy_registry = policy_registry

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        # Skip excluded paths and prefixes
        if request.url.path in self.EXCLUDED_PATHS or request.url.path.startswith(self.EXCLUDED_PREFIXES):
            return await call_next(request)

        start_time = time.time()
        
        # Extract user info from request state (set by auth middleware)
        user_id = getattr(request.state, "user_id")
        user_role_str = getattr(request.state, "user_role")
        department = getattr(request.state, "department")
        
        # Map role string to enum
        user_role = self._map_role(user_role_str)
        
        # Get policy for this role
        policy = self.policy_registry.get_policy(user_role)
        
        # --- Rate Limiting Check ---
        violation = None
        violation_details = None
        rate_limit_remaining = None
        
        if policy.rate_limit is not None:
            rate_result = await self.rate_limiter.check_and_record(
                user_id=user_id,
                policy=policy,
            )
            rate_limit_remaining = rate_result.remaining
            
            if not rate_result.allowed:
                # Rate limit exceeded - return 429 and log violation
                violation = ViolationType.RATE_LIMIT_EXCEEDED
                violation_details = (
                    f"Rate limit exceeded: {policy.rate_limit.requests_per_hour} "
                    f"requests per {policy.rate_limit.window_seconds} seconds"
                )
                
                response_time_ms = (time.time() - start_time) * 1000
                
                # Log the violation
                audit_entry = AuditEntry(
                    user_id=user_id,
                    username=user_id,
                    user_role=user_role,
                    department=department,
                    action="rate_limit_violation",
                    endpoint=request.url.path,
                    method=request.method,
                    request_size=0,
                    response_size=0,
                    response_time_ms=response_time_ms,
                    status_code=429,
                    pii_detected=False,
                    pii_types_found=[],
                    pii_count=0,
                    rate_limit_remaining=0,
                    ip_address=self._get_client_ip(request),
                    user_agent=request.headers.get("user-agent"),
                    violation=violation,
                    violation_details=violation_details,
                )
                await self.audit_logger.log(audit_entry)
                
                return JSONResponse(
                    status_code=429,
                    content={
                        "detail": "Rate limit exceeded",
                        "retry_after_seconds": rate_result.retry_after_seconds,
                    },
                    headers={"Retry-After": str(rate_result.retry_after_seconds or 60)},
                )

        # --- Process Request ---
        # Read request body for audit logging
        request_body = b""
        if request.method in ("POST", "PUT", "PATCH"):
            request_body = await request.body()
            # Recreate request with body for downstream handlers
            async def receive():
                return {"type": "http.request", "body": request_body}
            request._receive = receive

        # Call the actual endpoint
        response = await call_next(request)
        
        response_time_ms = (time.time() - start_time) * 1000
        
        # --- PII Redaction ---
        pii_detected = False
        pii_types_found = []
        pii_count = 0
        response_body = b""
        
        # Only process JSON responses for PII
        content_type = response.headers.get("content-type", "")
        if "application/json" in content_type:
            # Collect response body
            response_body_parts = []
            async for chunk in response.body_iterator:
                response_body_parts.append(chunk)
            response_body = b"".join(response_body_parts)
            
            # Apply PII redaction if enabled for this role
            if policy.pii_redaction_enabled and response_body:
                try:
                    body_text = response_body.decode("utf-8")
                    body_json = json.loads(body_text)
                    
                    # Extract language from response if present (demo endpoints include it)
                    language = self._extract_language(body_json)
                    
                    # Redact PII in the response
                    redacted_json, pii_info = await self._redact_json(body_json, language)
                    
                    pii_detected = pii_info["detected"]
                    pii_types_found = pii_info["types"]
                    pii_count = pii_info["count"]
                    
                    if pii_detected:
                        response_body = json.dumps(redacted_json).encode("utf-8")
                except (json.JSONDecodeError, UnicodeDecodeError):
                    # Not valid JSON, skip redaction
                    pass
            
            # Rebuild response with potentially redacted body
            # Remove Content-Length as it will be recalculated
            new_headers = {
                k: v for k, v in response.headers.items()
                if k.lower() != "content-length"
            }
            response = Response(
                content=response_body,
                status_code=response.status_code,
                headers=new_headers,
                media_type=response.media_type,
            )

        # --- Audit Logging ---
        audit_entry = AuditEntry(
            user_id=user_id,
            username=user_id,
            user_role=user_role,
            department=department,
            action=f"{request.method} {request.url.path}",
            endpoint=request.url.path,
            method=request.method,
            request_size=len(request_body),
            response_size=len(response_body),
            response_time_ms=response_time_ms,
            status_code=response.status_code,
            pii_detected=pii_detected,
            pii_types_found=pii_types_found,
            pii_count=pii_count,
            rate_limit_remaining=rate_limit_remaining,
            ip_address=self._get_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            violation=violation,
            violation_details=violation_details,
        )
        await self.audit_logger.log(audit_entry)

        return response

    async def _redact_json(
        self,
        data,
        language: SupportedLanguage = SupportedLanguage.ENGLISH,
    ) -> tuple:
        """
        Recursively redact PII from JSON data.
        
        Args:
            data: JSON data to redact (dict, list, str, etc.)
            language: Language to use for PII detection
            
        Returns:
            (redacted_data, pii_info)
        """
        pii_info = {"detected": False, "types": [], "count": 0}
        
        if isinstance(data, str):
            # Redact string values using the specified language
            result = await self.pii_redactor.redact(data, language=language)
            if result.entities_found:
                pii_info["detected"] = True
                pii_info["count"] = len(result.entities_found)
                pii_info["types"] = list(set(
                    e.entity_type.value for e in result.entities_found
                ))
            return result.redacted_text, pii_info
            
        elif isinstance(data, dict):
            redacted = {}
            for key, value in data.items():
                redacted_value, child_info = await self._redact_json(value, language)
                redacted[key] = redacted_value
                self._merge_pii_info(pii_info, child_info)
            return redacted, pii_info
            
        elif isinstance(data, list):
            redacted = []
            for item in data:
                redacted_item, child_info = await self._redact_json(item, language)
                redacted.append(redacted_item)
                self._merge_pii_info(pii_info, child_info)
            return redacted, pii_info
            
        else:
            # Numbers, booleans, null - return as-is
            return data, pii_info

    def _merge_pii_info(self, parent: dict, child: dict) -> None:
        """Merge child PII info into parent."""
        if child["detected"]:
            parent["detected"] = True
            parent["count"] += child["count"]
            parent["types"] = list(set(parent["types"] + child["types"]))

    def _extract_language(self, data: dict) -> SupportedLanguage:
        """
        Extract language from response data if present.
        
        Looks for a 'language' field in the response JSON.
        Falls back to English if not found.
        """
        if isinstance(data, dict):
            lang_str = data.get("language", "en")
            if lang_str == "it":
                return SupportedLanguage.ITALIAN
        return SupportedLanguage.ENGLISH

    def _map_role(self, role_str: str) -> UserRole:
        """Map role string to UserRole enum."""
        role_mapping = {
            "admin": UserRole.ADMIN,
            "junior_intern": UserRole.JUNIOR_INTERN,
            "intern": UserRole.JUNIOR_INTERN,
            "developer": UserRole.JUNIOR_INTERN,  # Default non-admin to junior
        }
        return role_mapping.get(role_str.lower(), UserRole.JUNIOR_INTERN)

    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request."""
        # Check for forwarded headers (behind proxy)
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"
