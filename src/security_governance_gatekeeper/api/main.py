"""
Security Gatekeeper - FastAPI Application Entry Point.

AI Security Gatekeeper with PII Redaction, Rate Limiting & Audit Logging.
"""

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi

from security_governance_gatekeeper.adapters.persistence.postgres_audit_adapter import PostgresAuditAdapter
from security_governance_gatekeeper.adapters.pii.presidio_adapter import PresidioAdapter
from security_governance_gatekeeper.adapters.rate_limiting.redis_adapter import RedisRateLimiterAdapter
from security_governance_gatekeeper.api.middleware.auth import AuthMiddleware
from security_governance_gatekeeper.api.middleware.security_gatekeeper import SecurityGatekeeperMiddleware
from security_governance_gatekeeper.api.routers.audit import router as audit_router
from security_governance_gatekeeper.api.routers.demo import router as demo_router
from security_governance_gatekeeper.domain.policies import RolePolicyRegistry


# ===========================================
# LOGGING CONFIGURATION
# ===========================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)

# ===========================================
# CONFIGURATION (from environment variables)
# ===========================================
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://gatekeeper:gatekeeper@localhost:5432/gatekeeper")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
ROLES_CONFIG_PATH = os.getenv("ROLES_CONFIG_PATH", "config/roles.yaml")
DEBUG = os.getenv("DEBUG", "false").lower() in ("true", "1", "yes")


# Adapter instances (module-level singletons)
_pii_redactor = None
_rate_limiter = None
_audit_logger = None


def get_pii_redactor():
    global _pii_redactor
    if _pii_redactor is None:
        _pii_redactor = PresidioAdapter()
    return _pii_redactor


def get_rate_limiter():
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RedisRateLimiterAdapter(redis_url=REDIS_URL)
    return _rate_limiter


def get_audit_logger():
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = PostgresAuditAdapter(database_url=DATABASE_URL, debug=DEBUG)
    return _audit_logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    # Startup - create database tables
    audit_logger = get_audit_logger()
    if hasattr(audit_logger, "create_tables"):
        await audit_logger.create_tables()
    
    yield
    
    # Shutdown - cleanup connections
    if _rate_limiter and hasattr(_rate_limiter, "close"):
        await _rate_limiter.close()
    if _audit_logger and hasattr(_audit_logger, "close"):
        await _audit_logger.close()


def create_app() -> FastAPI:
    """Application factory for creating the FastAPI app."""
    app = FastAPI(
        title="Security Gatekeeper",
        description=(
            "AI Security Gatekeeper with PII Redaction, Rate Limiting & Audit Logging.\n\n"
            "## Features\n"
            "- **PII Redaction**: Automatically detects and masks PII for non-privileged users\n"
            "- **Rate Limiting**: Role-based request quotas with Redis\n"
            "- **Audit Logging**: Full request/response tracking for compliance\n\n"
            "## Supported Languages\n"
            "- **English (en)**: Uses en_core_web_sm spaCy model\n"
            "- **Italian (it)**: Uses it_core_news_sm spaCy model with Italian-specific PII\n\n"
            "## Authentication (Mock)\n"
            "Use these headers to simulate different users:\n"
            "- `X-User-ID`: User identifier (e.g., `user_123`)\n"
            "- `X-User-Role`: `admin` or `junior_intern`\n"
            "- `X-Department`: Department name (e.g., `engineering`)"
        ),
        version="0.1.0",
        lifespan=lifespan,
        debug=DEBUG,
    )

    # Middleware order: LAST added runs FIRST
    # We need: Request → Auth → SecurityGatekeeper → CORS → endpoint
    # So we add: CORS first, then SecurityGatekeeper, then Auth last
    
    # CORS middleware (added first → runs last)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Security Gatekeeper middleware - handles PII, rate limiting, audit
    # (added second → runs after auth)
    policy_registry = RolePolicyRegistry(ROLES_CONFIG_PATH)
    app.add_middleware(
        SecurityGatekeeperMiddleware,
        pii_redactor=get_pii_redactor(),
        rate_limiter=get_rate_limiter(),
        audit_logger=get_audit_logger(),
        policy_registry=policy_registry,
    )

    # Auth middleware - extracts user info from headers
    # (added LAST → runs FIRST, before SecurityGatekeeper)
    app.add_middleware(AuthMiddleware)

    # Health check endpoint
    @app.get("/health", tags=["Health"])
    async def health_check():
        return {"status": "healthy"}

    # Include routers
    app.include_router(demo_router)
    app.include_router(audit_router)

    return app


# Create the application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "security_governance_gatekeeper.api.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )
