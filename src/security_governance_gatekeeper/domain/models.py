"""
Domain models for the Security Gatekeeper.

Contains all core entities, value objects, and enums used throughout the application.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ===========================================
# ENUMS
# ===========================================


class UserRole(str, Enum):
    """
    User roles defining access levels and policies.
    
    Roles are configurable via config/roles.yaml and can be extended
    by adding new entries to the YAML file.
    """

    ADMIN = "admin"
    JUNIOR_INTERN = "junior_intern"


class ViolationType(str, Enum):
    """Types of policy violations that can be logged."""

    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    INVALID_TOKEN = "invalid_token"


class PIIType(str, Enum):
    """
    Types of PII entities that can be detected and redacted.
    
    Maps to Presidio entity types.
    """

    # Common entities
    EMAIL_ADDRESS = "EMAIL_ADDRESS"
    PHONE_NUMBER = "PHONE_NUMBER"
    PERSON = "PERSON"
    CREDIT_CARD = "CREDIT_CARD"
    IP_ADDRESS = "IP_ADDRESS"
    LOCATION = "LOCATION"
    IBAN_CODE = "IBAN_CODE"
    URL = "URL"
    # Italian entities
    IT_FISCAL_CODE = "IT_FISCAL_CODE"
    IT_VAT_CODE = "IT_VAT_CODE"


class SupportedLanguage(str, Enum):
    """
    Languages supported for PII detection.
    
    Based on Presidio's multi-language support with spaCy models:
    - English: en_core_web_sm
    - Italian: it_core_news_sm
    """

    ENGLISH = "en"
    ITALIAN = "it"


# ===========================================
# DOMAIN ENTITIES
# ===========================================


class User(BaseModel):
    """User entity representing an authenticated user."""

    id: UUID = Field(default_factory=uuid4)
    username: str
    email: str
    role: UserRole
    department: Optional[str] = None
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        from_attributes = True


class PIIEntity(BaseModel):
    """
    Represents a detected PII entity in text.
    
    Attributes:
        entity_type: The type of PII detected (email, phone, etc.)
        start: Start position in the original text
        end: End position in the original text
        score: Confidence score of the detection (0.0 - 1.0)
        text: The original text that was detected (for logging only)
    """

    entity_type: PIIType
    start: int
    end: int
    score: float
    text: str  # Original text - never exposed to non-privileged users


class RedactionResult(BaseModel):
    """Result of a PII redaction operation."""

    original_length: int
    redacted_text: str
    entities_found: list[PIIEntity]
    entities_redacted: int
    processing_time_ms: float


class RateLimitResult(BaseModel):
    """Result of a rate limit check."""

    allowed: bool
    remaining: int
    limit: int
    reset_at: datetime
    retry_after_seconds: Optional[int] = None


class AuditEntry(BaseModel):
    """
    Audit log entry for compliance tracking.
    
    Records all relevant metadata about a request for governance purposes.
    """

    id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    # User information
    user_id: str
    username: Optional[str] = None
    user_role: UserRole
    department: Optional[str] = None
    
    # Request information
    action: str
    endpoint: str
    method: str
    request_size: int = 0
    response_size: int = 0
    response_time_ms: float = 0.0
    status_code: int = 200
    
    # PII tracking
    pii_detected: bool = False
    pii_types_found: list[PIIType] = Field(default_factory=list)
    pii_count: int = 0
    
    # Rate limiting
    rate_limit_remaining: Optional[int] = None
    
    # Metadata
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    # Violation tracking
    violation: Optional[ViolationType] = None
    violation_details: Optional[str] = None

    class Config:
        from_attributes = True


class AuditFilter(BaseModel):
    """Filter criteria for querying audit logs."""

    user_id: Optional[str] = None
    username: Optional[str] = None
    role: Optional[UserRole] = None
    department: Optional[str] = None
    action: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    has_violation: Optional[bool] = None
    pii_detected: Optional[bool] = None
    violation_type: Optional[ViolationType] = None


class DepartmentUsageStats(BaseModel):
    """Aggregated usage statistics by department."""

    department: str
    total_requests: int
    unique_users: int
    total_pii_detected: int
    total_violations: int
    avg_response_time_ms: float
