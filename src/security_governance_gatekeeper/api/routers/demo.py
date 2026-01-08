"""
Demo Router for PII Redaction Testing.

Provides endpoints to test PII detection and redaction in different languages.
"""

from typing import Optional

from fastapi import APIRouter, Header, Query
from pydantic import BaseModel, Field

from security_governance_gatekeeper.domain.models import SupportedLanguage


router = APIRouter(prefix="/demo", tags=["Demo"])


# ===========================================
# REQUEST/RESPONSE MODELS
# ===========================================


class DemoResponse(BaseModel):
    """Response model for demo endpoints."""
    
    query: str = Field(..., description="The original query")
    response: str = Field(..., description="The AI response (may contain PII)")
    language: str = Field(..., description="Language used for PII detection")
    confidence: float = Field(default=0.95, description="Confidence score")
    model: str = Field(default="gpt-4", description="AI model used")


class CustomTextRequest(BaseModel):
    """Request model for custom text analysis."""
    
    text: str = Field(..., description="Text to analyze for PII", min_length=1)


class CustomTextResponse(BaseModel):
    """Response model for custom text analysis."""
    
    original_text: str = Field(..., description="The original text submitted")
    language: str = Field(..., description="Language used for PII detection")


# ===========================================
# SAMPLE DATA
# ===========================================


ENGLISH_SAMPLE = {
    "query": "What are the customer's contact details?",
    "response": (
        "Based on our records, the customer John Smith can be contacted at "
        "john.smith@example.com or by phone at +1 (555) 123-4567. "
        "He lives at 123 Main Street, New York, NY 10001."
    ),
}

ITALIAN_SAMPLE = {
    "query": "Quali sono i dati di contatto del cliente?",
    "response": (
        "In base ai nostri archivi, il cliente Marco Rossi può essere contattato "
        "all'indirizzo marco.rossi@example.it oppure al telefono +39 02 1234567. "
        "Il suo codice fiscale è RSSMRC85M01H501Z. "
        "Risiede in Via Roma 42, 00100 Roma."
    ),
}


# ===========================================
# ENDPOINTS
# ===========================================


@router.get(
    "/english",
    response_model=DemoResponse,
    summary="English PII Demo",
    description=(
        "Returns a sample AI response containing English PII data.\n\n"
        "**PII included:**\n"
        "- Person name (John Smith)\n"
        "- Email address\n"
        "- US phone number\n"
        "- Street address\n\n"
        "**Role-based behavior:**\n"
        "- `admin`: Sees raw PII\n"
        "- `junior_intern`: PII is automatically redacted"
    ),
)
async def demo_english(
    x_user_id: str = Header(
        ...,
        alias="X-User-ID",
        description="User identifier (e.g., user_123)",
    ),
    x_user_role: str = Header(
        ...,
        alias="X-User-Role",
        description="User role: admin or junior_intern",
    ),
    x_department: str = Header(
        ...,
        alias="X-Department",
        description="Department name (e.g., engineering)",
    ),
) -> DemoResponse:
    """
    Demo endpoint with English PII data.
    
    Uses English NLP model (en_core_web_sm) for PII detection.
    """
    return DemoResponse(
        query=ENGLISH_SAMPLE["query"],
        response=ENGLISH_SAMPLE["response"],
        language=SupportedLanguage.ENGLISH.value,
        confidence=0.95,
        model="gpt-4",
    )


@router.get(
    "/italian",
    response_model=DemoResponse,
    summary="Italian PII Demo",
    description=(
        "Returns a sample AI response containing Italian PII data.\n\n"
        "**PII included:**\n"
        "- Person name (Marco Rossi)\n"
        "- Email address\n"
        "- Italian phone number \n"
        "- Codice Fiscale (RSSMRC85M01H501Z)\n"
        "- Italian address\n\n"
        "**Role-based behavior:**\n"
        "- `admin`: Sees raw PII\n"
        "- `junior_intern`: PII is automatically redacted"
    ),
)
async def demo_italian(
    x_user_id: str = Header(
        ...,
        alias="X-User-ID",
        description="User identifier (e.g., user_123)",
    ),
    x_user_role: str = Header(
        ...,
        alias="X-User-Role",
        description="User role: admin or junior_intern",
    ),
    x_department: str = Header(
        ...,
        alias="X-Department",
        description="Department name (e.g., engineering)",
    ),
) -> DemoResponse:
    """
    Demo endpoint with Italian PII data.
    
    Uses Italian NLP model (it_core_news_sm) for PII detection.
    Italian-specific PII includes Codice Fiscale.
    """
    return DemoResponse(
        query=ITALIAN_SAMPLE["query"],
        response=ITALIAN_SAMPLE["response"],
        language=SupportedLanguage.ITALIAN.value,
        confidence=0.95,
        model="gpt-4",
    )


@router.post(
    "/custom",
    response_model=CustomTextResponse,
    summary="Custom Text PII Demo",
    description=(
        "Submit custom text to test PII detection and redaction.\n\n"
        "**Supported Languages:**\n"
        "- `en` (English): Uses en_core_web_sm spaCy model\n"
        "- `it` (Italian): Uses it_core_news_sm spaCy model\n\n"
        "**Role-based behavior:**\n"
        "- `admin`: Sees original text\n"
        "- `junior_intern`: PII is automatically redacted"
    ),
)
async def demo_custom(
    request: CustomTextRequest,
    language: SupportedLanguage = Query(
        default=SupportedLanguage.ENGLISH,
        description="Language for PII detection (en or it)",
    ),
    x_user_id: str = Header(
        ...,
        alias="X-User-ID",
        description="User identifier (e.g., user_123)",
    ),
    x_user_role: str = Header(
        ...,
        alias="X-User-Role",
        description="User role: admin or junior_intern",
    ),
    x_department: str = Header(
        ...,
        alias="X-Department",
        description="Department name (e.g., engineering)",
    ),
) -> CustomTextResponse:
    """
    Custom text endpoint for testing PII detection.
    
    Submit any text and specify the language for analysis.
    The middleware will apply PII redaction based on user role.
    """
    return CustomTextResponse(
        original_text=request.text,
        language=language.value,
    )


@router.get(
    "/languages",
    summary="Supported Languages",
    description="Returns the list of supported languages for PII detection.",
)
async def get_supported_languages() -> dict:
    """
    Returns supported languages for PII detection.
    """
    return {
        "supported_languages": [
            {
                "code": SupportedLanguage.ENGLISH.value,
                "name": "English",
                "nlp_model": "en_core_web_sm",
                "description": "English NLP model with standard PII recognizers",
            },
            {
                "code": SupportedLanguage.ITALIAN.value,
                "name": "Italian",
                "nlp_model": "it_core_news_sm",
                "description": (
                    "Italian NLP model with Italian-specific recognizers "
                    "(Codice Fiscale, addresses, etc.)"
                ),
            },
        ],
    }
