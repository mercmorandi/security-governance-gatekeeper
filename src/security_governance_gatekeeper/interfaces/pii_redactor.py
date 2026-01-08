"""
PII Redactor Port (Interface).

Defines the abstract contract for PII detection and redaction operations.
Supports English and Italian languages via Presidio NLP models.
"""

from abc import ABC, abstractmethod
from typing import Optional

from security_governance_gatekeeper.domain.models import (
    PIIEntity,
    PIIType,
    RedactionResult,
    SupportedLanguage,
)


class PIIRedactorPort(ABC):
    """
    Port (interface) for PII detection and redaction.
    
    Implementations of this port handle the actual detection of personally
    identifiable information in text and redaction.
    
    Supported Languages:
        - English (en): Uses en_core_web_sm spaCy model
        - Italian (it): Uses it_core_news_sm spaCy model with Italian-specific
          recognizers (Codice Fiscale, Partita IVA, etc.)
    """

    @abstractmethod
    async def detect(
        self,
        text: str,
        language: SupportedLanguage = SupportedLanguage.ENGLISH,
    ) -> list[PIIEntity]:
        """
        Detect PII entities in the given text.
        
        Args:
            text: The text to scan for PII
            language: The language of the text (English or Italian).
                     Determines which NLP model and recognizers to use.
            
        Returns:
            List of detected PII entities with their positions and types
        """
        pass

    @abstractmethod
    async def redact(
        self,
        text: str,
        language: SupportedLanguage = SupportedLanguage.ENGLISH,
        entities_to_redact: Optional[list[PIIType]] = None,
    ) -> RedactionResult:
        """
        Redact PII from text.
        
        Detected PII is replaced with labels like [REDACTED_EMAIL].
        
        Args:
            text: The text to process
            language: The language of the text (English or Italian).
                     Determines which NLP model and recognizers to use.
            entities_to_redact: Optional list of specific entity types to redact.
                               If None, all detected PII types are redacted.
                               
        Returns:
            RedactionResult containing the processed text and metadata
        """
        pass



