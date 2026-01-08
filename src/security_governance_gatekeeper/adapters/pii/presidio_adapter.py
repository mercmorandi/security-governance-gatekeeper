"""
Presidio Adapter for PII Detection and Redaction.

Implements the PIIRedactorPort using Microsoft Presidio with YAML configuration
for no-code setup. Supports English and Italian languages.
"""

import logging
import time
from pathlib import Path
from typing import Optional

from presidio_analyzer import AnalyzerEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig

from security_governance_gatekeeper.domain.models import (
    PIIEntity,
    PIIType,
    RedactionResult,
    SupportedLanguage,
)
from security_governance_gatekeeper.interfaces.pii_redactor import PIIRedactorPort

logger = logging.getLogger(__name__)


class PresidioAdapter(PIIRedactorPort):
    """
    PII Redactor implementation using Microsoft Presidio with YAML configuration.
    
    Loads configuration from config/presidio.yaml for no-code setup.
    """

    # Mapping from Presidio entity types to our PIIType enum
    ENTITY_TYPE_MAPPING: dict[str, PIIType] = {
        "EMAIL_ADDRESS": PIIType.EMAIL_ADDRESS,
        "PHONE_NUMBER": PIIType.PHONE_NUMBER,
        "PERSON": PIIType.PERSON,
        "LOCATION": PIIType.LOCATION,
        "IT_FISCAL_CODE": PIIType.IT_FISCAL_CODE,
    }

    # Redaction labels for each entity type
    REDACTION_LABELS: dict[PIIType, str] = {
        PIIType.EMAIL_ADDRESS: "[REDACTED_EMAIL]",
        PIIType.PHONE_NUMBER: "[REDACTED_PHONE]",
        PIIType.PERSON: "[REDACTED_NAME]",
        PIIType.LOCATION: "[REDACTED_LOCATION]",
        PIIType.IT_FISCAL_CODE: "[REDACTED_CODICE_FISCALE]",
    }

    def __init__(self, config_path: str = "config/presidio.yaml"):
        """Initialize the Presidio adapter with YAML configuration."""
        config_file = Path(config_path)
        
        if not config_file.exists():
            raise FileNotFoundError(f"Presidio configuration file not found: {config_path}")
        
        logger.info(f"Loading Presidio configuration from: {config_path}")
        
        # Create analyzer engine from YAML configuration
        self._analyzer = AnalyzerEngineProvider(
            analyzer_engine_conf_file=str(config_file)
        ).create_engine()
        
        self._anonymizer = AnonymizerEngine()
        
        logger.info("Presidio adapter initialized with YAML configuration")

    async def detect(
        self,
        text: str,
        language: SupportedLanguage = SupportedLanguage.ENGLISH,
    ) -> list[PIIEntity]:
        """Detect PII entities in text using the specified language."""
        if not text:
            return []

        lang_code = language.value
        
        # Filter entities based on language
        entities_to_search = list(self.ENTITY_TYPE_MAPPING.keys())
        if lang_code != "it":
            # Remove Italian-specific entities when not using Italian
            entities_to_search = [e for e in entities_to_search if not e.startswith("IT_")]
        
        results = self._analyzer.analyze(
            text=text,
            language=lang_code,
            entities=entities_to_search,
        )
        
        logger.info(f"Presidio [{lang_code}]: {len(text)} chars → {len(results)} entities")
        for r in results:
            logger.debug(f"  {r.entity_type}: '{text[r.start:r.end]}' (score={r.score:.2f})")

        entities = []
        for result in results:
            if result.entity_type in self.ENTITY_TYPE_MAPPING:
                entities.append(
                    PIIEntity(
                        entity_type=self.ENTITY_TYPE_MAPPING[result.entity_type],
                        start=result.start,
                        end=result.end,
                        score=result.score,
                        text=text[result.start:result.end],
                    )
                )

        return entities

    async def redact(
        self,
        text: str,
        language: SupportedLanguage = SupportedLanguage.ENGLISH,
        entities_to_redact: Optional[list[PIIType]] = None,
    ) -> RedactionResult:
        """Redact PII from text using the specified language."""
        start_time = time.perf_counter()
        
        if not text:
            return RedactionResult(
                original_length=0,
                redacted_text="",
                entities_found=[],
                entities_redacted=0,
                processing_time_ms=0.0,
            )

        lang_code = language.value
        entities = await self.detect(text, language=language)

        if entities_to_redact:
            entities = [e for e in entities if e.entity_type in entities_to_redact]

        if not entities:
            return RedactionResult(
                original_length=len(text),
                redacted_text=text,
                entities_found=[],
                entities_redacted=0,
                processing_time_ms=(time.perf_counter() - start_time) * 1000,
            )

        # Build operators for anonymization
        operators = {}
        for entity in entities:
            presidio_type = self._get_presidio_type(entity.entity_type)
            label = self.REDACTION_LABELS.get(entity.entity_type, "[REDACTED]")
            operators[presidio_type] = OperatorConfig("replace", {"new_value": label})

        # Filter entities based on language
        entities_to_search = list(self.ENTITY_TYPE_MAPPING.keys())
        if lang_code != "it":
            # Remove Italian-specific entities when not using Italian
            entities_to_search = [e for e in entities_to_search if not e.startswith("IT_")]

        # Run analyzer and anonymizer
        analyzer_results = self._analyzer.analyze(
            text=text,
            language=lang_code,
            entities=entities_to_search,
        )

        anonymized = self._anonymizer.anonymize(
            text=text,
            analyzer_results=analyzer_results,  # type: ignore[arg-type]
            operators=operators,
        )

        return RedactionResult(
            original_length=len(text),
            redacted_text=anonymized.text,
            entities_found=entities,
            entities_redacted=len(entities),
            processing_time_ms=(time.perf_counter() - start_time) * 1000,
        )

    def _get_presidio_type(self, pii_type: PIIType) -> str:
        """Convert PIIType enum to Presidio entity type string."""
        for presidio_type, our_type in self.ENTITY_TYPE_MAPPING.items():
            if our_type == pii_type:
                return presidio_type
        return pii_type.value
