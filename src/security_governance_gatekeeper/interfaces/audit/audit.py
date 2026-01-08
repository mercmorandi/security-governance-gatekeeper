"""Audit Logger Port (Interface)."""

from abc import ABC, abstractmethod
from datetime import datetime

from security_governance_gatekeeper.domain.models import (
    AuditEntry,
    DepartmentUsageStats,
)


class AuditLoggerPort(ABC):
    """Port (interface) for audit logging operations."""

    @abstractmethod
    async def log(self, entry: AuditEntry) -> str:
        """Log an audit entry. Returns the ID of the created entry."""
        pass

    @abstractmethod
    async def get_by_user_id(
        self,
        user_id: str,
        limit: int = 50,
    ) -> list[AuditEntry]:
        """Get audit entries for a specific user."""
        pass

    @abstractmethod
    async def get_usage_by_department(
        self,
        start_date: datetime,
        end_date: datetime,
    ) -> list[DepartmentUsageStats]:
        """Get aggregated usage statistics grouped by department."""
        pass
