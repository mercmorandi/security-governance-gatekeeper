"""PostgreSQL Adapter for Audit Logging."""

from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Boolean, Float, func, select
from sqlalchemy.dialects.postgresql import ARRAY, UUID as PG_UUID
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from security_governance_gatekeeper.domain.models import (
    AuditEntry,
    DepartmentUsageStats,
    PIIType,
    UserRole,
    ViolationType,
)
from security_governance_gatekeeper.interfaces.audit.audit import AuditLoggerPort


class Base(DeclarativeBase):
    pass


class AuditLogModel(Base):
    """SQLAlchemy model for audit log entries."""
    
    __tablename__ = "audit_logs"

    id = Column(PG_UUID(as_uuid=True), primary_key=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    user_id = Column(String(255), nullable=False, index=True)
    username = Column(String(255), nullable=True)
    user_role = Column(String(50), nullable=False)
    department = Column(String(255), nullable=True, index=True)
    action = Column(String(255), nullable=False)
    endpoint = Column(String(500), nullable=False)
    method = Column(String(10), nullable=False)
    request_size = Column(Integer, default=0)
    response_size = Column(Integer, default=0)
    response_time_ms = Column(Float, default=0.0)
    status_code = Column(Integer, default=200)
    pii_detected = Column(Boolean, default=False)
    pii_types_found = Column(ARRAY(String), default=[])
    pii_count = Column(Integer, default=0)
    rate_limit_remaining = Column(Integer, nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    violation = Column(String(50), nullable=True)
    violation_details = Column(String(1000), nullable=True)


class PostgresAuditAdapter(AuditLoggerPort):
    """Audit logger implementation using PostgreSQL."""

    def __init__(
        self,
        database_url: str = "postgresql+asyncpg://gatekeeper:gatekeeper@localhost:5432/gatekeeper",
        debug: bool = False,
    ):
        self._engine = create_async_engine(database_url, pool_pre_ping=True)
        self._session_factory = async_sessionmaker(
            self._engine, class_=AsyncSession, expire_on_commit=False
        )

    async def create_tables(self) -> None:
        """Create database tables if they don't exist."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def log(self, entry: AuditEntry) -> str:
        """Log an audit entry to PostgreSQL."""
        async with self._session_factory() as session:
            db_entry = AuditLogModel(
                id=entry.id,
                timestamp=entry.timestamp,
                user_id=entry.user_id,
                username=entry.username,
                user_role=entry.user_role.value,
                department=entry.department,
                action=entry.action,
                endpoint=entry.endpoint,
                method=entry.method,
                request_size=entry.request_size,
                response_size=entry.response_size,
                response_time_ms=entry.response_time_ms,
                status_code=entry.status_code,
                pii_detected=entry.pii_detected,
                pii_types_found=[p.value for p in entry.pii_types_found],
                pii_count=entry.pii_count,
                rate_limit_remaining=entry.rate_limit_remaining,
                ip_address=entry.ip_address,
                user_agent=entry.user_agent,
                violation=entry.violation.value if entry.violation else None,
                violation_details=entry.violation_details,
            )
            session.add(db_entry)
            await session.commit()
            return str(entry.id)

    async def get_by_user_id(self, user_id: str, limit: int = 50) -> list[AuditEntry]:
        """Get audit entries for a specific user."""
        async with self._session_factory() as session:
            stmt = (
                select(AuditLogModel)
                .where(AuditLogModel.user_id == user_id)
                .order_by(AuditLogModel.timestamp.desc())
                .limit(limit)
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [self._to_domain(row) for row in rows]

    async def get_usage_by_department(
        self, start_date: datetime, end_date: datetime
    ) -> list[DepartmentUsageStats]:
        """Get aggregated usage statistics grouped by department."""
        async with self._session_factory() as session:
            stmt = (
                select(
                    AuditLogModel.department,
                    func.count(AuditLogModel.id).label("total_requests"),
                    func.count(func.distinct(AuditLogModel.user_id)).label("unique_users"),
                    func.sum(AuditLogModel.pii_count).label("total_pii_detected"),
                    func.count(AuditLogModel.violation).label("total_violations"),
                    func.avg(AuditLogModel.response_time_ms).label("avg_response_time_ms"),
                )
                .where(
                    AuditLogModel.timestamp >= start_date,
                    AuditLogModel.timestamp <= end_date,
                    AuditLogModel.department.isnot(None),
                )
                .group_by(AuditLogModel.department)
            )
            result = await session.execute(stmt)
            rows = result.all()
            return [
                DepartmentUsageStats(
                    department=row.department or "Unknown",
                    total_requests=row.total_requests or 0,
                    unique_users=row.unique_users or 0,
                    total_pii_detected=int(row.total_pii_detected or 0),
                    total_violations=row.total_violations or 0,
                    avg_response_time_ms=float(row.avg_response_time_ms or 0.0),
                )
                for row in rows
            ]

    def _to_domain(self, row: AuditLogModel) -> AuditEntry:
        """Convert SQLAlchemy model to domain entity."""
        # Handle unknown PII types gracefully (e.g., DATE_TIME from old records)
        pii_types = []
        for p in row.pii_types_found or []:
            try:
                pii_types.append(PIIType(p))
            except ValueError:
                pass  # Skip unknown PII types
        
        return AuditEntry(
            id=row.id,  # type: ignore[arg-type]
            timestamp=row.timestamp,  # type: ignore[arg-type]
            user_id=row.user_id,  # type: ignore[arg-type]
            username=row.username,  # type: ignore[arg-type]
            user_role=UserRole(row.user_role),  # type: ignore[arg-type]
            department=row.department,  # type: ignore[arg-type]
            action=row.action,  # type: ignore[arg-type]
            endpoint=row.endpoint,  # type: ignore[arg-type]
            method=row.method,  # type: ignore[arg-type]
            request_size=row.request_size,  # type: ignore[arg-type]
            response_size=row.response_size,  # type: ignore[arg-type]
            response_time_ms=row.response_time_ms,  # type: ignore[arg-type]
            status_code=row.status_code,  # type: ignore[arg-type]
            pii_detected=row.pii_detected,  # type: ignore[arg-type]
            pii_types_found=pii_types,
            pii_count=row.pii_count,  # type: ignore[arg-type]
            rate_limit_remaining=row.rate_limit_remaining,  # type: ignore[arg-type]
            ip_address=row.ip_address,  # type: ignore[arg-type]
            user_agent=row.user_agent,  # type: ignore[arg-type]
            violation=ViolationType(row.violation) if row.violation else None,  # type: ignore[arg-type]
            violation_details=row.violation_details,  # type: ignore[arg-type]
        )

    async def close(self) -> None:
        """Close database connections."""
        await self._engine.dispose()
