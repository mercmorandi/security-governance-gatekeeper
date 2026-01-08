"""Audit Router - Admin endpoints for monitoring usage."""

from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Query


router = APIRouter(prefix="/admin/audit", tags=["Admin - Audit"])


def _get_audit_logger():
    from security_governance_gatekeeper.api.main import get_audit_logger
    return get_audit_logger()


def require_admin(
    x_user_id: str = Header(..., alias="X-User-ID", description="User identifier"),
    x_user_role: str = Header(..., alias="X-User-Role", description="User role (must be 'admin')"),
    x_department: str = Header(..., alias="X-Department", description="Department name"),
) -> str:
    """Require admin role."""
    if x_user_role.lower() != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return x_user_role


@router.get("/logs/{user_id}")
async def get_audit_logs(
    user_id: str,
    _: str = Depends(require_admin),
    limit: int = Query(50, ge=1, le=100, description="Max records to return"),
):
    """
    Get audit logs for a specific user.
    
    **Admin only** - Requires X-User-Role: admin header.
    """
    audit_logger = _get_audit_logger()
    entries = await audit_logger.get_by_user_id(user_id=user_id, limit=limit)
    
    return {
        "user_id": user_id,
        "entries": [
            {
                "id": str(e.id),
                "timestamp": e.timestamp.isoformat(),
                "endpoint": e.endpoint,
                "method": e.method,
                "status_code": e.status_code,
                "pii_detected": e.pii_detected,
                "pii_count": e.pii_count,
            }
            for e in entries
        ],
        "count": len(entries),
    }


@router.get("/usage-by-department")
async def get_usage_by_department(
    _: str = Depends(require_admin),
    days: int = Query(7, ge=1, le=30, description="Number of days to look back"),
):
    """
    Get usage statistics grouped by department.
    
    **Admin only** - Requires X-User-Role: admin header.
    """
    audit_logger = _get_audit_logger()
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=days)
    
    stats = await audit_logger.get_usage_by_department(
        start_date=start_date,
        end_date=end_date,
    )
    
    return {
        "period": {"start": start_date.isoformat(), "end": end_date.isoformat()},
        "departments": [
            {
                "department": s.department,
                "total_requests": s.total_requests,
                "unique_users": s.unique_users,
                "total_pii_detected": s.total_pii_detected,
                "total_violations": s.total_violations,
                "avg_response_time_ms": round(s.avg_response_time_ms, 2),
            }
            for s in stats
        ],
    }
