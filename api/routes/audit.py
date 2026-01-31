"""
Audit Log Routes

Endpoints for querying audit logs.
"""

from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel

from agentgate.core.audit import AuditLogger, AuditEvent


router = APIRouter()


class AuditEventResponse(BaseModel):
    """Response model for audit events."""

    id: str
    action: str
    agent_id: str | None = None
    resource: str | None = None
    resource_id: str | None = None
    ip_address: str | None = None
    metadata: dict = {}
    created_at: str


class AuditLogResponse(BaseModel):
    """Response model for audit log query."""

    events: list[AuditEventResponse]
    total: int
    offset: int
    limit: int


def get_audit_logger(request: Request) -> AuditLogger:
    """Get audit logger dependency."""
    return AuditLogger(db_client=getattr(request.app.state, "db", None))


@router.get("", response_model=AuditLogResponse)
async def query_audit_log(
    agent_id: str | None = None,
    action: str | None = None,
    resource: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
    audit: AuditLogger = Depends(get_audit_logger),
):
    """
    Query audit log events.

    Requires: audit:read scope

    Filters:
    - agent_id: Filter by agent
    - action: Filter by action type (e.g., "agent.created")
    - resource: Filter by resource type
    - start_time: Events after this time (ISO format)
    - end_time: Events before this time (ISO format)
    """
    # Parse datetime filters
    start_dt = datetime.fromisoformat(start_time) if start_time else None
    end_dt = datetime.fromisoformat(end_time) if end_time else None
    agent_uuid = UUID(agent_id) if agent_id else None

    events = await audit.query(
        agent_id=agent_uuid,
        action=action,
        resource=resource,
        start_time=start_dt,
        end_time=end_dt,
        limit=limit,
        offset=offset,
    )

    return AuditLogResponse(
        events=[
            AuditEventResponse(
                id=str(e.id),
                action=e.action,
                agent_id=str(e.agent_id) if e.agent_id else None,
                resource=e.resource,
                resource_id=e.resource_id,
                ip_address=e.ip_address,
                metadata=e.metadata,
                created_at=e.created_at.isoformat(),
            )
            for e in events
        ],
        total=len(events),
        offset=offset,
        limit=limit,
    )


@router.get("/agent/{agent_id}", response_model=AuditLogResponse)
async def get_agent_activity(
    agent_id: str,
    limit: int = Query(default=50, ge=1, le=500),
    audit: AuditLogger = Depends(get_audit_logger),
):
    """
    Get recent activity for a specific agent.

    Requires: audit:read scope
    """
    events = await audit.get_agent_activity(UUID(agent_id), limit=limit)

    return AuditLogResponse(
        events=[
            AuditEventResponse(
                id=str(e.id),
                action=e.action,
                agent_id=str(e.agent_id) if e.agent_id else None,
                resource=e.resource,
                resource_id=e.resource_id,
                ip_address=e.ip_address,
                metadata=e.metadata,
                created_at=e.created_at.isoformat(),
            )
            for e in events
        ],
        total=len(events),
        offset=0,
        limit=limit,
    )


@router.get("/failures", response_model=AuditLogResponse)
async def get_auth_failures(
    start_time: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    audit: AuditLogger = Depends(get_audit_logger),
):
    """
    Get authentication failures for security monitoring.

    Requires: audit:admin scope
    """
    start_dt = datetime.fromisoformat(start_time) if start_time else None
    events = await audit.get_auth_failures(start_time=start_dt, limit=limit)

    return AuditLogResponse(
        events=[
            AuditEventResponse(
                id=str(e.id),
                action=e.action,
                agent_id=str(e.agent_id) if e.agent_id else None,
                resource=e.resource,
                resource_id=e.resource_id,
                ip_address=e.ip_address,
                metadata=e.metadata,
                created_at=e.created_at.isoformat(),
            )
            for e in events
        ],
        total=len(events),
        offset=0,
        limit=limit,
    )
