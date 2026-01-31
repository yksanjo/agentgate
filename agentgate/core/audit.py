"""
Audit Logging

Tracks all authentication and authorization events.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AuditAction(str, Enum):
    """Types of auditable actions."""

    # Agent actions
    AGENT_CREATED = "agent.created"
    AGENT_UPDATED = "agent.updated"
    AGENT_DELETED = "agent.deleted"

    # Key actions
    KEY_CREATED = "key.created"
    KEY_REVOKED = "key.revoked"
    KEY_ROTATED = "key.rotated"
    KEY_USED = "key.used"

    # Token actions
    TOKEN_CREATED = "token.created"
    TOKEN_VERIFIED = "token.verified"
    TOKEN_REVOKED = "token.revoked"
    TOKEN_REFRESHED = "token.refreshed"

    # Auth actions
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    AUTH_DENIED = "auth.denied"

    # Permission actions
    PERMISSION_GRANTED = "permission.granted"
    PERMISSION_DENIED = "permission.denied"


class AuditEventCreate(BaseModel):
    """Schema for creating an audit event."""

    action: str
    agent_id: str | None = None
    resource: str | None = None
    resource_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


@dataclass
class AuditEvent:
    """
    Represents an audit log entry.

    All security-relevant events are logged for compliance
    and forensic analysis.
    """

    id: UUID
    action: str
    agent_id: UUID | None = None
    resource: str | None = None
    resource_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": str(self.id),
            "action": self.action,
            "agent_id": str(self.agent_id) if self.agent_id else None,
            "resource": self.resource,
            "resource_id": self.resource_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AuditEvent":
        """Create from dictionary representation."""
        return cls(
            id=UUID(data["id"]) if isinstance(data["id"], str) else data["id"],
            action=data["action"],
            agent_id=(
                UUID(data["agent_id"])
                if data.get("agent_id") and isinstance(data["agent_id"], str)
                else data.get("agent_id")
            ),
            resource=data.get("resource"),
            resource_id=data.get("resource_id"),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
            metadata=data.get("metadata", {}),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if isinstance(data.get("created_at"), str)
                else data.get("created_at", datetime.utcnow())
            ),
        )


class AuditLogger:
    """
    Logs audit events for security tracking.

    Events are stored in the database and can be queried
    for compliance and forensic analysis.
    """

    def __init__(self, db_client=None):
        """
        Initialize the audit logger.

        Args:
            db_client: Database client (Supabase client)
        """
        self.db = db_client
        self._events: list[AuditEvent] = []  # In-memory buffer

    async def log(
        self,
        action: str | AuditAction,
        agent_id: UUID | None = None,
        resource: str | None = None,
        resource_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """
        Log an audit event.

        Args:
            action: The action being logged
            agent_id: The agent performing the action
            resource: The resource type being accessed
            resource_id: The specific resource ID
            ip_address: Client IP address
            user_agent: Client user agent
            metadata: Additional context

        Returns:
            The created AuditEvent
        """
        if isinstance(action, AuditAction):
            action = action.value

        event = AuditEvent(
            id=uuid4(),
            action=action,
            agent_id=agent_id,
            resource=resource,
            resource_id=resource_id,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {},
        )

        if self.db:
            self.db.table("audit_log").insert(
                {
                    "id": str(event.id),
                    "action": event.action,
                    "agent_id": str(event.agent_id) if event.agent_id else None,
                    "resource": event.resource,
                    "resource_id": event.resource_id,
                    "ip_address": event.ip_address,
                    "user_agent": event.user_agent,
                    "metadata": event.metadata,
                }
            ).execute()
        else:
            self._events.append(event)

        return event

    async def query(
        self,
        agent_id: UUID | None = None,
        action: str | None = None,
        resource: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AuditEvent]:
        """
        Query audit events.

        Args:
            agent_id: Filter by agent
            action: Filter by action type
            resource: Filter by resource type
            start_time: Filter events after this time
            end_time: Filter events before this time
            limit: Maximum results
            offset: Pagination offset

        Returns:
            List of matching AuditEvents
        """
        if self.db:
            query = self.db.table("audit_log").select("*")

            if agent_id:
                query = query.eq("agent_id", str(agent_id))
            if action:
                query = query.eq("action", action)
            if resource:
                query = query.eq("resource", resource)
            if start_time:
                query = query.gte("created_at", start_time.isoformat())
            if end_time:
                query = query.lte("created_at", end_time.isoformat())

            result = (
                query.order("created_at", desc=True)
                .range(offset, offset + limit - 1)
                .execute()
            )

            return [AuditEvent.from_dict(row) for row in result.data]

        # Filter in-memory events
        events = self._events

        if agent_id:
            events = [e for e in events if e.agent_id == agent_id]
        if action:
            events = [e for e in events if e.action == action]
        if resource:
            events = [e for e in events if e.resource == resource]
        if start_time:
            events = [e for e in events if e.created_at >= start_time]
        if end_time:
            events = [e for e in events if e.created_at <= end_time]

        # Sort by time descending
        events = sorted(events, key=lambda e: e.created_at, reverse=True)

        return events[offset : offset + limit]

    async def get_agent_activity(
        self,
        agent_id: UUID,
        limit: int = 50,
    ) -> list[AuditEvent]:
        """Get recent activity for an agent."""
        return await self.query(agent_id=agent_id, limit=limit)

    async def get_auth_failures(
        self,
        start_time: datetime | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        """Get authentication failures for security monitoring."""
        return await self.query(
            action=AuditAction.AUTH_FAILURE.value,
            start_time=start_time,
            limit=limit,
        )


# Global logger instance
_logger: AuditLogger | None = None


def get_logger() -> AuditLogger:
    """Get or create the global audit logger."""
    global _logger
    if _logger is None:
        _logger = AuditLogger()
    return _logger


async def log_event(
    action: str | AuditAction,
    agent_id: UUID | None = None,
    **kwargs: Any,
) -> AuditEvent:
    """Log an audit event using the global logger."""
    return await get_logger().log(action=action, agent_id=agent_id, **kwargs)
