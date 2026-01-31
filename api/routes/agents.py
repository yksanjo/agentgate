"""
Agent Management Routes

CRUD operations for agent identities.
"""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from agentgate.core.identity import (
    AgentIdentity,
    IdentityManager,
    AgentCreate,
    AgentUpdate,
)
from agentgate.core.audit import AuditLogger, AuditAction
from api.middleware.auth import get_current_agent, require_scope


router = APIRouter()


class AgentResponse(BaseModel):
    """Response model for agent data."""

    id: str
    name: str
    description: str | None = None
    owner_id: str | None = None
    capabilities: list[str] = []
    created_at: str
    updated_at: str


class AgentListResponse(BaseModel):
    """Response model for agent list."""

    agents: list[AgentResponse]
    total: int
    offset: int
    limit: int


def get_identity_manager(request: Request) -> IdentityManager:
    """Get identity manager dependency."""
    return IdentityManager(db_client=getattr(request.app.state, "db", None))


def get_audit_logger(request: Request) -> AuditLogger:
    """Get audit logger dependency."""
    return AuditLogger(db_client=getattr(request.app.state, "db", None))


@router.post("", response_model=AgentResponse)
async def create_agent(
    agent_data: AgentCreate,
    request: Request,
    manager: IdentityManager = Depends(get_identity_manager),
    audit: AuditLogger = Depends(get_audit_logger),
):
    """
    Create a new agent identity.

    Requires: agents:write scope
    """
    agent = await manager.create(
        name=agent_data.name,
        description=agent_data.description,
        capabilities=agent_data.capabilities,
        metadata=agent_data.metadata,
    )

    await audit.log(
        action=AuditAction.AGENT_CREATED,
        agent_id=agent.id,
        resource="agents",
        resource_id=str(agent.id),
        ip_address=request.client.host if request.client else None,
    )

    return AgentResponse(
        id=str(agent.id),
        name=agent.name,
        description=agent.description,
        owner_id=str(agent.owner_id) if agent.owner_id else None,
        capabilities=agent.capabilities,
        created_at=agent.created_at.isoformat(),
        updated_at=agent.updated_at.isoformat(),
    )


@router.get("", response_model=AgentListResponse)
async def list_agents(
    offset: int = 0,
    limit: int = 100,
    owner_id: str | None = None,
    manager: IdentityManager = Depends(get_identity_manager),
):
    """
    List agents with optional filtering.

    Requires: agents:read scope
    """
    owner_uuid = UUID(owner_id) if owner_id else None
    agents = await manager.list(owner_id=owner_uuid, limit=limit, offset=offset)

    return AgentListResponse(
        agents=[
            AgentResponse(
                id=str(a.id),
                name=a.name,
                description=a.description,
                owner_id=str(a.owner_id) if a.owner_id else None,
                capabilities=a.capabilities,
                created_at=a.created_at.isoformat(),
                updated_at=a.updated_at.isoformat(),
            )
            for a in agents
        ],
        total=len(agents),
        offset=offset,
        limit=limit,
    )


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    manager: IdentityManager = Depends(get_identity_manager),
):
    """
    Get an agent by ID.

    Requires: agents:read scope
    """
    agent = await manager.get(UUID(agent_id))
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    return AgentResponse(
        id=str(agent.id),
        name=agent.name,
        description=agent.description,
        owner_id=str(agent.owner_id) if agent.owner_id else None,
        capabilities=agent.capabilities,
        created_at=agent.created_at.isoformat(),
        updated_at=agent.updated_at.isoformat(),
    )


@router.patch("/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: str,
    updates: AgentUpdate,
    request: Request,
    manager: IdentityManager = Depends(get_identity_manager),
    audit: AuditLogger = Depends(get_audit_logger),
):
    """
    Update an agent.

    Requires: agents:write scope
    """
    update_data = updates.model_dump(exclude_unset=True)
    agent = await manager.update(UUID(agent_id), **update_data)

    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")

    await audit.log(
        action=AuditAction.AGENT_UPDATED,
        agent_id=agent.id,
        resource="agents",
        resource_id=str(agent.id),
        ip_address=request.client.host if request.client else None,
        metadata={"updates": list(update_data.keys())},
    )

    return AgentResponse(
        id=str(agent.id),
        name=agent.name,
        description=agent.description,
        owner_id=str(agent.owner_id) if agent.owner_id else None,
        capabilities=agent.capabilities,
        created_at=agent.created_at.isoformat(),
        updated_at=agent.updated_at.isoformat(),
    )


@router.delete("/{agent_id}")
async def delete_agent(
    agent_id: str,
    request: Request,
    manager: IdentityManager = Depends(get_identity_manager),
    audit: AuditLogger = Depends(get_audit_logger),
):
    """
    Delete an agent.

    Requires: agents:delete scope
    """
    deleted = await manager.delete(UUID(agent_id))

    if not deleted:
        raise HTTPException(status_code=404, detail="Agent not found")

    await audit.log(
        action=AuditAction.AGENT_DELETED,
        resource="agents",
        resource_id=agent_id,
        ip_address=request.client.host if request.client else None,
    )

    return {"deleted": True, "agent_id": agent_id}
