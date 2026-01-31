"""
API Key Management Routes

Endpoints for creating, listing, and revoking API keys.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from agentgate.core.keys import APIKeyManager, APIKeyCreate, APIKeyResponse
from agentgate.core.audit import AuditLogger, AuditAction


router = APIRouter()


class CreateKeyRequest(BaseModel):
    """Request body for creating an API key."""

    agent_id: str
    name: str = Field(..., min_length=1, max_length=255)
    scopes: list[str] = Field(default_factory=lambda: ["*"])
    expires_in_days: int | None = Field(default=None, ge=1, le=365)


class CreateKeyResponse(BaseModel):
    """Response for newly created key (includes the key!)."""

    id: str
    agent_id: str
    key_prefix: str
    name: str
    scopes: list[str]
    expires_at: str | None
    created_at: str
    key: str  # Only returned on creation!


class KeyInfo(BaseModel):
    """Key info without the actual key."""

    id: str
    agent_id: str
    key_prefix: str
    name: str
    scopes: list[str]
    expires_at: str | None
    created_at: str
    last_used_at: str | None


def get_key_manager(request: Request) -> APIKeyManager:
    """Get key manager dependency."""
    return APIKeyManager(db_client=getattr(request.app.state, "db", None))


def get_audit_logger(request: Request) -> AuditLogger:
    """Get audit logger dependency."""
    return AuditLogger(db_client=getattr(request.app.state, "db", None))


@router.post("", response_model=CreateKeyResponse)
async def create_key(
    key_data: CreateKeyRequest,
    request: Request,
    manager: APIKeyManager = Depends(get_key_manager),
    audit: AuditLogger = Depends(get_audit_logger),
):
    """
    Create a new API key for an agent.

    **Important**: The key is only returned once. Store it securely!

    Requires: keys:write scope
    """
    api_key, full_key = await manager.create(
        agent_id=UUID(key_data.agent_id),
        name=key_data.name,
        scopes=key_data.scopes,
        expires_in_days=key_data.expires_in_days,
    )

    await audit.log(
        action=AuditAction.KEY_CREATED,
        agent_id=UUID(key_data.agent_id),
        resource="api_keys",
        resource_id=str(api_key.id),
        ip_address=request.client.host if request.client else None,
        metadata={"key_prefix": api_key.key_prefix},
    )

    return CreateKeyResponse(
        id=str(api_key.id),
        agent_id=str(api_key.agent_id),
        key_prefix=api_key.key_prefix,
        name=api_key.name,
        scopes=api_key.scopes,
        expires_at=api_key.expires_at.isoformat() if api_key.expires_at else None,
        created_at=api_key.created_at.isoformat(),
        key=full_key,
    )


@router.get("/agent/{agent_id}", response_model=list[KeyInfo])
async def list_keys_for_agent(
    agent_id: str,
    manager: APIKeyManager = Depends(get_key_manager),
):
    """
    List all API keys for an agent.

    Requires: keys:read scope
    """
    keys = await manager.list_for_agent(UUID(agent_id))

    return [
        KeyInfo(
            id=str(k.id),
            agent_id=str(k.agent_id),
            key_prefix=k.key_prefix,
            name=k.name,
            scopes=k.scopes,
            expires_at=k.expires_at.isoformat() if k.expires_at else None,
            created_at=k.created_at.isoformat(),
            last_used_at=k.last_used_at.isoformat() if k.last_used_at else None,
        )
        for k in keys
    ]


@router.delete("/{key_id}")
async def revoke_key(
    key_id: str,
    request: Request,
    manager: APIKeyManager = Depends(get_key_manager),
    audit: AuditLogger = Depends(get_audit_logger),
):
    """
    Revoke an API key.

    Requires: keys:delete scope
    """
    revoked = await manager.revoke(UUID(key_id))

    if not revoked:
        raise HTTPException(status_code=404, detail="Key not found")

    await audit.log(
        action=AuditAction.KEY_REVOKED,
        resource="api_keys",
        resource_id=key_id,
        ip_address=request.client.host if request.client else None,
    )

    return {"revoked": True, "key_id": key_id}


@router.post("/{key_id}/rotate", response_model=CreateKeyResponse)
async def rotate_key(
    key_id: str,
    expires_in_days: int | None = None,
    request: Request = None,
    manager: APIKeyManager = Depends(get_key_manager),
    audit: AuditLogger = Depends(get_audit_logger),
):
    """
    Rotate an API key (revoke old, create new).

    Returns the new key. Store it securely!

    Requires: keys:write scope
    """
    result = await manager.rotate(UUID(key_id), expires_in_days=expires_in_days)

    if not result:
        raise HTTPException(status_code=404, detail="Key not found")

    new_key, full_key = result

    await audit.log(
        action=AuditAction.KEY_ROTATED,
        agent_id=new_key.agent_id,
        resource="api_keys",
        resource_id=str(new_key.id),
        ip_address=request.client.host if request and request.client else None,
        metadata={"old_key_id": key_id, "new_key_prefix": new_key.key_prefix},
    )

    return CreateKeyResponse(
        id=str(new_key.id),
        agent_id=str(new_key.agent_id),
        key_prefix=new_key.key_prefix,
        name=new_key.name,
        scopes=new_key.scopes,
        expires_at=new_key.expires_at.isoformat() if new_key.expires_at else None,
        created_at=new_key.created_at.isoformat(),
        key=full_key,
    )
