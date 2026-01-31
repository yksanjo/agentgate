"""
Token Management Routes

Endpoints for creating and managing JWT tokens.
"""

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Header, Request
from pydantic import BaseModel, Field

from agentgate.core.tokens import TokenManager, TokenCreate, TokenResponse
from agentgate.core.keys import APIKeyManager
from agentgate.core.audit import AuditLogger, AuditAction


router = APIRouter()


class TokenRequest(BaseModel):
    """Request body for creating a token."""

    scopes: list[str] = Field(default_factory=list)
    expires_in_seconds: int = Field(default=3600, ge=60, le=86400)


class TokenFromKeyRequest(BaseModel):
    """Request body for getting token from API key."""

    api_key: str


class TokenInfo(BaseModel):
    """Response with token information."""

    token: str
    token_type: str = "Bearer"
    expires_at: str
    agent_id: str
    scopes: list[str]


class TokenVerifyRequest(BaseModel):
    """Request body for token verification."""

    token: str


class TokenVerifyResponse(BaseModel):
    """Response from token verification."""

    valid: bool
    agent_id: str | None = None
    scopes: list[str] = []
    expires_at: str | None = None
    error: str | None = None


def get_token_manager(request: Request) -> TokenManager:
    """Get token manager dependency."""
    return TokenManager(db_client=getattr(request.app.state, "db", None))


def get_key_manager(request: Request) -> APIKeyManager:
    """Get key manager dependency."""
    return APIKeyManager(db_client=getattr(request.app.state, "db", None))


def get_audit_logger(request: Request) -> AuditLogger:
    """Get audit logger dependency."""
    return AuditLogger(db_client=getattr(request.app.state, "db", None))


@router.post("", response_model=TokenInfo)
async def create_token(
    token_data: TokenRequest,
    request: Request,
    x_api_key: str = Header(...),
    key_manager: APIKeyManager = Depends(get_key_manager),
    token_manager: TokenManager = Depends(get_token_manager),
    audit: AuditLogger = Depends(get_audit_logger),
):
    """
    Create a JWT token using API key authentication.

    Pass your API key in the X-API-Key header.
    """
    # Verify API key
    api_key = await key_manager.verify(x_api_key)
    if not api_key:
        await audit.log(
            action=AuditAction.AUTH_FAILURE,
            ip_address=request.client.host if request.client else None,
            metadata={"reason": "invalid_api_key"},
        )
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Determine scopes (intersection of requested and allowed)
    scopes = token_data.scopes or api_key.scopes
    if api_key.scopes != ["*"]:
        scopes = [s for s in scopes if s in api_key.scopes or "*" in api_key.scopes]

    # Create token
    token, expires_at = token_manager.create(
        agent_id=api_key.agent_id,
        scopes=scopes,
        expires_in_seconds=token_data.expires_in_seconds,
    )

    await audit.log(
        action=AuditAction.TOKEN_CREATED,
        agent_id=api_key.agent_id,
        resource="tokens",
        ip_address=request.client.host if request.client else None,
        metadata={"scopes": scopes},
    )

    return TokenInfo(
        token=token,
        token_type="Bearer",
        expires_at=expires_at.isoformat(),
        agent_id=str(api_key.agent_id),
        scopes=scopes,
    )


@router.post("/from-key", response_model=TokenInfo)
async def token_from_api_key(
    key_data: TokenFromKeyRequest,
    request: Request,
    key_manager: APIKeyManager = Depends(get_key_manager),
    token_manager: TokenManager = Depends(get_token_manager),
    audit: AuditLogger = Depends(get_audit_logger),
):
    """
    Exchange an API key for a JWT token.

    Alternative to using the X-API-Key header.
    """
    # Verify API key
    api_key = await key_manager.verify(key_data.api_key)
    if not api_key:
        await audit.log(
            action=AuditAction.AUTH_FAILURE,
            ip_address=request.client.host if request.client else None,
            metadata={"reason": "invalid_api_key"},
        )
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Create token with all key scopes
    token, expires_at = token_manager.create(
        agent_id=api_key.agent_id,
        scopes=api_key.scopes,
    )

    await audit.log(
        action=AuditAction.TOKEN_CREATED,
        agent_id=api_key.agent_id,
        resource="tokens",
        ip_address=request.client.host if request.client else None,
    )

    return TokenInfo(
        token=token,
        token_type="Bearer",
        expires_at=expires_at.isoformat(),
        agent_id=str(api_key.agent_id),
        scopes=api_key.scopes,
    )


@router.post("/refresh", response_model=TokenInfo)
async def refresh_token(
    request: Request,
    authorization: str = Header(...),
    token_manager: TokenManager = Depends(get_token_manager),
    audit: AuditLogger = Depends(get_audit_logger),
):
    """
    Refresh a JWT token.

    Pass the current token in the Authorization header as Bearer token.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    old_token = authorization[7:]  # Remove "Bearer " prefix

    try:
        new_token, expires_at = token_manager.refresh(old_token)
        decoded = token_manager.decode_without_verification(new_token)

        await audit.log(
            action=AuditAction.TOKEN_REFRESHED,
            agent_id=UUID(decoded["agent_id"]),
            resource="tokens",
            ip_address=request.client.host if request.client else None,
        )

        return TokenInfo(
            token=new_token,
            token_type="Bearer",
            expires_at=expires_at.isoformat(),
            agent_id=decoded["agent_id"],
            scopes=decoded.get("scopes", []),
        )
    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


@router.post("/revoke")
async def revoke_token(
    request: Request,
    authorization: str = Header(...),
    token_manager: TokenManager = Depends(get_token_manager),
    audit: AuditLogger = Depends(get_audit_logger),
):
    """
    Revoke a JWT token.

    Pass the token to revoke in the Authorization header.
    """
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")

    token = authorization[7:]

    try:
        decoded = token_manager.decode_without_verification(token)
        revoked = token_manager.revoke(token)

        if revoked:
            await audit.log(
                action=AuditAction.TOKEN_REVOKED,
                agent_id=UUID(decoded["agent_id"]),
                resource="tokens",
                ip_address=request.client.host if request.client else None,
            )

        return {"revoked": revoked}
    except Exception:
        return {"revoked": False}
