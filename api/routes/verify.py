"""
Token Verification Routes

Public endpoints for verifying tokens and API keys.
"""

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from agentgate.core.tokens import TokenManager, TokenExpiredError, TokenInvalidError
from agentgate.core.keys import APIKeyManager
from agentgate.core.audit import AuditLogger, AuditAction


router = APIRouter()


class VerifyTokenRequest(BaseModel):
    """Request body for token verification."""

    token: str


class VerifyTokenResponse(BaseModel):
    """Response from token verification."""

    valid: bool
    agent_id: str | None = None
    scopes: list[str] = []
    capabilities: list[str] = []
    expires_at: str | None = None
    issuer: str | None = None
    error: str | None = None


class VerifyKeyRequest(BaseModel):
    """Request body for API key verification."""

    api_key: str


class VerifyKeyResponse(BaseModel):
    """Response from API key verification."""

    valid: bool
    agent_id: str | None = None
    key_prefix: str | None = None
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


@router.post("/token", response_model=VerifyTokenResponse)
async def verify_token(
    verify_data: VerifyTokenRequest,
    request: Request,
    token_manager: TokenManager = Depends(get_token_manager),
    audit: AuditLogger = Depends(get_audit_logger),
):
    """
    Verify a JWT token.

    This endpoint is public - no authentication required.
    Used by other services to verify agent tokens.
    """
    try:
        decoded = token_manager.verify(verify_data.token)

        await audit.log(
            action=AuditAction.TOKEN_VERIFIED,
            agent_id=decoded.agent_id,
            resource="tokens",
            ip_address=request.client.host if request.client else None,
            metadata={"result": "valid"},
        )

        return VerifyTokenResponse(
            valid=True,
            agent_id=str(decoded.agent_id),
            scopes=decoded.scopes,
            capabilities=decoded.capabilities,
            expires_at=decoded.expires_at.isoformat(),
            issuer=decoded.issuer,
        )

    except TokenExpiredError:
        await audit.log(
            action=AuditAction.TOKEN_VERIFIED,
            ip_address=request.client.host if request.client else None,
            metadata={"result": "expired"},
        )
        return VerifyTokenResponse(
            valid=False,
            error="Token has expired",
        )

    except TokenInvalidError as e:
        await audit.log(
            action=AuditAction.TOKEN_VERIFIED,
            ip_address=request.client.host if request.client else None,
            metadata={"result": "invalid", "error": str(e)},
        )
        return VerifyTokenResponse(
            valid=False,
            error=str(e),
        )

    except Exception as e:
        return VerifyTokenResponse(
            valid=False,
            error=f"Verification failed: {e}",
        )


@router.post("/key", response_model=VerifyKeyResponse)
async def verify_api_key(
    verify_data: VerifyKeyRequest,
    request: Request,
    key_manager: APIKeyManager = Depends(get_key_manager),
    audit: AuditLogger = Depends(get_audit_logger),
):
    """
    Verify an API key.

    This endpoint is public - no authentication required.
    Used to validate API keys without exchanging for a token.
    """
    api_key = await key_manager.verify(verify_data.api_key)

    if api_key:
        await audit.log(
            action=AuditAction.KEY_USED,
            agent_id=api_key.agent_id,
            resource="api_keys",
            resource_id=str(api_key.id),
            ip_address=request.client.host if request.client else None,
            metadata={"result": "valid"},
        )

        return VerifyKeyResponse(
            valid=True,
            agent_id=str(api_key.agent_id),
            key_prefix=api_key.key_prefix,
            scopes=api_key.scopes,
            expires_at=api_key.expires_at.isoformat() if api_key.expires_at else None,
        )
    else:
        await audit.log(
            action=AuditAction.AUTH_FAILURE,
            ip_address=request.client.host if request.client else None,
            metadata={"result": "invalid_key"},
        )

        return VerifyKeyResponse(
            valid=False,
            error="Invalid or expired API key",
        )


@router.get("/health")
async def verify_health():
    """
    Verify endpoint health check.

    Use this to check if the verification service is available.
    """
    return {"status": "healthy", "service": "verify"}
