"""
Authentication Middleware

Handles API key and JWT authentication for protected routes.
"""

from typing import Callable
from uuid import UUID

from fastapi import Depends, Header, HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware

from agentgate.core.keys import APIKeyManager
from agentgate.core.tokens import TokenManager, DecodedToken
from agentgate.core.permissions import check_permission


class APIKeyMiddleware(BaseHTTPMiddleware):
    """
    Middleware for API key authentication.

    Validates X-API-Key header on protected routes.
    """

    # Routes that don't require authentication
    PUBLIC_PATHS = {
        "/",
        "/health",
        "/docs",
        "/redoc",
        "/openapi.json",
        "/api/v1/verify/token",
        "/api/v1/verify/key",
        "/api/v1/verify/health",
    }

    async def dispatch(self, request: Request, call_next: Callable):
        """Process the request."""
        # Skip auth for public paths
        if request.url.path in self.PUBLIC_PATHS:
            return await call_next(request)

        # Skip auth for OPTIONS (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        # Check for API key or Bearer token
        api_key = request.headers.get("X-API-Key")
        auth_header = request.headers.get("Authorization")

        if not api_key and not auth_header:
            # Continue without auth - routes can decide if they need it
            return await call_next(request)

        # Validate API key if present
        if api_key:
            key_manager = APIKeyManager(
                db_client=getattr(request.app.state, "db", None)
            )
            key_info = await key_manager.verify(api_key)

            if key_info:
                request.state.agent_id = key_info.agent_id
                request.state.scopes = key_info.scopes
                request.state.auth_type = "api_key"

        # Validate Bearer token if present
        elif auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]
            token_manager = TokenManager(
                db_client=getattr(request.app.state, "db", None)
            )

            try:
                decoded = token_manager.verify(token)
                request.state.agent_id = decoded.agent_id
                request.state.scopes = decoded.scopes
                request.state.capabilities = decoded.capabilities
                request.state.auth_type = "bearer"
            except Exception:
                pass  # Invalid token - continue without auth

        return await call_next(request)


async def get_current_agent(request: Request) -> UUID | None:
    """
    Dependency to get the current authenticated agent.

    Returns None if not authenticated.
    """
    return getattr(request.state, "agent_id", None)


async def require_auth(request: Request) -> UUID:
    """
    Dependency that requires authentication.

    Raises 401 if not authenticated.
    """
    agent_id = getattr(request.state, "agent_id", None)
    if not agent_id:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return agent_id


def require_scope(scope: str) -> Callable:
    """
    Dependency factory that requires a specific scope.

    Usage:
        @router.get("/protected")
        async def protected_route(
            agent_id: UUID = Depends(require_scope("agents:read"))
        ):
            ...
    """

    async def scope_checker(request: Request) -> UUID:
        agent_id = await require_auth(request)

        scopes = getattr(request.state, "scopes", [])
        if not check_permission(scope, scopes):
            raise HTTPException(
                status_code=403,
                detail=f"Missing required scope: {scope}",
            )

        return agent_id

    return scope_checker


def require_capability(capability: str) -> Callable:
    """
    Dependency factory that requires a specific capability.

    Usage:
        @router.post("/action")
        async def action(
            agent_id: UUID = Depends(require_capability("memory:write"))
        ):
            ...
    """

    async def capability_checker(request: Request) -> UUID:
        agent_id = await require_auth(request)

        capabilities = getattr(request.state, "capabilities", [])
        if capability not in capabilities:
            raise HTTPException(
                status_code=403,
                detail=f"Missing required capability: {capability}",
            )

        return agent_id

    return capability_checker


async def get_token_info(
    authorization: str = Header(None),
) -> DecodedToken | None:
    """
    Dependency to extract and decode token info.

    Returns None if no token or invalid token.
    """
    if not authorization or not authorization.startswith("Bearer "):
        return None

    token = authorization[7:]
    token_manager = TokenManager()

    try:
        return token_manager.verify(token)
    except Exception:
        return None
