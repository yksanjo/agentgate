"""
JWT Token Management

Handles creation and verification of JWT tokens for agent authentication.
"""

import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

import jwt
from pydantic import BaseModel, Field


class TokenCreate(BaseModel):
    """Schema for creating a new token."""

    scopes: list[str] = Field(default_factory=list)
    expires_in_seconds: int = Field(default=3600, ge=60, le=86400)
    claims: dict[str, Any] = Field(default_factory=dict)


class TokenResponse(BaseModel):
    """Schema for token response."""

    token: str
    token_type: str = "Bearer"
    expires_at: str
    agent_id: str
    scopes: list[str]


class TokenClaims(BaseModel):
    """Schema for decoded token claims."""

    agent_id: str
    scopes: list[str]
    iat: int
    exp: int
    iss: str = "agentgate"
    capabilities: list[str] = Field(default_factory=list)


@dataclass
class DecodedToken:
    """Represents a decoded and verified JWT token."""

    agent_id: UUID
    scopes: list[str]
    capabilities: list[str]
    issued_at: datetime
    expires_at: datetime
    issuer: str
    raw_claims: dict[str, Any]

    def is_expired(self) -> bool:
        """Check if the token has expired."""
        return datetime.utcnow() > self.expires_at

    def has_scope(self, scope: str) -> bool:
        """Check if token has a specific scope."""
        if "*" in self.scopes:
            return True
        for s in self.scopes:
            if s == scope or scope.startswith(f"{s}:"):
                return True
        return False

    def has_capability(self, capability: str) -> bool:
        """Check if token has a specific capability."""
        return capability in self.capabilities


class TokenError(Exception):
    """Base exception for token errors."""

    pass


class TokenExpiredError(TokenError):
    """Token has expired."""

    pass


class TokenInvalidError(TokenError):
    """Token is invalid."""

    pass


class TokenManager:
    """
    Manages JWT tokens for agent authentication.

    Supports token creation, verification, and revocation.
    Uses RS256 or HS256 algorithms.
    """

    DEFAULT_ALGORITHM = "HS256"
    DEFAULT_ISSUER = "agentgate"
    DEFAULT_EXPIRY_SECONDS = 3600  # 1 hour

    def __init__(
        self,
        secret_key: str | None = None,
        algorithm: str = DEFAULT_ALGORITHM,
        issuer: str = DEFAULT_ISSUER,
        db_client=None,
    ):
        """
        Initialize the token manager.

        Args:
            secret_key: Secret key for signing (uses env var if not provided)
            algorithm: JWT algorithm (HS256, RS256)
            issuer: Token issuer name
            db_client: Database client for blacklist
        """
        self.secret_key = secret_key or os.environ.get(
            "AGENTGATE_SECRET_KEY", "dev-secret-key-change-in-production"
        )
        self.algorithm = algorithm
        self.issuer = issuer
        self.db = db_client
        self._blacklist: set[str] = set()

    def create(
        self,
        agent_id: UUID,
        scopes: list[str] | None = None,
        capabilities: list[str] | None = None,
        expires_in_seconds: int = DEFAULT_EXPIRY_SECONDS,
        additional_claims: dict[str, Any] | None = None,
    ) -> tuple[str, datetime]:
        """
        Create a new JWT token.

        Args:
            agent_id: The agent's UUID
            scopes: Permission scopes for this token
            capabilities: Agent capabilities to include
            expires_in_seconds: Token lifetime
            additional_claims: Extra claims to include

        Returns:
            Tuple of (token string, expiration datetime)
        """
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=expires_in_seconds)

        payload = {
            "agent_id": str(agent_id),
            "scopes": scopes or ["*"],
            "capabilities": capabilities or [],
            "iat": int(now.timestamp()),
            "exp": int(expires_at.timestamp()),
            "iss": self.issuer,
            "jti": str(UUID(int=int(now.timestamp() * 1000000))),  # Unique token ID
        }

        if additional_claims:
            payload.update(additional_claims)

        token = jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

        return token, expires_at

    def verify(self, token: str) -> DecodedToken:
        """
        Verify and decode a JWT token.

        Args:
            token: The JWT token string

        Returns:
            DecodedToken with claims

        Raises:
            TokenExpiredError: If token has expired
            TokenInvalidError: If token is invalid
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                issuer=self.issuer,
            )
        except jwt.ExpiredSignatureError:
            raise TokenExpiredError("Token has expired")
        except jwt.InvalidTokenError as e:
            raise TokenInvalidError(f"Invalid token: {e}")

        # Check blacklist
        jti = payload.get("jti")
        if jti and jti in self._blacklist:
            raise TokenInvalidError("Token has been revoked")

        if self.db:
            result = (
                self.db.table("token_blacklist")
                .select("id")
                .eq("jti", jti)
                .execute()
            )
            if result.data:
                raise TokenInvalidError("Token has been revoked")

        return DecodedToken(
            agent_id=UUID(payload["agent_id"]),
            scopes=payload.get("scopes", []),
            capabilities=payload.get("capabilities", []),
            issued_at=datetime.fromtimestamp(payload["iat"]),
            expires_at=datetime.fromtimestamp(payload["exp"]),
            issuer=payload.get("iss", self.issuer),
            raw_claims=payload,
        )

    def revoke(self, token: str) -> bool:
        """
        Revoke a token by adding it to the blacklist.

        Args:
            token: The JWT token string

        Returns:
            True if revoked successfully
        """
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_exp": False},  # Allow revoking expired tokens
            )
        except jwt.InvalidTokenError:
            return False

        jti = payload.get("jti")
        if not jti:
            return False

        self._blacklist.add(jti)

        if self.db:
            self.db.table("token_blacklist").insert(
                {
                    "jti": jti,
                    "agent_id": payload.get("agent_id"),
                    "expires_at": datetime.fromtimestamp(payload["exp"]).isoformat(),
                }
            ).execute()

        return True

    def refresh(
        self,
        token: str,
        expires_in_seconds: int = DEFAULT_EXPIRY_SECONDS,
    ) -> tuple[str, datetime]:
        """
        Refresh a token by creating a new one with the same claims.

        Args:
            token: The current JWT token
            expires_in_seconds: New token lifetime

        Returns:
            Tuple of (new token, expiration datetime)
        """
        decoded = self.verify(token)

        # Revoke the old token
        self.revoke(token)

        # Create new token with same claims
        return self.create(
            agent_id=decoded.agent_id,
            scopes=decoded.scopes,
            capabilities=decoded.capabilities,
            expires_in_seconds=expires_in_seconds,
        )

    def decode_without_verification(self, token: str) -> dict[str, Any]:
        """
        Decode a token without verifying signature.
        Useful for inspecting tokens.

        Args:
            token: The JWT token string

        Returns:
            Token payload as dictionary
        """
        return jwt.decode(
            token,
            options={"verify_signature": False},
        )


# Convenience functions
_manager: TokenManager | None = None


def get_manager() -> TokenManager:
    """Get or create the global token manager."""
    global _manager
    if _manager is None:
        _manager = TokenManager()
    return _manager


def create_token(
    agent_id: UUID,
    scopes: list[str] | None = None,
    expires_in_seconds: int = 3600,
) -> tuple[str, datetime]:
    """Create a new JWT token."""
    return get_manager().create(
        agent_id=agent_id,
        scopes=scopes,
        expires_in_seconds=expires_in_seconds,
    )


def verify_token(token: str) -> DecodedToken:
    """Verify and decode a JWT token."""
    return get_manager().verify(token)
