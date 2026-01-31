"""
API Key Management

Handles generation, storage, and verification of API keys for agents.
"""

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class APIKeyCreate(BaseModel):
    """Schema for creating a new API key."""

    name: str = Field(..., min_length=1, max_length=255)
    scopes: list[str] = Field(default_factory=list)
    expires_in_days: int | None = Field(default=None, ge=1, le=365)


class APIKeyResponse(BaseModel):
    """Schema for API key response (includes the key only on creation)."""

    id: str
    agent_id: str
    key_prefix: str
    name: str
    scopes: list[str]
    expires_at: str | None
    created_at: str
    last_used_at: str | None
    key: str | None = None  # Only included on creation


@dataclass
class APIKey:
    """
    Represents an API key for an agent.

    The actual key is only available at creation time.
    Only the hash is stored for verification.
    """

    id: UUID
    agent_id: UUID
    key_hash: str
    key_prefix: str
    name: str
    scopes: list[str] = field(default_factory=list)
    expires_at: datetime | None = None
    last_used_at: datetime | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": str(self.id),
            "agent_id": str(self.agent_id),
            "key_prefix": self.key_prefix,
            "name": self.name,
            "scopes": self.scopes,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": (
                self.last_used_at.isoformat() if self.last_used_at else None
            ),
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "APIKey":
        """Create from dictionary representation."""
        return cls(
            id=UUID(data["id"]) if isinstance(data["id"], str) else data["id"],
            agent_id=(
                UUID(data["agent_id"])
                if isinstance(data["agent_id"], str)
                else data["agent_id"]
            ),
            key_hash=data["key_hash"],
            key_prefix=data["key_prefix"],
            name=data["name"],
            scopes=data.get("scopes", []),
            expires_at=(
                datetime.fromisoformat(data["expires_at"])
                if data.get("expires_at")
                else None
            ),
            last_used_at=(
                datetime.fromisoformat(data["last_used_at"])
                if data.get("last_used_at")
                else None
            ),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if isinstance(data.get("created_at"), str)
                else data.get("created_at", datetime.utcnow())
            ),
        )

    def is_expired(self) -> bool:
        """Check if the key has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    def has_scope(self, scope: str) -> bool:
        """Check if key has a specific scope."""
        # Wildcard scope grants all permissions
        if "*" in self.scopes:
            return True
        # Check for exact match or prefix match
        for s in self.scopes:
            if s == scope or scope.startswith(f"{s}:"):
                return True
        return False


class APIKeyManager:
    """
    Manages API keys for agents.

    Handles key generation, verification, and rotation.
    Keys are stored as hashes for security.
    """

    KEY_PREFIX = "ag"  # AgentGate
    KEY_LENGTH = 32  # Characters in the random part

    def __init__(self, db_client=None):
        """
        Initialize the key manager.

        Args:
            db_client: Database client (Supabase client)
        """
        self.db = db_client
        self._cache: dict[str, APIKey] = {}  # key_hash -> APIKey

    @staticmethod
    def _generate_key() -> tuple[str, str, str]:
        """
        Generate a new API key.

        Returns:
            Tuple of (full_key, key_prefix, key_hash)
        """
        # Generate random bytes
        random_part = secrets.token_urlsafe(APIKeyManager.KEY_LENGTH)

        # Create the full key
        full_key = f"{APIKeyManager.KEY_PREFIX}_{random_part}"

        # Extract prefix for display (first 8 chars after ag_)
        key_prefix = f"{APIKeyManager.KEY_PREFIX}_{random_part[:8]}"

        # Hash for storage
        key_hash = hashlib.sha256(full_key.encode()).hexdigest()

        return full_key, key_prefix, key_hash

    @staticmethod
    def hash_key(key: str) -> str:
        """Hash an API key for comparison."""
        return hashlib.sha256(key.encode()).hexdigest()

    async def create(
        self,
        agent_id: UUID,
        name: str,
        scopes: list[str] | None = None,
        expires_in_days: int | None = None,
    ) -> tuple[APIKey, str]:
        """
        Create a new API key for an agent.

        Args:
            agent_id: The agent's UUID
            name: Name/description for the key
            scopes: List of permission scopes
            expires_in_days: Days until expiration (None for no expiry)

        Returns:
            Tuple of (APIKey object, full key string)
            The full key is only returned here - store it safely!
        """
        full_key, key_prefix, key_hash = self._generate_key()

        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)

        api_key = APIKey(
            id=uuid4(),
            agent_id=agent_id,
            key_hash=key_hash,
            key_prefix=key_prefix,
            name=name,
            scopes=scopes or ["*"],
            expires_at=expires_at,
        )

        if self.db:
            self.db.table("api_keys").insert(
                {
                    "id": str(api_key.id),
                    "agent_id": str(api_key.agent_id),
                    "key_hash": api_key.key_hash,
                    "key_prefix": api_key.key_prefix,
                    "name": api_key.name,
                    "scopes": api_key.scopes,
                    "expires_at": (
                        api_key.expires_at.isoformat() if api_key.expires_at else None
                    ),
                }
            ).execute()

        self._cache[key_hash] = api_key
        return api_key, full_key

    async def verify(self, key: str) -> APIKey | None:
        """
        Verify an API key and return the associated key info.

        Args:
            key: The full API key string

        Returns:
            APIKey if valid, None if invalid or expired
        """
        # Validate format
        if not key.startswith(f"{self.KEY_PREFIX}_"):
            return None

        key_hash = self.hash_key(key)

        # Check cache
        if key_hash in self._cache:
            api_key = self._cache[key_hash]
            if api_key.is_expired():
                return None
            return api_key

        # Check database
        if self.db:
            result = (
                self.db.table("api_keys")
                .select("*")
                .eq("key_hash", key_hash)
                .execute()
            )

            if result.data:
                api_key = APIKey.from_dict(result.data[0])

                if api_key.is_expired():
                    return None

                # Update last used
                self.db.table("api_keys").update(
                    {"last_used_at": datetime.utcnow().isoformat()}
                ).eq("id", str(api_key.id)).execute()

                self._cache[key_hash] = api_key
                return api_key

        return None

    async def revoke(self, key_id: UUID) -> bool:
        """
        Revoke an API key.

        Args:
            key_id: The key's UUID

        Returns:
            True if revoked, False if not found
        """
        # Remove from cache
        to_remove = None
        for hash_key, api_key in self._cache.items():
            if api_key.id == key_id:
                to_remove = hash_key
                break
        if to_remove:
            del self._cache[to_remove]

        if self.db:
            result = (
                self.db.table("api_keys")
                .delete()
                .eq("id", str(key_id))
                .execute()
            )
            return len(result.data) > 0

        return True

    async def list_for_agent(self, agent_id: UUID) -> list[APIKey]:
        """
        List all API keys for an agent.

        Args:
            agent_id: The agent's UUID

        Returns:
            List of APIKey objects (without the actual keys)
        """
        if self.db:
            result = (
                self.db.table("api_keys")
                .select("*")
                .eq("agent_id", str(agent_id))
                .order("created_at", desc=True)
                .execute()
            )

            return [APIKey.from_dict(row) for row in result.data]

        return [k for k in self._cache.values() if k.agent_id == agent_id]

    async def rotate(
        self,
        key_id: UUID,
        expires_in_days: int | None = None,
    ) -> tuple[APIKey, str] | None:
        """
        Rotate an API key (revoke old, create new).

        Args:
            key_id: The key's UUID to rotate
            expires_in_days: Days until new key expires

        Returns:
            Tuple of (new APIKey, new key string) or None if not found
        """
        # Find the old key
        old_key = None
        for api_key in self._cache.values():
            if api_key.id == key_id:
                old_key = api_key
                break

        if not old_key and self.db:
            result = (
                self.db.table("api_keys")
                .select("*")
                .eq("id", str(key_id))
                .execute()
            )
            if result.data:
                old_key = APIKey.from_dict(result.data[0])

        if not old_key:
            return None

        # Create new key with same properties
        new_key, full_key = await self.create(
            agent_id=old_key.agent_id,
            name=f"{old_key.name} (rotated)",
            scopes=old_key.scopes,
            expires_in_days=expires_in_days,
        )

        # Revoke old key
        await self.revoke(key_id)

        return new_key, full_key


# Convenience functions
_manager: APIKeyManager | None = None


def get_manager() -> APIKeyManager:
    """Get or create the global key manager."""
    global _manager
    if _manager is None:
        _manager = APIKeyManager()
    return _manager


async def generate_api_key(
    agent_id: UUID,
    name: str = "Default Key",
    scopes: list[str] | None = None,
) -> tuple[APIKey, str]:
    """Generate a new API key for an agent."""
    return await get_manager().create(
        agent_id=agent_id,
        name=name,
        scopes=scopes,
    )


async def verify_api_key(key: str) -> APIKey | None:
    """Verify an API key."""
    return await get_manager().verify(key)
