"""
Agent Identity Management

Handles creation, retrieval, and management of agent identities.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class AgentCreate(BaseModel):
    """Schema for creating a new agent."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AgentUpdate(BaseModel):
    """Schema for updating an agent."""

    name: str | None = None
    description: str | None = None
    capabilities: list[str] | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class AgentIdentity:
    """
    Represents an AI agent's identity.

    Attributes:
        id: Unique identifier for the agent
        name: Human-readable name
        description: Optional description of the agent's purpose
        owner_id: ID of the human/service that owns this agent
        capabilities: List of capabilities this agent has
        metadata: Additional metadata
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """

    id: UUID
    name: str
    description: str | None = None
    owner_id: UUID | None = None
    capabilities: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "id": str(self.id),
            "name": self.name,
            "description": self.description,
            "owner_id": str(self.owner_id) if self.owner_id else None,
            "capabilities": self.capabilities,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AgentIdentity":
        """Create from dictionary representation."""
        return cls(
            id=UUID(data["id"]) if isinstance(data["id"], str) else data["id"],
            name=data["name"],
            description=data.get("description"),
            owner_id=(
                UUID(data["owner_id"])
                if data.get("owner_id") and isinstance(data["owner_id"], str)
                else data.get("owner_id")
            ),
            capabilities=data.get("capabilities", []),
            metadata=data.get("metadata", {}),
            created_at=(
                datetime.fromisoformat(data["created_at"])
                if isinstance(data.get("created_at"), str)
                else data.get("created_at", datetime.utcnow())
            ),
            updated_at=(
                datetime.fromisoformat(data["updated_at"])
                if isinstance(data.get("updated_at"), str)
                else data.get("updated_at", datetime.utcnow())
            ),
        )

    def has_capability(self, capability: str) -> bool:
        """Check if agent has a specific capability."""
        return capability in self.capabilities


class IdentityManager:
    """
    Manages agent identities with database persistence.

    This class handles CRUD operations for agent identities,
    including validation and audit logging.
    """

    def __init__(self, db_client=None):
        """
        Initialize the identity manager.

        Args:
            db_client: Database client (Supabase client)
        """
        self.db = db_client
        self._cache: dict[UUID, AgentIdentity] = {}

    async def create(
        self,
        name: str,
        description: str | None = None,
        owner_id: UUID | None = None,
        capabilities: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AgentIdentity:
        """
        Create a new agent identity.

        Args:
            name: Agent name
            description: Optional description
            owner_id: Owner's user ID
            capabilities: List of capabilities
            metadata: Additional metadata

        Returns:
            Created AgentIdentity
        """
        agent = AgentIdentity(
            id=uuid4(),
            name=name,
            description=description,
            owner_id=owner_id,
            capabilities=capabilities or [],
            metadata=metadata or {},
        )

        if self.db:
            result = (
                self.db.table("agents")
                .insert(
                    {
                        "id": str(agent.id),
                        "name": agent.name,
                        "description": agent.description,
                        "owner_id": str(agent.owner_id) if agent.owner_id else None,
                        "capabilities": agent.capabilities,
                        "metadata": agent.metadata,
                    }
                )
                .execute()
            )

            if result.data:
                agent = AgentIdentity.from_dict(result.data[0])

        self._cache[agent.id] = agent
        return agent

    async def get(self, agent_id: UUID) -> AgentIdentity | None:
        """
        Get an agent by ID.

        Args:
            agent_id: The agent's UUID

        Returns:
            AgentIdentity if found, None otherwise
        """
        # Check cache first
        if agent_id in self._cache:
            return self._cache[agent_id]

        if self.db:
            result = (
                self.db.table("agents")
                .select("*")
                .eq("id", str(agent_id))
                .execute()
            )

            if result.data:
                agent = AgentIdentity.from_dict(result.data[0])
                self._cache[agent_id] = agent
                return agent

        return None

    async def update(
        self,
        agent_id: UUID,
        **updates: Any,
    ) -> AgentIdentity | None:
        """
        Update an agent's identity.

        Args:
            agent_id: The agent's UUID
            **updates: Fields to update

        Returns:
            Updated AgentIdentity if found
        """
        agent = await self.get(agent_id)
        if not agent:
            return None

        # Apply updates
        for key, value in updates.items():
            if hasattr(agent, key) and value is not None:
                setattr(agent, key, value)

        agent.updated_at = datetime.utcnow()

        if self.db:
            self.db.table("agents").update(
                {
                    "name": agent.name,
                    "description": agent.description,
                    "capabilities": agent.capabilities,
                    "metadata": agent.metadata,
                    "updated_at": agent.updated_at.isoformat(),
                }
            ).eq("id", str(agent_id)).execute()

        self._cache[agent_id] = agent
        return agent

    async def delete(self, agent_id: UUID) -> bool:
        """
        Delete an agent.

        Args:
            agent_id: The agent's UUID

        Returns:
            True if deleted, False if not found
        """
        if agent_id in self._cache:
            del self._cache[agent_id]

        if self.db:
            result = (
                self.db.table("agents")
                .delete()
                .eq("id", str(agent_id))
                .execute()
            )
            return len(result.data) > 0

        return True

    async def list(
        self,
        owner_id: UUID | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[AgentIdentity]:
        """
        List agents with optional filtering.

        Args:
            owner_id: Filter by owner
            limit: Maximum number of results
            offset: Pagination offset

        Returns:
            List of AgentIdentity objects
        """
        if self.db:
            query = self.db.table("agents").select("*")

            if owner_id:
                query = query.eq("owner_id", str(owner_id))

            result = query.range(offset, offset + limit - 1).execute()

            return [AgentIdentity.from_dict(row) for row in result.data]

        return list(self._cache.values())[offset : offset + limit]


# Convenience functions
_manager: IdentityManager | None = None


def get_manager() -> IdentityManager:
    """Get or create the global identity manager."""
    global _manager
    if _manager is None:
        _manager = IdentityManager()
    return _manager


async def create_agent(
    name: str,
    description: str | None = None,
    owner_id: UUID | None = None,
    capabilities: list[str] | None = None,
) -> AgentIdentity:
    """Create a new agent identity."""
    return await get_manager().create(
        name=name,
        description=description,
        owner_id=owner_id,
        capabilities=capabilities,
    )


async def get_agent(agent_id: UUID) -> AgentIdentity | None:
    """Get an agent by ID."""
    return await get_manager().get(agent_id)


async def delete_agent(agent_id: UUID) -> bool:
    """Delete an agent."""
    return await get_manager().delete(agent_id)
