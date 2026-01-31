"""
Human-to-Agent Delegation

Handles human users delegating authority to AI agents.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from agentgate.core.tokens import TokenManager


@dataclass
class Delegation:
    """
    Represents a human delegation to an agent.

    When a human authorizes an agent to act on their behalf,
    a delegation record is created with specific scope limits.
    """

    id: UUID
    human_id: UUID
    agent_id: UUID
    scopes: list[str]
    constraints: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None
    revoked: bool = False
    revoked_at: datetime | None = None

    def is_active(self) -> bool:
        """Check if delegation is still active."""
        if self.revoked:
            return False
        if self.expires_at and datetime.utcnow() > self.expires_at:
            return False
        return True

    def has_scope(self, scope: str) -> bool:
        """Check if delegation includes a scope."""
        if not self.is_active():
            return False
        if "*" in self.scopes:
            return True
        return scope in self.scopes


class HumanDelegation:
    """
    Manages human-to-agent delegation.

    Supports:
    - Creating delegations with scope limits
    - Time-limited delegations
    - Delegation revocation
    - Constraint enforcement (e.g., spending limits)
    """

    def __init__(self, db_client=None, token_manager: TokenManager | None = None):
        """
        Initialize delegation manager.

        Args:
            db_client: Database client
            token_manager: Token manager for creating delegation tokens
        """
        self.db = db_client
        self.token_manager = token_manager or TokenManager()
        self._delegations: dict[UUID, Delegation] = {}

    async def create_delegation(
        self,
        human_id: UUID,
        agent_id: UUID,
        scopes: list[str],
        constraints: dict[str, Any] | None = None,
        expires_in_hours: int | None = None,
    ) -> tuple[Delegation, str]:
        """
        Create a new delegation from human to agent.

        Args:
            human_id: The human user's ID
            agent_id: The agent receiving delegation
            scopes: Scopes being delegated
            constraints: Optional constraints (e.g., spending limits)
            expires_in_hours: Optional expiration

        Returns:
            Tuple of (Delegation, delegation_token)
        """
        expires_at = None
        if expires_in_hours:
            expires_at = datetime.utcnow() + timedelta(hours=expires_in_hours)

        delegation = Delegation(
            id=uuid4(),
            human_id=human_id,
            agent_id=agent_id,
            scopes=scopes,
            constraints=constraints or {},
            expires_at=expires_at,
        )

        if self.db:
            self.db.table("delegations").insert(
                {
                    "id": str(delegation.id),
                    "human_id": str(human_id),
                    "agent_id": str(agent_id),
                    "scopes": scopes,
                    "constraints": constraints or {},
                    "expires_at": expires_at.isoformat() if expires_at else None,
                }
            ).execute()

        self._delegations[delegation.id] = delegation

        # Create delegation token
        token, _ = self.token_manager.create(
            agent_id=agent_id,
            scopes=scopes,
            expires_in_seconds=expires_in_hours * 3600 if expires_in_hours else 86400,
            additional_claims={
                "delegation_id": str(delegation.id),
                "human_id": str(human_id),
                "delegated": True,
                "constraints": constraints or {},
            },
        )

        return delegation, token

    async def revoke_delegation(self, delegation_id: UUID) -> bool:
        """
        Revoke a delegation.

        Args:
            delegation_id: The delegation to revoke

        Returns:
            True if revoked, False if not found
        """
        if delegation_id in self._delegations:
            self._delegations[delegation_id].revoked = True
            self._delegations[delegation_id].revoked_at = datetime.utcnow()

            if self.db:
                self.db.table("delegations").update(
                    {
                        "revoked": True,
                        "revoked_at": datetime.utcnow().isoformat(),
                    }
                ).eq("id", str(delegation_id)).execute()

            return True
        return False

    async def get_delegation(self, delegation_id: UUID) -> Delegation | None:
        """Get a delegation by ID."""
        if delegation_id in self._delegations:
            return self._delegations[delegation_id]

        if self.db:
            result = (
                self.db.table("delegations")
                .select("*")
                .eq("id", str(delegation_id))
                .execute()
            )
            if result.data:
                data = result.data[0]
                delegation = Delegation(
                    id=UUID(data["id"]),
                    human_id=UUID(data["human_id"]),
                    agent_id=UUID(data["agent_id"]),
                    scopes=data["scopes"],
                    constraints=data.get("constraints", {}),
                    created_at=datetime.fromisoformat(data["created_at"]),
                    expires_at=(
                        datetime.fromisoformat(data["expires_at"])
                        if data.get("expires_at")
                        else None
                    ),
                    revoked=data.get("revoked", False),
                )
                self._delegations[delegation_id] = delegation
                return delegation

        return None

    async def list_delegations_for_agent(self, agent_id: UUID) -> list[Delegation]:
        """List all active delegations for an agent."""
        result = []

        if self.db:
            data = (
                self.db.table("delegations")
                .select("*")
                .eq("agent_id", str(agent_id))
                .eq("revoked", False)
                .execute()
            )
            for row in data.data:
                delegation = Delegation(
                    id=UUID(row["id"]),
                    human_id=UUID(row["human_id"]),
                    agent_id=UUID(row["agent_id"]),
                    scopes=row["scopes"],
                    constraints=row.get("constraints", {}),
                    created_at=datetime.fromisoformat(row["created_at"]),
                    expires_at=(
                        datetime.fromisoformat(row["expires_at"])
                        if row.get("expires_at")
                        else None
                    ),
                    revoked=row.get("revoked", False),
                )
                if delegation.is_active():
                    result.append(delegation)
        else:
            result = [
                d
                for d in self._delegations.values()
                if d.agent_id == agent_id and d.is_active()
            ]

        return result

    async def verify_delegation_token(self, token: str) -> Delegation | None:
        """
        Verify a delegation token.

        Args:
            token: The delegation token

        Returns:
            Delegation if valid, None otherwise
        """
        try:
            decoded = self.token_manager.verify(token)
        except Exception:
            return None

        if not decoded.raw_claims.get("delegated"):
            return None

        delegation_id = decoded.raw_claims.get("delegation_id")
        if not delegation_id:
            return None

        delegation = await self.get_delegation(UUID(delegation_id))
        if not delegation or not delegation.is_active():
            return None

        return delegation

    async def check_constraint(
        self,
        delegation_id: UUID,
        constraint_name: str,
        value: Any,
    ) -> bool:
        """
        Check if a value satisfies a delegation constraint.

        Args:
            delegation_id: The delegation to check
            constraint_name: Name of the constraint
            value: Value to check

        Returns:
            True if constraint is satisfied
        """
        delegation = await self.get_delegation(delegation_id)
        if not delegation:
            return False

        if constraint_name not in delegation.constraints:
            return True  # No constraint = allowed

        constraint = delegation.constraints[constraint_name]

        # Handle different constraint types
        if isinstance(constraint, dict):
            if "max" in constraint and value > constraint["max"]:
                return False
            if "min" in constraint and value < constraint["min"]:
                return False
            if "allowed" in constraint and value not in constraint["allowed"]:
                return False
        elif isinstance(constraint, list):
            if value not in constraint:
                return False
        else:
            # Direct comparison
            if value != constraint:
                return False

        return True
