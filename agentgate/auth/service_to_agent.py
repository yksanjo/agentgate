"""
Service-to-Agent Authentication

Handles authentication between services/systems and AI agents.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from agentgate.core.keys import APIKeyManager, APIKey
from agentgate.core.tokens import TokenManager


@dataclass
class ServiceAccount:
    """
    Represents a service account for non-human services.

    Service accounts are used by backend systems, APIs,
    and automated processes to interact with agents.
    """

    id: UUID
    name: str
    description: str | None = None
    scopes: list[str] = field(default_factory=list)
    rate_limit: int = 1000  # Requests per minute
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    active: bool = True


class ServiceAuth:
    """
    Handles service-to-agent authentication.

    Supports:
    - Service account creation and management
    - API key authentication for services
    - Rate limiting per service
    - Service-specific scopes
    """

    def __init__(
        self,
        db_client=None,
        key_manager: APIKeyManager | None = None,
        token_manager: TokenManager | None = None,
    ):
        """
        Initialize service authentication.

        Args:
            db_client: Database client
            key_manager: API key manager
            token_manager: Token manager
        """
        self.db = db_client
        self.key_manager = key_manager or APIKeyManager(db_client)
        self.token_manager = token_manager or TokenManager(db_client=db_client)
        self._service_accounts: dict[UUID, ServiceAccount] = {}
        self._rate_limits: dict[UUID, list[datetime]] = {}

    async def create_service_account(
        self,
        name: str,
        description: str | None = None,
        scopes: list[str] | None = None,
        rate_limit: int = 1000,
    ) -> tuple[ServiceAccount, str]:
        """
        Create a new service account.

        Args:
            name: Service account name
            description: Description
            scopes: Allowed scopes
            rate_limit: Requests per minute

        Returns:
            Tuple of (ServiceAccount, API key)
        """
        account = ServiceAccount(
            id=uuid4(),
            name=name,
            description=description,
            scopes=scopes or ["*"],
            rate_limit=rate_limit,
        )

        if self.db:
            self.db.table("service_accounts").insert(
                {
                    "id": str(account.id),
                    "name": account.name,
                    "description": account.description,
                    "scopes": account.scopes,
                    "rate_limit": account.rate_limit,
                    "metadata": account.metadata,
                }
            ).execute()

        self._service_accounts[account.id] = account

        # Create API key for the service account
        api_key, full_key = await self.key_manager.create(
            agent_id=account.id,  # Using agent_id field for service account
            name=f"Service: {name}",
            scopes=account.scopes,
        )

        return account, full_key

    async def authenticate_service(
        self,
        api_key: str,
    ) -> tuple[ServiceAccount, str] | None:
        """
        Authenticate a service and get a session token.

        Args:
            api_key: The service's API key

        Returns:
            Tuple of (ServiceAccount, JWT token) if valid, None otherwise
        """
        # Verify API key
        key_info = await self.key_manager.verify(api_key)
        if not key_info:
            return None

        # Get service account
        account = await self.get_service_account(key_info.agent_id)
        if not account or not account.active:
            return None

        # Check rate limit
        if not self._check_rate_limit(account.id, account.rate_limit):
            return None

        # Create session token
        token, _ = self.token_manager.create(
            agent_id=account.id,
            scopes=key_info.scopes,
            expires_in_seconds=3600,
            additional_claims={
                "service_account": True,
                "service_name": account.name,
            },
        )

        return account, token

    async def get_service_account(self, account_id: UUID) -> ServiceAccount | None:
        """Get a service account by ID."""
        if account_id in self._service_accounts:
            return self._service_accounts[account_id]

        if self.db:
            result = (
                self.db.table("service_accounts")
                .select("*")
                .eq("id", str(account_id))
                .execute()
            )
            if result.data:
                data = result.data[0]
                account = ServiceAccount(
                    id=UUID(data["id"]),
                    name=data["name"],
                    description=data.get("description"),
                    scopes=data.get("scopes", []),
                    rate_limit=data.get("rate_limit", 1000),
                    metadata=data.get("metadata", {}),
                    created_at=datetime.fromisoformat(data["created_at"]),
                    active=data.get("active", True),
                )
                self._service_accounts[account_id] = account
                return account

        return None

    async def deactivate_service_account(self, account_id: UUID) -> bool:
        """
        Deactivate a service account.

        Args:
            account_id: The account to deactivate

        Returns:
            True if deactivated, False if not found
        """
        if account_id in self._service_accounts:
            self._service_accounts[account_id].active = False

            if self.db:
                self.db.table("service_accounts").update(
                    {"active": False}
                ).eq("id", str(account_id)).execute()

            return True
        return False

    def _check_rate_limit(self, account_id: UUID, limit: int) -> bool:
        """
        Check if request is within rate limit.

        Args:
            account_id: The service account
            limit: Requests per minute allowed

        Returns:
            True if within limit, False if exceeded
        """
        now = datetime.utcnow()
        minute_ago = datetime.utcnow().replace(second=0, microsecond=0)

        if account_id not in self._rate_limits:
            self._rate_limits[account_id] = []

        # Clean old entries
        self._rate_limits[account_id] = [
            t for t in self._rate_limits[account_id] if t > minute_ago
        ]

        # Check limit
        if len(self._rate_limits[account_id]) >= limit:
            return False

        # Record this request
        self._rate_limits[account_id].append(now)
        return True

    async def verify_service_token(self, token: str) -> ServiceAccount | None:
        """
        Verify a service session token.

        Args:
            token: The JWT token

        Returns:
            ServiceAccount if valid, None otherwise
        """
        try:
            decoded = self.token_manager.verify(token)
        except Exception:
            return None

        if not decoded.raw_claims.get("service_account"):
            return None

        return await self.get_service_account(decoded.agent_id)
