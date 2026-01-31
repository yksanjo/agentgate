"""
AgentGate - Agent Authentication Service

Identity and authentication for AI agents with support for:
- Agent identity management
- API key generation and rotation
- JWT token management
- Capability-based permissions
- Agent-to-agent authentication
"""

from agentgate.core.identity import AgentIdentity, create_agent, get_agent, delete_agent
from agentgate.core.keys import APIKeyManager, generate_api_key, verify_api_key
from agentgate.core.tokens import TokenManager, create_token, verify_token
from agentgate.core.permissions import Permission, PermissionSet, check_permission
from agentgate.core.audit import AuditLogger, log_event

__version__ = "0.1.0"
__all__ = [
    # Identity
    "AgentIdentity",
    "create_agent",
    "get_agent",
    "delete_agent",
    # Keys
    "APIKeyManager",
    "generate_api_key",
    "verify_api_key",
    # Tokens
    "TokenManager",
    "create_token",
    "verify_token",
    # Permissions
    "Permission",
    "PermissionSet",
    "check_permission",
    # Audit
    "AuditLogger",
    "log_event",
]


class AgentAuth:
    """
    Main SDK class for AgentGate authentication.

    Usage:
        auth = AgentAuth(api_key="ag_xxx")
        token = auth.get_token()

        # Verify another agent
        is_valid = auth.verify_agent(agent_id="...")
    """

    def __init__(
        self,
        api_key: str | None = None,
        base_url: str = "https://agentgate.railway.app",
    ):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self._token: str | None = None
        self._agent_id: str | None = None

        if api_key:
            self._authenticate()

    def _authenticate(self) -> None:
        """Authenticate with the API key and get agent info."""
        import httpx

        response = httpx.post(
            f"{self.base_url}/api/v1/auth/token",
            headers={"X-API-Key": self.api_key},
        )
        response.raise_for_status()
        data = response.json()
        self._token = data["token"]
        self._agent_id = data["agent_id"]

    @property
    def agent_id(self) -> str | None:
        """Get the authenticated agent's ID."""
        return self._agent_id

    @property
    def token(self) -> str | None:
        """Get the current JWT token."""
        return self._token

    def get_token(self, scopes: list[str] | None = None) -> str:
        """
        Get a JWT token for the authenticated agent.

        Args:
            scopes: Optional list of scopes to request

        Returns:
            JWT token string
        """
        import httpx

        response = httpx.post(
            f"{self.base_url}/api/v1/tokens",
            headers={"X-API-Key": self.api_key},
            json={"scopes": scopes or []},
        )
        response.raise_for_status()
        return response.json()["token"]

    def verify_agent(self, agent_id: str) -> dict:
        """
        Verify another agent's identity.

        Args:
            agent_id: The agent ID to verify

        Returns:
            Agent information if valid
        """
        import httpx

        response = httpx.get(
            f"{self.base_url}/api/v1/agents/{agent_id}",
            headers={"Authorization": f"Bearer {self._token}"},
        )
        response.raise_for_status()
        return response.json()

    def verify_token(self, token: str) -> dict:
        """
        Verify a JWT token.

        Args:
            token: The JWT token to verify

        Returns:
            Token claims if valid
        """
        import httpx

        response = httpx.post(
            f"{self.base_url}/api/v1/verify",
            json={"token": token},
        )
        response.raise_for_status()
        return response.json()
