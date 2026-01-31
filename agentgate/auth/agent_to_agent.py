"""
Agent-to-Agent Authentication

Handles authentication between AI agents, allowing secure
communication and capability delegation.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from agentgate.core.tokens import TokenManager, DecodedToken


@dataclass
class A2ASession:
    """
    Represents an authenticated session between two agents.

    Used for tracking agent-to-agent communication and
    enforcing delegated permissions.
    """

    session_id: str
    initiator_id: UUID
    responder_id: UUID
    delegated_scopes: list[str]
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class A2AAuth:
    """
    Handles agent-to-agent authentication.

    Supports:
    - Token-based auth (initiator presents token)
    - Mutual authentication (both agents verify each other)
    - Capability delegation (limited scope pass-through)
    """

    def __init__(self, token_manager: TokenManager | None = None):
        """
        Initialize A2A authentication.

        Args:
            token_manager: Token manager for verification
        """
        self.token_manager = token_manager or TokenManager()
        self._sessions: dict[str, A2ASession] = {}

    async def initiate_auth(
        self,
        initiator_token: str,
        responder_id: UUID,
        requested_scopes: list[str] | None = None,
    ) -> tuple[str, str]:
        """
        Initiate authentication with another agent.

        Args:
            initiator_token: The initiating agent's JWT token
            responder_id: The agent to authenticate with
            requested_scopes: Scopes to request from responder

        Returns:
            Tuple of (session_id, challenge_token)
        """
        # Verify initiator's token
        decoded = self.token_manager.verify(initiator_token)

        # Create session
        session_id = f"a2a_{decoded.agent_id}_{responder_id}_{datetime.utcnow().timestamp()}"

        # Determine delegated scopes (intersection of requested and available)
        delegated = requested_scopes or decoded.scopes

        session = A2ASession(
            session_id=session_id,
            initiator_id=decoded.agent_id,
            responder_id=responder_id,
            delegated_scopes=delegated,
        )

        self._sessions[session_id] = session

        # Create challenge token for responder
        challenge_token, _ = self.token_manager.create(
            agent_id=decoded.agent_id,
            scopes=["a2a:challenge"],
            expires_in_seconds=60,  # Short-lived challenge
            additional_claims={
                "session_id": session_id,
                "responder_id": str(responder_id),
            },
        )

        return session_id, challenge_token

    async def respond_to_auth(
        self,
        responder_token: str,
        session_id: str,
        accept: bool = True,
    ) -> str | None:
        """
        Respond to an authentication request.

        Args:
            responder_token: The responding agent's JWT token
            session_id: The session ID from the initiator
            accept: Whether to accept the auth request

        Returns:
            Session token if accepted, None if rejected
        """
        if session_id not in self._sessions:
            return None

        session = self._sessions[session_id]

        # Verify responder's token
        decoded = self.token_manager.verify(responder_token)

        if decoded.agent_id != session.responder_id:
            return None

        if not accept:
            del self._sessions[session_id]
            return None

        # Create session token with delegated scopes
        session_token, _ = self.token_manager.create(
            agent_id=session.initiator_id,
            scopes=session.delegated_scopes,
            expires_in_seconds=3600,  # 1 hour session
            additional_claims={
                "session_id": session_id,
                "a2a": True,
                "responder_id": str(session.responder_id),
            },
        )

        return session_token

    async def verify_session(self, session_token: str) -> A2ASession | None:
        """
        Verify an A2A session token.

        Args:
            session_token: The session token to verify

        Returns:
            A2ASession if valid, None otherwise
        """
        try:
            decoded = self.token_manager.verify(session_token)
        except Exception:
            return None

        session_id = decoded.raw_claims.get("session_id")
        if not session_id or session_id not in self._sessions:
            return None

        return self._sessions[session_id]

    async def end_session(self, session_id: str) -> bool:
        """
        End an A2A session.

        Args:
            session_id: The session to end

        Returns:
            True if session was ended, False if not found
        """
        if session_id in self._sessions:
            del self._sessions[session_id]
            return True
        return False


async def verify_a2a_request(
    token: str,
    expected_capability: str | None = None,
) -> DecodedToken | None:
    """
    Verify an agent-to-agent request.

    Args:
        token: The request token
        expected_capability: Optional capability to require

    Returns:
        DecodedToken if valid, None otherwise
    """
    try:
        manager = TokenManager()
        decoded = manager.verify(token)

        if not decoded.raw_claims.get("a2a"):
            return None

        if expected_capability and not decoded.has_capability(expected_capability):
            return None

        return decoded
    except Exception:
        return None
