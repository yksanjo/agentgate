"""Authentication protocols for different auth scenarios."""

from agentgate.auth.agent_to_agent import A2AAuth
from agentgate.auth.human_to_agent import HumanDelegation
from agentgate.auth.service_to_agent import ServiceAuth

__all__ = ["A2AAuth", "HumanDelegation", "ServiceAuth"]
