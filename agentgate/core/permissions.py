"""
Permission Management

Capability-based permissions for agent actions.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PermissionLevel(str, Enum):
    """Permission levels for hierarchical access."""

    NONE = "none"
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"

    def __ge__(self, other: "PermissionLevel") -> bool:
        levels = [self.NONE, self.READ, self.WRITE, self.ADMIN]
        return levels.index(self) >= levels.index(other)

    def __gt__(self, other: "PermissionLevel") -> bool:
        levels = [self.NONE, self.READ, self.WRITE, self.ADMIN]
        return levels.index(self) > levels.index(other)


@dataclass
class Permission:
    """
    Represents a single permission/capability.

    Permissions follow a hierarchical format:
    - resource:action (e.g., "memory:read", "agents:write")
    - resource:* for all actions on a resource
    - * for all permissions
    """

    resource: str
    action: str
    conditions: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return f"{self.resource}:{self.action}"

    @classmethod
    def from_string(cls, permission_str: str) -> "Permission":
        """Parse a permission string."""
        if ":" not in permission_str:
            return cls(resource=permission_str, action="*")

        parts = permission_str.split(":", 1)
        return cls(resource=parts[0], action=parts[1])

    def matches(self, other: "Permission") -> bool:
        """Check if this permission grants access to another permission."""
        # Wildcard matches everything
        if self.resource == "*" or self.action == "*":
            if self.resource == "*":
                return True
            return self.resource == other.resource

        # Exact match
        return self.resource == other.resource and self.action == other.action

    def to_scope(self) -> str:
        """Convert to scope string."""
        return str(self)


@dataclass
class PermissionSet:
    """
    A set of permissions for an agent or token.

    Supports hierarchical permission checking and merging.
    """

    permissions: list[Permission] = field(default_factory=list)

    def __contains__(self, permission: Permission | str) -> bool:
        """Check if a permission is granted."""
        if isinstance(permission, str):
            permission = Permission.from_string(permission)

        for p in self.permissions:
            if p.matches(permission):
                return True
        return False

    def add(self, permission: Permission | str) -> None:
        """Add a permission."""
        if isinstance(permission, str):
            permission = Permission.from_string(permission)
        if permission not in self.permissions:
            self.permissions.append(permission)

    def remove(self, permission: Permission | str) -> None:
        """Remove a permission."""
        if isinstance(permission, str):
            permission = Permission.from_string(permission)
        self.permissions = [p for p in self.permissions if not p.matches(permission)]

    def merge(self, other: "PermissionSet") -> "PermissionSet":
        """Merge with another permission set."""
        merged = PermissionSet(permissions=self.permissions.copy())
        for p in other.permissions:
            merged.add(p)
        return merged

    def intersection(self, other: "PermissionSet") -> "PermissionSet":
        """Get intersection with another permission set."""
        result = PermissionSet()
        for p in self.permissions:
            if p in other:
                result.add(p)
        return result

    def to_scopes(self) -> list[str]:
        """Convert to list of scope strings."""
        return [p.to_scope() for p in self.permissions]

    @classmethod
    def from_scopes(cls, scopes: list[str]) -> "PermissionSet":
        """Create from list of scope strings."""
        return cls(permissions=[Permission.from_string(s) for s in scopes])

    def can_read(self, resource: str) -> bool:
        """Check if can read a resource."""
        return Permission(resource, "read") in self or Permission(resource, "*") in self

    def can_write(self, resource: str) -> bool:
        """Check if can write to a resource."""
        return (
            Permission(resource, "write") in self or Permission(resource, "*") in self
        )

    def can_delete(self, resource: str) -> bool:
        """Check if can delete a resource."""
        return (
            Permission(resource, "delete") in self or Permission(resource, "*") in self
        )

    def can_admin(self, resource: str) -> bool:
        """Check if has admin access to a resource."""
        return (
            Permission(resource, "admin") in self or Permission(resource, "*") in self
        )


# Pre-defined permission sets
class DefaultPermissions:
    """Common permission sets."""

    # Full access
    ADMIN = PermissionSet.from_scopes(["*"])

    # Read-only access to all resources
    READ_ONLY = PermissionSet.from_scopes(
        [
            "agents:read",
            "memory:read",
            "traces:read",
        ]
    )

    # Standard agent permissions
    AGENT = PermissionSet.from_scopes(
        [
            "memory:read",
            "memory:write",
            "traces:write",
            "agents:read",
        ]
    )

    # Memory service permissions
    MEMORY_SERVICE = PermissionSet.from_scopes(
        [
            "memory:*",
            "agents:read",
        ]
    )

    # Observability service permissions
    OBSERVABILITY_SERVICE = PermissionSet.from_scopes(
        [
            "traces:*",
            "metrics:*",
            "agents:read",
        ]
    )


def check_permission(
    required: str | Permission,
    granted: list[str] | PermissionSet,
) -> bool:
    """
    Check if a required permission is granted.

    Args:
        required: The permission to check
        granted: List of granted permissions/scopes

    Returns:
        True if permission is granted
    """
    if isinstance(required, str):
        required = Permission.from_string(required)

    if isinstance(granted, list):
        granted = PermissionSet.from_scopes(granted)

    return required in granted


class PermissionDeniedError(Exception):
    """Raised when a permission check fails."""

    def __init__(self, required: str, message: str | None = None):
        self.required = required
        super().__init__(message or f"Permission denied: {required}")


def require_permission(
    required: str,
    granted: list[str] | PermissionSet,
) -> None:
    """
    Require a permission, raising an error if not granted.

    Args:
        required: The permission to require
        granted: List of granted permissions/scopes

    Raises:
        PermissionDeniedError: If permission is not granted
    """
    if not check_permission(required, granted):
        raise PermissionDeniedError(required)
