"""
Role-based policies for the Security Gatekeeper.

Defines security policies per role and provides a registry for loading
and accessing policies from YAML configuration.
"""

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import yaml

from security_governance_gatekeeper.domain.exceptions import (
    ConfigurationError,
    PolicyNotFoundError,
)
from security_governance_gatekeeper.domain.models import UserRole



@dataclass
class RateLimitConfig:
    """Rate limiting configuration for a role."""

    requests_per_hour: int
    window_seconds: int = 3600

    def __post_init__(self):
        if self.requests_per_hour < 0:
            raise ValueError("requests_per_hour must be non-negative")
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be positive")


@dataclass
class RolePolicy:
    """
    Security policy for a specific user role.
    
    Attributes:
        role: The user role this policy applies to
        pii_redaction_enabled: Whether PII should be redacted for this role
        rate_limit: Rate limiting configuration (None = no limit)
    """

    role: UserRole
    pii_redaction_enabled: bool
    rate_limit: Optional[RateLimitConfig] = None

    @property
    def has_rate_limit(self) -> bool:
        """Check if this role has rate limiting enabled."""
        return self.rate_limit is not None

    @property
    def is_privileged(self) -> bool:
        """Check if this role can see raw PII."""
        return not self.pii_redaction_enabled


class RolePolicyRegistry:
    """
    Registry for loading and accessing role policies.
    
    Loads policies from YAML configuration file.
    """

    def __init__(self, config_path: str = "config/roles.yaml"):
        self._config_path = config_path
        self._policies: dict[UserRole, RolePolicy] = {}
        self._load_policies()

    def _load_policies(self) -> None:
        """Load policies from YAML file."""
        config_path = Path(self._config_path)
        
        if not config_path.exists():
            raise ConfigurationError(
                f"Role configuration file not found: {self._config_path}",
                config_key="roles_config_path",
            )

        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ConfigurationError(
                f"Invalid YAML in role configuration: {e}",
                config_key="roles_config_path",
            )

        roles_config = config.get("roles", {})
        
        for role_name, policy_config in roles_config.items():
            try:
                role = UserRole(role_name)
            except ValueError:
                # Skip unknown roles in config but log warning
                continue
            
            # Build rate limit config if present
            rate_limit = None
            if policy_config.get("rate_limit"):
                rate_limit = RateLimitConfig(
                    requests_per_hour=policy_config["rate_limit"].get("requests_per_hour", 10),
                    window_seconds=policy_config["rate_limit"].get("window_seconds", 3600),
                )

            # Create policy
            policy = RolePolicy(
                role=role,
                pii_redaction_enabled=policy_config.get("pii_redaction_enabled", True),
                rate_limit=rate_limit,
            )
            
            self._policies[role] = policy



    def get_policy(self, role: UserRole) -> RolePolicy:
        """
        Get the policy for a specific role.
        
        Args:
            role: The user role to get policy for
            
        Returns:
            The RolePolicy for the given role
            
        Raises:
            PolicyNotFoundError: If no policy exists for the role
        """
        if role not in self._policies:
            raise PolicyNotFoundError(role.value)
        return self._policies[role]

    def get_all_policies(self) -> dict[UserRole, RolePolicy]:
        """Get all registered policies."""
        return self._policies.copy()

    def reload(self) -> None:
        """Reload policies from configuration file."""
        self._policies.clear()
        self._load_policies()

