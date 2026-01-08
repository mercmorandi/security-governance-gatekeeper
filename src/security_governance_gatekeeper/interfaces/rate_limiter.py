"""
Rate Limiter Port (Interface).

Defines the abstract contract for rate limiting operations.
"""

from abc import ABC, abstractmethod

from security_governance_gatekeeper.domain.models import RateLimitResult
from security_governance_gatekeeper.domain.policies import RolePolicy


class RateLimiterPort(ABC):
    """
    Port (interface) for rate limiting operations.
    
    Implementations of this port handle tracking request counts
    and enforcing role-based rate limits.
    """

    @abstractmethod
    async def check_and_record(
        self,
        user_id: str,
        policy: RolePolicy,
    ) -> RateLimitResult:
        """
        Check if request is within rate limits and record the request.
        
        This method atomically checks the current request count against
        the policy's rate limit and records the new request.
        
        Args:
            user_id: Unique identifier for the user
            policy: The role policy containing rate limit configuration
            
        Returns:
            RateLimitResult indicating if request is allowed and remaining quota
            
        Note:
            If policy.rate_limit is None, request is always allowed with
            remaining=-1 indicating unlimited.
        """
        pass

    @abstractmethod
    async def get_remaining(
        self,
        user_id: str,
        policy: RolePolicy,
    ) -> RateLimitResult:
        """
        Get remaining quota for a user without recording a request.
        
        Args:
            user_id: Unique identifier for the user
            policy: The role policy containing rate limit configuration
            
        Returns:
            RateLimitResult with current remaining quota
        """
        pass

    @abstractmethod
    async def reset(self, user_id: str) -> None:
        """
        Reset rate limit counter for a user.
        
        Primarily used for testing and administrative purposes.
        
        Args:
            user_id: Unique identifier for the user
        """
        pass
