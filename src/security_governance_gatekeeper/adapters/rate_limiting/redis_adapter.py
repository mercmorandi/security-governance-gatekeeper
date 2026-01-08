"""
Redis Adapter for Rate Limiting.

Implements the RateLimiterPort using Redis with a sliding window algorithm.
"""

from datetime import datetime, timedelta
from typing import Optional

import redis.asyncio as redis

from security_governance_gatekeeper.domain.models import RateLimitResult
from security_governance_gatekeeper.domain.policies import RolePolicy
from security_governance_gatekeeper.interfaces.rate_limiter import RateLimiterPort


class RedisRateLimiterAdapter(RateLimiterPort):
    """
    Rate limiter implementation using Redis sorted sets.
    
    Uses a sliding window algorithm where each request is stored
    with its timestamp as the score. Expired requests are automatically
    removed during each check.
    """

    KEY_PREFIX = "ratelimit:"

    def __init__(self, redis_url: str = "redis://localhost:6379/0"):
        """
        Initialize the Redis rate limiter adapter.
        
        Args:
            redis_url: Redis connection URL
        """
        self._redis_url = redis_url
        self._redis: Optional[redis.Redis] = None


    async def _get_client(self) -> redis.Redis:
        """Get or create Redis client connection."""
        if self._redis is None:
            self._redis = redis.from_url(
                self._redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
        return self._redis

    def _get_key(self, user_id: str) -> str:
        """Generate Redis key for a user's rate limit counter."""
        return f"{self.KEY_PREFIX}{user_id}"

    async def check_and_record(
        self,
        user_id: str,
        policy: RolePolicy,
    ) -> RateLimitResult:
        """
        Check if request is within rate limits and record the request.
        
        Uses Redis sorted sets with timestamps as scores for sliding window.
        """
        # If no rate limit configured, always allow
        if not policy.has_rate_limit or policy.rate_limit is None:
            return RateLimitResult(
                allowed=True,
                remaining=-1,  # -1 indicates unlimited
                limit=-1,
                reset_at=datetime.utcnow(),
            )

        client = await self._get_client()
        key = self._get_key(user_id)
        now = datetime.utcnow()
        now_ts = now.timestamp()
        window_seconds = policy.rate_limit.window_seconds
        window_start = now_ts - window_seconds
        limit = policy.rate_limit.requests_per_hour

        # Use pipeline for atomic operations
        pipe = client.pipeline()
        
        # Remove expired entries (outside the sliding window)
        pipe.zremrangebyscore(key, "-inf", window_start)
        
        # Count current requests in window
        pipe.zcard(key)
        
        # Execute pipeline
        results = await pipe.execute()
        current_count = results[1]

        # Check if under limit
        if current_count < limit:
            # Add new request with current timestamp as score
            await client.zadd(key, {f"{now_ts}:{user_id}": now_ts})
            
            # Set expiry on the key to auto-cleanup
            await client.expire(key, window_seconds + 60)
            
            return RateLimitResult(
                allowed=True,
                remaining=limit - current_count - 1,
                limit=limit,
                reset_at=now + timedelta(seconds=window_seconds),
            )

        # Rate limit exceeded
        # Find when the oldest request will expire
        oldest = await client.zrange(key, 0, 0, withscores=True)
        if oldest:
            oldest_ts = oldest[0][1]
            retry_after = int(oldest_ts + window_seconds - now_ts) + 1
        else:
            retry_after = window_seconds

        return RateLimitResult(
            allowed=False,
            remaining=0,
            limit=limit,
            reset_at=now + timedelta(seconds=retry_after),
            retry_after_seconds=max(1, retry_after),
        )

    async def get_remaining(
        self,
        user_id: str,
        policy: RolePolicy,
    ) -> RateLimitResult:
        """
        Get remaining quota for a user without recording a request.
        """
        if not policy.has_rate_limit or policy.rate_limit is None:
            return RateLimitResult(
                allowed=True,
                remaining=-1,
                limit=-1,
                reset_at=datetime.utcnow(),
            )

        client = await self._get_client()
        key = self._get_key(user_id)
        now = datetime.utcnow()
        now_ts = now.timestamp()
        window_seconds = policy.rate_limit.window_seconds
        window_start = now_ts - window_seconds
        limit = policy.rate_limit.requests_per_hour

        # Remove expired and count
        await client.zremrangebyscore(key, "-inf", window_start)
        current_count = await client.zcard(key)

        remaining = max(0, limit - current_count)
        
        return RateLimitResult(
            allowed=remaining > 0,
            remaining=remaining,
            limit=limit,
            reset_at=now + timedelta(seconds=window_seconds),
            retry_after_seconds=0 if remaining > 0 else window_seconds,
        )

    async def reset(self, user_id: str) -> None:
        """Reset rate limit counter for a user."""
        client = await self._get_client()
        key = self._get_key(user_id)
        await client.delete(key)

    async def close(self) -> None:
        """Close Redis connection."""
        if self._redis:
            await self._redis.close()
            self._redis = None
