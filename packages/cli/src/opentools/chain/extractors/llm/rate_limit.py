"""Per-(provider, user_id) rate limiting for LLM calls.

Uses aiolimiter.AsyncLimiter under the hood. Rates are read from
ChainConfig.llm.<provider>. Multi-worker deployments get N x the
nominal rate (documented limitation).

Note: ``functools.lru_cache`` is not async-safe on cache key hashing.
For this use case (small number of unique keys per process) the hash
collision probability is negligible, so lru_cache is acceptable.
"""
from __future__ import annotations

from functools import lru_cache
from uuid import UUID

from aiolimiter import AsyncLimiter

from opentools.chain.config import ChainConfig, get_chain_config


@lru_cache(maxsize=256)
def _cached_limiter(provider: str, user_key: str, rate: float, period: float) -> AsyncLimiter:
    return AsyncLimiter(max_rate=rate, time_period=period)


def get_limiter(
    *,
    provider: str,
    user_id: UUID | None,
    config: ChainConfig | None = None,
) -> AsyncLimiter:
    """Return a cached AsyncLimiter for (provider, user_id).

    Rate taken from config.llm.<provider>.requests_per_minute. If the
    provider has no rate limit set (None), returns a very-high-rate
    limiter that effectively doesn't block.

    Raises ValueError for unknown provider names.
    """
    cfg = config or get_chain_config()
    provider_cfg = getattr(cfg.llm, provider, None)
    if provider_cfg is None:
        raise ValueError(f"unknown provider: {provider!r}")
    rpm = getattr(provider_cfg, "requests_per_minute", None)
    rate = float(rpm) if rpm is not None else 100_000.0
    period = 60.0
    user_key = str(user_id) if user_id else "anonymous"
    return _cached_limiter(provider, user_key, rate, period)


def reset_limiter_cache() -> None:
    """Test helper — clear the LRU cache so tests start from a clean state."""
    _cached_limiter.cache_clear()
