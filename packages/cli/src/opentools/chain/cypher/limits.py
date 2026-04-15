"""Resource limits for query execution."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class QueryLimits(BaseModel):
    model_config = ConfigDict(frozen=True)

    timeout_seconds: float = 30.0
    max_rows: int = 1000
    intermediate_binding_cap: int = 10_000
    max_var_length_hops: int = 10
