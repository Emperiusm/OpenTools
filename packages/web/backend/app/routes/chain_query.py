"""Cypher query DSL web API endpoints."""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.dependencies import get_current_user
from app.models import User

router = APIRouter(prefix="/api/chain/query", tags=["chain-query"])


class QueryRequest(BaseModel):
    query: str
    engagement_id: Optional[str] = None
    include_candidates: bool = False
    timeout: float = 30.0
    max_rows: int = 1000


class QueryResponse(BaseModel):
    columns: list[str]
    rows: list[dict[str, Any]]
    subgraph: Optional[dict] = None
    stats: dict
    truncated: bool


@router.post("", response_model=QueryResponse)
async def execute_query(
    request: QueryRequest,
    current_user: User = Depends(get_current_user),
):
    """Execute a Cypher query against the attack chain knowledge graph.

    NOTE: Full integration with PostgresChainStore requires the store
    to implement fetch_all_mentions_in_scope. This endpoint is a
    placeholder that validates the request and returns proper error
    responses. Full store integration will be wired up when the
    PostgresChainStore backend method is implemented.
    """
    from opentools.chain.cypher.errors import QueryParseError, QueryResourceError, QueryValidationError
    from opentools.chain.cypher.parser import parse_cypher
    from opentools.chain.cypher.planner import plan_query
    from opentools.chain.cypher.limits import QueryLimits

    try:
        # Validate the query parses successfully
        limits = QueryLimits(timeout_seconds=request.timeout, max_rows=request.max_rows)
        ast = parse_cypher(request.query)
        plan = plan_query(ast, limits)

        # For now return an empty result - full execution requires
        # PostgresChainStore.fetch_all_mentions_in_scope which is
        # defined in the protocol but not yet implemented in the backend
        return QueryResponse(
            columns=[],
            rows=[],
            subgraph=None,
            stats={"duration_ms": 0, "bindings_explored": 0, "rows_returned": 0},
            truncated=False,
        )

    except QueryParseError as e:
        raise HTTPException(status_code=400, detail=f"Parse error: {e}")
    except QueryValidationError as e:
        raise HTTPException(status_code=400, detail=f"Validation error: {e}")
    except QueryResourceError as e:
        raise HTTPException(status_code=400, detail=f"Resource limit: {e}")


@router.get("/functions")
async def list_functions(
    current_user: User = Depends(get_current_user),
):
    """List all available query functions (built-in and plugin)."""
    from opentools.chain.cypher.builtins import list_builtins

    result = []
    for name, info in list_builtins().items():
        result.append({"name": name, "kind": "builtin", "help": info.get("help", "")})
    return result
