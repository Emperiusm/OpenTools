"""Cypher query DSL web API endpoints."""
from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.dependencies import get_current_user, get_db
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
    db=Depends(get_db),
):
    """Execute a Cypher query against the attack chain knowledge graph."""
    from opentools.chain.config import get_chain_config
    from opentools.chain.cypher import parse_and_execute
    from opentools.chain.cypher.errors import QueryParseError, QueryResourceError, QueryValidationError
    from opentools.chain.cypher.limits import QueryLimits
    from opentools.chain.cypher.virtual_graph import VirtualGraphCache
    from opentools.chain.query.graph_cache import GraphCache
    from app.services.chain_store_factory import chain_store_from_session

    try:
        cfg = get_chain_config()
        store = chain_store_from_session(db)
        await store.initialize()

        graph_cache = GraphCache(store=store, maxsize=cfg.query.graph_cache_size)
        vg_cache = VirtualGraphCache(store=store, graph_cache=graph_cache, maxsize=cfg.cypher.virtual_graph_cache_size)

        engagement_ids = frozenset([request.engagement_id]) if request.engagement_id else None
        limits = QueryLimits(timeout_seconds=request.timeout, max_rows=request.max_rows)

        result = await parse_and_execute(
            request.query,
            store=store,
            graph_cache=graph_cache,
            vg_cache=vg_cache,
            user_id=current_user.id,
            include_candidates=request.include_candidates,
            engagement_ids=engagement_ids,
            limits=limits,
        )

        subgraph_data = None
        if result.subgraph:
            subgraph_data = {
                "nodes": [{"index": idx} for idx in result.subgraph.node_indices],
                "edges": [{"source": s, "target": t} for s, t in result.subgraph.edge_tuples],
            }

        return QueryResponse(
            columns=result.columns,
            rows=result.rows,
            subgraph=subgraph_data,
            stats={
                "duration_ms": result.stats.duration_ms,
                "bindings_explored": result.stats.bindings_explored,
                "rows_returned": result.stats.rows_returned,
            },
            truncated=result.truncated,
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
