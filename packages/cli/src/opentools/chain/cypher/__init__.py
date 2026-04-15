"""Cypher-style query DSL for the attack chain knowledge graph."""
from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import UUID

from opentools.chain.cypher.errors import QueryParseError, QueryResourceError, QueryValidationError
from opentools.chain.cypher.executor import CypherExecutor
from opentools.chain.cypher.limits import QueryLimits
from opentools.chain.cypher.parser import parse_cypher
from opentools.chain.cypher.planner import plan_query
from opentools.chain.cypher.plugins import PluginFunctionRegistry
from opentools.chain.cypher.result import QueryResult
from opentools.chain.cypher.session import QuerySession
from opentools.chain.cypher.virtual_graph import VirtualGraphCache

if TYPE_CHECKING:
    from opentools.chain.config import ChainConfig
    from opentools.chain.query.graph_cache import GraphCache
    from opentools.chain.store_protocol import ChainStoreProtocol


async def parse_and_execute(
    query: str,
    *,
    store: "ChainStoreProtocol",
    graph_cache: "GraphCache",
    vg_cache: VirtualGraphCache,
    session: QuerySession | None = None,
    plugin_registry: PluginFunctionRegistry | None = None,
    user_id: UUID | None = None,
    include_candidates: bool = False,
    engagement_ids: frozenset[str] | None = None,
    limits: QueryLimits | None = None,
) -> QueryResult:
    """Parse, plan, and execute a Cypher query — main entry point."""
    if session is None:
        session = QuerySession()
    if plugin_registry is None:
        plugin_registry = PluginFunctionRegistry()
    if limits is None:
        limits = QueryLimits()

    ast = parse_cypher(query)
    plan = plan_query(ast, limits)

    vg = await vg_cache.get(
        user_id=user_id,
        include_candidates=include_candidates,
        engagement_ids=engagement_ids,
    )

    executor = CypherExecutor(
        virtual_graph=vg,
        plan=plan,
        session=session,
        plugin_registry=plugin_registry,
        limits=limits,
    )
    result = await executor.execute()

    # Store in session if this was a session assignment
    if ast.session_assignment:
        session.store(ast.session_assignment, result)

    return result


class CypherSession:
    """High-level session object for CLI REPL and web editor."""

    def __init__(
        self,
        *,
        store: "ChainStoreProtocol",
        graph_cache: "GraphCache",
        config: "ChainConfig",
        user_id: UUID | None = None,
    ) -> None:
        self.store = store
        self.graph_cache = graph_cache
        self.user_id = user_id
        self.session = QuerySession()
        self.plugin_registry = PluginFunctionRegistry()
        self.limits = QueryLimits(
            timeout_seconds=config.cypher.timeout_seconds,
            max_rows=config.cypher.max_rows,
            intermediate_binding_cap=config.cypher.intermediate_binding_cap,
            max_var_length_hops=config.cypher.max_var_length_hops,
        )
        self.vg_cache = VirtualGraphCache(
            store=store,
            graph_cache=graph_cache,
            maxsize=config.cypher.virtual_graph_cache_size,
        )
        self._engagement_ids: frozenset[str] | None = None
        self._include_candidates = False

    def set_engagement_scope(self, engagement_ids: frozenset[str] | None) -> None:
        self._engagement_ids = engagement_ids

    def set_include_candidates(self, include: bool) -> None:
        self._include_candidates = include

    async def execute(self, query: str) -> QueryResult:
        return await parse_and_execute(
            query,
            store=self.store,
            graph_cache=self.graph_cache,
            vg_cache=self.vg_cache,
            session=self.session,
            plugin_registry=self.plugin_registry,
            user_id=self.user_id,
            include_candidates=self._include_candidates,
            engagement_ids=self._engagement_ids,
            limits=self.limits,
        )
