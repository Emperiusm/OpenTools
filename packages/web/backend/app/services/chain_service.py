"""Chain service — thin wrapper over PostgresChainStore + shared query engine.

Phase 5B of the chain async-store refactor delegated the MUTATING
paths (``create_linker_run_pending``, ``k_shortest_paths``) to
:class:`opentools.chain.stores.postgres_async.PostgresChainStore` but
left the READ path on raw SQLModel ORM selects for pragmatic
reasons (the routes expected web row shapes).

The deferred follow-up (tracked in the session 4 handoff) closes
that gap: every read method now delegates to
``PostgresChainStore`` too and converts the CLI domain return
values to response dicts via :mod:`app.services.chain_dto`. Zero
remaining hand-rolled ORM selects in this module — the service is
now a thin adapter over the shared pipeline.

Read-only queries open a store around the request-scoped
``AsyncSession`` (via :func:`chain_store_from_session`) and DO NOT
call ``store.close()`` — session cleanup is handled by FastAPI's DI.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.services.chain_dto import (
    entities_to_list,
    entity_to_dict,
    linker_run_to_dict,
    relation_to_link_dict,
    relations_to_list,
)
from app.services.chain_store_factory import chain_store_from_session


@dataclass
class ChainQueryPathRequest:
    from_finding_id: str
    to_finding_id: str
    k: int = 5
    max_hops: int = 6
    include_candidates: bool = False


@dataclass
class ChainPathResultDTO:
    nodes: list[dict]
    edges: list[dict]
    total_cost: float
    length: int


class ChainService:
    """Async chain-layer service backed by ``PostgresChainStore``.

    The service does not hold state itself — every method constructs a
    fresh store around the caller-supplied session. This matches the
    original ChainService contract (stateless) while routing every
    call through the protocol-conformant backend.

    Read methods return plain dicts (produced by
    :mod:`app.services.chain_dto`) rather than ORM rows so there is
    no SQLModel coupling leaking up into the route handlers.
    """

    # ── Entity queries ───────────────────────────────────────────────

    async def list_entities(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        type_: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List entities for a user, optionally filtered by type."""
        store = chain_store_from_session(session)
        await store.initialize()
        entities = await store.list_entities(
            user_id=user_id,
            entity_type=type_,
            limit=limit,
            offset=offset,
        )
        return entities_to_list(entities)

    async def get_entity(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        entity_id: str,
    ) -> dict[str, Any] | None:
        """Fetch a single entity by id, scoped to the user."""
        store = chain_store_from_session(session)
        await store.initialize()
        entity = await store.get_entity(entity_id, user_id=user_id)
        return entity_to_dict(entity) if entity is not None else None

    async def relations_for_finding(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        finding_id: str,
    ) -> list[dict[str, Any]]:
        """Fetch all relations touching ``finding_id`` (source or target)."""
        store = chain_store_from_session(session)
        await store.initialize()
        relations = await store.relations_for_finding(
            finding_id, user_id=user_id
        )
        return relations_to_list(relations)

    # ── Query engine ─────────────────────────────────────────────────

    async def k_shortest_paths(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        request: ChainQueryPathRequest,
    ) -> list[ChainPathResultDTO]:
        """Run Yen's k-shortest-paths through the shared query engine.

        This delegates to :class:`ChainQueryEngine` which builds a master
        graph via :class:`GraphCache` — same code path the CLI uses.
        """
        from opentools.chain.config import get_chain_config
        from opentools.chain.query.endpoints import parse_endpoint_spec
        from opentools.chain.query.engine import ChainQueryEngine
        from opentools.chain.query.graph_cache import GraphCache

        store = chain_store_from_session(session)
        await store.initialize()

        cfg = get_chain_config()
        cache = GraphCache(store=store, maxsize=4)
        qe = ChainQueryEngine(store=store, graph_cache=cache, config=cfg)

        try:
            from_spec = parse_endpoint_spec(request.from_finding_id)
            to_spec = parse_endpoint_spec(request.to_finding_id)
        except Exception:
            return []

        try:
            paths = await qe.k_shortest_paths(
                from_spec=from_spec,
                to_spec=to_spec,
                user_id=user_id,
                k=request.k,
                max_hops=request.max_hops,
                include_candidates=request.include_candidates,
            )
        except Exception:
            # If the graph is empty or endpoints can't be resolved the
            # engine raises; the old stub returned [] in that case.
            return []

        results: list[ChainPathResultDTO] = []
        for p in paths:
            nodes = [
                {
                    "finding_id": n.finding_id,
                    "severity": getattr(n, "severity", None),
                    "tool": getattr(n, "tool", None),
                    "title": getattr(n, "title", None),
                }
                for n in p.nodes
            ]
            edges = [
                {
                    "source": e.source_finding_id,
                    "target": e.target_finding_id,
                    "weight": e.weight,
                }
                for e in p.edges
            ]
            results.append(
                ChainPathResultDTO(
                    nodes=nodes,
                    edges=edges,
                    total_cost=p.total_cost,
                    length=p.length,
                )
            )
        return results

    # Back-compat alias so older route code keeps compiling. The
    # _stub suffix was from the 3C.1 MVP — it's now the real deal.
    k_shortest_paths_stub = k_shortest_paths

    # ── Linker run lifecycle ────────────────────────────────────────

    async def create_linker_run_pending(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        engagement_id: str | None,
    ) -> dict[str, Any]:
        """Create a linker run in the 'pending' state via the store protocol.

        Delegates to :meth:`PostgresChainStore.start_linker_run` which
        generates the run id, picks the next generation, and commits.
        Returns a DTO dict (with ``id``, ``status``, ``status_text``,
        etc.) so the route keeps reading the same field names it did
        when this method handed back an ORM row.
        """
        from opentools.chain.types import LinkerMode, LinkerScope

        store = chain_store_from_session(session)
        await store.initialize()
        run = await store.start_linker_run(
            scope=(
                LinkerScope.ENGAGEMENT
                if engagement_id
                else LinkerScope.CROSS_ENGAGEMENT
            ),
            scope_id=engagement_id,
            mode=LinkerMode.RULES_ONLY,
            user_id=user_id,
        )
        return linker_run_to_dict(run)

    # Back-compat alias matching the original route expectation.
    create_linker_run_stub = create_linker_run_pending

    async def get_linker_run(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        run_id: str,
    ) -> dict[str, Any] | None:
        """Fetch one linker run by id, scoped to the user."""
        store = chain_store_from_session(session)
        await store.initialize()
        run = await store.fetch_linker_run_by_id(run_id, user_id=user_id)
        return linker_run_to_dict(run) if run is not None else None

    # ── Subgraph queries ────────────────────────────────────────────

    async def subgraph_for_engagement(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        engagement_id: str,
        severities: set[str] | None = None,
        statuses: set[str] | None = None,
        max_nodes: int = 500,
        seed_finding_id: str | None = None,
        hops: int = 2,
        format: str = "force-graph",
    ) -> dict[str, Any]:
        """Build a filtered subgraph for one engagement.

        Returns a dict with 'graph' (force-graph or canonical shape)
        and 'meta' (total_findings, rendered_findings, filtered, generation).
        """
        from sqlalchemy import select, func
        from app.models import Finding, ChainFindingRelation, ChainLinkerRun

        store = chain_store_from_session(session)
        await store.initialize()

        # Count total findings in engagement (for meta)
        total_stmt = select(func.count()).select_from(Finding).where(
            Finding.engagement_id == engagement_id,
            Finding.user_id == user_id,
            Finding.deleted_at.is_(None),
        )
        total_result = await session.execute(total_stmt)
        total_findings = total_result.scalar() or 0

        # Fetch findings for this engagement, applying severity filter
        finding_stmt = select(Finding).where(
            Finding.engagement_id == engagement_id,
            Finding.user_id == user_id,
            Finding.deleted_at.is_(None),
        )
        if severities:
            finding_stmt = finding_stmt.where(Finding.severity.in_(severities))
        finding_stmt = finding_stmt.limit(max_nodes)

        finding_result = await session.execute(finding_stmt)
        findings = list(finding_result.scalars().all())
        finding_ids = {f.id for f in findings}

        if not finding_ids:
            empty_graph = (
                {"nodes": [], "links": []}
                if format == "force-graph"
                else {
                    "schema_version": "1.0",
                    "nodes": [],
                    "edges": [],
                    "metadata": {},
                }
            )
            return {
                "graph": empty_graph,
                "meta": {
                    "total_findings": total_findings,
                    "rendered_findings": 0,
                    "filtered": bool(severities) or total_findings > max_nodes,
                    "generation": 0,
                },
            }

        # Default status filter
        if statuses is None:
            statuses = {"auto_confirmed", "user_confirmed", "candidate"}

        # Fetch relations where both endpoints are in finding_ids
        rel_stmt = select(ChainFindingRelation).where(
            ChainFindingRelation.user_id == user_id,
            ChainFindingRelation.source_finding_id.in_(finding_ids),
            ChainFindingRelation.target_finding_id.in_(finding_ids),
            ChainFindingRelation.status.in_(statuses),
        )
        rel_result = await session.execute(rel_stmt)
        relations_orm = list(rel_result.scalars().all())

        # Build nodes
        nodes = [
            {
                "id": f.id,
                "name": f.title,
                "severity": f.severity,
                "tool": f.tool,
                "phase": f.phase,
            }
            for f in findings
        ]

        # Build links via DTO
        from opentools.chain.stores.postgres_async import _orm_to_relation

        links = [
            relation_to_link_dict(_orm_to_relation(r))
            for r in relations_orm
        ]

        # Get latest generation from most recent linker run
        gen_stmt = (
            select(ChainLinkerRun.generation)
            .where(ChainLinkerRun.user_id == user_id)
            .order_by(ChainLinkerRun.started_at.desc())
            .limit(1)
        )
        gen_result = await session.execute(gen_stmt)
        generation = gen_result.scalar() or 0

        if format == "force-graph":
            graph = {"nodes": nodes, "links": links}
        else:
            graph = {
                "schema_version": "1.0",
                "nodes": [
                    {
                        "id": n["id"],
                        "type": "finding",
                        "severity": n["severity"],
                        "tool": n["tool"],
                        "title": n["name"],
                    }
                    for n in nodes
                ],
                "edges": [
                    {
                        "source": lnk["source"],
                        "target": lnk["target"],
                        "weight": lnk["value"],
                        "status": lnk["status"],
                        "symmetric": False,
                        "reasons": lnk["reasons"],
                        "relation_type": lnk["relation_type"],
                        "rationale": lnk["rationale"],
                    }
                    for lnk in links
                ],
                "metadata": {
                    "generation": generation,
                    "max_weight": max(
                        (lnk["value"] for lnk in links), default=0
                    ),
                },
            }

        return {
            "graph": graph,
            "meta": {
                "total_findings": total_findings,
                "rendered_findings": len(findings),
                "filtered": bool(severities) or len(findings) < total_findings,
                "generation": generation,
            },
        }
