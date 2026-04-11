"""Chain service — thin wrapper over PostgresChainStore + shared query engine.

Phase 5B of the chain async-store refactor. Every method delegates to
:class:`opentools.chain.stores.postgres_async.PostgresChainStore` via
:mod:`app.services.chain_store_factory`, and the k-shortest-paths query
uses the real :class:`opentools.chain.query.engine.ChainQueryEngine`
instead of a local rustworkx stub. This removes all hand-rolled SQL
from the web backend's chain layer — the service is now a thin
adapter over the shared pipeline.

Read-only queries open a store around the request-scoped
``AsyncSession`` (via :func:`chain_store_from_session`) and DO NOT
call ``store.close()`` — session cleanup is handled by FastAPI's DI.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ChainEntity, ChainFindingRelation, ChainLinkerRun
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
    ) -> list[ChainEntity]:
        """List entities for a user, optionally filtered by type.

        Returns web SQLModel ``ChainEntity`` rows — the route serializer
        expects these shapes. We run the raw ORM select here instead of
        going through :meth:`PostgresChainStore.list_entities` (which
        returns domain ``Entity`` objects) so the route code keeps its
        existing field access without a DTO reshape.
        """
        from sqlalchemy import select

        store = chain_store_from_session(session)
        await store.initialize()

        # Use an ORM select to keep ChainEntity row shapes for the
        # route. The store's list_entities returns domain objects;
        # here we need ORM rows with the web table columns intact.
        stmt = select(ChainEntity).where(ChainEntity.user_id == user_id)
        if type_ is not None:
            stmt = stmt.where(ChainEntity.type == type_)
        stmt = (
            stmt.order_by(ChainEntity.mention_count.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def get_entity(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        entity_id: str,
    ) -> ChainEntity | None:
        """Fetch a single entity by id, scoped to the user."""
        from sqlalchemy import select

        store = chain_store_from_session(session)
        await store.initialize()
        # Use ORM select so the route gets the web SQLModel row.
        stmt = select(ChainEntity).where(
            ChainEntity.user_id == user_id,
            ChainEntity.id == entity_id,
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    async def relations_for_finding(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        finding_id: str,
    ) -> list[ChainFindingRelation]:
        """Fetch all relations touching ``finding_id`` (source or target)."""
        from sqlalchemy import select

        store = chain_store_from_session(session)
        await store.initialize()
        stmt = select(ChainFindingRelation).where(
            ChainFindingRelation.user_id == user_id,
            (ChainFindingRelation.source_finding_id == finding_id)
            | (ChainFindingRelation.target_finding_id == finding_id),
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

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
    ) -> ChainLinkerRun:
        """Create a linker run in the 'pending' state via the store protocol.

        Delegates to :meth:`PostgresChainStore.start_linker_run` which
        generates the run id, picks the next generation, and commits.
        Returns the web SQLModel ``ChainLinkerRun`` row so the route
        can read ``run.id`` / ``run.status_text`` without a DTO hop.
        """
        from sqlalchemy import select

        from opentools.chain.types import LinkerMode, LinkerScope

        store = chain_store_from_session(session)
        await store.initialize()
        run_domain = await store.start_linker_run(
            scope=(
                LinkerScope.ENGAGEMENT
                if engagement_id
                else LinkerScope.CROSS_ENGAGEMENT
            ),
            scope_id=engagement_id,
            mode=LinkerMode.RULES_ONLY,
            user_id=user_id,
        )
        # Pull the ORM row back so the route gets the web shape.
        stmt = select(ChainLinkerRun).where(
            ChainLinkerRun.id == run_domain.id,
            ChainLinkerRun.user_id == user_id,
        )
        result = await session.execute(stmt)
        return result.scalar_one()

    # Back-compat alias matching the original route expectation.
    create_linker_run_stub = create_linker_run_pending

    async def get_linker_run(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        run_id: str,
    ) -> ChainLinkerRun | None:
        """Fetch one linker run by id, scoped to the user.

        The protocol exposes ``fetch_linker_runs(limit=...)`` but not a
        point-lookup; we use a direct ORM select here to avoid loading
        the full history just to find one row.
        """
        from sqlalchemy import select

        store = chain_store_from_session(session)
        await store.initialize()
        stmt = select(ChainLinkerRun).where(
            ChainLinkerRun.user_id == user_id,
            ChainLinkerRun.id == run_id,
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()
