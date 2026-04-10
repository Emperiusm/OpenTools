"""Chain service — async SQLModel queries for chain data.

READ-ONLY for 3C.1 MVP. Rebuild endpoint returns a stub response;
actual extraction/linking via the CLI package is deferred to a
follow-up implementation task.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ChainEntity, ChainEntityMention, ChainFindingRelation, ChainLinkerRun


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
    """Async read-only queries over chain data, scoped per user."""

    async def list_entities(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        type_: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[ChainEntity]:
        stmt = select(ChainEntity).where(ChainEntity.user_id == user_id)
        if type_:
            stmt = stmt.where(ChainEntity.type == type_)
        stmt = stmt.order_by(ChainEntity.mention_count.desc()).offset(offset).limit(limit)
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def get_entity(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        entity_id: str,
    ) -> ChainEntity | None:
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
        stmt = select(ChainFindingRelation).where(
            ChainFindingRelation.user_id == user_id,
            (ChainFindingRelation.source_finding_id == finding_id)
            | (ChainFindingRelation.target_finding_id == finding_id),
        )
        result = await session.execute(stmt)
        return list(result.scalars().all())

    async def k_shortest_paths_stub(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        request: ChainQueryPathRequest,
    ) -> list[ChainPathResultDTO]:
        """Stub implementation for 3C.1 web MVP.

        Fetches relations from Postgres, builds an in-memory rustworkx
        graph, and runs Yen's on it. Reuses the CLI query package.
        """
        # Load relations for this user
        stmt = select(ChainFindingRelation).where(ChainFindingRelation.user_id == user_id)
        if not request.include_candidates:
            stmt = stmt.where(ChainFindingRelation.status.in_(["auto_confirmed", "user_confirmed"]))

        result = await session.execute(stmt)
        relations = list(result.scalars().all())

        if not relations:
            return []

        # Build a simple rustworkx graph
        try:
            import rustworkx as rx
            from opentools.chain.query.yen import yens_k_shortest
        except ImportError:
            # rustworkx or CLI chain package not available in this environment
            return []

        g = rx.PyDiGraph()
        node_map: dict[str, int] = {}

        def _get_node(fid: str) -> int:
            if fid not in node_map:
                node_map[fid] = g.add_node(fid)
            return node_map[fid]

        for r in relations:
            src = _get_node(r.source_finding_id)
            tgt = _get_node(r.target_finding_id)
            g.add_edge(src, tgt, r.weight)
            if r.symmetric:
                g.add_edge(tgt, src, r.weight)

        from_idx = node_map.get(request.from_finding_id)
        to_idx = node_map.get(request.to_finding_id)
        if from_idx is None or to_idx is None:
            return []

        def _cost_fn(weight: float) -> float:
            # Inverse weight so higher weight = lower cost
            return 1.0 / max(weight, 0.01)

        raw_paths = yens_k_shortest(
            g, from_idx, to_idx, k=request.k, max_hops=request.max_hops, cost_key=_cost_fn,
        )
        results = []
        for rp in raw_paths:
            finding_ids = [g.get_node_data(i) for i in rp.node_indices]
            results.append(ChainPathResultDTO(
                nodes=[{"finding_id": fid} for fid in finding_ids],
                edges=[
                    {"source": finding_ids[i], "target": finding_ids[i + 1]}
                    for i in range(len(finding_ids) - 1)
                ],
                total_cost=rp.total_cost,
                length=rp.hops,
            ))
        return results

    async def create_linker_run_stub(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        engagement_id: str | None,
    ) -> ChainLinkerRun:
        """Create a stub linker run row that a future task will populate."""
        run = ChainLinkerRun(
            id=f"run_{uuid.uuid4().hex[:12]}",
            user_id=user_id,
            started_at=datetime.now(timezone.utc),
            scope="engagement" if engagement_id else "cross_engagement",
            scope_id=engagement_id,
            mode="rules_only",
            status_text="pending",
        )
        session.add(run)
        await session.commit()
        await session.refresh(run)
        return run

    async def get_linker_run(
        self,
        session: AsyncSession,
        *,
        user_id: uuid.UUID,
        run_id: str,
    ) -> ChainLinkerRun | None:
        stmt = select(ChainLinkerRun).where(
            ChainLinkerRun.user_id == user_id,
            ChainLinkerRun.id == run_id,
        )
        result = await session.execute(stmt)
        return result.scalar_one_or_none()
