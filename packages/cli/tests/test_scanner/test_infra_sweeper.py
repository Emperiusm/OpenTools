"""Tests for sweep_orphaned_nodes."""
from __future__ import annotations

import pytest

from opentools.scanner.infra.sweeper import sweep_orphaned_nodes


# ---------------------------------------------------------------------------
# Fake providers
# ---------------------------------------------------------------------------


class FakeSweepProvider:
    """Provider that supports list_nodes_by_tag and destroy_node."""

    def __init__(self, orphan_ids: list[str], fail_on: set[str] | None = None) -> None:
        self.orphan_ids = list(orphan_ids)
        self.fail_on: set[str] = fail_on or set()
        self.destroyed_ids: list[str] = []

    async def list_nodes_by_tag(self, tag: str) -> list[str]:
        return list(self.orphan_ids)

    async def destroy_node(self, node_id: str) -> None:
        if node_id in self.fail_on:
            raise RuntimeError(f"destroy failed for {node_id}")
        self.destroyed_ids.append(node_id)


class NoListProvider:
    """Provider that lacks list_nodes_by_tag entirely."""

    async def destroy_node(self, node_id: str) -> None:
        pass  # pragma: no cover


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestSweepOrphanedNodes:
    @pytest.mark.asyncio
    async def test_destroys_orphans(self) -> None:
        """Two orphan IDs are both destroyed; returns 2."""
        provider = FakeSweepProvider(orphan_ids=["node-1", "node-2"])

        count = await sweep_orphaned_nodes(provider)

        assert count == 2
        assert set(provider.destroyed_ids) == {"node-1", "node-2"}

    @pytest.mark.asyncio
    async def test_no_orphans(self) -> None:
        """Empty list from provider returns 0 without calling destroy."""
        provider = FakeSweepProvider(orphan_ids=[])

        count = await sweep_orphaned_nodes(provider)

        assert count == 0
        assert provider.destroyed_ids == []

    @pytest.mark.asyncio
    async def test_destroy_failure_continues(self) -> None:
        """One node fails to destroy; the other succeeds; returns 1."""
        provider = FakeSweepProvider(orphan_ids=["node-ok", "node-bad"], fail_on={"node-bad"})

        count = await sweep_orphaned_nodes(provider)

        assert count == 1
        assert provider.destroyed_ids == ["node-ok"]

    @pytest.mark.asyncio
    async def test_provider_without_list_method(self) -> None:
        """Provider without list_nodes_by_tag returns 0 immediately."""
        provider = NoListProvider()

        count = await sweep_orphaned_nodes(provider)

        assert count == 0
