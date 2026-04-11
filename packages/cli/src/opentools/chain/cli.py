"""CLI command surface for the chain subcommand group.

Minimal implementation for 3C.1 MVP. Commands not listed here are
documented in the spec but deferred to a later implementation pass.

Commands implemented:
- status       — print entity count, relation count, last linker run
- rebuild      — re-run extraction + linking for all findings in an engagement
- entities     — list entities with optional --type filter
- path         — run k-shortest path query
- export       — export chain data
- query        — run a named preset

Commands deferred (not implemented in 3C.1 MVP):
- merge        — merge two entities (use entity_ops.merge_entities directly)
- split        — split entity mentions (use entity_ops.split_entity directly)
- import       — import chain data from JSON (use exporter.import_chain directly)
- llm-pass     — run LLM classification pass on candidates
"""
from __future__ import annotations

import asyncio
import functools
from pathlib import Path
from typing import TYPE_CHECKING

import typer
from rich import print as rprint
from rich.console import Console
from rich.table import Table

from opentools.chain.config import get_chain_config
from opentools.chain.exporter import export_chain
from opentools.chain.linker.engine import get_default_rules
from opentools.chain.query.endpoints import parse_endpoint_spec
from opentools.chain.query.engine import ChainQueryEngine
from opentools.chain.query.graph_cache import GraphCache
from opentools.chain.query.presets import (
    crown_jewel,
    external_to_internal,
    lateral_movement,
    list_presets,
    mitre_coverage,
    priv_esc_chains,
)
from opentools.chain.store_extensions import ChainStore
from opentools.engagement.store import EngagementStore

if TYPE_CHECKING:
    from opentools.chain.stores.sqlite_async import AsyncChainStore

app = typer.Typer(name="chain", help="Attack chain extraction and path queries")
console = Console()


def _default_db_path() -> Path:
    """Return the default database path used by the CLI."""
    return Path.home() / ".opentools" / "engagements.db"


def _get_stores() -> tuple[EngagementStore, ChainStore]:
    db = _default_db_path()
    db.parent.mkdir(parents=True, exist_ok=True)
    engagement_store = EngagementStore(db_path=db)
    chain_store = ChainStore(engagement_store._conn)
    return engagement_store, chain_store


def _async_command(coro_fn):
    """Expose an ``async def`` function as a synchronous Typer command body.

    Typer 0.24 does not recognize ``async def`` commands natively — the
    coroutine object is created and silently discarded without ever
    running. This adapter wraps a coroutine function in ``asyncio.run``
    so it can be registered via ``@app.command()``. ``functools.wraps``
    preserves the signature so Typer can introspect Options and
    Arguments declared on the async function.
    """
    @functools.wraps(coro_fn)
    def _wrapper(*args, **kwargs):
        return asyncio.run(coro_fn(*args, **kwargs))
    return _wrapper


async def _get_stores_async() -> tuple[EngagementStore, "AsyncChainStore"]:
    """Async variant of :func:`_get_stores`.

    Returns an :class:`EngagementStore` (sync, holds its own sqlite3
    connection) and an :class:`AsyncChainStore` (holds an aiosqlite
    connection to the same file in WAL mode). Callers are responsible
    for awaiting ``chain_store.close()`` when done.
    """
    from opentools.chain.stores.sqlite_async import AsyncChainStore

    db = _default_db_path()
    db.parent.mkdir(parents=True, exist_ok=True)
    engagement_store = EngagementStore(db_path=db)
    chain_store = AsyncChainStore(db_path=db)
    await chain_store.initialize()
    return engagement_store, chain_store


@app.command()
@_async_command
async def status() -> None:
    """Show chain data statistics (entity count, relation count, last run)."""
    _engagement_store, chain_store = await _get_stores_async()
    try:
        entities_list = await chain_store.list_entities(
            user_id=None, limit=1_000_000,
        )
        relations = await chain_store.fetch_relations_in_scope(
            user_id=None, statuses=None,
        )
        runs = await chain_store.fetch_linker_runs(user_id=None, limit=1)

        table = Table(title="Chain Status")
        table.add_column("Metric")
        table.add_column("Value", justify="right")
        table.add_row("Entities", str(len(entities_list)))
        table.add_row("Relations", str(len(relations)))
        if runs:
            run = runs[0]
            table.add_row("Last linker run", f"{run.id} at {run.started_at}")
            table.add_row("  Findings processed", str(run.findings_processed))
            table.add_row("  Relations created", str(run.relations_created))
        else:
            table.add_row("Last linker run", "never")
        console.print(table)
    finally:
        await chain_store.close()


@app.command()
@_async_command
async def rebuild(
    engagement: str | None = typer.Option(None, "--engagement", help="Engagement id to rebuild (default: all)"),
    force: bool = typer.Option(False, "--force", help="Re-extract even unchanged findings"),
) -> None:
    """Re-run extraction and linking for all findings (optionally scoped to one engagement)."""
    from opentools.chain.extractors.pipeline import AsyncExtractionPipeline
    from opentools.chain.linker.engine import AsyncLinkerEngine

    engagement_store, chain_store = await _get_stores_async()
    try:
        cfg = get_chain_config()

        if engagement:
            finding_ids = await chain_store.fetch_findings_for_engagement(
                engagement, user_id=None,
            )
        else:
            finding_ids = [f.id for f in engagement_store.list_findings()]

        if not finding_ids:
            rprint("[yellow]no findings to process[/yellow]")
            return

        findings = await chain_store.fetch_findings_by_ids(
            finding_ids, user_id=None,
        )

        pipeline = AsyncExtractionPipeline(store=chain_store, config=cfg)
        engine = AsyncLinkerEngine(
            store=chain_store, config=cfg, rules=get_default_rules(cfg),
        )

        processed = 0
        for f in findings:
            try:
                await pipeline.extract_for_finding(f, force=force)
            except Exception as exc:
                rprint(f"[red]extract failed for {f.id}: {exc}[/red]")
                continue
            processed += 1

        ctx = await engine.make_context(user_id=None)
        for f in findings:
            try:
                await engine.link_finding(
                    f.id, user_id=None, context=ctx,
                )
            except Exception as exc:
                rprint(f"[red]link failed for {f.id}: {exc}[/red]")

        rprint(
            f"[green]rebuild complete: {processed} findings processed[/green]"
        )
    finally:
        await chain_store.close()


@app.command()
@_async_command
async def entities(
    type_: str | None = typer.Option(None, "--type", help="Filter by entity type"),
    limit: int = typer.Option(50, "--limit", help="Max rows"),
) -> None:
    """List entities."""
    _engagement_store, chain_store = await _get_stores_async()
    try:
        rows = await chain_store.list_entities(
            user_id=None, entity_type=type_, limit=limit,
        )

        table = Table(title=f"Entities{' (type=' + type_ + ')' if type_ else ''}")
        table.add_column("ID")
        table.add_column("Type")
        table.add_column("Value")
        table.add_column("Mentions", justify="right")
        for r in rows:
            table.add_row(r.id, r.type, r.canonical_value, str(r.mention_count))
        console.print(table)
    finally:
        await chain_store.close()


@app.command()
@_async_command
async def path(
    from_: str = typer.Argument(..., metavar="FROM", help="Source endpoint (finding id, type:value, or key=value)"),
    to: str = typer.Argument(..., help="Target endpoint"),
    k: int = typer.Option(5, "-k", help="Number of paths"),
    max_hops: int = typer.Option(6, "--max-hops", help="Max path length"),
    include_candidates: bool = typer.Option(False, "--include-candidates", help="Include candidate-status edges"),
) -> None:
    """Run a k-shortest paths query between two endpoints."""
    _engagement_store, chain_store = await _get_stores_async()
    try:
        cfg = get_chain_config()
        cache = GraphCache(store=chain_store, maxsize=4)
        qe = ChainQueryEngine(store=chain_store, graph_cache=cache, config=cfg)

        try:
            from_spec = parse_endpoint_spec(from_)
            to_spec = parse_endpoint_spec(to)
        except ValueError as exc:
            rprint(f"[red]invalid endpoint: {exc}[/red]")
            raise typer.Exit(code=1)

        results = await qe.k_shortest_paths(
            from_spec=from_spec, to_spec=to_spec,
            user_id=None, k=k, max_hops=max_hops,
            include_candidates=include_candidates,
        )

        if not results:
            rprint("[yellow]no paths found[/yellow]")
            return

        for i, p in enumerate(results, 1):
            rprint(f"[bold]Path {i}[/bold] cost={p.total_cost:.3f} length={p.length}")
            for j, n in enumerate(p.nodes):
                arrow = " -> " if j < len(p.nodes) - 1 else ""
                rprint(f"  {n.finding_id} ({n.severity}, {n.tool}): {n.title}{arrow}")
    finally:
        await chain_store.close()


@app.command()
@_async_command
async def export(
    engagement: str | None = typer.Option(None, "--engagement"),
    output: Path = typer.Option(..., "--output", help="Output JSON path"),
) -> None:
    """Export chain data to JSON."""
    _engagement_store, chain_store = await _get_stores_async()
    try:
        result = await export_chain(
            store=chain_store,
            engagement_id=engagement,
            output_path=output,
        )
        rprint(
            f"[green]Exported[/green] {result.entities_exported} entities, "
            f"{result.mentions_exported} mentions, {result.relations_exported} relations "
            f"to {result.output_path}"
        )
    finally:
        await chain_store.close()


@app.command()
@_async_command
async def query(
    preset: str = typer.Argument(..., help="Preset name (lateral-movement, priv-esc-chains, external-to-internal, crown-jewel, mitre-coverage)"),
    engagement: str = typer.Option(..., "--engagement", help="Engagement id"),
    entity_ref: str | None = typer.Option(None, "--entity", help="Required for crown-jewel preset"),
) -> None:
    """Run a named query preset."""
    _engagement_store, chain_store = await _get_stores_async()
    try:
        cfg = get_chain_config()
        cache = GraphCache(store=chain_store, maxsize=4)

        if preset == "lateral-movement":
            results = await lateral_movement(
                engagement, cache=cache, store=chain_store, config=cfg,
            )
        elif preset == "priv-esc-chains":
            results = await priv_esc_chains(
                engagement, cache=cache, store=chain_store, config=cfg,
            )
        elif preset == "external-to-internal":
            results = await external_to_internal(
                engagement, cache=cache, store=chain_store, config=cfg,
            )
        elif preset == "crown-jewel":
            if not entity_ref:
                rprint("[red]crown-jewel preset requires --entity[/red]")
                raise typer.Exit(code=1)
            results = await crown_jewel(
                engagement, entity_ref,
                cache=cache, store=chain_store, config=cfg,
            )
        elif preset == "mitre-coverage":
            result = await mitre_coverage(engagement, store=chain_store)
            rprint(f"[bold]MITRE Coverage for {engagement}[/bold]")
            rprint(f"Tactics present: {', '.join(result.tactics_present) or 'none'}")
            rprint(f"Tactics missing: {', '.join(result.tactics_missing)}")
            return
        else:
            presets = list_presets()
            rprint(f"[red]unknown preset: {preset}[/red]")
            rprint(f"Available: {', '.join(presets.keys())}")
            raise typer.Exit(code=1)

        if not results:
            rprint("[yellow]no results[/yellow]")
            return

        for i, p in enumerate(results, 1):
            rprint(f"[bold]Result {i}[/bold] cost={p.total_cost:.3f} length={p.length}")
            for n in p.nodes:
                rprint(f"  {n.finding_id}: {n.title}")
    finally:
        await chain_store.close()
