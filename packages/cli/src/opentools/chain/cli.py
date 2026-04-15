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
from opentools.engagement.store import EngagementStore

if TYPE_CHECKING:
    from opentools.chain.stores.sqlite_async import AsyncChainStore

app = typer.Typer(name="chain", help="Attack chain extraction and path queries")
console = Console()


def _default_db_path() -> Path:
    """Return the default database path used by the CLI."""
    return Path.home() / ".opentools" / "engagements.db"


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


async def _get_stores() -> tuple[EngagementStore, "AsyncChainStore"]:
    """Build an :class:`EngagementStore` + :class:`AsyncChainStore` pair.

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
    _engagement_store, chain_store = await _get_stores()
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
    from opentools.chain.extractors.pipeline import ExtractionPipeline
    from opentools.chain.linker.engine import LinkerEngine

    engagement_store, chain_store = await _get_stores()
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

        pipeline = ExtractionPipeline(store=chain_store, config=cfg)
        engine = LinkerEngine(
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
    _engagement_store, chain_store = await _get_stores()
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
    _engagement_store, chain_store = await _get_stores()
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
    _engagement_store, chain_store = await _get_stores()
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


# ─── query sub-app ──────────────────────────────────────────────────

query_app = typer.Typer(help="Cypher query DSL and preset commands")
app.add_typer(query_app, name="query")


@query_app.command("preset")
@_async_command
async def query_preset(
    preset: str = typer.Argument(..., help="Preset name (lateral-movement, priv-esc-chains, external-to-internal, crown-jewel, mitre-coverage)"),
    engagement: str = typer.Option(..., "--engagement", help="Engagement id"),
    entity_ref: str | None = typer.Option(None, "--entity", help="Required for crown-jewel preset"),
) -> None:
    """Run a named query preset."""
    _engagement_store, chain_store = await _get_stores()
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


@query_app.command("run")
@_async_command
async def query_run(
    cypher: str = typer.Argument(..., help="Cypher query string"),
    timeout: float = typer.Option(30.0, "--timeout", help="Query timeout in seconds"),
    max_rows: int = typer.Option(1000, "--max-rows", help="Maximum result rows"),
    engagement: str | None = typer.Option(None, "--engagement", help="Scope to engagement"),
    include_candidates: bool = typer.Option(False, "--include-candidates", help="Include candidate edges"),
    format_: str = typer.Option("table", "--format", help="Output format: table, json, csv"),
    no_subgraph: bool = typer.Option(False, "--no-subgraph", help="Skip subgraph projection"),
) -> None:
    """Execute a Cypher query."""
    import json
    from opentools.chain.cypher import CypherSession
    from opentools.chain.cypher.limits import QueryLimits

    _engagement_store, chain_store = await _get_stores()
    try:
        cfg = get_chain_config()
        cache = GraphCache(store=chain_store, maxsize=cfg.query.graph_cache_size)
        cypher_session = CypherSession(store=chain_store, graph_cache=cache, config=cfg)

        if engagement:
            cypher_session.set_engagement_scope(frozenset([engagement]))
        cypher_session.set_include_candidates(include_candidates)
        cypher_session.limits = QueryLimits(timeout_seconds=timeout, max_rows=max_rows)

        result = await cypher_session.execute(cypher)

        if format_ == "json":
            rprint(json.dumps(
                {"columns": result.columns, "rows": result.rows,
                 "stats": {"duration_ms": result.stats.duration_ms, "rows_returned": result.stats.rows_returned},
                 "truncated": result.truncated},
                indent=2, default=str,
            ))
        elif format_ == "csv":
            if result.columns:
                rprint(",".join(result.columns))
                for row in result.rows:
                    rprint(",".join(str(row.get(c, "")) for c in result.columns))
        else:
            if not result.rows:
                rprint("[yellow]no results[/yellow]")
                return
            table = Table()
            for col in result.columns:
                table.add_column(col)
            for row in result.rows:
                table.add_row(*[str(row.get(c, "")) for c in result.columns])
            console.print(table)
            rprint(f"[dim]{result.stats.rows_returned} rows, {result.stats.duration_ms:.1f}ms[/dim]")
            if result.truncated:
                rprint(f"[yellow]truncated: {result.truncation_reason}[/yellow]")
    finally:
        await chain_store.close()


@query_app.command("explain")
@_async_command
async def query_explain(
    cypher: str = typer.Argument(..., help="Cypher query string"),
) -> None:
    """Show the query plan without executing."""
    from opentools.chain.cypher.limits import QueryLimits
    from opentools.chain.cypher.parser import parse_cypher
    from opentools.chain.cypher.planner import plan_query

    limits = QueryLimits()
    ast = parse_cypher(cypher)
    plan = plan_query(ast, limits)

    rprint("[bold]Query Plan[/bold]")
    for i, step in enumerate(plan.steps, 1):
        rprint(f"  {i}. {step.kind}: {step.target_var} (label={step.label}, direction={step.direction})")
        if step.predicates:
            rprint(f"     predicates: {len(step.predicates)} pushed down")
        if step.min_hops is not None:
            rprint(f"     hops: {step.min_hops}..{step.max_hops}")


@query_app.command("repl")
@_async_command
async def query_repl(
    engagement: str | None = typer.Option(None, "--engagement", help="Scope to engagement"),
    include_candidates: bool = typer.Option(False, "--include-candidates"),
) -> None:
    """Start an interactive Cypher query REPL."""
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import InMemoryHistory
    from opentools.chain.cypher import CypherSession
    from opentools.chain.cypher.errors import QueryParseError, QueryResourceError, QueryValidationError

    _engagement_store, chain_store = await _get_stores()
    try:
        cfg = get_chain_config()
        cache = GraphCache(store=chain_store, maxsize=cfg.query.graph_cache_size)
        cypher_session = CypherSession(store=chain_store, graph_cache=cache, config=cfg)

        if engagement:
            cypher_session.set_engagement_scope(frozenset([engagement]))
        cypher_session.set_include_candidates(include_candidates)

        prompt_session = PromptSession(history=InMemoryHistory())
        rprint("[bold]OpenTools Cypher REPL[/bold] (type :help for help, :quit to exit)")

        while True:
            try:
                text = prompt_session.prompt("cypher> ")
            except (EOFError, KeyboardInterrupt):
                break

            text = text.strip()
            if not text:
                continue

            while text.endswith("-") or text.endswith("|") or text.count("(") > text.count(")"):
                try:
                    continuation = prompt_session.prompt("   ...> ")
                    text += " " + continuation.strip()
                except (EOFError, KeyboardInterrupt):
                    break

            if text.startswith(":"):
                cmd = text[1:].strip().lower()
                if cmd in ("quit", "exit"):
                    break
                elif cmd == "help":
                    rprint("Cypher query DSL. MATCH (a:Finding)-[r:LINKED]->(b:Finding) WHERE ... RETURN ...")
                    rprint("Labels: Finding, Host, IP, CVE, Domain, Port, MitreAttack, Entity")
                    rprint("Edges: LINKED, MENTIONED_IN")
                elif cmd == "functions":
                    from opentools.chain.cypher.builtins import list_builtins
                    for name, info in list_builtins().items():
                        rprint(f"  {name}: {info.get('help', '')}")
                    for name, info in cypher_session.plugin_registry.list_all().items():
                        rprint(f"  {name}: {info.get('help', '')} [{info.get('kind', '')}]")
                elif cmd == "clear":
                    cypher_session.session.clear()
                    rprint("[dim]session cleared[/dim]")
                elif cmd.startswith("limits"):
                    rprint(f"timeout: {cypher_session.limits.timeout_seconds}s")
                    rprint(f"max_rows: {cypher_session.limits.max_rows}")
                    rprint(f"intermediate_cap: {cypher_session.limits.intermediate_binding_cap}")
                else:
                    rprint(f"[red]unknown command: {text}[/red]")
                continue

            if text in cypher_session.session.list_variables():
                stored = cypher_session.session.get(text)
                if stored:
                    for row in stored.rows[:20]:
                        rprint(row)
                    if len(stored.rows) > 20:
                        rprint(f"[dim]... {len(stored.rows) - 20} more rows[/dim]")
                continue

            try:
                result = await cypher_session.execute(text)
                if not result.rows:
                    rprint("[yellow]no results[/yellow]")
                else:
                    table = Table()
                    for col in result.columns:
                        table.add_column(col)
                    for row in result.rows:
                        table.add_row(*[str(row.get(c, "")) for c in result.columns])
                    console.print(table)
                    rprint(f"[dim]{result.stats.rows_returned} rows, {result.stats.duration_ms:.1f}ms[/dim]")
            except (QueryParseError, QueryValidationError) as e:
                rprint(f"[red]Parse error: {e}[/red]")
            except QueryResourceError as e:
                rprint(f"[red]Resource limit: {e}[/red]")
            except Exception as e:
                rprint(f"[red]Error: {e}[/red]")

        rprint("[dim]bye[/dim]")
    finally:
        await chain_store.close()
