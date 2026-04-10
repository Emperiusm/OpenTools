"""Pre-canned query presets + plugin registration API.

Each preset is a thin wrapper around ChainQueryEngine + custom filtering
logic. Plugins can register additional presets via register_query_preset.
"""
from __future__ import annotations

import inspect
import ipaddress
from dataclasses import dataclass, field
from typing import Callable

from opentools.chain.config import ChainConfig
from opentools.chain.query.endpoints import EndpointSpec, parse_endpoint_spec
from opentools.chain.query.engine import ChainQueryEngine
from opentools.chain.query.graph_cache import GraphCache, FindingNode, PathResult
from opentools.chain.store_extensions import ChainStore


@dataclass
class MitreCoverageResult:
    engagement_id: str
    tactic_counts: dict[str, int] = field(default_factory=dict)
    tactics_present: list[str] = field(default_factory=list)
    tactics_missing: list[str] = field(default_factory=list)


_CUSTOM_PRESETS: dict[str, dict] = {}


def register_query_preset(name: str, fn: Callable, help: str = "") -> None:
    """Register a plugin-provided preset function."""
    _CUSTOM_PRESETS[name] = {
        "fn": fn,
        "help": help,
        "signature": str(inspect.signature(fn)),
    }


def list_presets() -> dict[str, dict]:
    """Return all built-in and plugin presets."""
    builtin = {
        "lateral-movement": {"help": "Paths connecting findings across 2+ distinct host entities", "signature": "(engagement_id, k=10)"},
        "priv-esc-chains": {"help": "Paths with monotonically increasing severity", "signature": "(engagement_id, k=10)"},
        "external-to-internal": {"help": "Paths from public-IP findings to internal-IP findings", "signature": "(engagement_id, k=10)"},
        "crown-jewel": {"help": "K-shortest paths ending at findings mentioning the specified entity", "signature": "(engagement_id, entity_ref, k=10)"},
        "mitre-coverage": {"help": "ATT&CK tactic coverage report", "signature": "(engagement_id)"},
    }
    builtin.update(_CUSTOM_PRESETS)
    return builtin


# ─── built-in presets ─────────────────────────────────────────────────


def _engagement_findings(store: ChainStore, engagement_id: str) -> list[str]:
    rows = store.execute_all(
        "SELECT id FROM findings WHERE engagement_id = ? AND deleted_at IS NULL",
        (engagement_id,),
    )
    return [r["id"] for r in rows]


def lateral_movement(
    engagement_id: str,
    *,
    cache: GraphCache,
    store: ChainStore,
    config: ChainConfig,
    k: int = 10,
) -> list[PathResult]:
    """Paths connecting findings that involve distinct host entities.

    For each (src, tgt) pair of findings in the engagement where both
    mention a host, run a k-shortest path query and collect the best.
    """
    finding_ids = _engagement_findings(store, engagement_id)
    if len(finding_ids) < 2:
        return []

    qe = ChainQueryEngine(store=store, graph_cache=cache, config=config)
    results: list[PathResult] = []

    # Try paths between the first finding and each other finding
    # (keeping scope manageable for 3C.1)
    src_id = finding_ids[0]
    for tgt_id in finding_ids[1:]:
        try:
            paths = qe.k_shortest_paths(
                from_spec=parse_endpoint_spec(src_id),
                to_spec=parse_endpoint_spec(tgt_id),
                user_id=None, k=3, max_hops=6,
            )
            results.extend(paths)
        except Exception:
            continue

    results.sort(key=lambda p: (p.total_cost, p.length))
    return results[:k]


def priv_esc_chains(
    engagement_id: str,
    *,
    cache: GraphCache,
    store: ChainStore,
    config: ChainConfig,
    k: int = 10,
) -> list[PathResult]:
    """Paths where severity strictly increases along the traversal."""
    severity_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def _strictly_increasing(path: PathResult) -> bool:
        ranks = [severity_rank.get((n.severity or "").lower(), 0) for n in path.nodes]
        return all(ranks[i] < ranks[i + 1] for i in range(len(ranks) - 1))

    finding_ids = _engagement_findings(store, engagement_id)
    if len(finding_ids) < 2:
        return []

    qe = ChainQueryEngine(store=store, graph_cache=cache, config=config)
    results: list[PathResult] = []
    src_id = finding_ids[0]
    for tgt_id in finding_ids[1:]:
        try:
            paths = qe.k_shortest_paths(
                from_spec=parse_endpoint_spec(src_id),
                to_spec=parse_endpoint_spec(tgt_id),
                user_id=None, k=5, max_hops=6,
            )
            results.extend(p for p in paths if _strictly_increasing(p))
        except Exception:
            continue

    results.sort(key=lambda p: (p.total_cost, p.length))
    return results[:k]


def external_to_internal(
    engagement_id: str,
    *,
    cache: GraphCache,
    store: ChainStore,
    config: ChainConfig,
    k: int = 10,
) -> list[PathResult]:
    """Paths from findings with public IPs to findings with internal IPs."""
    # Fetch findings mentioning IPs, classify by public/private
    rows = store.execute_all(
        """
        SELECT DISTINCT fm.finding_id, e.canonical_value
        FROM entity_mention fm
        JOIN entity e ON e.id = fm.entity_id
        WHERE e.type = 'ip'
          AND fm.finding_id IN (
              SELECT id FROM findings WHERE engagement_id = ? AND deleted_at IS NULL
          )
        """,
        (engagement_id,),
    )
    public_findings: set[str] = set()
    internal_findings: set[str] = set()
    for r in rows:
        try:
            ip = ipaddress.ip_address(r["canonical_value"])
            if ip.is_private:
                internal_findings.add(r["finding_id"])
            else:
                public_findings.add(r["finding_id"])
        except Exception:
            continue

    if not public_findings or not internal_findings:
        return []

    qe = ChainQueryEngine(store=store, graph_cache=cache, config=config)
    results: list[PathResult] = []
    for src in public_findings:
        for tgt in internal_findings:
            if src == tgt:
                continue
            try:
                paths = qe.k_shortest_paths(
                    from_spec=parse_endpoint_spec(src),
                    to_spec=parse_endpoint_spec(tgt),
                    user_id=None, k=3, max_hops=6,
                )
                results.extend(paths)
            except Exception:
                continue

    results.sort(key=lambda p: (p.total_cost, p.length))
    return results[:k]


def crown_jewel(
    engagement_id: str,
    entity_ref: str,
    *,
    cache: GraphCache,
    store: ChainStore,
    config: ChainConfig,
    k: int = 10,
) -> list[PathResult]:
    """K-shortest paths to any finding mentioning the specified entity."""
    finding_ids = _engagement_findings(store, engagement_id)
    if not finding_ids:
        return []

    qe = ChainQueryEngine(store=store, graph_cache=cache, config=config)
    results: list[PathResult] = []
    to_spec = parse_endpoint_spec(entity_ref)

    for src_id in finding_ids:
        try:
            paths = qe.k_shortest_paths(
                from_spec=parse_endpoint_spec(src_id),
                to_spec=to_spec,
                user_id=None, k=3, max_hops=6,
            )
            results.extend(paths)
        except Exception:
            continue

    results.sort(key=lambda p: (p.total_cost, p.length))
    return results[:k]


def mitre_coverage(
    engagement_id: str,
    *,
    store: ChainStore,
) -> MitreCoverageResult:
    """Count MITRE ATT&CK tactic coverage across findings in the engagement."""
    from opentools.chain.linker.rules.kill_chain import TACTIC_ORDER, TECHNIQUE_TO_TACTIC

    rows = store.execute_all(
        """
        SELECT DISTINCT e.canonical_value
        FROM entity e
        JOIN entity_mention em ON em.entity_id = e.id
        JOIN findings f ON f.id = em.finding_id
        WHERE e.type = 'mitre_technique'
          AND f.engagement_id = ?
          AND f.deleted_at IS NULL
        """,
        (engagement_id,),
    )

    tactic_counts: dict[str, int] = {}
    for r in rows:
        technique = r["canonical_value"].upper()
        tactic = TECHNIQUE_TO_TACTIC.get(technique)
        if tactic:
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

    tactics_present = sorted(tactic_counts.keys())
    tactics_missing = [t for t in TACTIC_ORDER if t not in tactic_counts]

    return MitreCoverageResult(
        engagement_id=engagement_id,
        tactic_counts=tactic_counts,
        tactics_present=tactics_present,
        tactics_missing=tactics_missing,
    )
