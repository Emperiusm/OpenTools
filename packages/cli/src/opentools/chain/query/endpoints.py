"""Endpoint resolver: turn user-provided endpoint specs into rustworkx node index sets."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Literal

from opentools.chain.models import entity_id_for
from opentools.chain.normalizers import normalize
from opentools.chain.query.graph_cache import MasterGraph
from opentools.chain.store_extensions import ChainStore


@dataclass
class EndpointSpec:
    kind: Literal["finding_id", "entity", "predicate"]
    finding_id: str | None = None
    entity_type: str | None = None
    entity_value: str | None = None
    predicate: Callable | None = None
    # Raw source string for error messages
    raw: str | None = None


def parse_endpoint_spec(raw: str) -> EndpointSpec:
    """Parse a CLI endpoint specification.

    - ``fnd_xxx`` / ``fnd-xxx`` / any token with underscore that starts
      with 'fnd' → finding_id endpoint
    - ``type:value`` (colon-separated) → entity endpoint
    - ``key=value`` (equals-separated) → predicate endpoint

    Finding_id is tried first; type:value takes precedence if the token
    contains a colon AND no equals sign.
    """
    stripped = raw.strip()
    if not stripped:
        raise ValueError("empty endpoint spec")

    if "=" in stripped and ":" not in stripped.split("=", 1)[0]:
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip()
        predicate = _build_predicate(key, value)
        return EndpointSpec(kind="predicate", predicate=predicate, raw=raw)

    if ":" in stripped:
        entity_type, entity_value = stripped.split(":", 1)
        return EndpointSpec(
            kind="entity",
            entity_type=entity_type.strip(),
            entity_value=entity_value.strip(),
            raw=raw,
        )

    # Treat as finding_id
    return EndpointSpec(kind="finding_id", finding_id=stripped, raw=raw)


def _build_predicate(key: str, value: str) -> Callable:
    """Build a node-filter predicate from key=value syntax."""
    def predicate(node) -> bool:
        return getattr(node, key, None) == value
    return predicate


def resolve_endpoint(
    spec: EndpointSpec,
    master: MasterGraph,
    store: ChainStore,
) -> set[int]:
    """Return rustworkx node indices matching the spec."""
    if spec.kind == "finding_id":
        if spec.finding_id is None:
            raise ValueError("finding_id spec missing finding_id")
        idx = master.node_map.get(spec.finding_id)
        return {idx} if idx is not None else set()

    if spec.kind == "entity":
        if spec.entity_type is None or spec.entity_value is None:
            raise ValueError("entity spec missing type or value")
        canonical = normalize(spec.entity_type, spec.entity_value)
        ent_id = entity_id_for(spec.entity_type, canonical)
        rows = store.execute_all(
            "SELECT DISTINCT finding_id FROM entity_mention WHERE entity_id = ?",
            (ent_id,),
        )
        result = set()
        for r in rows:
            idx = master.node_map.get(r["finding_id"])
            if idx is not None:
                result.add(idx)
        return result

    if spec.kind == "predicate":
        if spec.predicate is None:
            raise ValueError("predicate spec missing callable")
        result = set()
        for idx in master.graph.node_indices():
            node = master.graph.get_node_data(idx)
            try:
                if spec.predicate(node):
                    result.add(idx)
            except Exception:
                continue
        return result

    raise ValueError(f"unknown endpoint kind: {spec.kind}")
