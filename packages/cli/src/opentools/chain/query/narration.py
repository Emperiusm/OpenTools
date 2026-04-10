"""LLM path narration with content-addressed cache."""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone

import orjson

from opentools.chain.extractors.llm.base import LLMExtractionProvider
from opentools.chain.query.graph_cache import PathResult
from opentools.chain.store_extensions import ChainStore

logger = logging.getLogger(__name__)


def _cache_key(
    path: PathResult, provider_name: str, model: str, schema_version: int
) -> str:
    finding_ids = ",".join(n.finding_id for n in path.nodes)
    edge_reasons = "|".join(
        "+".join(sorted(e.reasons_summary)) for e in path.edges
    )
    payload = f"narration|{finding_ids}|{edge_reasons}|{provider_name}|{model}|{schema_version}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def narrate_path(
    path: PathResult,
    *,
    provider: LLMExtractionProvider,
    store: ChainStore,
    cache_schema_version: int = 1,
) -> str | None:
    """Return an LLM-generated narrative for the path, or None on error."""
    if not path.nodes:
        return None

    key = _cache_key(path, provider.name, provider.model, cache_schema_version)
    cached = store.execute_one(
        "SELECT classification_json FROM llm_link_cache WHERE cache_key = ?",
        (key,),
    )
    if cached is not None:
        try:
            data = orjson.loads(cached["classification_json"])
            return data.get("narration") if isinstance(data, dict) else str(data)
        except Exception:
            pass

    # Load findings + edges for the path to pass to the provider
    findings_data = [{"id": n.finding_id, "title": n.title, "severity": n.severity, "tool": n.tool} for n in path.nodes]
    edges_data = [
        {
            "source": e.source_finding_id,
            "target": e.target_finding_id,
            "reasons": e.reasons_summary,
            "rationale": e.llm_rationale,
        }
        for e in path.edges
    ]

    try:
        narration = await provider.generate_path_narration(findings_data, edges_data)
    except Exception as exc:
        logger.warning("LLM narration failed: %s", exc)
        return None

    if not isinstance(narration, str):
        return None

    # Cache the result
    try:
        store._conn.execute(
            """
            INSERT OR REPLACE INTO llm_link_cache
                (cache_key, provider, model, schema_version, classification_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                key,
                provider.name,
                provider.model,
                cache_schema_version,
                orjson.dumps({"narration": narration}),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        store._conn.commit()
    except Exception:
        pass

    return narration
