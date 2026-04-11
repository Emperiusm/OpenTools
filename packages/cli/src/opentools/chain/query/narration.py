"""LLM path narration with content-addressed cache."""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import orjson

from opentools.chain._cache_keys import narration_cache_key
from opentools.chain.extractors.llm.base import LLMExtractionProvider
from opentools.chain.query.graph_cache import PathResult

if TYPE_CHECKING:
    from opentools.chain.store_protocol import ChainStoreProtocol

logger = logging.getLogger(__name__)


async def narrate_path(
    path: PathResult,
    *,
    provider: LLMExtractionProvider,
    store: "ChainStoreProtocol",
    cache_schema_version: int = 1,
    user_id=None,
) -> str | None:
    """Return an LLM-generated narrative for the path, or None on error."""
    if not path.nodes:
        return None

    # Build the content-addressed cache key from path topology + provider.
    path_finding_ids = [n.finding_id for n in path.nodes]
    edge_reasons_summary = [
        "+".join(sorted(e.reasons_summary)) for e in path.edges
    ]
    cache_key = narration_cache_key(
        path_finding_ids=path_finding_ids,
        edge_reasons_summary=edge_reasons_summary,
        provider=provider.name,
        model=provider.model,
        schema_version=cache_schema_version,
        user_id=user_id,
    )

    cached_bytes = await store.get_llm_link_cache(cache_key, user_id=user_id)
    if cached_bytes is not None:
        try:
            data = orjson.loads(cached_bytes)
            if isinstance(data, dict):
                narration = data.get("narration")
                if isinstance(narration, str):
                    return narration
        except Exception:
            pass

    # Load findings + edges for the path to pass to the provider
    findings_data = [
        {
            "id": n.finding_id,
            "title": n.title,
            "severity": n.severity,
            "tool": n.tool,
        }
        for n in path.nodes
    ]
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

    # Cache the result via protocol methods.
    try:
        async with store.transaction():
            await store.put_llm_link_cache(
                cache_key=cache_key,
                provider=provider.name,
                model=provider.model,
                schema_version=cache_schema_version,
                classification_json=orjson.dumps({"narration": narration}),
                user_id=user_id,
            )
    except Exception as exc:
        logger.warning("Failed to cache narration: %s", exc)

    return narration
