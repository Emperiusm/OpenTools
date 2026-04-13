"""Startup sweeper for orphaned ephemeral proxy nodes."""
from __future__ import annotations
import logging
from opentools.scanner.infra.proxy import PROXY_TAG

logger = logging.getLogger(__name__)

async def sweep_orphaned_nodes(provider: object) -> int:
    """Destroy nodes tagged with PROXY_TAG from previous runs.
    Provider must implement list_nodes_by_tag(tag) and destroy_node(id).
    Returns count of nodes successfully destroyed."""
    if not hasattr(provider, "list_nodes_by_tag"):
        logger.debug("Provider does not support list_nodes_by_tag, skipping sweep")
        return 0
    orphan_ids = await provider.list_nodes_by_tag(PROXY_TAG)
    if not orphan_ids:
        return 0
    logger.info("Found %d orphaned proxy nodes to sweep", len(orphan_ids))
    destroyed = 0
    for node_id in orphan_ids:
        try:
            await provider.destroy_node(node_id)
            destroyed += 1
            logger.info("Destroyed orphaned node %s", node_id)
        except Exception:
            logger.exception("Failed to destroy orphaned node %s", node_id)
    return destroyed
