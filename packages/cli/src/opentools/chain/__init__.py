"""Attack chain data layer — entity extraction, knowledge graph, path queries.

Phase 3C.1. See docs/superpowers/specs/2026-04-10-phase3c1-attack-chain-data-layer-design.md
"""

from opentools.chain.config import (
    ChainConfig,
    get_chain_config,
    reset_chain_config,
    set_chain_config,
)

__all__ = ["ChainConfig", "get_chain_config", "reset_chain_config", "set_chain_config"]

# Built-in entity type registrations are wired up in Task 6.
# from opentools.chain import normalizers  # noqa: F401,E402
