"""ChainStoreProtocol — backend-agnostic async interface for chain data.

See docs/superpowers/specs/2026-04-10-phase3c1-5-async-store-refactor-design.md
§4 for the full method list and contracts.

Method count: 32. Organized into sections:
- Lifecycle (4)
- Entity CRUD (6)
- Mention CRUD (7)
- Relation CRUD (5)
- Linker-specific queries (5)
- LinkerRun lifecycle (5)
- Extraction state + parser output (3)
- LLM caches (4)
- Export (2)

Actual method signatures are defined in Tasks 3a, 3b, 3c.
"""
from __future__ import annotations
