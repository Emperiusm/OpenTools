# Phase 3 Decomposition

**Date:** 2026-04-09
**Status:** Planning
**Author:** slabl + Claude

## Sub-Phases

Phase 3 decomposes into 5 independent sub-projects, built in this order:

| Sub-Phase | Feature | Dependencies | Est. Scope |
|-----------|---------|-------------|------------|
| **3A** | Web Dashboard (FastAPI + HTMX) | Store API (exists) | ~3,000 lines |
| **3B** | IOC Correlation & Trending | Store (exists), cross-engagement queries (exist) | ~1,500 lines |
| **3C** | Attack Chain Visualization | New finding-linking model + UI | ~2,000 lines |
| **3D** | Team Collaboration | Web dashboard (3A) + auth | ~2,000 lines |
| **3E** | Plugin Marketplace | Independent | ~1,500 lines |

## Order Rationale

1. **3A first** — the web dashboard is the foundation for team collaboration (3D) and provides a richer UI surface for visualization (3C). It also makes IOC correlation (3B) more accessible to non-CLI users.

2. **3B second** — builds on the existing store's `search_ioc()` cross-engagement query. Backend logic is independent of the web dashboard but benefits from a web UI for timeline/trend views.

3. **3C third** — requires a new data model (finding links / attack chains) that extends the existing engagement schema. The visualization component needs either the TUI or web dashboard.

4. **3D fourth** — multi-user requires authentication, authorization, and shared state. This naturally builds on the web dashboard (3A) since the TUI is inherently single-user.

5. **3E last** — plugin marketplace is distribution infrastructure, independent of all feature work. It's lowest priority until the product has enough users to warrant a marketplace.

## Each sub-phase gets its own:
- Design spec (`docs/superpowers/specs/`)
- Implementation plan (`docs/superpowers/plans/`)
- Feature branch + PR
