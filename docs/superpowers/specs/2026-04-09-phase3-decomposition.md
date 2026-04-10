# Phase 3 Decomposition

**Date:** 2026-04-09
**Status:** Planning
**Author:** slabl + Claude

## Sub-Phases

Phase 3 decomposes into 5 independent sub-projects, built in this order. Phase 3C itself further decomposes into 4 sub-phases (see below).

| Sub-Phase | Feature | Dependencies | Est. Scope |
|-----------|---------|-------------|------------|
| **3A** | Web Dashboard (FastAPI + Vue 3 + PrimeVue) | Store API (exists) | ~3,000 lines |
| **3B** | IOC Correlation & Trending | Store (exists), cross-engagement queries (exist) | ~1,500 lines |
| **3C** | Attack Chain Visualization (decomposes into 3C.1-3C.4) | 3B | ~15,000 lines total |
| **3D** | Team Collaboration | Web dashboard (3A) + auth | ~2,000 lines |
| **3E** | Plugin Marketplace | Independent | ~1,500 lines |

### Phase 3C Sub-Phases

Phase 3C expanded beyond the original ~2,000-line estimate after brainstorming. Split into four sub-phases, each with its own spec, plan, and PR:

| Sub-Phase | Feature | Depends on | Est. Scope |
|---|---|---|---|
| **3C.1** | Data layer: entity extraction, knowledge graph, rule-based linking with optional LLM pass, path query engine, CLI commands, read-only web API | 3B | ~8,250 lines |
| **3C.2** | Per-engagement interactive graph view (`force-graph` vasturiano), edge curation UI (confirm/reject), MITRE ATT&CK phase coloring | 3C.1 | ~2,500 lines |
| **3C.3** | Global cross-engagement view, attack vector scoring, timeline playback, path-as-report export, Bayesian weight calibration from accumulated user decisions | 3C.2 | ~2,500 lines |
| **3C.4** | Cypher-style query DSL: parser/AST/executor over `rustworkx`, CLI REPL, web query editor, plugin query functions | 3C.1-3C.3 | ~2,000 lines |

## Order Rationale

1. **3A first** — the web dashboard is the foundation for team collaboration (3D) and provides a richer UI surface for visualization (3C). It also makes IOC correlation (3B) more accessible to non-CLI users.

2. **3B second** — builds on the existing store's `search_ioc()` cross-engagement query. Backend logic is independent of the web dashboard but benefits from a web UI for timeline/trend views.

3. **3C third** — requires a new data model (finding links / attack chains) that extends the existing engagement schema. Decomposed into 3C.1 (data layer, no viz), 3C.2 (per-engagement viz), 3C.3 (global view + advanced + Bayesian calibration), 3C.4 (Cypher-style query DSL).

4. **3D fourth** — multi-user requires authentication, authorization, and shared state. This naturally builds on the web dashboard (3A) since the TUI is inherently single-user.

5. **3E last** — plugin marketplace is distribution infrastructure, independent of all feature work. It's lowest priority until the product has enough users to warrant a marketplace.

## Each sub-phase gets its own:
- Design spec (`docs/superpowers/specs/`)
- Implementation plan (`docs/superpowers/plans/`)
- Feature branch + PR
