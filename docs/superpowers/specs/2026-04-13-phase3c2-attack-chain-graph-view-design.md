# Phase 3C.2: Per-Engagement Attack Chain Graph View — Design Specification

**Date:** 2026-04-13
**Status:** Draft
**Author:** slabl + Claude
**Depends on:** Phase 3C.1 (merged)

## 1. Overview

Phase 3C.2 adds an interactive, per-engagement attack chain graph visualization to the web dashboard. Users explore how findings relate to each other within an engagement — clicking nodes to inspect findings, hovering edges to see linking reasons, and confirming or rejecting candidate links to curate the graph.

The visualization uses `force-graph` (vasturiano) rendered on a standalone page. Scale is handled server-side: the backend filters and caps the subgraph so the renderer always gets a manageable dataset regardless of engagement size.

No global cross-engagement view (3C.3), no Cypher DSL (3C.4), no Bayesian calibration (3C.3).

## 2. Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Graph library | `force-graph` (vasturiano) | Purpose-built force-directed graph renderer, ~50KB, rich interaction API, existing `to_force_graph()` adapter from 3C.1 |
| Single library | Yes — no cosmograph fallback | Scale is solved server-side via filtering and max_nodes cap; the renderer never sees more than ~1,000 nodes. A second library adds maintenance burden for a problem the backend already solves |
| Page placement | Standalone page at `/engagements/:id/chain` | Force-graph needs maximum viewport; a tab would constrain height. Graph curation is a focused workflow, not a quick-glance tab |
| Node coloring | Severity-based (critical=red, high=orange, medium=yellow, low=blue, info=gray) | Consistent with existing `SeverityBadge.vue` palette. MITRE phase shown as small abbreviation pill, not primary color |
| MITRE ATT&CK display | Small tactic abbreviation pill on nodes (e.g. "IA", "EX", "PE"), not swim lanes | Swim lanes constrain layout and add complexity; deferred to 3C.3 as optional layout mode |
| Edge curation scope | Global (user-scoped) | `FindingRelation` unique constraint is `(source, target, user_id)`. One edge, one status. Consistent across views. Required for 3C.3 Bayesian calibration |
| Detail panel | Right-side drawer (30% width) | Curation requires stable surface for reasons/rationale + confirm/reject buttons. Popovers are too transient |
| Post-curation update | Optimistic local update | Re-fetching would reset the force simulation and destroy the user's spatial mental model |
| Filter changes | Re-fetch with position preservation | Pin `fx`/`fy` on nodes present in both old and new datasets. New nodes animate in from neighbors. Removed nodes fade out |
| Neighborhood expansion | Explicit "Expand Neighbors" button in detail panel | Avoids ambiguous double-click. Button shows neighbor count. Fetches via `seed_finding_id` + `hops` params |

## 3. Architecture

### 3.1 Data flow

```
EngagementDetailView                    ChainGraphView (standalone page)
  [View Attack Chain] ──────────────►  GET /api/chain/subgraph?engagement_id=X
                                            &severity=critical,high
                                            &status=auto_confirmed,user_confirmed,candidate
                                            &max_nodes=500
                                                │
                                                ▼
                                        to_force_graph() adapter
                                                │
                                                ▼
                                        force-graph renderer
                                                │
                                      ┌─────────┴──────────┐
                                      ▼                     ▼
                               node click              edge click
                                      │                     │
                                      ▼                     ▼
                              Detail panel:          Detail panel:
                              finding info,          reasons, rationale,
                              entities,              drift badge,
                              [Expand Neighbors]     [Confirm] [Reject]
                                      │                     │
                                      ▼                     ▼
                              GET subgraph           PATCH /api/chain/relations/:id
                              (seed + hops,          {status: "user_confirmed"}
                               merge into graph)     (optimistic local update)
```

### 3.2 No new database tables

Everything builds on existing 3C.1 tables: `ChainFindingRelation`, `ChainEntity`, `ChainEntityMention`. The `RelationStatus` enum already includes `USER_CONFIRMED` and `USER_REJECTED`. The only addition is a computed `drift` boolean derived from comparing current `reasons_json` against `confirmed_at_reasons_json`.

## 4. Backend API

### 4.1 `GET /api/chain/subgraph`

Returns a filtered, capped subgraph for an engagement.

**Query parameters:**

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| `engagement_id` | string | required | Engagement to query |
| `severity` | comma-separated | all | Filter nodes by severity |
| `status` | comma-separated | `auto_confirmed,user_confirmed,candidate` | Filter edges by relation status |
| `max_nodes` | int | 500 | Hard cap on returned nodes |
| `seed_finding_id` | string | null | Start from this node's neighborhood (for expansion). When set, `max_nodes` still applies to the neighborhood result. |
| `hops` | int | 2 | Neighborhood radius when `seed_finding_id` is provided |
| `format` | string | `force-graph` | `force-graph` or `canonical` |

**Response (force-graph format):**

```json
{
  "graph": {
    "nodes": [
      {
        "id": "f-abc",
        "name": "SQL Injection in /login",
        "severity": "critical",
        "tool": "sqlmap",
        "phase": "initial-access"
      }
    ],
    "links": [
      {
        "id": "rel-123",
        "source": "f-abc",
        "target": "f-def",
        "value": 0.82,
        "status": "auto_confirmed",
        "drift": false,
        "reasons": ["shared_strong_entity", "temporal"],
        "relation_type": "enables",
        "rationale": "Both findings target the same host (10.0.0.5) with temporal proximity..."
      }
    ]
  },
  "meta": {
    "total_findings": 1832,
    "rendered_findings": 247,
    "filtered": true,
    "generation": 3
  }
}
```

**Implementation:** new method on `ChainService` that delegates to `PostgresChainStore` for the filtered query, runs `to_force_graph()` adapter, computes drift on each relation, and attaches metadata.

**Link objects include `id`** so the frontend can issue `PATCH` requests for curation without reverse-looking up by source+target.

**Drift computation:** for each link with status `user_confirmed`, compare `reasons_json` to `confirmed_at_reasons_json`. If they differ, `drift: true`. Computed server-side in the DTO layer, not pushed to the frontend to diff.

### 4.2 `PATCH /api/chain/relations/{relation_id}`

Updates edge status for curation.

**Request:**

```json
{
  "status": "user_confirmed"
}
```

**Validation:** only `user_confirmed` and `user_rejected` are accepted. Attempting to set `auto_confirmed`, `candidate`, or `rejected` returns 422.

**Response:** the updated relation object with new status.

**Side effect:** when setting `user_confirmed`, snapshot current `reasons_json` into `confirmed_at_reasons_json` (for future drift detection).

**Auth:** scoped to current user's relations. Returns 404 if the relation belongs to another user.

### 4.3 Existing endpoints used as-is

- `POST /api/chain/rebuild` — trigger chain analysis for the engagement
- `GET /api/chain/runs/{run_id}` — poll rebuild progress

## 5. Frontend

### 5.1 Page layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  ← Back    Engagement Name    [Run Analysis]  [Severity] [Status]  │
├──────────────────────────────────────────────────┬──────────────────┤
│                                                  │                  │
│                                                  │   Detail Panel   │
│                                                  │                  │
│              force-graph canvas                  │   (node or edge  │
│              (fills remaining height)            │    details)      │
│                                                  │                  │
│                                                  │   [Confirm]      │
│                                                  │   [Reject]       │
│                                                  │                  │
│                                                  │   [Expand        │
│                                                  │    12 Neighbors] │
│                                                  │                  │
├──────────────────────────────────────────────────┴──────────────────┤
│  ● Critical ● High ● Medium ● Low ● Info                           │
│  ── Confirmed  ╌╌ Candidate  ── Rejected   Showing 247 of 1,832    │
└─────────────────────────────────────────────────────────────────────┘
```

- **Graph area:** ~70% width when detail panel is open, 100% when closed. Full viewport height minus toolbar and legend bar.
- **Detail panel:** right-side drawer, ~30% width. Opens on node/edge click, closes on X or clicking empty canvas.
- **Legend bar:** bottom strip, always visible. Severity color key, edge style key, filtered/total node count.

### 5.2 Node rendering

Custom `nodeCanvasObject` callback:

- **Shape:** filled circle, radius scaled by connection count (capped to avoid giant nodes)
- **Color:** severity-mapped — critical: `#e74c3c`, high: `#e67e22`, medium: `#f1c40f`, low: `#3498db`, info: `#95a5a6`. Matches `SeverityBadge.vue` palette.
- **Label:** finding title, truncated to ~30 chars, rendered below node. Hidden at low zoom, always shown on hover.
- **MITRE pill:** small tactic abbreviation (e.g. "IA", "EX", "PE") top-right of node. Visible at medium+ zoom.
- **Selection indicator:** bright highlight ring (thicker stroke, contrasting color) when selected.

### 5.3 Edge rendering

Custom `linkCanvasObject` callback:

| Status | Style |
|--------|-------|
| `auto_confirmed` | Solid line, opacity proportional to weight |
| `user_confirmed` | Solid line, full opacity, slightly thicker |
| `candidate` | Dashed line, lower opacity |
| `rejected` / `user_rejected` | Thin red dashed line (hidden by default filter) |

- **Direction:** small arrowhead at target end
- **Drift badge:** small warning triangle (▲) at edge midpoint when `drift: true`
- **Selection indicator:** thicker line with glow effect when selected

### 5.4 Interactions

| Action | Result |
|--------|--------|
| Click node | Open detail panel with finding info (title, severity, tool, phase, linked entities, neighbor count). Show "Expand N Neighbors" button. |
| Click edge | Open detail panel with weight, status, all firing rule reasons with individual weight contributions, LLM rationale (if present), drift warning (if applicable). Show Confirm/Reject buttons. |
| Hover node | Tooltip with title + severity. Highlight connected edges. |
| Hover edge | Tooltip with weight + status + primary reason. |
| Click empty canvas | Close detail panel. Deselect current node/edge. |
| Scroll | Zoom in/out. Node labels appear/hide based on zoom level threshold. |
| Drag node | Reposition (force-graph handles natively). |

### 5.5 Neighborhood expansion

1. User clicks node → detail panel shows "Expand N Neighbors" button with count
2. User clicks button
3. Frontend calls `GET /api/chain/subgraph?seed_finding_id=X&hops=2` with current severity/status filters
4. Merge response into existing graph data (deduplicate nodes/links by ID)
5. New nodes animate in from the seed node's position (force simulation handles naturally)
6. Legend bar node count updates

### 5.6 Edge curation flow

1. User clicks an edge → detail panel opens
2. Panel shows: source finding title → target finding title, weight, status badge, each rule reason with its weight contribution, LLM rationale (if any), drift warning (if any)
3. User clicks Confirm or Reject
4. `PATCH /api/chain/relations/:id` fires
5. Optimistic update: edge style changes immediately (e.g. dashed candidate → solid confirmed)
6. On error: revert edge style, show PrimeVue toast with error message

### 5.7 Filter toolbar

Integrated into the top toolbar row:

- **Severity toggles:** PrimeVue `SelectButton` (multi-select) for critical/high/medium/low/info. Default: all on.
- **Status toggles:** PrimeVue `SelectButton` (multi-select) for confirmed/candidate/rejected. Default: confirmed + candidate on.
- **Reset button:** restores default filter state.

Changing any filter re-fetches `GET /api/chain/subgraph` with updated params. On re-fetch, nodes present in both old and new datasets preserve their `fx`/`fy` positions. New nodes animate in. Removed nodes are dropped.

### 5.8 Empty state

When engagement has zero chain relations:

- Centered empty-state component: icon + "No attack chain data yet"
- "Run Chain Analysis" primary button
- Click triggers `POST /api/chain/rebuild` with `engagement_id`
- Progress bar appears, polls `GET /api/chain/runs/:id` every 2 seconds
- On completion (`status: "done"`), auto-fetches subgraph and renders graph
- On failure, shows error toast with the run's error message

### 5.9 Navigation

- **Entry point:** "View Attack Chain" button added to `EngagementDetailView.vue` header (next to the Delete button)
- **Route:** `/engagements/:id/chain` added to router
- **Back navigation:** "← Back" button in toolbar navigates to `/engagements/:id`

### 5.10 Vue components

| Component | Purpose | Est. lines |
|-----------|---------|------------|
| `ChainGraphView.vue` | Page component — data fetching, filter state, layout orchestration | ~200 |
| `ForceGraphCanvas.vue` | Wrapper around `force-graph` instance — rendering config, custom draw callbacks, interaction events | ~300 |
| `ChainDetailPanel.vue` | Right drawer — node details, edge details with reasons, curation buttons | ~250 |
| `ChainFilterToolbar.vue` | Severity/status toggle buttons | ~80 |
| `ChainLegend.vue` | Bottom bar — severity color key, edge style key, node count | ~60 |
| `ChainEmptyState.vue` | Empty state + rebuild progress | ~80 |

## 6. Testing

### 6.1 Backend tests

- **Subgraph endpoint:** filter combinations (severity subset, status subset, max_nodes cap), seed + hops neighborhood query, empty engagement (no findings), engagement with findings but no chain data (no relations), format parameter (force-graph vs canonical)
- **Relation PATCH:** valid transitions (candidate → user_confirmed, candidate → user_rejected, user_confirmed → user_rejected, user_rejected → user_confirmed), invalid status values return 422, auth scoping (404 for another user's relation), `confirmed_at_reasons_json` snapshot on confirm
- **Drift computation:** relation with unchanged reasons → `drift: false`, relation with changed reasons since confirm → `drift: true`, relation never confirmed → `drift: false`
- **Rebuild → subgraph integration:** trigger rebuild, poll to completion, fetch subgraph, verify non-empty nodes and edges

### 6.2 Frontend tests

- **`ChainDetailPanel`:** renders node details (title, severity, tool, phase, entity list, neighbor count), renders edge details (weight, status, reasons with contributions, rationale, drift badge), confirm/reject buttons emit correct events with relation ID
- **`ChainFilterToolbar`:** toggle state management, emits filter change event with correct severity/status arrays
- **`ChainEmptyState`:** shows rebuild button, shows progress bar during polling
- **`ForceGraphCanvas`:** no unit tests (canvas rendering not testable in jsdom). Manual browser verification.

## 7. Scope boundaries

### 7.1 In scope (3C.2)

- `force-graph` per-engagement standalone page at `/engagements/:id/chain`
- "View Attack Chain" button on `EngagementDetailView`
- `GET /api/chain/subgraph` with filtering, max_nodes cap, seed neighborhood expansion
- `PATCH /api/chain/relations/:id` for edge curation (confirm/reject)
- Severity color coding on nodes
- MITRE tactic abbreviation pill on nodes
- Edge style encoding (solid/dashed/red by status, opacity by weight)
- Right-side detail panel with node info, edge reasons/rationale, confirm/reject
- Drift badge on edges where reasons changed post-confirmation
- Filter toolbar (severity and status toggles)
- Legend bar with color key, edge style key, and node count
- Empty state with "Run Analysis" → rebuild polling → auto-load
- Optimistic curation updates
- Position-preserving re-renders on filter change
- Neighborhood expansion via explicit button in detail panel
- Selected node/edge highlight indicator

### 7.2 Out of scope (deferred)

| Feature | Deferred to |
|---------|-------------|
| Global cross-engagement graph view | 3C.3 |
| Swim lane layout by MITRE phase | 3C.3 |
| Attack vector scoring | 3C.3 |
| Timeline playback | 3C.3 |
| Path-as-report export | 3C.3 |
| Bayesian weight calibration | 3C.3 |
| Cypher query DSL / query editor | 3C.4 |
| Server-side node clustering/aggregation | 3C.3 |
| Keyboard shortcuts for graph navigation | Future |
| Canvas accessibility (screen reader support) | Future |

## 8. Estimated size

| Layer | New/Modified | Est. lines |
|-------|-------------|------------|
| Backend: subgraph endpoint + service method | New | ~150 |
| Backend: relation PATCH endpoint | New | ~50 |
| Backend: drift computation in DTO | Modified | ~30 |
| Frontend: `ChainGraphView.vue` | New | ~200 |
| Frontend: `ForceGraphCanvas.vue` | New | ~300 |
| Frontend: `ChainDetailPanel.vue` | New | ~250 |
| Frontend: `ChainFilterToolbar.vue` | New | ~80 |
| Frontend: `ChainLegend.vue` | New | ~60 |
| Frontend: `ChainEmptyState.vue` | New | ~80 |
| Frontend: router + nav link | Modified | ~10 |
| Tests: backend | New | ~250 |
| Tests: frontend | New | ~150 |
| **Total** | | **~1,610** |

## 9. Forward context (for 3C.3, 3C.4)

### 9.1 Cross-engagement view (3C.3)

- The subgraph endpoint is scoped by `engagement_id` in 3C.2. In 3C.3, a `null` or omitted `engagement_id` returns user-wide cross-engagement data.
- Swim lane layout by MITRE phase becomes an optional layout mode toggle on the toolbar.
- If cross-engagement scale exceeds what `force-graph` handles comfortably even with max_nodes filtering, server-side node clustering (grouping findings by host or phase into aggregate nodes) is the next lever.

### 9.2 Cypher DSL (3C.4)

- The graph view gains a query editor panel (CodeMirror + Cypher mode) where users type queries. Results highlight matching subgraphs in the existing force-graph canvas.
- No architectural changes needed — queries return canonical graph-json, which feeds through the same `to_force_graph()` adapter.
