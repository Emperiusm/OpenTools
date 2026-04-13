# Phase 3C.3: Global View, Bayesian Calibration & Advanced Features — Design Specification

**Date:** 2026-04-13
**Status:** Draft
**Author:** slabl + Claude
**Depends on:** Phase 3C.2 (merged)

## 1. Overview

Phase 3C.3 adds six features to the attack chain infrastructure:

1. **Global cross-engagement graph view** — standalone page showing findings across all engagements with engagement color coding and filter chips
2. **Bayesian weight calibration** — Beta-prior Bayesian model that learns from user confirm/reject decisions to improve edge weights
3. **Timeline playback** — time-range scrubber with activity heatmap and temporal anchoring for stable layout
4. **Path-as-report export** — Markdown report from selected attack paths
5. **Swim lane layout** — Kill Chain view with full lane dividers, phase headers, and curved inter-lane edges
6. **Attack vector scoring** — path-level risk scores and node-level pivotality (betweenness centrality)

No Cypher DSL (3C.4), no PDF export, no server-side clustering.

## 2. Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Global view placement | Separate dedicated page at `/chain/global` | Cross-engagement work needs engagement color coding and filter chips — different UI affordances than the per-engagement page |
| Global view node coloring | Engagement-based primary color, severity as ring/border | At cross-engagement scale, knowing which engagement a finding belongs to matters more than severity (which is shown on hover/click) |
| Bayesian model | Full Bayesian with Beta distribution priors | Handles sparse data better than simple empirical counts; rules with few observations fall back to the prior gracefully |
| Bayesian priors | Beta(2,1) for strong rules (shared_entity, cve_adjacency), Beta(1,1) for others | Encodes mild belief that entity-based rules are more reliable before any user data |
| Calibration minimum threshold | 20 user-decided edges | Prevents wild swings from sparse data; below threshold, additive_v1 weights used unchanged |
| Timeline approach | Temporal anchoring — pre-calculated layout, visibility animation | Prevents layout jitter; nodes exist at anchor positions, opacity controlled by time window |
| Timeline interaction | Dual-handle time range selector with activity heatmap | Windowed time filtering more useful than linear playback for investigating specific time slices |
| Report format | Markdown only | Immediately useful (paste into any report), no server-side rendering dependencies; PDF deferred to future |
| Swim lane rendering | Full lane rendering — visible dividers, phase headers, curved inter-lane edges | More polished than fixed-X-free-Y; worth the rendering code investment |
| Attack vector scoring | Both path-level risk scores and node-level pivotality | Different purposes: "which chain is most dangerous" vs "which finding is most pivotal"; neither is expensive to compute |
| Pivotality computation | rustworkx betweenness_centrality on backend | Millisecond-scale even for 1,000 nodes; result added to subgraph response |

## 3. Feature 1: Global Cross-Engagement View

### 3.1 New page

**Route:** `/chain/global`
**Nav entry:** new "Attack Chain" item in the main Menubar (alongside Engagements, Recipes, Containers, IOCs).

### 3.2 Backend changes

The existing `GET /api/chain/subgraph` endpoint's `engagement_id` parameter becomes optional:
- When provided: per-engagement behavior (unchanged from 3C.2)
- When omitted: queries findings across all engagements for the authenticated user

The `meta` response gains an `engagements` array:
```json
{
  "meta": {
    "total_findings": 4200,
    "rendered_findings": 500,
    "filtered": true,
    "generation": 7,
    "engagements": [
      {"id": "eng-1", "name": "Corporate Pentest Q1"},
      {"id": "eng-2", "name": "Web App Assessment"}
    ]
  }
}
```

Node objects gain an `engagement_id` field so the frontend can color-code by engagement.

### 3.3 Frontend

**New component:** `GlobalChainView.vue` — page component similar to `ChainGraphView.vue` but with:
- **Engagement color palette:** each engagement gets a distinct color from a 10-color palette. Nodes use engagement color as primary fill, severity as border ring.
- **Engagement filter chips:** a row of toggle chips above the graph, one per engagement (name + color dot). Click to include/exclude. Default: all included. Toggling re-fetches the subgraph with an `engagement_ids` filter param.
- **Cross-engagement edge emphasis:** edges from the `cross_engagement_ioc` rule rendered thicker with a distinct color (these are the most interesting cross-cutting connections).

**Reuses:** `ForceGraphCanvas`, `ChainDetailPanel`, `ChainLegend`, `ChainFilterToolbar` components from 3C.2. `ForceGraphCanvas` needs a minor extension to accept a custom node color function (currently hardcoded to severity colors).

### 3.4 Backend: engagement_ids filter

New optional query parameter on `GET /api/chain/subgraph`:
```
engagement_ids=eng-1,eng-2
```
Only valid when `engagement_id` is omitted (global mode). Filters to findings from the specified engagements. Ignored if `engagement_id` is set. Enables the filter chips to exclude engagements without client-side filtering.

## 4. Feature 2: Bayesian Weight Calibration

### 4.1 Model

Each of the 6 default linking rules gets a Beta(α, β) prior:

| Rule | Default Prior | Rationale |
|---|---|---|
| shared_strong_entity | Beta(2, 1) | Strong entity matches are inherently reliable |
| cve_adjacency | Beta(2, 1) | CVE-based links are high-signal |
| temporal_proximity | Beta(1, 1) | Uninformative — could go either way |
| kill_chain | Beta(1, 1) | Uninformative |
| tool_chain | Beta(1, 1) | Uninformative |
| cross_engagement_ioc | Beta(1, 1) | Uninformative |

**Update rule:** for each user-decided edge:
- Inspect which rules fired (from `reasons` list)
- If `user_confirmed`: α += 1 for each fired rule
- If `user_rejected`: β += 1 for each fired rule
- Posterior mean for rule r = α_r / (α_r + β_r)

**Re-scoring:** each edge's rule contributions are multiplied by the posterior mean for that rule. Edge weight is recomputed, `weight_model_version` set to `"bayesian_v1"`.

**Minimum threshold:** 20 total user decisions (confirmed + rejected) required before calibration activates. Below that, the endpoint returns a 422 with a message indicating insufficient data.

**Coexistence:** `additive_v1` and `bayesian_v1` edges coexist. Re-running the linker after calibration produces `bayesian_v1` edges; old edges are updated in place.

### 4.2 Storage

New table `ChainCalibrationState`:

```python
class ChainCalibrationState(SQLModel, table=True):
    __tablename__ = "chain_calibration_state"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    rule: str                    # linking rule name
    alpha: float = Field(default=1.0)
    beta: float = Field(default=1.0)
    observations: int = Field(default=0)
    last_calibrated_at: datetime = Field(**_TZ_KW)
```

Max 6 rows per user (one per rule). Seeded with default priors on first calibration run.

### 4.3 CLI command

```
opentools chain calibrate [--scope engagement|user] [--dry-run]
```

- `--scope user` (default): aggregates all user decisions across engagements
- `--scope engagement --engagement <id>`: uses only decisions within one engagement
- `--dry-run`: prints per-rule posteriors and edge count that would change, without writing

### 4.4 Web endpoint

```
POST /api/chain/calibrate
Body: { "scope": "user" }  // or { "scope": "engagement", "engagement_id": "..." }

Response: {
  "rules": [
    {"rule": "shared_strong_entity", "alpha": 15, "beta": 3, "posterior": 0.833, "observations": 18},
    ...
  ],
  "edges_updated": 142,
  "below_threshold": false
}
```

### 4.5 Graph view integration

After calibration, the detail panel shows both weights when viewing an edge:
- "Weight: 0.82 (additive)" or "Weight: 0.91 (calibrated)"
- Small "Calibrated" badge on edges with `weight_model_version="bayesian_v1"`

## 5. Feature 3: Timeline Playback

### 5.1 Layout strategy

1. On page load, the full subgraph is fetched and `force-graph` runs its simulation to completion (warmup phase)
2. All node positions (x, y) are recorded as "anchor" positions
3. During playback, nodes exist at their anchor positions but visibility is controlled by opacity — `0` when outside the time window, `1` when inside, with a 200ms fade transition
4. Edges are visible only when both endpoints are visible

### 5.2 Backend change

Add `created_at` to node objects in the subgraph response:
```json
{
  "id": "f-abc",
  "name": "SQL Injection in /login",
  "severity": "critical",
  "tool": "sqlmap",
  "phase": "initial-access",
  "created_at": "2026-04-10T14:30:00Z"
}
```

### 5.3 UI components

**New component:** `ChainTimelineScrubber.vue`

- **Dual-handle slider:** two handles on a horizontal bar. Left = window start, right = window end. Drag either to adjust.
- **Play button:** left of the scrubber. Animates the left handle forward at configurable speed (1x, 2x, 5x, 10x via dropdown).
- **Activity heatmap:** rendered on the scrubber bar background as a histogram of node density over time. Bright spikes indicate bursts of discovery.
- **Time readout:** displays the current window as "Apr 10 14:00 – Apr 10 14:15" above the scrubber.
- **Reset button:** sets window to full time range (all nodes visible).

### 5.4 Integration

The scrubber emits a `time-range-change` event with `{ start: Date, end: Date }`. The parent page (`ChainGraphView` or `GlobalChainView`) passes this to `ForceGraphCanvas`, which applies opacity filtering to nodes based on their `created_at`.

`ForceGraphCanvas` changes:
- Accept optional `timeRange: { start: Date, end: Date } | null` prop
- In `nodeCanvasObject`, set node opacity to 0 if `created_at` is outside the range
- In `linkCanvasObject`, set edge opacity to 0 if either endpoint is hidden
- Edges and nodes that are outside the time window are not interactive (clicks pass through)

### 5.5 Applies to both pages

The timeline scrubber is available on both `/engagements/:id/chain` and `/chain/global`.

## 6. Feature 4: Path-as-Report Export

### 6.1 Backend endpoint

```
POST /api/chain/export/path
Body: {
  "finding_ids": ["f-1", "f-2", "f-3", "f-4"],
  "engagement_id": "eng-1"  // optional, for report header
}

Response: {
  "markdown": "# Attack Path Report: Corporate Pentest Q1\n\n..."
}
```

The endpoint:
1. Fetches each finding in order
2. Fetches the relation between consecutive findings for linking reasons
3. Assembles the Markdown using a template
4. If the existing narration module has LLM access, generates a one-paragraph summary; otherwise uses a template-based summary

### 6.2 Markdown structure

```markdown
# Attack Path Report

**Engagement:** [name]
**Generated:** [timestamp]
**Path length:** [N] steps
**Risk score:** [score]/10

## Summary

[Template-based or LLM-generated narrative summarizing the attack path]

## Step 1: [finding title] ([severity])

- **Tool:** [tool]
- **Phase:** [MITRE phase]
- **Evidence:** [evidence field, truncated to 500 chars]
- **Remediation:** [remediation field]

**Link to Step 2:** [rule reasons], weight: [weight]

## Step 2: [finding title] ([severity])
...

## Recommendations

[Ordered list of remediation steps from each finding's remediation field, deduplicated]
```

### 6.3 CLI command

```
opentools chain path <from> <to> --format markdown
```

Extends the existing `chain path` command with `markdown` as a new format option alongside `table`, `json`, `graph-json`, `dot`.

### 6.4 Frontend

"Export Path" button in `ChainDetailPanel` when a path is displayed. Clicks the endpoint and triggers a browser download of `attack-path-report.md`.

## 7. Feature 5: Swim Lane Layout (Kill Chain Mode)

### 7.1 Toggle

"Layout" button in the toolbar toggles between "Force" (default) and "Kill Chain". State persisted in the component (not in URL).

### 7.2 Kill Chain rendering

When active:
- **Lane columns:** one per MITRE tactic phase, ordered left-to-right: Reconnaissance → Resource Development → Initial Access → Execution → Persistence → Privilege Escalation → Defense Evasion → Credential Access → Discovery → Lateral Movement → Collection → C2 → Exfiltration → Impact. Plus an "Other" lane on the far right for findings without a phase.
- **Lane dividers:** vertical lines rendered on the canvas via `onRenderFramePost` callback. Subtle dashed lines with phase header labels at the top.
- **Node positioning:** `fx` set to the lane center X coordinate based on node's `phase` field. Force simulation handles Y positioning freely within each lane.
- **Inter-lane edges:** rendered as quadratic bezier curves to avoid visual clutter. Control point offset perpendicular to the straight-line path.
- **Intra-lane edges:** rendered as short arcs (semicircular curves) within the lane.

### 7.3 ForceGraphCanvas changes

- Accept `layoutMode: 'force' | 'killchain'` prop
- When `killchain`: compute lane X positions from canvas width, set `fx` on all nodes, swap `linkCanvasObject` to bezier rendering, add `onRenderFramePost` for lane dividers
- When switching back to `force`: clear `fx`/`fy`, restore straight-line edge rendering, remove lane dividers

## 8. Feature 6: Attack Vector Scoring

### 8.1 Path risk score

For each path from k-shortest-paths results:

```
score = sum(edge_weights) * max_severity_multiplier / hop_count_penalty
```

Severity multipliers: critical=5, high=4, medium=3, low=2, info=1.
`max_severity_multiplier` = highest severity multiplier among all findings in the path.
`hop_count_penalty` = `sqrt(hop_count)` (longer paths are penalized but not linearly).

Normalized to 0-10 scale. Displayed in the detail panel when a path is viewed, and included in the Markdown export.

### 8.2 Node pivotality score

Betweenness centrality computed via `rustworkx.betweenness_centrality()` on the subgraph. Added to each node in the subgraph response:

```json
{
  "id": "f-abc",
  "name": "SQL Injection in /login",
  "severity": "critical",
  "tool": "sqlmap",
  "phase": "initial-access",
  "created_at": "2026-04-10T14:30:00Z",
  "pivotality": 0.73
}
```

**Visualization:** nodes with high pivotality get a glow effect — a larger, semi-transparent circle behind the main node circle. Intensity proportional to pivotality score. Helps users spot single points of failure at a glance.

**Computation:** performed server-side in the subgraph service method. `rustworkx.betweenness_centrality()` returns a dict of node_index → score; mapped to finding IDs and normalized to 0-1.

## 9. Testing

### 9.1 Backend tests

- **Subgraph global mode:** `engagement_id` omitted returns cross-engagement data with `engagements` in meta
- **Subgraph engagement_ids filter:** returns only findings from specified engagements
- **Subgraph node fields:** `created_at`, `pivotality`, `engagement_id` present in response
- **Calibration endpoint:** enough decisions → returns posteriors + edges_updated; below threshold → 422; dry-run → no writes
- **Calibration math:** known inputs (5 confirmed, 2 rejected for a rule with Beta(2,1) prior) → correct posterior (α=7, β=3, posterior=0.7)
- **Export endpoint:** valid path → Markdown string with all sections; invalid finding_ids → 404
- **Pivotality computation:** known star-topology graph → center node has highest score
- **Path risk score:** known path → expected normalized score

### 9.2 Frontend tests

- **Timeline scrubber:** emits correct time range on handle drag; play button advances handle
- **Engagement filter chips:** toggle emits correct engagement_ids
- **Layout toggle:** switching modes emits correct layoutMode
- **No canvas tests** (manual verification for rendering)

## 10. Scope Boundaries

### 10.1 In scope

- Global cross-engagement page at `/chain/global` with engagement color coding and filter chips
- `engagement_id` made optional on subgraph endpoint; `engagement_ids` filter added
- `engagement_id`, `created_at`, `pivotality` added to subgraph node response
- `engagements` array added to subgraph meta response
- Bayesian calibration: Beta priors, `ChainCalibrationState` table, CLI command, web endpoint
- Timeline playback: dual-handle scrubber, activity heatmap, temporal anchoring, configurable speed
- Path-as-report: Markdown export endpoint, CLI format option, frontend download button
- Swim lane: Kill Chain toggle, full lane dividers with headers, curved inter-lane edges
- Path risk scoring: composite score displayed in detail panel and export
- Node pivotality: betweenness centrality, glow visualization

### 10.2 Out of scope

| Feature | Deferred to |
|---------|-------------|
| Cypher query DSL / query editor | 3C.4 |
| PDF report export | Future |
| Server-side node clustering/aggregation | Future |
| Keyframe auto-detection for timeline | Future |
| Mark-as-keyframe for report synergy | Future |
| Multi-user calibration (shared priors across team) | 3D |
| Activity heatmap as separate standalone widget | Future |

## 11. Estimated Size

| Layer | Est. lines |
|-------|------------|
| Backend: subgraph endpoint changes (optional engagement_id, engagement_ids, created_at, pivotality, engagements meta) | ~100 |
| Backend: calibration service + endpoint + CLI | ~300 |
| Backend: export endpoint + CLI format | ~150 |
| Backend: pivotality computation | ~40 |
| Backend: Alembic migration (calibration_state table) | ~30 |
| Frontend: GlobalChainView.vue (page + engagement chips) | ~250 |
| Frontend: ChainTimelineScrubber.vue | ~200 |
| Frontend: ForceGraphCanvas.vue extensions (time filtering, kill chain layout, pivotality glow, engagement colors) | ~300 |
| Frontend: ChainDetailPanel.vue extensions (calibrated badge, path export button, risk score) | ~50 |
| Frontend: router + nav | ~10 |
| Tests: backend | ~300 |
| Tests: frontend | ~100 |
| **Total** | **~1,830** |

## 12. Forward Context (for 3C.4)

### 12.1 Cypher DSL integration

- The global graph view gains a query editor panel (CodeMirror + Cypher mode) in 3C.4
- Query results highlight matching subgraphs in the existing force-graph canvas
- No architectural changes needed from 3C.3 — queries return canonical graph-json through `to_force_graph()` adapter
- The Kill Chain layout mode works with query-filtered subgraphs the same way it works with filter-chip-filtered subgraphs
