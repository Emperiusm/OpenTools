# Phase 4 Decomposition — Cognitive Exploitation / AI Red Team Platform

**Date:** 2026-04-17
**Status:** Planning
**Author:** slabl + Claude

## Goal

Extend OpenTools to target, map, and exploit enterprise AI integrations — RAG pipelines, autonomous agents, and LLM-backed features — with the same deterministic engagement state, kill-chain integration, HITL safety gates, and findings taxonomy that the existing platform applies to traditional offensive security.

## Scope

**In scope**

- A `/ai-redteam` Claude Code skill peer to `/pentest`, `/reverse`, etc.
- A scanner profile + executors + parsers that wrap existing AI red-team tooling (`garak`, `PyRIT`, `TextAttack`, `promptfoo`) as first-class OpenTools tools.
- Modules targeting three attack classes: RAG poisoning / context smuggling, agentic tool hijacking, polymorphic prompt-injection autogeneration.
- A shared payload / delivery / verification framework, offline lab harness, multi-modal payload support, and defense fingerprinting.
- Engagement store and kill-chain schema extensions for probabilistic findings and AI-specific entities/relations mapped to MITRE ATLAS, OWASP LLM Top 10 v2, and AVID.
- Plugin-core marketplace packaging (Phase 3E) for the tool suite and payload corpora.

**Out of scope**

- Building from scratch anything `garak` / `PyRIT` / `promptfoo` already does well.
- Training custom LLMs (beyond optionally fine-tuning small surrogate scoring models).
- Defensive features (guardrails, prompt shields) — OpenTools is a red-team tool. Output of Phase 4 is *findings with mitigations*, not enforcement.
- Autonomous wild-target discovery. Every Phase 4 action runs against an authorized engagement target, under the same HITL model that gates Sliver and the Vultr infra provider today.

## Architectural Principles

1. **Wrap, don't rebuild.** OpenTools wraps `nmap`, `nuclei`, `sqlmap`, `volatility`. Apply the same principle to `garak` (probes + detectors), `PyRIT` (converters + orchestrators + scorers), `TextAttack` (adversarial mutation), `promptfoo` (regression eval). OpenTools's value-add remains what it already is: engagement state, kill-chain integration, HITL gates, dedup, cross-tool DAG.
2. **Findings are probabilistic.** The same prompt injection succeeds 73 % of the time. Findings carry `success_rate`, `sample_size`, `confidence_interval`; kill-chain edges carry weights.
3. **Provenance is mandatory.** Every finding records `(model_version, temperature, seed, system_prompt_fingerprint, timestamp, tool_version)` so clients can replay.
4. **Budget is enforced.** Per-engagement and per-target ceilings on tokens, dollars, and RPS, with hard stops. No autogen loop runs without a budget.
5. **Payloads are content-addressed and engagement-scoped.** Every payload — seed or evolved — is stored by SHA-256 in a content-addressable store, stamped with the originating engagement, and surfaced through an immutable ledger. Evolved payloads cannot silently leak across engagements or into artifacts.
6. **HITL gates high-risk actions.** Live writes to target vector DBs, moderation-API probing at volume, and any autogen run exceeding a budget threshold require per-action approval, matching the Sliver / Vultr pattern.
7. **Simulator-first.** Discovery fingerprints the target stack; the exploit pre-flights against a matching local harness (Ollama + chroma/qdrant + the detected agent framework). Only graduated winners hit the live target.

## Libraries to Wrap (Treat as First-Class Tools)

| Library | Role | Sub-spec |
|---|---|---|
| `garak` (NVIDIA) | Probe + detector architecture; prompt-injection, encoding, continuation, DAN, XSS-in-LLM probes | 3, 4, 5 |
| `PyRIT` (Microsoft) | Converters (mutation), attack strategies (orchestrators), scorers (verifiers) | 2, 5 |
| `TextAttack` | GA / paraphrase / char-level adversarial NLP mutation | 5 |
| `promptfoo` | CI-friendly eval and regression corpus | 6 |
| `LlamaGuard` (Meta, 7B, self-hostable) | Cheap inner-loop fitness oracle | 5 |
| `ShieldGemma` (Google) | Alternative self-hostable fitness oracle | 5 |
| `sentence-transformers`, `faiss`, `chromadb`, `qdrant` | Lab-stack vector DBs mirroring prod | 2 |
| `vec2text` (Morris et al.) | Embedding inversion when targets expose embeddings | 3 |
| `LangChain` / `LangGraph` / `LlamaIndex` / `AutoGen` / `crewAI` / `Semantic Kernel` | Agent simulators in the lab stack | 2, 4 |
| `ollama` + `llama.cpp` | Local LLM for offline harness | 2 |
| `stegano`, `pdfplumber`, `reportlab`, Pillow | Multi-modal payload crafting | 2 |
| `tiktoken` + HF tokenizers | Tokenizer fingerprinting; tokenizer-boundary mutation | 1, 5 |
| OpenTelemetry | Trace spans for `attack.generate`/`deliver`/`verify`/`score` | 0 |
| `tenacity`, `aiolimiter` | Retries, rate limits | 0 |

## Shared Foundations (Sub-Spec 0 Deliverables)

All downstream sub-specs depend on these. Sub-spec 0 is the non-negotiable gate.

- **Taxonomies.** MITRE ATLAS + OWASP LLM Top 10 v2 + AVID schema. NIST AI RMF mapping for enterprise reports.
- **Finding schema extensions.** `success_rate`, `sample_size`, `confidence_interval`, provenance tuple, mitigation recommendation field, ATLAS technique ID, OWASP LLM category, AVID vuln ID.
- **Kill-chain schema extensions.** New entity types (LLM backend, RAG pipeline, vector DB, agent orchestrator, tool surface, guardrail). New relation types (poisoned-by, hijacks, bypasses). Weighted edges.
- **HITL gate model.** Per-action approval for: moderation-API probing above threshold, live vector-DB writes, autogen runs exceeding budget, multi-modal payload uploads to shared target surfaces. Reuses Sliver audit-log pattern.
- **Budget / cost control.** Engagement-scoped `TokenBudget`, `DollarBudget`, `RPSBudget` with hard stops. Accounting per tool, per target, per session.
- **CAS payload ledger.** SHA-256-keyed immutable store; every payload tagged with originating engagement, generation method, parent payload(s), fitness scores, moderation verdicts. Export controls prevent evolved payloads from leaking into artifacts without explicit declassification.
- **OpenTelemetry spans.** `attack.generate`, `attack.deliver`, `attack.verify`, `attack.score` with standardized attributes.

## Sub-Specs

| # | Sub-spec | Depends on | Est. scope |
|---|---|---|---|
| **0** | Foundation: taxonomy, safety/HITL, schema, budget, CAS ledger, telemetry | existing engagement store + Phase 3E sandbox policy | ~2,500 lines |
| **1** | Target-surface discovery: LLM backend fingerprint, framework detection, defense fingerprinting cache, attack-surface enumeration | 0 | ~1,500 lines |
| **2** | Payload / delivery / verification framework + lab harness + garak/PyRIT wrapper layer + multi-modal adapters | 0 | ~4,000 lines |
| **3** | RAG poisoning / context smuggling: vector-DB writes, document-loader poisoning, chunk-boundary splits, reranker manipulation, metadata-filter bypass; wraps garak encoding/continuation probes | 1, 2 | ~2,500 lines |
| **4** | Agent tool hijacking: per-framework probe packs (LangChain / LlamaIndex / AutoGen / crewAI / Semantic Kernel); three sub-classes (selection / argument / chain-composition); simulator-first pre-flight | 1, 2 | ~3,000 lines |
| **5** | Polymorphic prompt-injection autogen: wrap PyRIT converters + TextAttack; LlamaGuard inner-loop fitness → real moderation API outer gate; plateau detection + adaptive mutation rate; surrogate fitness model (stretch); HITL-gated | 0, 2 | ~3,000 lines |
| **6** | `/ai-redteam` skill + plugin packaging + reporting: methodology doc, OWASP LLM Top 10 checklist, scanner profile glue, plugin-core manifest (signed, sandboxed), ATLAS-mapped report template, AVID export | 3, 4, 5 | ~2,000 lines |

Sub-spec 7 (multi-modal payloads) is **folded into sub-spec 2** per user decision 2026-04-17.

## Build Order

```
0 (foundation) ──┬──> 1 (discovery) ──┬──> 3 (RAG)   ──┐
                 │                    │                 │
                 └──> 2 (framework) ──┼──> 4 (agents) ──┼──> 6 (skill + plugin + reporting)
                                      │                 │
                                      └──> 5 (autogen) ─┘
```

1. **0 first.** Taxonomy + schema + safety + budget + CAS ledger + telemetry. Nothing else can land without them.
2. **1 and 2 in parallel.** Discovery (recon) and framework (plumbing) have no cross-dependency; different engineering shapes; both block 3/4/5.
3. **3, 4, 5 in parallel** once 1 and 2 land. All three are exploit modules that share 1's fingerprints and 2's plumbing but are independently developable and shippable.
4. **6 last.** Skill + plugin + reporting wraps the platform surface around whatever 3/4/5 produced. Can begin stub work (methodology doc, checklist scaffolding) earlier.

## Per-Sub-Spec Key Decisions to Resolve in Normal Brainstorm

Each sub-spec gets its own brainstorm → spec → plan cycle. Anchor questions for each:

**Sub-spec 0**
- ATLAS vs. ATT&CK mapping: do we dual-map or ATLAS-only?
- Budget enforcement granularity: per-tool vs. per-module vs. per-engagement (likely all three, hierarchical).
- CAS ledger: separate store or extension of the existing engagement SQLite schema?

**Sub-spec 1**
- Active-probe budget during discovery (latency-based fingerprinting burns tokens).
- Defense-fingerprint refresh policy (once per engagement? per session? per day?).
- Should discovery return to the scanner-parser / findings-dedup flow, or emit a separate "surface map" artifact?

**Sub-spec 2**
- Wrap garak as an external subprocess (like nmap) or link as a library (different posture; library link gives finer control but couples us to garak's lifecycle)?
- Lab-harness default stack vs. per-engagement custom stack.
- Streaming verifier implementation (SSE / WebSocket support in delivery adapters + verifier early-exit hooks).
- Multi-modal payload adapter surface: PDF, image, audio — which ship in v1 vs. deferred?

**Sub-spec 3**
- Vector-DB write delivery: do we require target to expose write API, or only exploit-via-document-ingestion paths?
- Reranker manipulation: need a local reranker in the lab stack — which model?

**Sub-spec 4**
- Per-framework simulator fidelity: how closely must the LangChain simulator mirror a target's actual tool graph? Probably fingerprint-driven.
- Tool-argument smuggling fuzzers: separate engine or reuse existing scanner fuzzing primitives?

**Sub-spec 5**
- LlamaGuard inner-loop quota vs. real moderation API outer-gate promotion rate.
- Surrogate fitness model: P1 or phase-2 stretch? Default: stretch.
- Adaptive mutation rate algorithm: published GA variants vs. custom.

**Sub-spec 6**
- Plugin packaging: one `ai-redteam` meta-plugin or one plugin per sub-spec module?
- Report template: extend existing Jinja2 templates or new top-level template family?

## Dependencies on Existing OpenTools Work

- **Phase 3C.1+ kill-chain data layer** — sub-spec 0's entity/relation extensions plug into here. Schema migration required.
- **Phase 3E plugin marketplace + sandbox policy** — sub-spec 6 ships through this; sub-spec 2's payload corpora ship as signed plugin artifacts.
- **Scanner DAG + findings dedup + CWE inference** — sub-specs 3/4/5 emit findings through the existing pipeline; 0 extends dedup keys to handle probabilistic findings.
- **HITL approval gate (Sliver / Vultr pattern)** — sub-spec 0 reuses this audit-log pattern for moderation-API probing and live writes.
- **Engagement store (aiosqlite / SQLAlchemy async)** — schema extensions from sub-spec 0 land here.

## Risk / Open Questions

- **Legal and ethics for polymorphic moderation-bypass autogen.** Even in an authorized engagement, evolved payloads are dual-use. Sub-spec 0 must nail the ledger + export-control story tightly enough that payloads can't leak without a declassification action, and evolved payloads should not ship in client artifacts by default.
- **Cost visibility for operators.** Red-teamers need a real-time dollar burn-down UI (web dashboard extension) before they trust autogen. Likely a sub-spec 6 deliverable, but may warrant an earlier small add to 5.
- **Moderation-API ToS.** Adversarial probing of OpenAI Moderation / Azure AI Content Safety / Bedrock Guardrails may violate provider ToS even in authorized engagements. Sub-spec 5 must document the provider posture and require operators to attest authorization before calling paid moderation APIs.
- **Non-determinism in regression.** Classic CI fails for probabilistic findings. Sub-spec 6's reporting and sub-spec 2's replay mode jointly solve this (replay pinned request/response pairs rather than re-hitting the target).
- **Per-framework probe-pack rot.** LangChain / AutoGen ship breaking changes quickly. Sub-spec 4's probe packs need a version-pinned policy and a CI job that runs against pinned framework versions in the lab harness.

## Each Sub-Spec Gets Its Own

- Design spec (`docs/superpowers/specs/`)
- Implementation plan (`docs/superpowers/plans/`)
- Feature branch + PR
