# HITL Approval Gate + Vultr Provider — Design Spec

**Date:** 2026-04-13
**Status:** Draft
**Depends on:** [2026-04-13-dag-mutation-ephemeral-proxy.md](../plans/2026-04-13-dag-mutation-ephemeral-proxy.md) (Phase A + B)

---

## 1. Problem Statement

### 1.1 HITL Approval Gate

OpenTools is an authorized pentest automation platform. Certain execution nodes — dropping a C2 agent, modifying target state, escalating privileges — require explicit operator approval before firing. The engine must suspend a specific task's execution indefinitely (up to a configurable timeout) until a human operator provides an API signal, without blocking the main event loop or holding up parallel safe branches.

### 1.2 Vultr Provider

The existing plan (Phase B) defines a `CloudNodeProvider` ABC with a DigitalOcean implementation. Vultr is the preferred provider for production use. A `VultrProvider` implementation is needed, with explicit SSH key injection to enable immediate automated tunnel establishment on boot.

---

## 2. HITL Approval Gate

### 2.1 Core Invariants

These three rules are non-negotiable. Every code path must enforce them.

1. **Write-before-signal**: The FastAPI route writes the operator's decision to SQLite *before* calling `event.set()`. If the server crashes between the DB write and the signal, the decision is safe in the database.

2. **Read-after-wake**: The gate executor never trusts why it woke up. After `event.wait()` returns (or times out), it always reads the authoritative status from SQLite. The in-memory event is a notification mechanism, not a source of truth.

3. **Database-owned expiry**: `approval_expires_at` is a UTC timestamp persisted to SQLite. On restart, `remaining = expires_at - utcnow()`. If negative, auto-reject. The timer is never held in memory alone.

### 2.2 Execution Wrapper Model (Not a Separate TaskType)

The approval gate is **not** a separate `TaskType`. It is a lifecycle wrapper around any existing task type. This avoids the "two-phase YAML trap" where every gated action requires paired tasks with wired dependencies.

**YAML profile syntax:**

```yaml
tasks:
  - id: deploy-agent
    task_type: shell
    tool: "c2-agent-drop"
    command: "sliver generate --mtls 10.0.0.1"
    depends_on: [nmap-scan]
    requires_approval:
      timeout_seconds: 3600
      description: "Deploy Sliver agent on 10.0.0.1"
```

One task, one slot, one YAML block. The gate phase runs inside `_execute_task` before the real executor fires. If approved, the coroutine proceeds to shell execution within the same task. If rejected or timed out, it returns a failure code and the branch is skipped.

### 2.3 Model Additions

**New model on `ScanTask`:**

```python
class ApprovalRequirement(BaseModel):
    """Gate metadata, defined in YAML profile."""
    timeout_seconds: int = 3600
    description: str = ""
```

**New fields on `ScanTask`:**

```python
class ScanTask(BaseModel):
    # ... existing fields ...
    requires_approval: ApprovalRequirement | None = None
    approval_ticket_id: str | None = None
    approval_expires_at: datetime | None = None
```

**New value in `TaskStatus`:**

```python
class TaskStatus(StrEnum):
    # ... existing values ...
    AWAITING_APPROVAL = "awaiting_approval"
```

No new `TaskType` enum value. No new executor class.

### 2.4 ApprovalRegistry — In-Memory Notification Hub

The registry is deliberately thin. It holds `asyncio.Event` objects only. No decision state, no metadata, no timestamps — all of that lives in SQLite.

```python
class ApprovalRegistry:
    """In-memory notification hub. NOT the source of truth.
    
    The sole purpose is to provide a handle for FastAPI routes to wake
    sleeping gate coroutines. If a ticket is missing (e.g., server
    restarted before the engine reconstructed it), the route still
    writes the decision to SQLite — the executor will pick it up on
    its next DB read.
    """
    
    def __init__(self) -> None:
        self._events: dict[str, asyncio.Event] = {}
    
    def register(self, ticket_id: str) -> asyncio.Event:
        """Create and store an event for a gate ticket."""
        event = asyncio.Event()
        self._events[ticket_id] = event
        return event
    
    def signal(self, ticket_id: str) -> bool:
        """Signal the event if it exists. Returns False if not in registry."""
        event = self._events.get(ticket_id)
        if event is None:
            return False
        event.set()
        return True
    
    def remove(self, ticket_id: str) -> None:
        """Clean up after a gate resolves."""
        self._events.pop(ticket_id, None)
```

Singleton instance: shared between `ScanEngine` (registers + awaits) and FastAPI routes (signals).

### 2.5 Engine Integration — Gate Phase in `_execute_task`

The gate phase inserts into the existing `_execute_task` method, between resource acquisition and executor dispatch:

```
_execute_task(task, executor):
  1. Cache check                          ← existing
  2. IF task.requires_approval:
       acquire from "approval_gate" group (9999 limit)
     ELSE:
       acquire from task's normal resource group   ← existing
  3. ── GATE PHASE (if task.requires_approval) ──
     a. ticket_id = f"gate-{task.id}-{uuid4().hex[:8]}"
     b. expires_at = utcnow() + timedelta(seconds=timeout)
     c. PERSIST to SQLite:
          task.status = AWAITING_APPROVAL
          task.approval_ticket_id = ticket_id
          task.approval_expires_at = expires_at
     d. Publish SSE event: "approval_required"
     e. Register event in ApprovalRegistry
     f. remaining = (expires_at - utcnow()).total_seconds()
     g. try:
          await asyncio.wait_for(event.wait(), timeout=remaining)
        except asyncio.TimeoutError:
          pass  # handled below
     h. READ TRUTH from SQLite:
          status == 'approved'  → proceed to step 4
          status == 'rejected'  → return TaskOutput(exit_code=1,
                                    stderr="rejected by operator")
          still 'awaiting_approval' → timeout expired
                                    → write 'approval_expired' to SQLite
                                    → return TaskOutput(exit_code=2,
                                        stderr="approval expired")
     i. Cleanup: registry.remove(ticket_id)
     j. Release "approval_gate" resource group
     k. Re-acquire from task's normal resource group
  4. Execute via real executor             ← existing
  5. Resource release                      ← existing
  6. Cache result                          ← existing
```

### 2.6 Resource Pool Configuration

```python
pool = AdaptiveResourcePool(
    global_limit=10,
    group_limits={
        "approval_gate": 9999,   # sleeping coroutines: ~0 CPU, ~bytes RAM
    },
)
```

During the gate phase, the task holds one slot from the `approval_gate` group (effectively unlimited). After approval, it releases that slot and acquires from its normal resource group before executing. This means 500 sleeping gates consume zero capacity from the real worker pool.

### 2.7 FastAPI Routes

Three new endpoints on the existing scan router:

**List pending gates:**
```
GET /api/v1/scans/{scan_id}/gates

Response: {
  "gates": [
    {
      "ticket_id": "gate-deploy-agent-a1b2c3d4",
      "task_id": "deploy-agent",
      "tool": "c2-agent-drop",
      "command": "sliver generate --mtls 10.0.0.1",
      "description": "Deploy Sliver agent on 10.0.0.1",
      "status": "awaiting_approval",
      "created_at": "2026-04-13T14:00:00Z",
      "expires_at": "2026-04-13T15:00:00Z"
    }
  ]
}
```

**Approve a gate:**
```
POST /api/v1/scans/{scan_id}/gates/{ticket_id}/approve

Sequence:
  1. Validate ticket exists in SQLite with status='awaiting_approval'
  2. UPDATE scan_tasks SET status='approved' WHERE approval_ticket_id=?
  3. registry.signal(ticket_id)  — may return False if engine restarted
  4. Return 200 {"ticket_id": "...", "decision": "approved"}
```

**Reject a gate:**
```
POST /api/v1/scans/{scan_id}/gates/{ticket_id}/reject
Body: {"reason": "Target out of scope"}  (optional)

Sequence:
  1. Validate ticket exists in SQLite with status='awaiting_approval'
  2. UPDATE scan_tasks SET status='rejected' WHERE approval_ticket_id=?
  3. registry.signal(ticket_id)
  4. Return 200 {"ticket_id": "...", "decision": "rejected"}
```

All three routes enforce write-before-signal. The `registry.signal()` call is best-effort — if the event isn't in the registry (restart race), the gate executor will read the decision from SQLite on its next DB poll or restart reconstruction.

### 2.8 SSE Event Payload

Published when a gate enters the waiting state:

```json
{
  "type": "approval_required",
  "data": {
    "ticket_id": "gate-deploy-agent-a1b2c3d4",
    "task_id": "deploy-agent",
    "scan_id": "scan-1",
    "tool": "c2-agent-drop",
    "command": "sliver generate --mtls 10.0.0.1",
    "description": "Deploy Sliver agent on 10.0.0.1",
    "expires_at": "2026-04-13T15:00:00Z"
  }
}
```

The `command` field is pulled directly from the task's own context — because the gate *is* the task, not a separate checkpoint. The operator sees exactly what they're approving.

### 2.9 Restart / Durable Resume

On engine startup:

1. Query SQLite: `SELECT * FROM scan_tasks WHERE status IN ('awaiting_approval', 'approved') AND scan_id = ?`
2. For each `awaiting_approval` task:
   - `remaining = approval_expires_at - utcnow()`
   - If `remaining <= 0`: write `status='approval_expired'`, mark failed, skip dependents
   - If `remaining > 0`: create fresh `asyncio.Event`, register in `ApprovalRegistry`, re-enter gate wait with `timeout=remaining`
3. For each `approved` task (decision was persisted before crash):
   - Skip gate phase entirely, dispatch directly to the real executor
4. `rejected` / `approval_expired` tasks: already terminal, skip as normal

### 2.10 Crash Safety Matrix

| Crash point | DB state after crash | Restart behavior |
|---|---|---|
| After gate persists AWAITING, before operator acts | `awaiting_approval` + `expires_at` | Re-enter wait with remaining time |
| After operator approves (DB written), before event.set() | `approved` | Skip gate, execute immediately |
| After event.set(), before executor reads DB | `approved` | Skip gate, execute immediately |
| After executor reads DB, before shell execution starts | `approved` | Re-dispatch to shell executor |
| After shell execution completes | `completed` | Normal — nothing to resume |
| During timeout expiry handling | `awaiting_approval` | Re-check timeout, auto-expire |

Every row is safe. The database is always the source of truth.

---

## 3. Vultr Provider

### 3.1 Overview

`VultrProvider` implements the `CloudNodeProvider` ABC from Phase B. It provisions ephemeral Vultr instances via their REST API using `httpx.AsyncClient`. The implementation mirrors `DigitalOceanProvider` in structure but targets the Vultr API.

### 3.2 SSH Key Requirement

The orchestrator must establish an automated SSH tunnel (`ssh -D 1080 -N root@<ip>`) the instant `main_ip` is active. This requires the orchestrator's public key to be pre-registered in Vultr and passed as `sshkey_id` in the instance creation payload.

**Prerequisite:** The operator registers their SSH public key in Vultr's dashboard or via `POST /v2/ssh-keys` and records the returned key ID. This ID is passed to `VultrProvider` at construction time.

**If `sshkey_id` is missing from the creation payload**, the instance boots with no authorized keys. The SSH tunnel will fail with `Permission denied (publickey)` and the entire proxy lifecycle fails. This is not a soft dependency — it is a hard requirement.

### 3.3 API Mapping

| Operation | Endpoint | Method |
|---|---|---|
| Create instance | `https://api.vultr.com/v2/instances` | POST |
| Poll status | `https://api.vultr.com/v2/instances/{id}` | GET |
| Destroy instance | `https://api.vultr.com/v2/instances/{id}` | DELETE |
| List by tag | `https://api.vultr.com/v2/instances?tag={tag}` | GET |

### 3.4 Create Payload

```json
{
  "region": "ewr",
  "plan": "vc2-1c-0.5gb",
  "os_id": 2284,
  "label": "ot-proxy-a1b2c3d4",
  "sshkey_id": ["ssh-key-uuid-from-vultr"],
  "tags": ["opentools-ephemeral-proxy", "scan:scan-1"],
  "backups": "disabled",
  "activation_email": false
}
```

**Field details:**

- `region`: Vultr region slug (e.g., `"ewr"` for New Jersey, `"lax"` for Los Angeles). Passed through from `CloudNodeProvider.create_node(region=...)`.
- `plan`: `"vc2-1c-0.5gb"` — the cheapest Vultr Cloud Compute tier. 1 vCPU, 0.5 GB RAM, 10 GB SSD. Billed hourly, destroyed after use.
- `os_id`: `2284` = Ubuntu 24.04 LTS. Numeric ID required by the Vultr API (not a slug).
- `label`: Human-readable name with random suffix for identification.
- `sshkey_id`: **Required array of Vultr SSH key UUIDs.** These keys are injected into `/root/.ssh/authorized_keys` during instance provisioning via cloud-init. Without this, the SSH tunnel cannot authenticate.
- `tags`: Used by the orphan sweeper to identify and clean up nodes from crashed runs.
- `backups`: Disabled — ephemeral nodes don't need backup snapshots.
- `activation_email`: Disabled — suppress Vultr's default activation notification spam.

### 3.5 Poll Response Parsing

```json
{
  "instance": {
    "id": "cb676a46-66fd-4dfb-b839-443f2e6c0b60",
    "status": "active",
    "power_status": "running",
    "main_ip": "149.28.xxx.xxx",
    "label": "ot-proxy-a1b2c3d4",
    "region": "ewr",
    "plan": "vc2-1c-0.5gb",
    "tags": ["opentools-ephemeral-proxy"]
  }
}
```

**Status mapping:**

| Vultr `status` | `CloudNodeProvider` status |
|---|---|
| `"pending"` | `"creating"` |
| `"active"` (with `power_status == "running"` and `main_ip != "0.0.0.0"`) | `"active"` |
| `"active"` (with `main_ip == "0.0.0.0"`) | `"creating"` (IP not yet assigned) |
| Any other | `"creating"` |

**Important:** Vultr can report `status: "active"` before the IP is assigned. The provider must check `main_ip != "0.0.0.0"` before returning `"active"`.

### 3.6 Destroy (Idempotent)

```
DELETE /v2/instances/{id}
```

- `204`: Successfully destroyed
- `404`: Already gone — idempotent, do not raise

### 3.7 List by Tag (for Orphan Sweeper)

```
GET /v2/instances?tag=opentools-ephemeral-proxy
```

Returns all instances with the proxy tag. The orphan sweeper iterates and destroys each. `VultrProvider` implements the optional `list_nodes_by_tag(tag: str) -> list[str]` method that the sweeper calls.

### 3.8 Constructor

```python
class VultrProvider(CloudNodeProvider):
    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    @classmethod
    def from_token(cls, api_token: str) -> VultrProvider:
        client = httpx.AsyncClient(
            base_url="https://api.vultr.com/v2",
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=30.0,
        )
        return cls(client=client)
```

The `ssh_public_key` parameter in `create_node(region, ssh_public_key, tags)` maps directly to `sshkey_id` in the Vultr payload. The caller passes the Vultr SSH key UUID (pre-registered), not the raw public key content.

---

## 4. Integration Points

### 4.1 Where These Fit in the Existing Plan

| Addition | Integrates into | Type |
|---|---|---|
| HITL Approval Gate | Phase C (new phase) | Tasks 10-13 |
| Vultr Provider | Phase B, Task 6b (new task) | After Task 6 |

### 4.2 Dependencies

- The Approval Gate depends on Phase A (engine exists with mutation support) but NOT on Phase B (proxy routing). It can be built independently.
- The Vultr Provider depends on Phase B's `CloudNodeProvider` ABC (Task 6) being in place.
- Neither depends on the other.

---

## 5. Out of Scope

- **Approve-with-modification** (operator edits command before approving) — deferred to V2.
- **Multi-approver workflows** (require 2-of-3 operators to approve) — deferred to V2.
- **Dashboard UI for approval gates** — the SSE events and API endpoints are sufficient for V1. A dedicated UI can be built against them later.
- **Vultr SSH key registration automation** — the key must be pre-registered in Vultr. Automating `POST /v2/ssh-keys` is out of scope for V1.
