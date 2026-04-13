# Dynamic DAG Mutation + Ephemeral Proxy Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Transform OpenTools from a static scan pipeline into a reactive execution engine that mutates its own DAG based on tool output, and optionally routes high-throughput scans through ephemeral proxy infrastructure for rate-limit resilience.

**Architecture:** Two independent subsystems. Phase A adds a mutation layer (OutputAnalyzer → KillChainState → MutationStrategy) that hooks into the existing `ScanEngine._mark_completed` path — all synchronous within a single event loop turn, so no race conditions. Phase B adds an `AsyncContextManager`-based ephemeral proxy lifecycle that wraps `run_streaming` calls, with shielded teardown guaranteeing cloud node destruction even under cancellation. Both phases compose: a MutationStrategy can spawn tasks with `isolation: network_isolated`, and the ProxiedShellExecutor handles routing transparently.

**Tech Stack:** Python 3.12+, Pydantic v2, asyncio, httpx (already in deps), pytest + pytest-asyncio

---

## File Structure

### Phase A — Dynamic DAG Mutation

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `packages/cli/src/opentools/scanner/mutation/__init__.py` | Package exports |
| Create | `packages/cli/src/opentools/scanner/mutation/models.py` | `IntelBundle`, `DiscoveredService`, `DiscoveredVuln`, `KillChainState` |
| Create | `packages/cli/src/opentools/scanner/mutation/analyzer.py` | `OutputAnalyzer` protocol + `NmapAnalyzer` + `NucleiAnalyzer` |
| Create | `packages/cli/src/opentools/scanner/mutation/strategy.py` | `MutationStrategy` protocol + `RedisProbeStrategy` + `get_builtin_strategies()` |
| Modify | `packages/cli/src/opentools/scanner/engine.py` | Add mutation fields to `__init__`, hook mutation into `_mark_completed`, harden `_inject_tasks` |
| Create | `packages/cli/tests/test_scanner/test_mutation_models.py` | Tests for models |
| Create | `packages/cli/tests/test_scanner/test_mutation_analyzer.py` | Tests for analyzers |
| Create | `packages/cli/tests/test_scanner/test_mutation_strategy.py` | Tests for strategies |
| Create | `packages/cli/tests/test_scanner/test_engine_mutation.py` | Integration: engine + mutation layer |

### Phase B — Ephemeral Proxy Routing

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `packages/cli/src/opentools/shared/subprocess.py` | Add `env` parameter to `run_streaming` |
| Create | `packages/cli/src/opentools/scanner/infra/__init__.py` | Package exports |
| Create | `packages/cli/src/opentools/scanner/infra/provider.py` | `CloudNodeProvider` ABC, `EphemeralNode`, `ProvisioningError` |
| Create | `packages/cli/src/opentools/scanner/infra/digitalocean.py` | `DigitalOceanProvider` (httpx-based) |
| Create | `packages/cli/src/opentools/scanner/infra/proxy.py` | `ephemeral_proxy` context manager, `ProxyEndpoint`, `_shielded_destroy` |
| Create | `packages/cli/src/opentools/scanner/infra/sweeper.py` | `sweep_orphaned_nodes` startup cleanup |
| Create | `packages/cli/src/opentools/scanner/executor/proxied_shell.py` | `ProxiedShellExecutor` |
| Modify | `packages/cli/src/opentools/scanner/executor/__init__.py` | Export `ProxiedShellExecutor` |
| Modify | `packages/cli/tests/test_scanner/test_shared_subprocess.py` | Add `env` parameter test |
| Create | `packages/cli/tests/test_scanner/test_infra_provider.py` | Tests for provider ABC + DO provider |
| Create | `packages/cli/tests/test_scanner/test_infra_proxy.py` | Tests for proxy context manager + shielded teardown |
| Create | `packages/cli/tests/test_scanner/test_executor_proxied_shell.py` | Tests for proxied executor |

---

## Phase A: Dynamic DAG Mutation

### Task 1: KillChainState + IntelBundle Models

**Files:**
- Create: `packages/cli/src/opentools/scanner/mutation/__init__.py`
- Create: `packages/cli/src/opentools/scanner/mutation/models.py`
- Test: `packages/cli/tests/test_scanner/test_mutation_models.py`

- [ ] **Step 1: Write failing tests for IntelBundle and DiscoveredService**

```python
# packages/cli/tests/test_scanner/test_mutation_models.py
"""Tests for mutation layer data models."""

from opentools.scanner.mutation.models import (
    DiscoveredService,
    DiscoveredVuln,
    IntelBundle,
    KillChainState,
)


class TestDiscoveredService:
    def test_construction(self):
        svc = DiscoveredService(
            host="10.0.0.1",
            port=6379,
            protocol="tcp",
            service="redis",
        )
        assert svc.host == "10.0.0.1"
        assert svc.port == 6379
        assert svc.protocol == "tcp"
        assert svc.service == "redis"
        assert svc.product is None
        assert svc.version is None

    def test_with_product_and_version(self):
        svc = DiscoveredService(
            host="10.0.0.1",
            port=80,
            protocol="tcp",
            service="http",
            product="Apache httpd",
            version="2.4.51",
        )
        assert svc.product == "Apache httpd"
        assert svc.version == "2.4.51"


class TestDiscoveredVuln:
    def test_construction(self):
        vuln = DiscoveredVuln(
            host="10.0.0.1",
            port=443,
            template_id="CVE-2021-44228",
            severity="critical",
            matched_at="https://10.0.0.1:443/api",
            extracted_data={"payload": "jndi:ldap"},
        )
        assert vuln.template_id == "CVE-2021-44228"
        assert vuln.severity == "critical"

    def test_port_optional(self):
        vuln = DiscoveredVuln(
            host="10.0.0.1",
            port=None,
            template_id="exposed-git",
            severity="medium",
            matched_at="http://10.0.0.1/.git/config",
            extracted_data={},
        )
        assert vuln.port is None


class TestIntelBundle:
    def test_empty_default(self):
        bundle = IntelBundle()
        assert bundle.services == []
        assert bundle.vulns == []
        assert bundle.urls == []
        assert bundle.metadata == {}

    def test_with_services(self):
        svc = DiscoveredService(
            host="10.0.0.1", port=22, protocol="tcp", service="ssh",
        )
        bundle = IntelBundle(services=[svc])
        assert len(bundle.services) == 1
        assert bundle.services[0].service == "ssh"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_mutation_models.py::TestDiscoveredService -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'opentools.scanner.mutation'`

- [ ] **Step 3: Implement IntelBundle, DiscoveredService, DiscoveredVuln**

```python
# packages/cli/src/opentools/scanner/mutation/__init__.py
"""Dynamic DAG mutation layer — output analysis, state accumulation, task synthesis."""
```

```python
# packages/cli/src/opentools/scanner/mutation/models.py
"""Data models for the mutation layer.

IntelBundle carries structured intelligence extracted from tool output.
KillChainState accumulates intel across all completed tasks, enabling
cross-task reasoning for dynamic task injection.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class DiscoveredService(BaseModel):
    """A network service discovered by a scanning tool."""
    host: str
    port: int
    protocol: str              # "tcp" | "udp"
    service: str               # e.g., "redis", "http", "ssh"
    product: str | None = None # e.g., "Redis", "Apache httpd"
    version: str | None = None # e.g., "6.2.7", "2.4.51"
    banner: str | None = None


class DiscoveredVuln(BaseModel):
    """A vulnerability discovered by a scanning tool."""
    host: str
    port: int | None
    template_id: str           # nuclei template ID or CVE
    severity: str
    matched_at: str            # URL or host:port
    extracted_data: dict = Field(default_factory=dict)


class IntelBundle(BaseModel):
    """Structured intelligence extracted from a single task's output.

    Produced by an OutputAnalyzer, consumed by KillChainState.ingest().
    """
    services: list[DiscoveredService] = Field(default_factory=list)
    vulns: list[DiscoveredVuln] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class KillChainState(BaseModel):
    """Accumulated attack surface knowledge across all completed tasks.

    Only mutated inside ScanEngine._mark_completed (synchronous within
    a single event loop turn), so no locking is needed.
    """
    services: dict[str, DiscoveredService] = Field(default_factory=dict)
    vulns: dict[str, DiscoveredVuln] = Field(default_factory=dict)
    urls: set[str] = Field(default_factory=set)
    tasks_spawned: dict[str, int] = Field(default_factory=dict)
    total_spawned: int = 0

    def ingest(self, bundle: IntelBundle) -> None:
        """Merge an IntelBundle into accumulated state. Deduplicates by key."""
        for svc in bundle.services:
            key = f"{svc.host}:{svc.port}/{svc.protocol}"
            self.services[key] = svc
        for vuln in bundle.vulns:
            key = f"{vuln.host}:{vuln.template_id}"
            self.vulns[key] = vuln
        self.urls.update(bundle.urls)

    def has_service(self, service_name: str) -> bool:
        """Check if any discovered service matches the given name."""
        return any(s.service == service_name for s in self.services.values())

    def get_services(self, service_name: str) -> list[DiscoveredService]:
        """Return all discovered services matching the given name."""
        return [s for s in self.services.values() if s.service == service_name]

    def record_spawn(self, strategy_name: str, count: int = 1) -> None:
        """Record that a strategy spawned tasks."""
        self.tasks_spawned[strategy_name] = (
            self.tasks_spawned.get(strategy_name, 0) + count
        )
        self.total_spawned += count
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_mutation_models.py::TestDiscoveredService tests/test_scanner/test_mutation_models.py::TestDiscoveredVuln tests/test_scanner/test_mutation_models.py::TestIntelBundle -v`
Expected: All PASS

- [ ] **Step 5: Write failing tests for KillChainState**

Add to `packages/cli/tests/test_scanner/test_mutation_models.py`:

```python
class TestKillChainState:
    def test_empty_default(self):
        state = KillChainState()
        assert state.services == {}
        assert state.vulns == {}
        assert len(state.urls) == 0
        assert state.total_spawned == 0

    def test_ingest_services(self):
        state = KillChainState()
        bundle = IntelBundle(services=[
            DiscoveredService(
                host="10.0.0.1", port=6379, protocol="tcp", service="redis",
            ),
            DiscoveredService(
                host="10.0.0.1", port=80, protocol="tcp", service="http",
            ),
        ])
        state.ingest(bundle)
        assert len(state.services) == 2
        assert "10.0.0.1:6379/tcp" in state.services
        assert "10.0.0.1:80/tcp" in state.services

    def test_ingest_deduplicates(self):
        state = KillChainState()
        svc = DiscoveredService(
            host="10.0.0.1", port=6379, protocol="tcp", service="redis",
        )
        state.ingest(IntelBundle(services=[svc]))
        state.ingest(IntelBundle(services=[svc]))
        assert len(state.services) == 1

    def test_ingest_vulns(self):
        state = KillChainState()
        vuln = DiscoveredVuln(
            host="10.0.0.1", port=443, template_id="CVE-2021-44228",
            severity="critical", matched_at="https://10.0.0.1:443/",
            extracted_data={},
        )
        state.ingest(IntelBundle(vulns=[vuln]))
        assert "10.0.0.1:CVE-2021-44228" in state.vulns

    def test_ingest_urls(self):
        state = KillChainState()
        state.ingest(IntelBundle(urls=["http://10.0.0.1/admin"]))
        state.ingest(IntelBundle(urls=["http://10.0.0.1/admin", "http://10.0.0.1/api"]))
        assert len(state.urls) == 2

    def test_has_service(self):
        state = KillChainState()
        state.ingest(IntelBundle(services=[
            DiscoveredService(
                host="10.0.0.1", port=6379, protocol="tcp", service="redis",
            ),
        ]))
        assert state.has_service("redis") is True
        assert state.has_service("mysql") is False

    def test_get_services(self):
        state = KillChainState()
        state.ingest(IntelBundle(services=[
            DiscoveredService(host="10.0.0.1", port=6379, protocol="tcp", service="redis"),
            DiscoveredService(host="10.0.0.2", port=6379, protocol="tcp", service="redis"),
            DiscoveredService(host="10.0.0.1", port=80, protocol="tcp", service="http"),
        ]))
        redis_services = state.get_services("redis")
        assert len(redis_services) == 2
        assert all(s.service == "redis" for s in redis_services)

    def test_record_spawn(self):
        state = KillChainState()
        state.record_spawn("redis_probe", 2)
        assert state.tasks_spawned["redis_probe"] == 2
        assert state.total_spawned == 2
        state.record_spawn("redis_probe", 1)
        assert state.tasks_spawned["redis_probe"] == 3
        assert state.total_spawned == 3
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_mutation_models.py -v`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add packages/cli/src/opentools/scanner/mutation/__init__.py packages/cli/src/opentools/scanner/mutation/models.py packages/cli/tests/test_scanner/test_mutation_models.py
git commit -m "feat(mutation): add IntelBundle, DiscoveredService, KillChainState models"
```

---

### Task 2: OutputAnalyzer Protocol + NmapAnalyzer

**Files:**
- Create: `packages/cli/src/opentools/scanner/mutation/analyzer.py`
- Test: `packages/cli/tests/test_scanner/test_mutation_analyzer.py`

**Context:** The existing `NmapParser` in `packages/cli/src/opentools/scanner/parsing/parsers/nmap.py` converts nmap XML into `RawFinding` objects for the findings pipeline. `NmapAnalyzer` converts the same XML into `DiscoveredService` objects for the mutation layer. Different output, different consumer — but same XML parsing logic.

- [ ] **Step 1: Write failing tests for NmapAnalyzer**

```python
# packages/cli/tests/test_scanner/test_mutation_analyzer.py
"""Tests for OutputAnalyzer implementations."""

from opentools.scanner.mutation.analyzer import (
    AnalyzerRegistry,
    NmapAnalyzer,
    NucleiAnalyzer,
    OutputAnalyzer,
)
from opentools.scanner.mutation.models import IntelBundle


# Minimal valid nmap XML with two open ports
NMAP_XML_TWO_PORTS = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames><hostname name="target.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis" product="Redis" version="6.2.7"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.51"/>
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

NMAP_XML_NO_OPEN = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="filtered"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

NMAP_XML_MULTI_HOST = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" product="MySQL" version="8.0"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


class TestNmapAnalyzer:
    def setup_method(self):
        self.analyzer = NmapAnalyzer()

    def test_tool_name(self):
        assert self.analyzer.tool == "nmap"

    def test_extracts_open_services(self):
        bundle = self.analyzer.analyze(NMAP_XML_TWO_PORTS, "")
        assert isinstance(bundle, IntelBundle)
        assert len(bundle.services) == 2
        services_by_port = {s.port: s for s in bundle.services}
        assert 6379 in services_by_port
        assert services_by_port[6379].service == "redis"
        assert services_by_port[6379].product == "Redis"
        assert services_by_port[6379].version == "6.2.7"
        assert services_by_port[6379].host == "10.0.0.1"
        assert 80 in services_by_port
        assert services_by_port[80].service == "http"

    def test_skips_closed_ports(self):
        bundle = self.analyzer.analyze(NMAP_XML_TWO_PORTS, "")
        ports = [s.port for s in bundle.services]
        assert 22 not in ports

    def test_no_open_ports_returns_empty(self):
        bundle = self.analyzer.analyze(NMAP_XML_NO_OPEN, "")
        assert bundle.services == []

    def test_multi_host(self):
        bundle = self.analyzer.analyze(NMAP_XML_MULTI_HOST, "")
        assert len(bundle.services) == 2
        hosts = {s.host for s in bundle.services}
        assert hosts == {"10.0.0.1", "10.0.0.2"}

    def test_invalid_xml_returns_empty(self):
        bundle = self.analyzer.analyze("not xml at all", "")
        assert bundle.services == []

    def test_empty_stdout_returns_empty(self):
        bundle = self.analyzer.analyze("", "")
        assert bundle.services == []


# Minimal nuclei JSON lines output
NUCLEI_JSONL = (
    '{"template-id":"CVE-2021-44228","host":"10.0.0.1","port":"443",'
    '"matched-at":"https://10.0.0.1:443/api","info":{"severity":"critical"},'
    '"extracted-results":["jndi:ldap"]}\n'
    '{"template-id":"exposed-git","host":"10.0.0.1","port":"80",'
    '"matched-at":"http://10.0.0.1/.git/config","info":{"severity":"medium"},'
    '"extracted-results":[]}\n'
)


class TestNucleiAnalyzer:
    def setup_method(self):
        self.analyzer = NucleiAnalyzer()

    def test_tool_name(self):
        assert self.analyzer.tool == "nuclei"

    def test_extracts_vulns(self):
        bundle = self.analyzer.analyze(NUCLEI_JSONL, "")
        assert len(bundle.vulns) == 2
        template_ids = {v.template_id for v in bundle.vulns}
        assert "CVE-2021-44228" in template_ids
        assert "exposed-git" in template_ids

    def test_vuln_fields(self):
        bundle = self.analyzer.analyze(NUCLEI_JSONL, "")
        cve = next(v for v in bundle.vulns if v.template_id == "CVE-2021-44228")
        assert cve.host == "10.0.0.1"
        assert cve.port == 443
        assert cve.severity == "critical"
        assert cve.matched_at == "https://10.0.0.1:443/api"

    def test_extracts_urls_from_matched_at(self):
        bundle = self.analyzer.analyze(NUCLEI_JSONL, "")
        assert len(bundle.urls) == 2

    def test_empty_output_returns_empty(self):
        bundle = self.analyzer.analyze("", "")
        assert bundle.vulns == []

    def test_invalid_json_lines_skipped(self):
        mixed = '{"template-id":"x","host":"h","matched-at":"u","info":{"severity":"low"}}\nnot json\n'
        bundle = self.analyzer.analyze(mixed, "")
        assert len(bundle.vulns) == 1


class TestAnalyzerRegistry:
    def test_register_and_get(self):
        registry = AnalyzerRegistry()
        analyzer = NmapAnalyzer()
        registry.register(analyzer)
        assert registry.get("nmap") is analyzer

    def test_get_missing_returns_none(self):
        registry = AnalyzerRegistry()
        assert registry.get("nonexistent") is None

    def test_get_builtin_analyzers(self):
        registry = AnalyzerRegistry()
        registry.register_builtins()
        assert registry.get("nmap") is not None
        assert registry.get("nuclei") is not None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_mutation_analyzer.py::TestNmapAnalyzer::test_tool_name -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement OutputAnalyzer protocol, NmapAnalyzer, NucleiAnalyzer, AnalyzerRegistry**

```python
# packages/cli/src/opentools/scanner/mutation/analyzer.py
"""OutputAnalyzer protocol and builtin implementations.

OutputAnalyzers extract structured attack surface intelligence from tool
output.  They are distinct from ParserPlugin (which produces RawFinding
objects for the findings pipeline) — analyzers produce IntelBundle objects
for the mutation layer's KillChainState.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from typing import Protocol, runtime_checkable

from opentools.scanner.mutation.models import (
    DiscoveredService,
    DiscoveredVuln,
    IntelBundle,
)


@runtime_checkable
class OutputAnalyzer(Protocol):
    """Extracts attack surface intelligence from raw tool output."""
    tool: str

    def analyze(self, stdout: str, stderr: str) -> IntelBundle: ...


class NmapAnalyzer:
    """Extract DiscoveredService objects from nmap XML output."""
    tool = "nmap"

    def analyze(self, stdout: str, stderr: str) -> IntelBundle:
        if not stdout.strip():
            return IntelBundle()

        try:
            root = ET.fromstring(stdout)
        except ET.ParseError:
            return IntelBundle()

        services: list[DiscoveredService] = []

        for host in root.findall("host"):
            addr_el = host.find("address")
            addr = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port in ports_el.findall("port"):
                state_el = port.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue

                svc_el = port.find("service")
                services.append(DiscoveredService(
                    host=addr,
                    port=int(port.get("portid", "0")),
                    protocol=port.get("protocol", "tcp"),
                    service=svc_el.get("name", "") if svc_el is not None else "",
                    product=svc_el.get("product") if svc_el is not None else None,
                    version=svc_el.get("version") if svc_el is not None else None,
                ))

        return IntelBundle(services=services)


class NucleiAnalyzer:
    """Extract DiscoveredVuln objects from nuclei JSON-lines output."""
    tool = "nuclei"

    def analyze(self, stdout: str, stderr: str) -> IntelBundle:
        if not stdout.strip():
            return IntelBundle()

        vulns: list[DiscoveredVuln] = []
        urls: list[str] = []

        for line in stdout.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = data.get("template-id", "")
            host = data.get("host", "")
            matched_at = data.get("matched-at", "")
            info = data.get("info", {})
            severity = info.get("severity", "unknown") if isinstance(info, dict) else "unknown"

            port_raw = data.get("port", "")
            port: int | None = None
            if port_raw:
                try:
                    port = int(port_raw)
                except (ValueError, TypeError):
                    pass

            extracted = data.get("extracted-results", [])
            extracted_data = {"results": extracted} if extracted else {}

            vulns.append(DiscoveredVuln(
                host=host,
                port=port,
                template_id=template_id,
                severity=severity,
                matched_at=matched_at,
                extracted_data=extracted_data,
            ))

            if matched_at:
                urls.append(matched_at)

        return IntelBundle(vulns=vulns, urls=urls)


class AnalyzerRegistry:
    """Registry of OutputAnalyzer instances, keyed by tool name."""

    def __init__(self) -> None:
        self._analyzers: dict[str, OutputAnalyzer] = {}

    def register(self, analyzer: OutputAnalyzer) -> None:
        self._analyzers[analyzer.tool] = analyzer

    def get(self, tool: str) -> OutputAnalyzer | None:
        return self._analyzers.get(tool)

    def register_builtins(self) -> None:
        """Register all builtin analyzers."""
        self.register(NmapAnalyzer())
        self.register(NucleiAnalyzer())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_mutation_analyzer.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/mutation/analyzer.py packages/cli/tests/test_scanner/test_mutation_analyzer.py
git commit -m "feat(mutation): add OutputAnalyzer protocol with Nmap and Nuclei analyzers"
```

---

### Task 3: MutationStrategy Protocol + RedisProbeStrategy

**Files:**
- Create: `packages/cli/src/opentools/scanner/mutation/strategy.py`
- Test: `packages/cli/tests/test_scanner/test_mutation_strategy.py`

**Context:** Strategies examine the accumulated `KillChainState` (not just one task's output) and synthesize new `ScanTask` objects. Each strategy is idempotent — it tracks what it has already spawned via task ID conventions to avoid duplicates.

- [ ] **Step 1: Write failing tests for MutationStrategy and RedisProbeStrategy**

```python
# packages/cli/tests/test_scanner/test_mutation_strategy.py
"""Tests for MutationStrategy implementations."""

from opentools.scanner.mutation.models import (
    DiscoveredService,
    IntelBundle,
    KillChainState,
)
from opentools.scanner.mutation.strategy import (
    MutationStrategy,
    RedisProbeStrategy,
    get_builtin_strategies,
)
from opentools.scanner.models import ScanTask, TaskType, ExecutionTier


def _make_task(
    task_id: str = "nmap-1",
    tool: str = "nmap",
    scan_id: str = "scan-1",
) -> ScanTask:
    return ScanTask(
        id=task_id,
        scan_id=scan_id,
        name=f"{tool}-task",
        tool=tool,
        task_type=TaskType.SHELL,
    )


def _state_with_redis() -> KillChainState:
    state = KillChainState()
    state.ingest(IntelBundle(services=[
        DiscoveredService(
            host="10.0.0.1", port=6379, protocol="tcp", service="redis",
            product="Redis", version="6.2.7",
        ),
    ]))
    return state


def _state_with_http_only() -> KillChainState:
    state = KillChainState()
    state.ingest(IntelBundle(services=[
        DiscoveredService(
            host="10.0.0.1", port=80, protocol="tcp", service="http",
        ),
    ]))
    return state


class TestRedisProbeStrategy:
    def setup_method(self):
        self.strategy = RedisProbeStrategy()

    def test_name(self):
        assert self.strategy.name == "redis_probe"

    def test_max_spawns(self):
        assert self.strategy.max_spawns == 10

    def test_spawns_redis_probe_when_redis_discovered(self):
        state = _state_with_redis()
        task = _make_task(tool="nmap")
        new_tasks = self.strategy.evaluate(state, "scan-1", task)
        assert len(new_tasks) == 1
        t = new_tasks[0]
        assert t.tool == "redis-cli"
        assert t.task_type == TaskType.DOCKER_EXEC
        assert "10.0.0.1" in t.command
        assert "6379" in t.command
        assert t.scan_id == "scan-1"
        assert t.spawned_by == "nmap-1"
        assert "redis" in t.spawned_reason.lower()

    def test_no_spawn_when_no_redis(self):
        state = _state_with_http_only()
        task = _make_task(tool="nmap")
        new_tasks = self.strategy.evaluate(state, "scan-1", task)
        assert new_tasks == []

    def test_no_spawn_when_already_spawned(self):
        """Idempotent: evaluate() self-tracks, second call returns empty."""
        state = _state_with_redis()
        task = _make_task(tool="nmap")
        first = self.strategy.evaluate(state, "scan-1", task)
        assert len(first) == 1

        # Second evaluate on the same strategy instance — should be empty
        # because evaluate() marked the service key internally.
        second = self.strategy.evaluate(state, "scan-1", task)
        assert second == []

    def test_spawns_for_multiple_redis_instances(self):
        state = KillChainState()
        state.ingest(IntelBundle(services=[
            DiscoveredService(host="10.0.0.1", port=6379, protocol="tcp", service="redis"),
            DiscoveredService(host="10.0.0.2", port=6379, protocol="tcp", service="redis"),
        ]))
        task = _make_task(tool="nmap")
        new_tasks = self.strategy.evaluate(state, "scan-1", task)
        assert len(new_tasks) == 2
        hosts = {t.command.split("-h ")[1].split(" ")[0] for t in new_tasks}
        assert hosts == {"10.0.0.1", "10.0.0.2"}

    def test_ignores_non_nmap_tool(self):
        """Only triggers on nmap/masscan completions."""
        state = _state_with_redis()
        task = _make_task(tool="semgrep")
        new_tasks = self.strategy.evaluate(state, "scan-1", task)
        assert new_tasks == []

    def test_task_ids_are_deterministic(self):
        """Same input produces same task IDs, enabling dedup in _inject_tasks."""
        state = _state_with_redis()
        task = _make_task(tool="nmap")
        tasks_a = self.strategy.evaluate(state, "scan-1", task)
        # Reset strategy state for second evaluation
        strategy_b = RedisProbeStrategy()
        tasks_b = strategy_b.evaluate(state, "scan-1", task)
        assert tasks_a[0].id == tasks_b[0].id


class TestGetBuiltinStrategies:
    def test_returns_list(self):
        strategies = get_builtin_strategies()
        assert isinstance(strategies, list)

    def test_contains_redis_probe(self):
        strategies = get_builtin_strategies()
        names = [s.name for s in strategies]
        assert "redis_probe" in names

    def test_all_satisfy_protocol(self):
        strategies = get_builtin_strategies()
        for s in strategies:
            assert isinstance(s, MutationStrategy)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_mutation_strategy.py::TestRedisProbeStrategy::test_name -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement MutationStrategy protocol, RedisProbeStrategy, get_builtin_strategies**

```python
# packages/cli/src/opentools/scanner/mutation/strategy.py
"""MutationStrategy protocol and builtin implementations.

Strategies evaluate the accumulated KillChainState after each task
completion and synthesize new ScanTask objects for injection into
the DAG.  Each strategy tracks what it has already spawned to
maintain idempotency.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from opentools.scanner.models import (
    ExecutionTier,
    ScanTask,
    TaskType,
)
from opentools.scanner.mutation.models import KillChainState


@runtime_checkable
class MutationStrategy(Protocol):
    """Evaluates kill chain state and synthesizes new tasks."""
    name: str
    max_spawns: int

    def evaluate(
        self,
        state: KillChainState,
        scan_id: str,
        completed_task: ScanTask,
    ) -> list[ScanTask]: ...


class RedisProbeStrategy:
    """Spawn redis-cli INFO probes when nmap discovers Redis services.

    Uses DOCKER_EXEC to run redis-cli inside a container, avoiding
    the need for redis-cli on the host.

    Self-tracking: marks service keys as spawned inside evaluate(),
    so the engine doesn't need to call back.
    """
    name = "redis_probe"
    max_spawns = 10

    # Tools that discover network services
    _TRIGGER_TOOLS = {"nmap", "masscan"}

    def __init__(self) -> None:
        self._spawned_keys: set[str] = set()

    def evaluate(
        self,
        state: KillChainState,
        scan_id: str,
        completed_task: ScanTask,
    ) -> list[ScanTask]:
        if completed_task.tool not in self._TRIGGER_TOOLS:
            return []

        redis_services = state.get_services("redis")
        if not redis_services:
            return []

        tasks: list[ScanTask] = []
        for svc in redis_services:
            key = f"{svc.host}:{svc.port}/{svc.protocol}"
            if key in self._spawned_keys:
                continue

            self._spawned_keys.add(key)  # self-track immediately
            task_id = f"redis-probe-{svc.host}-{svc.port}"
            tasks.append(ScanTask(
                id=task_id,
                scan_id=scan_id,
                name=f"Redis probe {svc.host}:{svc.port}",
                tool="redis-cli",
                task_type=TaskType.DOCKER_EXEC,
                command=f"redis-cli -h {svc.host} -p {svc.port} INFO",
                depends_on=[completed_task.id],
                priority=20,
                tier=ExecutionTier.FAST,
                spawned_by=completed_task.id,
                spawned_reason=f"nmap discovered Redis on {svc.host}:{svc.port}",
            ))

        return tasks


def get_builtin_strategies() -> list[MutationStrategy]:
    """Return all builtin mutation strategies."""
    return [
        RedisProbeStrategy(),
    ]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_mutation_strategy.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/mutation/strategy.py packages/cli/tests/test_scanner/test_mutation_strategy.py
git commit -m "feat(mutation): add MutationStrategy protocol with RedisProbeStrategy"
```

---

### Task 4: Engine Integration — Wire Mutation Layer into ScanEngine

**Files:**
- Modify: `packages/cli/src/opentools/scanner/engine.py:35-63` (`__init__`)
- Modify: `packages/cli/src/opentools/scanner/engine.py:257-274` (`_mark_completed`)
- Modify: `packages/cli/src/opentools/scanner/engine.py:350-357` (`_inject_tasks`)
- Test: `packages/cli/tests/test_scanner/test_engine_mutation.py`

**Context:** The mutation layer hooks into `_mark_completed` after the existing pipeline queueing and before the existing reactive edge evaluation. All mutation logic is synchronous — no `await` points — so the single-threaded event loop guarantee holds. The existing reactive edges remain backward compatible.

- [ ] **Step 1: Write failing integration tests**

```python
# packages/cli/tests/test_scanner/test_engine_mutation.py
"""Integration tests: ScanEngine + mutation layer."""

import asyncio
from datetime import datetime, timezone
from typing import Callable

import pytest

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.engine import ScanEngine
from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.models import (
    Scan,
    ScanStatus,
    ScanTask,
    TaskStatus,
    TaskType,
    TargetType,
)
from opentools.scanner.mutation.analyzer import AnalyzerRegistry, NmapAnalyzer
from opentools.scanner.mutation.models import KillChainState
from opentools.scanner.mutation.strategy import RedisProbeStrategy
from opentools.shared.progress import EventBus
from opentools.shared.resource_pool import AdaptiveResourcePool


# Nmap XML that discovers a Redis service
NMAP_REDIS_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis" product="Redis" version="6.2.7"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

# Nmap XML with no interesting services
NMAP_HTTP_ONLY_XML = """\
<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>"""


class MockExecutor:
    def __init__(self, results: dict[str, TaskOutput] | None = None):
        self._results = results or {}
        self._default = TaskOutput(exit_code=0, stdout="ok", duration_ms=10)
        self.executed: list[str] = []

    async def execute(
        self, task: ScanTask, on_output: Callable[[bytes], None],
        cancellation: CancellationToken,
    ) -> TaskOutput:
        self.executed.append(task.id)
        return self._results.get(task.id, self._default)


def _make_scan() -> Scan:
    return Scan(
        id="scan-1", engagement_id="eng-1", target="10.0.0.1",
        target_type=TargetType.NETWORK, status=ScanStatus.PENDING,
        created_at=datetime.now(timezone.utc),
    )


def _make_engine_with_mutation(
    tasks: list[ScanTask],
    executor: MockExecutor,
    max_mutation_spawns: int = 100,
) -> ScanEngine:
    pool = AdaptiveResourcePool(global_limit=4)
    executors = {
        TaskType.SHELL: executor,
        TaskType.DOCKER_EXEC: executor,
        TaskType.MCP_CALL: executor,
    }
    engine = ScanEngine(
        scan=_make_scan(),
        resource_pool=pool,
        executors=executors,
        event_bus=EventBus(),
        cancellation=CancellationToken(),
    )

    # Wire up mutation layer
    analyzer_registry = AnalyzerRegistry()
    analyzer_registry.register_builtins()
    engine.set_analyzer_registry(analyzer_registry)
    engine.set_mutation_strategies([RedisProbeStrategy()])
    engine.set_max_mutation_spawns(max_mutation_spawns)

    engine.load_tasks(tasks)
    return engine


class TestEngineMutationIntegration:
    @pytest.mark.asyncio
    async def test_nmap_redis_spawns_probe(self):
        """Nmap finds Redis → engine spawns redis-cli probe → probe runs."""
        executor = MockExecutor(results={
            "nmap-scan": TaskOutput(
                exit_code=0, stdout=NMAP_REDIS_XML, duration_ms=100,
            ),
        })
        nmap_task = ScanTask(
            id="nmap-scan", scan_id="scan-1", name="nmap",
            tool="nmap", task_type=TaskType.SHELL, command="nmap 10.0.0.1",
        )
        engine = _make_engine_with_mutation([nmap_task], executor)
        await engine.run()

        # The spawned redis probe should have been executed
        assert "nmap-scan" in executor.executed
        assert "redis-probe-10.0.0.1-6379" in executor.executed

        # Verify the spawned task has correct metadata
        spawned = engine._tasks["redis-probe-10.0.0.1-6379"]
        assert spawned.tool == "redis-cli"
        assert spawned.spawned_by == "nmap-scan"
        assert spawned.status == TaskStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_no_mutation_when_no_interesting_services(self):
        """Nmap finds only HTTP → no mutation strategies fire."""
        executor = MockExecutor(results={
            "nmap-scan": TaskOutput(
                exit_code=0, stdout=NMAP_HTTP_ONLY_XML, duration_ms=100,
            ),
        })
        nmap_task = ScanTask(
            id="nmap-scan", scan_id="scan-1", name="nmap",
            tool="nmap", task_type=TaskType.SHELL, command="nmap 10.0.0.1",
        )
        engine = _make_engine_with_mutation([nmap_task], executor)
        await engine.run()

        assert executor.executed == ["nmap-scan"]
        assert len(engine._tasks) == 1

    @pytest.mark.asyncio
    async def test_mutation_respects_global_budget(self):
        """Global spawn budget prevents unbounded task injection."""
        executor = MockExecutor(results={
            "nmap-scan": TaskOutput(
                exit_code=0, stdout=NMAP_REDIS_XML, duration_ms=100,
            ),
        })
        nmap_task = ScanTask(
            id="nmap-scan", scan_id="scan-1", name="nmap",
            tool="nmap", task_type=TaskType.SHELL, command="nmap 10.0.0.1",
        )
        engine = _make_engine_with_mutation(
            [nmap_task], executor, max_mutation_spawns=0,
        )
        await engine.run()

        # Budget is 0 — no mutations allowed
        assert executor.executed == ["nmap-scan"]
        assert len(engine._tasks) == 1

    @pytest.mark.asyncio
    async def test_mutation_coexists_with_reactive_edges(self):
        """Both mutation strategies AND reactive edges can fire on the same task."""
        from opentools.scanner.models import ReactiveEdge

        executor = MockExecutor(results={
            "nmap-scan": TaskOutput(
                exit_code=0, stdout=NMAP_REDIS_XML, duration_ms=100,
            ),
        })

        edge_task = ScanTask(
            id="edge-spawned", scan_id="scan-1", name="edge-task",
            tool="test", task_type=TaskType.SHELL, command="echo edge",
        )
        edge = ReactiveEdge(
            id="edge-1", trigger_task_id="nmap-scan",
            evaluator="always", spawns=[edge_task],
        )
        nmap_task = ScanTask(
            id="nmap-scan", scan_id="scan-1", name="nmap",
            tool="nmap", task_type=TaskType.SHELL, command="nmap 10.0.0.1",
            reactive_edges=[edge],
        )

        engine = _make_engine_with_mutation([nmap_task], executor)
        engine.register_edge_evaluator("always", lambda t, o, e: e.spawns or [])
        await engine.run()

        # Both mutation-spawned AND edge-spawned tasks should run
        assert "redis-probe-10.0.0.1-6379" in executor.executed
        assert "edge-spawned" in executor.executed

    @pytest.mark.asyncio
    async def test_kill_chain_state_accessible(self):
        """Engine exposes kill chain state for inspection."""
        executor = MockExecutor(results={
            "nmap-scan": TaskOutput(
                exit_code=0, stdout=NMAP_REDIS_XML, duration_ms=100,
            ),
        })
        nmap_task = ScanTask(
            id="nmap-scan", scan_id="scan-1", name="nmap",
            tool="nmap", task_type=TaskType.SHELL, command="nmap 10.0.0.1",
        )
        engine = _make_engine_with_mutation([nmap_task], executor)
        await engine.run()

        state = engine.kill_chain_state
        assert state.has_service("redis")
        assert state.total_spawned == 1

    @pytest.mark.asyncio
    async def test_no_mutation_without_registry(self):
        """Engine works normally when no mutation layer is configured."""
        executor = MockExecutor(results={
            "nmap-scan": TaskOutput(
                exit_code=0, stdout=NMAP_REDIS_XML, duration_ms=100,
            ),
        })
        nmap_task = ScanTask(
            id="nmap-scan", scan_id="scan-1", name="nmap",
            tool="nmap", task_type=TaskType.SHELL, command="nmap 10.0.0.1",
        )
        # Build engine WITHOUT mutation layer
        pool = AdaptiveResourcePool(global_limit=4)
        engine = ScanEngine(
            scan=_make_scan(), resource_pool=pool,
            executors={TaskType.SHELL: executor, TaskType.DOCKER_EXEC: executor},
            event_bus=EventBus(), cancellation=CancellationToken(),
        )
        engine.load_tasks([nmap_task])
        await engine.run()

        # Should complete normally with no mutations
        assert executor.executed == ["nmap-scan"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine_mutation.py::TestEngineMutationIntegration::test_nmap_redis_spawns_probe -v`
Expected: FAIL with `AttributeError: 'ScanEngine' object has no attribute 'set_analyzer_registry'`

- [ ] **Step 3: Modify ScanEngine.__init__ — add mutation fields**

In `packages/cli/src/opentools/scanner/engine.py`, add after the existing `self._cache` and `self._pipeline_results` fields (around line 69):

```python
        # Mutation layer (optional — engine works without it)
        self._analyzer_registry: AnalyzerRegistry | None = None
        self._mutation_strategies: list[Any] = []
        self._kill_chain = KillChainState()
        self._max_mutation_spawns: int = 100
```

Add the imports at the top of the file (after the existing imports):

```python
from opentools.scanner.mutation.models import KillChainState
```

Add these public methods after the existing `set_cache` method (around line 122):

```python
    def set_analyzer_registry(self, registry: Any) -> None:
        """Set the OutputAnalyzer registry for mutation layer."""
        self._analyzer_registry = registry

    def set_mutation_strategies(self, strategies: list[Any]) -> None:
        """Set the mutation strategies for dynamic task injection."""
        self._mutation_strategies = list(strategies)

    def set_max_mutation_spawns(self, limit: int) -> None:
        """Set the global budget for mutation-spawned tasks."""
        self._max_mutation_spawns = limit

    @property
    def kill_chain_state(self) -> KillChainState:
        """Read-only access to accumulated attack surface state."""
        return self._kill_chain
```

- [ ] **Step 4: Modify ScanEngine._mark_completed — hook mutation layer**

Replace the existing `_mark_completed` method (lines 257-274) with:

```python
    def _mark_completed(self, task_id: str, output: TaskOutput) -> None:
        task = self._tasks[task_id]
        task.status = TaskStatus.COMPLETED
        task.exit_code = output.exit_code
        task.stdout = output.stdout
        task.stderr = output.stderr
        task.duration_ms = output.duration_ms
        task.cached = output.cached
        self._completed.add(task_id)

        # Queue output for pipeline processing
        if self._pipeline is not None:
            self._pipeline_results[task_id] = output

        # --- Mutation layer: analyze → ingest → evaluate strategies ---
        mutation_tasks = self._evaluate_mutations(task, output)

        # --- Existing reactive edges (backward compatible) ---
        edge_tasks = self._evaluate_edges(task, output)

        all_new = mutation_tasks + edge_tasks
        if all_new:
            self._inject_tasks(all_new)
```

Add the `_evaluate_mutations` method after `_evaluate_edges` (after line 348):

```python
    def _evaluate_mutations(
        self, task: ScanTask, output: TaskOutput
    ) -> list[ScanTask]:
        """Run mutation layer: analyze output, update state, evaluate strategies."""
        if self._analyzer_registry is None:
            return []

        # 1. Extract intel from tool output
        analyzer = self._analyzer_registry.get(task.tool)
        if analyzer is not None and output.stdout:
            bundle = analyzer.analyze(output.stdout, output.stderr or "")
            self._kill_chain.ingest(bundle)

        # 2. Evaluate strategies against accumulated state
        new_tasks: list[ScanTask] = []
        if self._kill_chain.total_spawned >= self._max_mutation_spawns:
            return []

        for strategy in self._mutation_strategies:
            budget_used = self._kill_chain.tasks_spawned.get(strategy.name, 0)
            if budget_used >= strategy.max_spawns:
                continue

            remaining_strategy = strategy.max_spawns - budget_used
            remaining_global = self._max_mutation_spawns - self._kill_chain.total_spawned

            spawned = strategy.evaluate(self._kill_chain, self.scan.id, task)

            allowed = min(remaining_strategy, remaining_global, len(spawned))
            accepted: list[ScanTask] = []
            for s in spawned[:allowed]:
                if s.id not in self._tasks:
                    accepted.append(s)

            # Strategies self-track their spawned keys inside evaluate(),
            # so the engine only needs to update the global budget.
            if accepted:
                self._kill_chain.record_spawn(strategy.name, len(accepted))
                new_tasks.extend(accepted)

        return new_tasks
```

- [ ] **Step 5: Harden _inject_tasks with dependency validation**

Replace the existing `_inject_tasks` method (lines 350-357) with:

```python
    def _inject_tasks(self, tasks: list[ScanTask]) -> None:
        """Add dynamically spawned tasks to the graph.

        Validates that all dependencies exist. Drops tasks with unknown
        dependencies to prevent forward-reference cycles.
        """
        for t in tasks:
            if t.id in self._tasks:
                continue
            # Validate all dependencies exist in the graph
            valid = True
            for dep in t.depends_on:
                if dep not in self._tasks:
                    import logging
                    logging.getLogger(__name__).warning(
                        "Dropping spawned task %s: depends on unknown task %s",
                        t.id, dep,
                    )
                    valid = False
                    break
            if valid:
                self._tasks[t.id] = t
                for dep in t.depends_on:
                    self._dependents[dep].add(t.id)
```

- [ ] **Step 6: Run integration tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine_mutation.py -v`
Expected: All PASS

- [ ] **Step 7: Run existing engine tests to verify backward compatibility**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engine.py -v`
Expected: All PASS — no regressions

- [ ] **Step 8: Commit**

```bash
git add packages/cli/src/opentools/scanner/engine.py packages/cli/tests/test_scanner/test_engine_mutation.py
git commit -m "feat(engine): integrate mutation layer — analyzer → state → strategy → inject"
```

---

## Phase B: Ephemeral Proxy Routing

### Task 5: Add `env` Parameter to `run_streaming`

**Files:**
- Modify: `packages/cli/src/opentools/shared/subprocess.py:43-48` (function signature)
- Modify: `packages/cli/src/opentools/shared/subprocess.py:68` (`create_subprocess_exec` call)
- Modify: `packages/cli/tests/test_scanner/test_shared_subprocess.py`

- [ ] **Step 1: Write failing test for env parameter**

Add to `packages/cli/tests/test_scanner/test_shared_subprocess.py`:

```python
class TestRunStreamingEnv:
    @pytest.mark.asyncio
    async def test_env_vars_passed_to_subprocess(self):
        """Custom env dict is forwarded to the child process."""
        import os
        custom_env = {**os.environ, "OT_TEST_PROXY": "socks5://127.0.0.1:1080"}
        result = await run_streaming(
            [sys.executable, "-c", "import os; print(os.environ.get('OT_TEST_PROXY', 'MISSING'))"],
            on_output=lambda _: None,
            env=custom_env,
        )
        assert result.exit_code == 0
        assert "socks5://127.0.0.1:1080" in result.stdout

    @pytest.mark.asyncio
    async def test_env_none_inherits_parent(self):
        """env=None (default) inherits the parent process environment."""
        result = await run_streaming(
            [sys.executable, "-c", "import os; print(os.environ.get('PATH', 'MISSING'))"],
            on_output=lambda _: None,
        )
        assert result.exit_code == 0
        assert "MISSING" not in result.stdout
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_shared_subprocess.py::TestRunStreamingEnv -v`
Expected: FAIL with `TypeError: run_streaming() got an unexpected keyword argument 'env'`

- [ ] **Step 3: Add env parameter to run_streaming**

In `packages/cli/src/opentools/shared/subprocess.py`, change the function signature (line 43):

```python
async def run_streaming(
    args: list[str],
    on_output: Callable[[bytes], None],
    timeout: int = 300,
    cancellation: object | None = None,  # CancellationToken
    env: dict[str, str] | None = None,
) -> SubprocessResult:
```

And pass it through at line 68:

```python
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
```

- [ ] **Step 4: Run all subprocess tests to verify pass + no regressions**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_shared_subprocess.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/shared/subprocess.py packages/cli/tests/test_scanner/test_shared_subprocess.py
git commit -m "feat(subprocess): add env parameter to run_streaming for proxy injection"
```

---

### Task 6: CloudNodeProvider ABC + DigitalOcean Implementation

**Files:**
- Create: `packages/cli/src/opentools/scanner/infra/__init__.py`
- Create: `packages/cli/src/opentools/scanner/infra/provider.py`
- Create: `packages/cli/src/opentools/scanner/infra/digitalocean.py`
- Test: `packages/cli/tests/test_scanner/test_infra_provider.py`

- [ ] **Step 1: Write failing tests**

```python
# packages/cli/tests/test_scanner/test_infra_provider.py
"""Tests for CloudNodeProvider and DigitalOceanProvider."""

import asyncio
import json

import httpx
import pytest

from opentools.scanner.infra.provider import (
    CloudNodeProvider,
    EphemeralNode,
    ProvisioningError,
    ProvisioningTimeout,
)
from opentools.scanner.infra.digitalocean import DigitalOceanProvider


class TestEphemeralNode:
    def test_construction(self):
        node = EphemeralNode(
            provider_id="12345",
            ip_address="1.2.3.4",
            region="nyc3",
            ssh_key_fingerprint="aa:bb:cc",
        )
        assert node.provider_id == "12345"
        assert node.ip_address == "1.2.3.4"
        assert node.tags == []


class TestDigitalOceanProvider:
    @pytest.mark.asyncio
    async def test_create_node_sends_correct_request(self):
        """Verify the POST payload sent to the DO API."""
        captured_request = None

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal captured_request
            captured_request = request
            return httpx.Response(
                200, json={"droplet": {"id": 12345}},
            )

        transport = httpx.MockTransport(mock_handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.digitalocean.com/v2")
        provider = DigitalOceanProvider(client=client)

        result = await provider.create_node(
            region="nyc3", ssh_public_key="fp:aa:bb", tags=["test"],
        )
        assert result == "12345"
        body = json.loads(captured_request.content)
        assert body["region"] == "nyc3"
        assert "test" in body["tags"]

    @pytest.mark.asyncio
    async def test_poll_status_active(self):
        async def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "droplet": {
                    "id": 12345, "status": "active",
                    "networks": {"v4": [{"ip_address": "1.2.3.4", "type": "public"}]},
                },
            })

        transport = httpx.MockTransport(mock_handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.digitalocean.com/v2")
        provider = DigitalOceanProvider(client=client)

        status, ip = await provider.poll_status("12345")
        assert status == "active"
        assert ip == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_poll_status_creating(self):
        async def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "droplet": {"id": 12345, "status": "new", "networks": {"v4": []}},
            })

        transport = httpx.MockTransport(mock_handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.digitalocean.com/v2")
        provider = DigitalOceanProvider(client=client)

        status, ip = await provider.poll_status("12345")
        assert status == "creating"
        assert ip is None

    @pytest.mark.asyncio
    async def test_destroy_node_204(self):
        async def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(204)

        transport = httpx.MockTransport(mock_handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.digitalocean.com/v2")
        provider = DigitalOceanProvider(client=client)

        await provider.destroy_node("12345")  # should not raise

    @pytest.mark.asyncio
    async def test_destroy_node_404_is_idempotent(self):
        async def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        transport = httpx.MockTransport(mock_handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.digitalocean.com/v2")
        provider = DigitalOceanProvider(client=client)

        await provider.destroy_node("12345")  # should not raise

    @pytest.mark.asyncio
    async def test_wait_until_ready_success(self):
        call_count = 0

        async def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                return httpx.Response(200, json={
                    "droplet": {"id": 12345, "status": "new", "networks": {"v4": []}},
                })
            return httpx.Response(200, json={
                "droplet": {
                    "id": 12345, "status": "active",
                    "networks": {"v4": [{"ip_address": "1.2.3.4", "type": "public"}]},
                },
            })

        transport = httpx.MockTransport(mock_handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.digitalocean.com/v2")
        provider = DigitalOceanProvider(client=client)

        ip = await provider.wait_until_ready("12345", poll_interval=0.01, max_polls=10)
        assert ip == "1.2.3.4"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_wait_until_ready_timeout(self):
        async def mock_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={
                "droplet": {"id": 12345, "status": "new", "networks": {"v4": []}},
            })

        transport = httpx.MockTransport(mock_handler)
        client = httpx.AsyncClient(transport=transport, base_url="https://api.digitalocean.com/v2")
        provider = DigitalOceanProvider(client=client)

        with pytest.raises(ProvisioningTimeout):
            await provider.wait_until_ready("12345", poll_interval=0.01, max_polls=3)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_infra_provider.py::TestEphemeralNode -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement CloudNodeProvider, EphemeralNode, DigitalOceanProvider**

```python
# packages/cli/src/opentools/scanner/infra/__init__.py
"""Ephemeral infrastructure provisioning for proxied scan execution."""
```

```python
# packages/cli/src/opentools/scanner/infra/provider.py
"""CloudNodeProvider ABC and shared types for ephemeral infrastructure."""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class EphemeralNode(BaseModel):
    """A provisioned ephemeral cloud node."""
    provider_id: str
    ip_address: str
    region: str
    ssh_key_fingerprint: str
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProvisioningError(Exception):
    """Cloud node provisioning failed."""


class ProvisioningTimeout(ProvisioningError):
    """Cloud node did not become ready within the polling budget."""


class CloudNodeProvider(ABC):
    """Abstract base for provisioning ephemeral proxy nodes.

    All methods are async — they make HTTP calls and must never block
    the event loop.
    """

    @abstractmethod
    async def create_node(
        self, region: str, ssh_public_key: str, tags: list[str],
    ) -> str:
        """Create a node. Returns the provider resource ID (not yet ready)."""
        ...

    @abstractmethod
    async def poll_status(self, provider_id: str) -> tuple[str, str | None]:
        """Returns (status, ip_address | None). Status: "creating" | "active" | "error"."""
        ...

    @abstractmethod
    async def destroy_node(self, provider_id: str) -> None:
        """Destroy a node. Idempotent — must not raise if already gone."""
        ...

    async def wait_until_ready(
        self,
        provider_id: str,
        poll_interval: float = 3.0,
        max_polls: int = 60,
    ) -> str:
        """Poll until active. Returns IP address. Yields to event loop between polls."""
        for attempt in range(max_polls):
            status, ip = await self.poll_status(provider_id)
            if status == "active" and ip is not None:
                logger.info("Node %s ready at %s after %d polls", provider_id, ip, attempt + 1)
                return ip
            if status == "error":
                raise ProvisioningError(f"Node {provider_id} entered error state")
            await asyncio.sleep(poll_interval)
        raise ProvisioningTimeout(
            f"Node {provider_id} not ready after {max_polls * poll_interval:.0f}s"
        )
```

```python
# packages/cli/src/opentools/scanner/infra/digitalocean.py
"""DigitalOcean CloudNodeProvider implementation."""

from __future__ import annotations

import uuid

import httpx

from opentools.scanner.infra.provider import CloudNodeProvider


class DigitalOceanProvider(CloudNodeProvider):
    """Provision ephemeral droplets via the DigitalOcean API."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    @classmethod
    def from_token(cls, api_token: str) -> DigitalOceanProvider:
        """Create a provider with a new httpx client using the given API token."""
        client = httpx.AsyncClient(
            base_url="https://api.digitalocean.com/v2",
            headers={"Authorization": f"Bearer {api_token}"},
            timeout=30.0,
        )
        return cls(client=client)

    async def create_node(
        self, region: str, ssh_public_key: str, tags: list[str],
    ) -> str:
        resp = await self._client.post("/droplets", json={
            "name": f"ot-proxy-{uuid.uuid4().hex[:8]}",
            "region": region,
            "size": "s-1vcpu-512mb-10gb",
            "image": "ubuntu-24-04-x64",
            "ssh_keys": [ssh_public_key],
            "tags": tags,
        })
        resp.raise_for_status()
        return str(resp.json()["droplet"]["id"])

    async def poll_status(self, provider_id: str) -> tuple[str, str | None]:
        resp = await self._client.get(f"/droplets/{provider_id}")
        resp.raise_for_status()
        droplet = resp.json()["droplet"]
        status = "active" if droplet["status"] == "active" else "creating"
        ip = None
        for net in droplet.get("networks", {}).get("v4", []):
            if net.get("type") == "public":
                ip = net["ip_address"]
                break
        return status, ip

    async def destroy_node(self, provider_id: str) -> None:
        resp = await self._client.delete(f"/droplets/{provider_id}")
        if resp.status_code not in (204, 404):
            resp.raise_for_status()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_infra_provider.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/infra/__init__.py packages/cli/src/opentools/scanner/infra/provider.py packages/cli/src/opentools/scanner/infra/digitalocean.py packages/cli/tests/test_scanner/test_infra_provider.py
git commit -m "feat(infra): add CloudNodeProvider ABC with DigitalOcean implementation"
```

---

### Task 7: Ephemeral Proxy Context Manager + Shielded Teardown

**Files:**
- Create: `packages/cli/src/opentools/scanner/infra/proxy.py`
- Test: `packages/cli/tests/test_scanner/test_infra_proxy.py`

**Context:** This is the critical piece — the `AsyncContextManager` that composes provision → tunnel → teardown with guaranteed cleanup. The `_shielded_destroy` pattern ensures the cloud API DELETE fires even when the parent task is cancelled.

- [ ] **Step 1: Write failing tests for proxy lifecycle**

```python
# packages/cli/tests/test_scanner/test_infra_proxy.py
"""Tests for ephemeral_proxy context manager and shielded teardown."""

import asyncio

import pytest

from opentools.scanner.infra.provider import (
    CloudNodeProvider,
    ProvisioningError,
)
from opentools.scanner.infra.proxy import (
    ProxyEndpoint,
    _shielded_destroy,
    ephemeral_proxy,
)


class FakeProvider(CloudNodeProvider):
    """In-memory provider for testing. No real cloud calls."""

    def __init__(
        self,
        ready_after_polls: int = 1,
        ip_address: str = "1.2.3.4",
        fail_create: bool = False,
        fail_destroy: bool = False,
    ):
        self.ready_after_polls = ready_after_polls
        self.ip_address = ip_address
        self.fail_create = fail_create
        self.fail_destroy = fail_destroy
        self.created_ids: list[str] = []
        self.destroyed_ids: list[str] = []
        self._poll_count = 0

    async def create_node(self, region, ssh_public_key, tags):
        if self.fail_create:
            raise ProvisioningError("create failed")
        node_id = f"fake-{len(self.created_ids)}"
        self.created_ids.append(node_id)
        return node_id

    async def poll_status(self, provider_id):
        self._poll_count += 1
        if self._poll_count >= self.ready_after_polls:
            return "active", self.ip_address
        return "creating", None

    async def destroy_node(self, provider_id):
        if self.fail_destroy:
            raise ProvisioningError("destroy failed")
        self.destroyed_ids.append(provider_id)


class TestShieldedDestroy:
    @pytest.mark.asyncio
    async def test_normal_destroy(self):
        provider = FakeProvider()
        provider.created_ids.append("node-1")
        await _shielded_destroy(provider, "node-1")
        assert "node-1" in provider.destroyed_ids

    @pytest.mark.asyncio
    async def test_destroy_survives_cancellation(self):
        """The destroy call completes even when the outer scope is cancelled."""
        provider = FakeProvider()
        provider.created_ids.append("node-1")
        destroyed = False

        async def destroy_with_delay():
            """Simulate a destroy that takes some time."""
            await asyncio.sleep(0.05)
            await _shielded_destroy(provider, "node-1")
            nonlocal destroyed
            destroyed = True

        task = asyncio.ensure_future(destroy_with_delay())
        await asyncio.sleep(0.01)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        # Give the shielded destroy time to complete
        await asyncio.sleep(0.1)
        assert "node-1" in provider.destroyed_ids

    @pytest.mark.asyncio
    async def test_destroy_failure_does_not_raise(self):
        """Destroy errors are logged, not raised — we can't do more."""
        provider = FakeProvider(fail_destroy=True)
        # Should not raise
        await _shielded_destroy(provider, "node-1")


class TestProxyEndpoint:
    def test_env_includes_proxy_vars(self):
        endpoint = ProxyEndpoint(host="1.2.3.4", socks_port=10800)
        env = endpoint.env
        assert "socks5://127.0.0.1:10800" in env["HTTP_PROXY"]
        assert "socks5://127.0.0.1:10800" in env["HTTPS_PROXY"]
        assert "socks5://127.0.0.1:10800" in env["ALL_PROXY"]
        # Both upper and lower case for tool compatibility
        assert "socks5://127.0.0.1:10800" in env["http_proxy"]
        assert "socks5://127.0.0.1:10800" in env["https_proxy"]

    def test_env_inherits_parent_env(self):
        """Proxy env vars are merged with parent environment."""
        import os
        endpoint = ProxyEndpoint(host="1.2.3.4", socks_port=10800)
        env = endpoint.env
        assert "PATH" in env or "Path" in env  # platform-dependent casing


class TestEphemeralProxyLifecycle:
    @pytest.mark.asyncio
    async def test_provision_and_teardown(self):
        """Happy path: provision → yield endpoint → destroy."""
        provider = FakeProvider(ready_after_polls=1)

        async with ephemeral_proxy(
            provider=provider,
            region="nyc3",
            ssh_key="test-key",
            local_socks_port=10800,
            scan_id="scan-1",
            _skip_tunnel=True,  # skip real SSH for unit test
        ) as endpoint:
            assert isinstance(endpoint, ProxyEndpoint)
            assert endpoint.host == "1.2.3.4"
            assert endpoint.socks_port == 10800

        # After exit, node must be destroyed
        assert len(provider.created_ids) == 1
        assert len(provider.destroyed_ids) == 1
        assert provider.created_ids[0] == provider.destroyed_ids[0]

    @pytest.mark.asyncio
    async def test_teardown_on_exception(self):
        """Node is destroyed even if the body raises."""
        provider = FakeProvider(ready_after_polls=1)

        with pytest.raises(ValueError, match="deliberate"):
            async with ephemeral_proxy(
                provider=provider, region="nyc3", ssh_key="k",
                local_socks_port=10800, scan_id="s1",
                _skip_tunnel=True,
            ):
                raise ValueError("deliberate")

        assert len(provider.destroyed_ids) == 1

    @pytest.mark.asyncio
    async def test_create_failure_no_destroy(self):
        """If creation fails, no destroy is attempted (nothing to destroy)."""
        provider = FakeProvider(fail_create=True)

        with pytest.raises(ProvisioningError):
            async with ephemeral_proxy(
                provider=provider, region="nyc3", ssh_key="k",
                local_socks_port=10800, scan_id="s1",
                _skip_tunnel=True,
            ):
                pass  # pragma: no cover

        assert provider.destroyed_ids == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_infra_proxy.py::TestProxyEndpoint -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement ephemeral_proxy, ProxyEndpoint, _shielded_destroy**

```python
# packages/cli/src/opentools/scanner/infra/proxy.py
"""Ephemeral proxy context manager with guaranteed teardown.

Usage::

    async with ephemeral_proxy(provider, region="nyc3", ...) as endpoint:
        result = await run_streaming(args, on_output, env=endpoint.env)
    # Node is destroyed here, guaranteed.
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

from opentools.scanner.infra.provider import CloudNodeProvider, ProvisioningError

logger = logging.getLogger(__name__)

PROXY_TAG = "opentools-ephemeral-proxy"


class ProxyEndpoint:
    """The usable result of a provisioned proxy — env vars for subprocess injection."""

    def __init__(self, host: str, socks_port: int) -> None:
        self.host = host
        self.socks_port = socks_port

    @property
    def env(self) -> dict[str, str]:
        """Environment dict with proxy vars merged into parent env."""
        proxy_url = f"socks5://127.0.0.1:{self.socks_port}"
        return {
            **os.environ,
            "HTTP_PROXY": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "http_proxy": proxy_url,
            "https_proxy": proxy_url,
            "ALL_PROXY": proxy_url,
        }


@asynccontextmanager
async def ephemeral_proxy(
    provider: CloudNodeProvider,
    region: str = "nyc3",
    ssh_key: str = "",
    ssh_key_path: str = "~/.ssh/id_ed25519",
    local_socks_port: int = 10800,
    scan_id: str = "",
    _skip_tunnel: bool = False,
) -> AsyncIterator[ProxyEndpoint]:
    """Provision ephemeral proxy, optionally establish tunnel, yield endpoint.

    GUARANTEE: The cloud node is destroyed on exit regardless of how the
    body terminates — normal return, exception, timeout, or cancellation.
    The destroy call is shielded from asyncio.CancelledError.

    Args:
        _skip_tunnel: If True, skip SSH tunnel setup (for unit testing).
    """
    tags = [PROXY_TAG, f"scan:{scan_id}"]
    provider_id: str | None = None
    tunnel_proc: asyncio.subprocess.Process | None = None

    try:
        # Phase 1: Provision
        provider_id = await provider.create_node(
            region=region, ssh_public_key=ssh_key, tags=tags,
        )
        logger.info("Provisioning node %s in %s", provider_id, region)

        ip_address = await provider.wait_until_ready(provider_id)

        # Phase 2: SSH tunnel (skippable for testing)
        if not _skip_tunnel:
            tunnel_proc = await _establish_tunnel(
                ip_address=ip_address,
                ssh_key_path=ssh_key_path,
                local_port=local_socks_port,
            )

        endpoint = ProxyEndpoint(host=ip_address, socks_port=local_socks_port)
        logger.info(
            "Proxy ready: 127.0.0.1:%d → %s (node %s)",
            local_socks_port, ip_address, provider_id,
        )

        yield endpoint

    finally:
        # Phase 3: Teardown (reverse order)

        # 3a. Kill SSH tunnel
        if tunnel_proc is not None and tunnel_proc.returncode is None:
            tunnel_proc.terminate()
            try:
                await asyncio.wait_for(tunnel_proc.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                tunnel_proc.kill()
                await tunnel_proc.wait()
            logger.info("SSH tunnel terminated")

        # 3b. Destroy cloud node (shielded from cancellation)
        if provider_id is not None:
            await _shielded_destroy(provider, provider_id)


async def _shielded_destroy(provider: CloudNodeProvider, provider_id: str) -> None:
    """Destroy a cloud node, shielded from asyncio.CancelledError.

    Pattern: create a concrete Task, shield it, and if CancelledError fires
    in our scope, await the task directly (it's still running unaffected).
    """
    destroy_task = asyncio.ensure_future(provider.destroy_node(provider_id))
    try:
        await asyncio.shield(destroy_task)
        logger.info("Node %s destroyed", provider_id)
    except asyncio.CancelledError:
        try:
            await destroy_task
            logger.info("Node %s destroyed (post-cancellation)", provider_id)
        except Exception:
            logger.exception("Failed to destroy node %s during cancellation", provider_id)
        raise
    except Exception:
        logger.exception("Failed to destroy node %s", provider_id)


async def _establish_tunnel(
    ip_address: str,
    ssh_key_path: str,
    local_port: int,
    max_retries: int = 5,
    retry_delay: float = 3.0,
) -> asyncio.subprocess.Process:
    """Start SSH dynamic SOCKS5 tunnel with retry for sshd startup race."""
    expanded_key = os.path.expanduser(ssh_key_path)

    for attempt in range(max_retries):
        proc = await asyncio.create_subprocess_exec(
            "ssh",
            "-D", str(local_port),
            "-N",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=10",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-o", "ExitOnForwardFailure=yes",
            "-i", expanded_key,
            f"root@{ip_address}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.sleep(2.0)
        if proc.returncode is None:
            return proc

        stderr = b""
        if proc.stderr:
            stderr = await proc.stderr.read()
        if attempt < max_retries - 1:
            logger.debug(
                "SSH attempt %d failed: %s — retrying",
                attempt + 1, stderr.decode(errors="replace").strip(),
            )
            await asyncio.sleep(retry_delay)
            continue

        raise ProvisioningError(
            f"SSH tunnel failed after {max_retries} attempts: {stderr.decode(errors='replace')}"
        )

    raise ProvisioningError("SSH tunnel failed: exhausted retries")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_infra_proxy.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/infra/proxy.py packages/cli/tests/test_scanner/test_infra_proxy.py
git commit -m "feat(infra): ephemeral_proxy context manager with shielded teardown"
```

---

### Task 8: ProxiedShellExecutor

**Files:**
- Create: `packages/cli/src/opentools/scanner/executor/proxied_shell.py`
- Modify: `packages/cli/src/opentools/scanner/executor/__init__.py`
- Test: `packages/cli/tests/test_scanner/test_executor_proxied_shell.py`

**Context:** Wraps the existing shell execution path. Tasks opt in to proxying via `task.isolation == TaskIsolation.NETWORK_ISOLATED`. Non-proxied tasks fall through to a plain `run_streaming` call identical to `ShellExecutor`.

- [ ] **Step 1: Write failing tests**

```python
# packages/cli/tests/test_scanner/test_executor_proxied_shell.py
"""Tests for ProxiedShellExecutor."""

import sys

import pytest

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.executor.proxied_shell import ProxiedShellExecutor
from opentools.scanner.infra.provider import CloudNodeProvider, ProvisioningError
from opentools.scanner.models import ScanTask, TaskIsolation, TaskType


class FakeProvider(CloudNodeProvider):
    def __init__(self):
        self.created = []
        self.destroyed = []
        self._poll_count = 0

    async def create_node(self, region, ssh_public_key, tags):
        self.created.append(region)
        return "fake-node"

    async def poll_status(self, provider_id):
        self._poll_count += 1
        return "active", "1.2.3.4"

    async def destroy_node(self, provider_id):
        self.destroyed.append(provider_id)


def _make_task(
    task_id: str = "t1",
    command: str = f"{sys.executable} -c \"print('hello')\"",
    isolation: TaskIsolation = TaskIsolation.NONE,
    tool: str = "nuclei",
) -> ScanTask:
    return ScanTask(
        id=task_id, scan_id="scan-1", name="test",
        tool=tool, task_type=TaskType.SHELL,
        command=command, isolation=isolation,
    )


class TestProxiedShellExecutor:
    @pytest.mark.asyncio
    async def test_non_proxied_task_runs_directly(self):
        """Tasks without NETWORK_ISOLATED run as plain subprocess."""
        executor = ProxiedShellExecutor(provider=None)
        task = _make_task(isolation=TaskIsolation.NONE)
        cancel = CancellationToken()
        result = await executor.execute(task, lambda _: None, cancel)
        assert result.exit_code == 0
        assert "hello" in result.stdout

    @pytest.mark.asyncio
    async def test_no_provider_falls_through(self):
        """NETWORK_ISOLATED task with no provider configured runs directly."""
        executor = ProxiedShellExecutor(provider=None)
        task = _make_task(isolation=TaskIsolation.NETWORK_ISOLATED)
        cancel = CancellationToken()
        result = await executor.execute(task, lambda _: None, cancel)
        assert result.exit_code == 0

    @pytest.mark.asyncio
    async def test_proxied_task_provisions_and_destroys(self):
        """NETWORK_ISOLATED task with provider triggers full lifecycle."""
        provider = FakeProvider()
        executor = ProxiedShellExecutor(
            provider=provider, ssh_key="k", ssh_key_path="/dev/null",
            _skip_tunnel=True,
        )
        task = _make_task(isolation=TaskIsolation.NETWORK_ISOLATED)
        cancel = CancellationToken()
        result = await executor.execute(task, lambda _: None, cancel)
        assert result.exit_code == 0
        assert len(provider.created) == 1
        assert len(provider.destroyed) == 1

    @pytest.mark.asyncio
    async def test_missing_command_raises(self):
        executor = ProxiedShellExecutor(provider=None)
        task = ScanTask(
            id="t1", scan_id="s1", name="no-cmd",
            tool="test", task_type=TaskType.SHELL,
        )
        cancel = CancellationToken()
        with pytest.raises(ValueError, match="no command"):
            await executor.execute(task, lambda _: None, cancel)

    @pytest.mark.asyncio
    async def test_socks_port_increments(self):
        """Each proxied task gets a unique SOCKS port."""
        executor = ProxiedShellExecutor(
            provider=FakeProvider(), ssh_key="k",
            base_socks_port=10800, _skip_tunnel=True,
        )
        assert executor._next_socks_port() == 10800
        assert executor._next_socks_port() == 10801
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_executor_proxied_shell.py::TestProxiedShellExecutor::test_non_proxied_task_runs_directly -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement ProxiedShellExecutor**

```python
# packages/cli/src/opentools/scanner/executor/proxied_shell.py
"""ProxiedShellExecutor — optionally routes tool traffic through ephemeral proxy."""

from __future__ import annotations

import shlex
from typing import Callable

from opentools.scanner.cancellation import CancellationToken
from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.infra.provider import CloudNodeProvider
from opentools.scanner.infra.proxy import ephemeral_proxy
from opentools.scanner.models import ScanTask, TaskIsolation
from opentools.shared.subprocess import run_streaming


class ProxiedShellExecutor:
    """Shell executor with optional ephemeral proxy routing.

    Tasks with ``isolation == TaskIsolation.NETWORK_ISOLATED`` are routed
    through an ephemeral SOCKS5 proxy.  All other tasks run as plain
    subprocesses, identical to ShellExecutor.
    """

    def __init__(
        self,
        provider: CloudNodeProvider | None,
        ssh_key: str = "",
        ssh_key_path: str = "~/.ssh/id_ed25519",
        default_timeout: int = 300,
        base_socks_port: int = 10800,
        _skip_tunnel: bool = False,
    ) -> None:
        self._provider = provider
        self._ssh_key = ssh_key
        self._ssh_key_path = ssh_key_path
        self._default_timeout = default_timeout
        self._base_socks_port = base_socks_port
        self._port_counter = 0
        self._skip_tunnel = _skip_tunnel

    def _next_socks_port(self) -> int:
        port = self._base_socks_port + self._port_counter
        self._port_counter += 1
        return port

    async def execute(
        self,
        task: ScanTask,
        on_output: Callable[[bytes], None],
        cancellation: CancellationToken,
    ) -> TaskOutput:
        if task.command is None:
            raise ValueError(f"Task {task.id} has no command")

        needs_proxy = (
            self._provider is not None
            and task.isolation == TaskIsolation.NETWORK_ISOLATED
        )

        if not needs_proxy:
            return await self._run_direct(task, on_output, cancellation)

        return await self._run_proxied(task, on_output, cancellation)

    async def _run_direct(
        self, task: ScanTask, on_output: Callable[[bytes], None],
        cancellation: CancellationToken,
    ) -> TaskOutput:
        args = shlex.split(task.command)
        result = await run_streaming(
            args=args, on_output=on_output,
            timeout=self._default_timeout, cancellation=cancellation,
        )
        return TaskOutput(
            exit_code=result.exit_code, stdout=result.stdout,
            stderr=result.stderr, duration_ms=result.duration_ms,
        )

    async def _run_proxied(
        self, task: ScanTask, on_output: Callable[[bytes], None],
        cancellation: CancellationToken,
    ) -> TaskOutput:
        socks_port = self._next_socks_port()

        async with ephemeral_proxy(
            provider=self._provider,
            region="nyc3",
            ssh_key=self._ssh_key,
            ssh_key_path=self._ssh_key_path,
            local_socks_port=socks_port,
            scan_id=task.scan_id,
            _skip_tunnel=self._skip_tunnel,
        ) as proxy:
            args = shlex.split(task.command)
            result = await run_streaming(
                args=args, on_output=on_output,
                timeout=self._default_timeout, cancellation=cancellation,
                env=proxy.env,
            )

        return TaskOutput(
            exit_code=result.exit_code, stdout=result.stdout,
            stderr=result.stderr, duration_ms=result.duration_ms,
        )
```

- [ ] **Step 4: Update executor __init__.py exports**

In `packages/cli/src/opentools/scanner/executor/__init__.py`, add:

```python
from opentools.scanner.executor.proxied_shell import ProxiedShellExecutor
```

And add `"ProxiedShellExecutor"` to the `__all__` list.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_executor_proxied_shell.py -v`
Expected: All PASS

- [ ] **Step 6: Run all executor tests for regression check**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_executor_shell.py tests/test_scanner/test_executor_docker.py -v`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add packages/cli/src/opentools/scanner/executor/proxied_shell.py packages/cli/src/opentools/scanner/executor/__init__.py packages/cli/tests/test_scanner/test_executor_proxied_shell.py
git commit -m "feat(executor): add ProxiedShellExecutor with ephemeral proxy routing"
```

---

### Task 9: Orphan Sweeper + Final Integration

**Files:**
- Create: `packages/cli/src/opentools/scanner/infra/sweeper.py`
- Test: `packages/cli/tests/test_scanner/test_infra_sweeper.py` (inline below)

- [ ] **Step 1: Write failing tests for sweep_orphaned_nodes**

```python
# packages/cli/tests/test_scanner/test_infra_sweeper.py
"""Tests for orphan node sweeper."""

import pytest

from opentools.scanner.infra.sweeper import sweep_orphaned_nodes


class FakeListableProvider:
    """Provider that also supports listing nodes by tag."""
    def __init__(self, orphan_ids: list[str]):
        self._orphan_ids = orphan_ids
        self.destroyed_ids: list[str] = []

    async def list_nodes_by_tag(self, tag: str) -> list[str]:
        return list(self._orphan_ids)

    async def destroy_node(self, provider_id: str) -> None:
        self.destroyed_ids.append(provider_id)


class TestSweepOrphanedNodes:
    @pytest.mark.asyncio
    async def test_destroys_orphans(self):
        provider = FakeListableProvider(orphan_ids=["orphan-1", "orphan-2"])
        count = await sweep_orphaned_nodes(provider)
        assert count == 2
        assert set(provider.destroyed_ids) == {"orphan-1", "orphan-2"}

    @pytest.mark.asyncio
    async def test_no_orphans(self):
        provider = FakeListableProvider(orphan_ids=[])
        count = await sweep_orphaned_nodes(provider)
        assert count == 0
        assert provider.destroyed_ids == []

    @pytest.mark.asyncio
    async def test_destroy_failure_continues(self):
        """One destroy failure should not stop cleanup of remaining nodes."""
        class PartialFailProvider(FakeListableProvider):
            async def destroy_node(self, provider_id):
                if provider_id == "orphan-1":
                    raise Exception("API error")
                self.destroyed_ids.append(provider_id)

        provider = PartialFailProvider(orphan_ids=["orphan-1", "orphan-2"])
        count = await sweep_orphaned_nodes(provider)
        # orphan-2 was destroyed, orphan-1 failed
        assert count == 1
        assert "orphan-2" in provider.destroyed_ids
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_infra_sweeper.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Implement sweep_orphaned_nodes**

```python
# packages/cli/src/opentools/scanner/infra/sweeper.py
"""Startup sweeper for orphaned ephemeral proxy nodes.

Call sweep_orphaned_nodes() during ScanEngine initialization to clean
up nodes from crashed previous runs. Uses the PROXY_TAG to identify
resources that belong to OpenTools.
"""

from __future__ import annotations

import logging

from opentools.scanner.infra.proxy import PROXY_TAG

logger = logging.getLogger(__name__)


async def sweep_orphaned_nodes(provider: object) -> int:
    """Destroy any nodes tagged with PROXY_TAG from previous runs.

    The provider must implement ``list_nodes_by_tag(tag) -> list[str]``
    and ``destroy_node(provider_id)``.

    Returns the number of nodes successfully destroyed.
    """
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_infra_sweeper.py -v`
Expected: All PASS

- [ ] **Step 5: Run the full test suite for both phases**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_mutation_models.py tests/test_scanner/test_mutation_analyzer.py tests/test_scanner/test_mutation_strategy.py tests/test_scanner/test_engine_mutation.py tests/test_scanner/test_engine.py tests/test_scanner/test_shared_subprocess.py tests/test_scanner/test_infra_provider.py tests/test_scanner/test_infra_proxy.py tests/test_scanner/test_executor_proxied_shell.py tests/test_scanner/test_infra_sweeper.py -v`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add packages/cli/src/opentools/scanner/infra/sweeper.py packages/cli/tests/test_scanner/test_infra_sweeper.py
git commit -m "feat(infra): add orphan node sweeper for startup cleanup"
```

---

## Appendix: Concurrency Safety Proof

The mutation layer introduces zero new concurrency hazards. Here is the execution trace through a single event loop turn:

```
await asyncio.wait(in_flight, FIRST_COMPLETED)          # ← yield point
│
├─ for completed_future in done:                         # synchronous
│   ├─ _mark_completed(task_id, output)                  # synchronous
│   │   ├─ analyzer.analyze(stdout, stderr)              # synchronous (XML/JSON parse)
│   │   ├─ kill_chain.ingest(bundle)                     # synchronous (dict mutation)
│   │   ├─ strategy.evaluate(state, scan_id, task)       # synchronous
│   │   ├─ _evaluate_edges(task, output)                 # synchronous (existing)
│   │   └─ _inject_tasks(new_tasks)                      # synchronous (dict mutation)
│   └─ (next completed_future)
│
├─ ready_tasks_by_priority()                             # sees injected tasks
├─ dispatch → asyncio.ensure_future(...)                 # schedules, no yield
└─ await asyncio.wait(...)                               # ← next yield point
```

No `await` between state mutation and the next readiness check. The asyncio event loop cannot context-switch during this chain.
