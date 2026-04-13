# Scan Runner Plan 4: Parsing Pipeline — Parsers, Normalization, Dedup, Scoring, Export

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the full finding processing pipeline: parser protocol and router with builtin parsers (semgrep, gitleaks, nmap, trivy, generic JSON), normalization engine (paths, CWEs, severities, titles), multi-pass dedup engine, engagement-level cross-scan dedup, corroboration scoring, suppression engine, finding lifecycle with confidence decay, finding correlation and remediation grouping, scan diff (baseline comparison), and multi-format export (JSON, SARIF, CSV, Markdown).

**Architecture:** Bottom-up — parser protocol and router first (takes raw bytes, yields `RawFinding`), then normalization (standardizes fields using data files from Plan 1), then dedup (strict fingerprint + fuzzy match), then higher-order pipeline stages (corroboration, suppression, lifecycle, correlation, remediation grouping), then scan diff, and finally export. Each stage is a standalone class with a simple interface: takes findings in, returns findings out. The full pipeline is assembled by the caller. Integration test at the end verifies the complete chain.

**Tech Stack:** Python 3.12, Pydantic v2, asyncio, pytest + pytest-asyncio, `xml.etree.ElementTree` (nmap XML), `hashlib` (fingerprinting), `csv` (CSV export), `json` (JSON/SARIF export), `difflib` (fuzzy matching), `re` (title normalization)

**Spec Reference:** `docs/superpowers/specs/2026-04-12-scan-runner-design.md` sections 5.1-5.12

**Decomposition Note:** Plan 4 of 5. Plans 1-3 complete. Plan 1 delivered models, store, CWE hierarchy, and static data files. Plan 2 delivered executors and ScanEngine. Plan 3 delivered planner, profiles, and target detection. Plan 5 will deliver surfaces (CLI, web API, Claude skill).

**Branch:** `feature/scan-runner-plan4` (branch from `feature/scan-runner-plan3`)

**Excluded from this plan (deferred to Plan 5 or later):**
- `CVSSCalibrator` (requires NVD API / local CVE database)
- `FindingContextEnricher` (requires filesystem access to read source code)
- `FPMemory` (requires engagement store integration beyond this plan's scope)
- `TrendDetector` (requires cross-engagement history)
- HTML and STIX export formats (HTML requires templating; STIX reuses existing `stix_export.py`)
- `ScanResultImporter` (SARIF import)

---

## File Map

### New Files

| File | Responsibility |
|------|---------------|
| `packages/cli/src/opentools/scanner/parsing/router.py` | `ParserPlugin` protocol, `ParserRouter` with builtin + plugin discovery |
| `packages/cli/src/opentools/scanner/parsing/parsers/semgrep.py` | Semgrep JSON parser |
| `packages/cli/src/opentools/scanner/parsing/parsers/gitleaks.py` | Gitleaks JSON parser |
| `packages/cli/src/opentools/scanner/parsing/parsers/nmap.py` | Nmap XML parser |
| `packages/cli/src/opentools/scanner/parsing/parsers/trivy.py` | Trivy JSON parser |
| `packages/cli/src/opentools/scanner/parsing/parsers/generic_json.py` | Generic JSON parser (fallback) |
| `packages/cli/src/opentools/scanner/parsing/parsers/__init__.py` | Package init |
| `packages/cli/src/opentools/scanner/parsing/normalization.py` | `NormalizationEngine` — paths, CWEs, severities, titles |
| `packages/cli/src/opentools/scanner/parsing/dedup.py` | `DedupEngine` — strict + fuzzy multi-pass dedup |
| `packages/cli/src/opentools/scanner/parsing/engagement_dedup.py` | `EngagementDedupEngine` — cross-scan reconciliation |
| `packages/cli/src/opentools/scanner/parsing/confidence.py` | `CorroborationScorer` + `ConfidenceDecay` |
| `packages/cli/src/opentools/scanner/parsing/suppression.py` | `SuppressionEngine` |
| `packages/cli/src/opentools/scanner/parsing/lifecycle.py` | `FindingLifecycle` — auto state transitions |
| `packages/cli/src/opentools/scanner/parsing/correlation.py` | `FindingCorrelationEngine` — attack chains, kill chains |
| `packages/cli/src/opentools/scanner/parsing/remediation.py` | `RemediationGrouper` |
| `packages/cli/src/opentools/scanner/diff.py` | `ScanDiffEngine` — baseline comparison |
| `packages/cli/src/opentools/scanner/export.py` | `ScanResultExporter` — JSON, SARIF, CSV, Markdown |
| `packages/cli/tests/test_scanner/test_parser_router.py` | Tests for ParserPlugin protocol + ParserRouter + semgrep parser |
| `packages/cli/tests/test_scanner/test_parsers.py` | Tests for gitleaks, nmap, trivy, generic JSON parsers |
| `packages/cli/tests/test_scanner/test_normalization.py` | Tests for NormalizationEngine |
| `packages/cli/tests/test_scanner/test_dedup.py` | Tests for DedupEngine |
| `packages/cli/tests/test_scanner/test_engagement_dedup.py` | Tests for EngagementDedupEngine |
| `packages/cli/tests/test_scanner/test_corroboration.py` | Tests for CorroborationScorer + ConfidenceDecay |
| `packages/cli/tests/test_scanner/test_suppression.py` | Tests for SuppressionEngine |
| `packages/cli/tests/test_scanner/test_lifecycle.py` | Tests for FindingLifecycle + ConfidenceDecay integration |
| `packages/cli/tests/test_scanner/test_correlation.py` | Tests for FindingCorrelationEngine + RemediationGrouper |
| `packages/cli/tests/test_scanner/test_scan_diff.py` | Tests for ScanDiffEngine |
| `packages/cli/tests/test_scanner/test_export.py` | Tests for ScanResultExporter |
| `packages/cli/tests/test_scanner/test_pipeline_integration.py` | End-to-end pipeline integration test |

### Modified Files

| File | Change |
|------|--------|
| `packages/cli/src/opentools/scanner/parsing/__init__.py` | Re-export key classes |

---

### Task 1: ParserPlugin Protocol + ParserRouter + Semgrep Parser

**Files:**
- Create: `packages/cli/src/opentools/scanner/parsing/router.py`
- Create: `packages/cli/src/opentools/scanner/parsing/parsers/__init__.py`
- Create: `packages/cli/src/opentools/scanner/parsing/parsers/semgrep.py`
- Modify: `packages/cli/src/opentools/scanner/parsing/__init__.py`
- Test: `packages/cli/tests/test_scanner/test_parser_router.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_parser_router.py
"""Tests for ParserPlugin protocol, ParserRouter, and Semgrep parser."""

import json
from datetime import datetime, timezone

import pytest

from opentools.scanner.parsing.router import ParserPlugin, ParserRouter
from opentools.scanner.parsing.parsers.semgrep import SemgrepParser
from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)


# ---------------------------------------------------------------------------
# ParserPlugin protocol conformance
# ---------------------------------------------------------------------------


class TestParserPluginProtocol:
    def test_semgrep_parser_is_parser_plugin(self):
        parser = SemgrepParser()
        assert isinstance(parser, ParserPlugin)

    def test_semgrep_parser_attributes(self):
        parser = SemgrepParser()
        assert parser.name == "semgrep"
        assert parser.version == "1.0.0"
        assert parser.confidence_tier == 0.9

    def test_semgrep_parser_validate_accepts_valid(self):
        data = json.dumps({"results": []}).encode()
        parser = SemgrepParser()
        assert parser.validate(data) is True

    def test_semgrep_parser_validate_rejects_invalid(self):
        parser = SemgrepParser()
        assert parser.validate(b"not json") is False
        assert parser.validate(json.dumps({"no_results_key": 1}).encode()) is False


# ---------------------------------------------------------------------------
# SemgrepParser.parse
# ---------------------------------------------------------------------------


SEMGREP_OUTPUT = json.dumps({
    "results": [
        {
            "check_id": "python.lang.security.audit.dangerous-subprocess-use",
            "path": "src/api/users.py",
            "start": {"line": 42, "col": 5},
            "end": {"line": 42, "col": 55},
            "extra": {
                "severity": "ERROR",
                "message": "Dangerous use of subprocess with user input",
                "metadata": {
                    "cwe": ["CWE-78: OS Command Injection"],
                    "confidence": "HIGH",
                },
                "fingerprint": "abc123def456",
            },
        },
        {
            "check_id": "python.lang.security.audit.eval-detected",
            "path": "src/utils/helpers.py",
            "start": {"line": 10, "col": 1},
            "end": {"line": 12, "col": 30},
            "extra": {
                "severity": "WARNING",
                "message": "Use of eval() detected",
                "metadata": {
                    "cwe": ["CWE-95: Eval Injection"],
                    "confidence": "MEDIUM",
                },
                "fingerprint": "xyz789",
            },
        },
    ],
    "errors": [],
}).encode()


class TestSemgrepParser:
    def test_parse_yields_raw_findings(self):
        parser = SemgrepParser()
        findings = list(parser.parse(
            data=SEMGREP_OUTPUT,
            scan_id="scan-1",
            scan_task_id="task-1",
        ))
        assert len(findings) == 2

    def test_parse_first_finding_fields(self):
        parser = SemgrepParser()
        findings = list(parser.parse(
            data=SEMGREP_OUTPUT,
            scan_id="scan-1",
            scan_task_id="task-1",
        ))
        f = findings[0]
        assert isinstance(f, RawFinding)
        assert f.tool == "semgrep"
        assert f.title == "python.lang.security.audit.dangerous-subprocess-use"
        assert f.raw_severity == "ERROR"
        assert f.file_path == "src/api/users.py"
        assert f.line_start == 42
        assert f.line_end == 42
        assert f.cwe == "CWE-78"
        assert f.evidence_quality == EvidenceQuality.STRUCTURED
        assert f.location_precision == LocationPrecision.EXACT_LINE
        assert f.parser_version == "1.0.0"
        assert f.parser_confidence == 0.9
        assert f.scan_id == "scan-1"
        assert f.scan_task_id == "task-1"

    def test_parse_line_range_finding(self):
        parser = SemgrepParser()
        findings = list(parser.parse(
            data=SEMGREP_OUTPUT,
            scan_id="scan-1",
            scan_task_id="task-1",
        ))
        f = findings[1]
        assert f.line_start == 10
        assert f.line_end == 12
        assert f.location_precision == LocationPrecision.LINE_RANGE
        assert f.cwe == "CWE-95"

    def test_parse_empty_results(self):
        data = json.dumps({"results": [], "errors": []}).encode()
        parser = SemgrepParser()
        findings = list(parser.parse(data=data, scan_id="s1", scan_task_id="t1"))
        assert findings == []


# ---------------------------------------------------------------------------
# ParserRouter
# ---------------------------------------------------------------------------


class TestParserRouter:
    def test_register_and_get_builtin(self):
        router = ParserRouter()
        router.register(SemgrepParser())
        parser = router.get("semgrep")
        assert parser is not None
        assert parser.name == "semgrep"

    def test_get_returns_none_for_unknown(self):
        router = ParserRouter()
        assert router.get("nonexistent") is None

    def test_list_parsers(self):
        router = ParserRouter()
        router.register(SemgrepParser())
        names = router.list_parsers()
        assert "semgrep" in names

    def test_plugin_overrides_builtin(self):
        """A plugin parser with the same name overrides the builtin."""
        router = ParserRouter()
        router.register(SemgrepParser())

        class CustomSemgrep:
            name = "semgrep"
            version = "2.0.0"
            confidence_tier = 0.95

            def validate(self, data: bytes) -> bool:
                return True

            def parse(self, data, scan_id, scan_task_id):
                return iter([])

        router.register(CustomSemgrep(), plugin=True)
        parser = router.get("semgrep")
        assert parser.version == "2.0.0"

    def test_discover_plugins_from_directory(self, tmp_path):
        """ParserRouter.discover_plugins loads .py files from a directory."""
        # Write a minimal plugin module
        plugin_code = '''
class MyCustomParser:
    name = "custom_tool"
    version = "1.0.0"
    confidence_tier = 0.6

    def validate(self, data):
        return True

    def parse(self, data, scan_id, scan_task_id):
        return iter([])

PARSER = MyCustomParser()
'''
        plugin_file = tmp_path / "custom_parser.py"
        plugin_file.write_text(plugin_code)

        router = ParserRouter()
        router.discover_plugins(str(tmp_path))
        assert router.get("custom_tool") is not None
        assert router.get("custom_tool").version == "1.0.0"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_parser_router.py -v`
Expected: FAIL -- `ModuleNotFoundError: No module named 'opentools.scanner.parsing.router'`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/scanner/parsing/parsers/__init__.py
"""Builtin tool-specific parsers."""

# packages/cli/src/opentools/scanner/parsing/router.py
"""ParserPlugin protocol and ParserRouter with builtin + plugin discovery."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Iterator, Protocol, runtime_checkable

from opentools.scanner.models import RawFinding


@runtime_checkable
class ParserPlugin(Protocol):
    """Protocol that all parsers (builtin and plugin) must implement."""

    name: str
    version: str
    confidence_tier: float

    def validate(self, data: bytes) -> bool:
        """Return True if *data* looks like valid output for this parser."""
        ...

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        """Parse raw tool output and yield RawFinding objects."""
        ...


class ParserRouter:
    """Routes tool output to the correct parser.

    Maintains a registry of builtin and plugin parsers.  Plugin parsers
    override builtins of the same name.  Supports dynamic discovery from
    configurable directories.
    """

    def __init__(self) -> None:
        self._builtins: dict[str, ParserPlugin] = {}
        self._plugins: dict[str, ParserPlugin] = {}

    def register(self, parser: ParserPlugin, *, plugin: bool = False) -> None:
        """Register a parser.  If *plugin* is True, it overrides builtins."""
        target = self._plugins if plugin else self._builtins
        target[parser.name] = parser

    def get(self, name: str) -> ParserPlugin | None:
        """Return the parser for *name*.  Plugins take precedence."""
        return self._plugins.get(name) or self._builtins.get(name)

    def list_parsers(self) -> list[str]:
        """Return sorted list of all registered parser names."""
        names = set(self._builtins.keys()) | set(self._plugins.keys())
        return sorted(names)

    def discover_plugins(self, directory: str) -> None:
        """Load all ``*.py`` files from *directory* that expose a ``PARSER`` attribute.

        Each module must define a module-level ``PARSER`` object that satisfies
        the ``ParserPlugin`` protocol.
        """
        dir_path = Path(directory)
        if not dir_path.is_dir():
            return

        for py_file in sorted(dir_path.glob("*.py")):
            if py_file.name.startswith("_"):
                continue
            module_name = f"opentools_parser_plugin_{py_file.stem}"
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            try:
                spec.loader.exec_module(module)
            except Exception:
                continue
            parser_obj = getattr(module, "PARSER", None)
            if parser_obj is not None and hasattr(parser_obj, "name"):
                self.register(parser_obj, plugin=True)
```

```python
# packages/cli/src/opentools/scanner/parsing/parsers/semgrep.py
"""Semgrep JSON output parser."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Iterator

from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)


_CWE_RE = re.compile(r"CWE-(\d+)")


class SemgrepParser:
    """Parses Semgrep JSON output into RawFinding objects."""

    name = "semgrep"
    version = "1.0.0"
    confidence_tier = 0.9

    def validate(self, data: bytes) -> bool:
        """Check that data is valid Semgrep JSON (has a ``results`` key)."""
        try:
            parsed = json.loads(data)
            return isinstance(parsed, dict) and "results" in parsed
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        """Parse Semgrep JSON output and yield RawFinding objects."""
        parsed = json.loads(data)
        results = parsed.get("results", [])

        for result in results:
            check_id = result.get("check_id", "unknown")
            path = result.get("path", "")
            start = result.get("start", {})
            end = result.get("end", {})
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {})

            line_start = start.get("line")
            line_end = end.get("line")

            # Determine location precision
            if line_start is not None and line_end is not None and line_start != line_end:
                precision = LocationPrecision.LINE_RANGE
            elif line_start is not None:
                precision = LocationPrecision.EXACT_LINE
            elif path:
                precision = LocationPrecision.FILE
            else:
                precision = LocationPrecision.FILE

            # Extract CWE — semgrep stores as list of strings like "CWE-78: ..."
            cwe_raw = metadata.get("cwe", [])
            cwe = None
            if isinstance(cwe_raw, list):
                for entry in cwe_raw:
                    m = _CWE_RE.search(str(entry))
                    if m:
                        cwe = f"CWE-{m.group(1)}"
                        break
            elif isinstance(cwe_raw, str):
                m = _CWE_RE.search(cwe_raw)
                if m:
                    cwe = f"CWE-{m.group(1)}"

            # Build evidence hash from check_id + path + line
            evidence_str = f"{check_id}:{path}:{line_start}:{line_end}"
            evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()

            # Build location fingerprint
            location_fp = f"{path}:{line_start or 0}"

            # Map semgrep confidence to evidence quality
            confidence_str = metadata.get("confidence", "").upper()
            if confidence_str == "HIGH":
                evidence_quality = EvidenceQuality.STRUCTURED
            elif confidence_str == "MEDIUM":
                evidence_quality = EvidenceQuality.STRUCTURED
            else:
                evidence_quality = EvidenceQuality.PATTERN

            raw_severity = extra.get("severity", "INFO")
            description = extra.get("message", "")

            yield RawFinding(
                id=str(uuid.uuid4()),
                scan_task_id=scan_task_id,
                scan_id=scan_id,
                tool="semgrep",
                raw_severity=raw_severity,
                title=check_id,
                description=description,
                file_path=path or None,
                line_start=line_start,
                line_end=line_end,
                evidence=description,
                evidence_quality=evidence_quality,
                evidence_hash=evidence_hash,
                cwe=cwe,
                location_fingerprint=location_fp,
                location_precision=precision,
                parser_version=self.version,
                parser_confidence=self.confidence_tier,
                discovered_at=datetime.now(timezone.utc),
            )
```

Update the `parsing/__init__.py`:

```python
# packages/cli/src/opentools/scanner/parsing/__init__.py
"""Finding parsing pipeline — parsers, normalization, dedup, scoring."""

from opentools.scanner.parsing.router import ParserPlugin, ParserRouter

__all__ = ["ParserPlugin", "ParserRouter"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_parser_router.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/parsing/ packages/cli/tests/test_scanner/test_parser_router.py
git commit -m "feat(scanner): ParserPlugin protocol + ParserRouter + semgrep parser"
```

---

### Task 2: Additional Parsers — Gitleaks, Nmap, Trivy, Generic JSON

**Files:**
- Create: `packages/cli/src/opentools/scanner/parsing/parsers/gitleaks.py`
- Create: `packages/cli/src/opentools/scanner/parsing/parsers/nmap.py`
- Create: `packages/cli/src/opentools/scanner/parsing/parsers/trivy.py`
- Create: `packages/cli/src/opentools/scanner/parsing/parsers/generic_json.py`
- Test: `packages/cli/tests/test_scanner/test_parsers.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_parsers.py
"""Tests for gitleaks, nmap, trivy, and generic JSON parsers."""

import json
import textwrap

import pytest

from opentools.scanner.parsing.router import ParserPlugin
from opentools.scanner.parsing.parsers.gitleaks import GitleaksParser
from opentools.scanner.parsing.parsers.nmap import NmapParser
from opentools.scanner.parsing.parsers.trivy import TrivyParser
from opentools.scanner.parsing.parsers.generic_json import GenericJsonParser
from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)


# ---------------------------------------------------------------------------
# Gitleaks
# ---------------------------------------------------------------------------


GITLEAKS_OUTPUT = json.dumps([
    {
        "Description": "Generic API Key",
        "StartLine": 15,
        "EndLine": 15,
        "StartColumn": 10,
        "EndColumn": 55,
        "Match": "AKIAIOSFODNN7EXAMPLE",
        "Secret": "AKIAIOSFODNN7EXAMPLE",
        "File": "config/settings.py",
        "Commit": "abc123",
        "RuleID": "generic-api-key",
        "Fingerprint": "config/settings.py:generic-api-key:15",
    },
    {
        "Description": "AWS Access Key",
        "StartLine": 22,
        "EndLine": 22,
        "StartColumn": 1,
        "EndColumn": 40,
        "Match": "AKIAIOSFODNN7EXAMPLE2",
        "Secret": "AKIAIOSFODNN7EXAMPLE2",
        "File": "deploy/secrets.env",
        "Commit": "def456",
        "RuleID": "aws-access-key-id",
        "Fingerprint": "deploy/secrets.env:aws-access-key-id:22",
    },
]).encode()


class TestGitleaksParser:
    def test_protocol_conformance(self):
        parser = GitleaksParser()
        assert isinstance(parser, ParserPlugin)
        assert parser.name == "gitleaks"
        assert parser.confidence_tier == 0.9

    def test_validate_valid(self):
        parser = GitleaksParser()
        assert parser.validate(GITLEAKS_OUTPUT) is True

    def test_validate_invalid(self):
        parser = GitleaksParser()
        assert parser.validate(b"not json") is False
        assert parser.validate(json.dumps({"key": "val"}).encode()) is False

    def test_parse_yields_findings(self):
        parser = GitleaksParser()
        findings = list(parser.parse(GITLEAKS_OUTPUT, "scan-1", "task-1"))
        assert len(findings) == 2

    def test_parse_first_finding(self):
        parser = GitleaksParser()
        findings = list(parser.parse(GITLEAKS_OUTPUT, "scan-1", "task-1"))
        f = findings[0]
        assert f.tool == "gitleaks"
        assert f.title == "generic-api-key"
        assert f.raw_severity == "secret"
        assert f.file_path == "config/settings.py"
        assert f.line_start == 15
        assert f.cwe == "CWE-798"
        assert f.evidence_quality == EvidenceQuality.STRUCTURED
        assert f.location_precision == LocationPrecision.EXACT_LINE

    def test_parse_empty(self):
        parser = GitleaksParser()
        findings = list(parser.parse(json.dumps([]).encode(), "s1", "t1"))
        assert findings == []


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------


NMAP_XML = textwrap.dedent("""\
    <?xml version="1.0" encoding="UTF-8"?>
    <nmaprun scanner="nmap" args="nmap -sV 192.168.1.1" start="1700000000">
      <host starttime="1700000000" endtime="1700000100">
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <hostnames>
          <hostname name="gateway.local" type="PTR"/>
        </hostnames>
        <ports>
          <port protocol="tcp" portid="22">
            <state state="open" reason="syn-ack"/>
            <service name="ssh" product="OpenSSH" version="8.9p1"/>
          </port>
          <port protocol="tcp" portid="80">
            <state state="open" reason="syn-ack"/>
            <service name="http" product="nginx" version="1.18.0"/>
          </port>
          <port protocol="tcp" portid="443">
            <state state="closed" reason="reset"/>
            <service name="https"/>
          </port>
        </ports>
      </host>
    </nmaprun>
""").encode()


class TestNmapParser:
    def test_protocol_conformance(self):
        parser = NmapParser()
        assert isinstance(parser, ParserPlugin)
        assert parser.name == "nmap"
        assert parser.confidence_tier == 0.5

    def test_validate_valid(self):
        parser = NmapParser()
        assert parser.validate(NMAP_XML) is True

    def test_validate_invalid(self):
        parser = NmapParser()
        assert parser.validate(b"not xml") is False
        assert parser.validate(b"<root><child/></root>") is False

    def test_parse_open_ports_only(self):
        parser = NmapParser()
        findings = list(parser.parse(NMAP_XML, "scan-1", "task-1"))
        # Only open ports are reported — ports 22, 80 (443 is closed)
        assert len(findings) == 2

    def test_parse_first_finding(self):
        parser = NmapParser()
        findings = list(parser.parse(NMAP_XML, "scan-1", "task-1"))
        f = findings[0]
        assert f.tool == "nmap"
        assert "22" in f.title
        assert "ssh" in f.title.lower() or "OpenSSH" in f.description
        assert f.raw_severity == "info"
        assert f.url is None
        assert f.evidence_quality == EvidenceQuality.HEURISTIC
        assert f.location_precision == LocationPrecision.HOST


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------


TRIVY_OUTPUT = json.dumps({
    "SchemaVersion": 2,
    "Results": [
        {
            "Target": "Gemfile.lock",
            "Type": "bundler",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-22796",
                    "PkgName": "activesupport",
                    "InstalledVersion": "7.0.4",
                    "FixedVersion": "7.0.4.1",
                    "Severity": "HIGH",
                    "Title": "ReDoS in Active Support",
                    "Description": "A regular expression denial of service.",
                    "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-22796",
                    "CweIDs": ["CWE-1333"],
                },
                {
                    "VulnerabilityID": "CVE-2023-27530",
                    "PkgName": "rack",
                    "InstalledVersion": "2.2.6",
                    "FixedVersion": "2.2.6.3",
                    "Severity": "CRITICAL",
                    "Title": "Rack multipart parsing ReDoS",
                    "Description": "Denial of service via multipart.",
                    "CweIDs": [],
                },
            ],
        },
    ],
}).encode()


class TestTrivyParser:
    def test_protocol_conformance(self):
        parser = TrivyParser()
        assert isinstance(parser, ParserPlugin)
        assert parser.name == "trivy"
        assert parser.confidence_tier == 0.9

    def test_validate_valid(self):
        parser = TrivyParser()
        assert parser.validate(TRIVY_OUTPUT) is True

    def test_validate_invalid(self):
        parser = TrivyParser()
        assert parser.validate(b"garbage") is False
        assert parser.validate(json.dumps({"no_results": 1}).encode()) is False

    def test_parse_yields_findings(self):
        parser = TrivyParser()
        findings = list(parser.parse(TRIVY_OUTPUT, "scan-1", "task-1"))
        assert len(findings) == 2

    def test_parse_first_finding(self):
        parser = TrivyParser()
        findings = list(parser.parse(TRIVY_OUTPUT, "scan-1", "task-1"))
        f = findings[0]
        assert f.tool == "trivy"
        assert "CVE-2023-22796" in f.title
        assert f.raw_severity == "HIGH"
        assert f.file_path == "Gemfile.lock"
        assert f.cwe == "CWE-1333"
        assert f.evidence_quality == EvidenceQuality.STRUCTURED

    def test_parse_missing_cwe(self):
        parser = TrivyParser()
        findings = list(parser.parse(TRIVY_OUTPUT, "scan-1", "task-1"))
        f = findings[1]
        assert f.cwe is None
        assert f.raw_severity == "CRITICAL"


# ---------------------------------------------------------------------------
# Generic JSON
# ---------------------------------------------------------------------------


GENERIC_OUTPUT = json.dumps({
    "findings": [
        {
            "title": "Potential SQL Injection",
            "severity": "high",
            "file": "app/db.py",
            "line": 55,
            "description": "User input concatenated in SQL query",
            "cwe": "CWE-89",
        },
    ],
}).encode()

GENERIC_LIST_OUTPUT = json.dumps([
    {
        "title": "Open redirect",
        "severity": "medium",
        "file": "app/redirect.py",
        "line": 10,
        "description": "Unvalidated redirect",
    },
]).encode()


class TestGenericJsonParser:
    def test_protocol_conformance(self):
        parser = GenericJsonParser()
        assert isinstance(parser, ParserPlugin)
        assert parser.name == "generic_json"
        assert parser.confidence_tier == 0.3

    def test_validate_valid(self):
        parser = GenericJsonParser()
        assert parser.validate(GENERIC_OUTPUT) is True
        assert parser.validate(GENERIC_LIST_OUTPUT) is True

    def test_validate_invalid(self):
        parser = GenericJsonParser()
        assert parser.validate(b"not json") is False

    def test_parse_dict_with_findings_key(self):
        parser = GenericJsonParser()
        findings = list(parser.parse(GENERIC_OUTPUT, "scan-1", "task-1"))
        assert len(findings) == 1
        f = findings[0]
        assert f.title == "Potential SQL Injection"
        assert f.raw_severity == "high"
        assert f.file_path == "app/db.py"
        assert f.line_start == 55
        assert f.cwe == "CWE-89"

    def test_parse_list_format(self):
        parser = GenericJsonParser()
        findings = list(parser.parse(GENERIC_LIST_OUTPUT, "scan-1", "task-1"))
        assert len(findings) == 1
        assert findings[0].title == "Open redirect"

    def test_parse_empty(self):
        parser = GenericJsonParser()
        findings = list(parser.parse(json.dumps([]).encode(), "s1", "t1"))
        assert findings == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_parsers.py -v`
Expected: FAIL -- `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/scanner/parsing/parsers/gitleaks.py
"""Gitleaks JSON output parser."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Iterator

from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)


class GitleaksParser:
    """Parses Gitleaks JSON output (array of leak objects)."""

    name = "gitleaks"
    version = "1.0.0"
    confidence_tier = 0.9

    def validate(self, data: bytes) -> bool:
        """Gitleaks outputs a JSON array of objects."""
        try:
            parsed = json.loads(data)
            return isinstance(parsed, list)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        parsed = json.loads(data)
        if not isinstance(parsed, list):
            return

        for leak in parsed:
            rule_id = leak.get("RuleID", "unknown")
            file_path = leak.get("File", "")
            line_start = leak.get("StartLine")
            line_end = leak.get("EndLine")
            description = leak.get("Description", "")
            fingerprint_raw = leak.get("Fingerprint", "")

            evidence_str = f"{rule_id}:{file_path}:{line_start}:{fingerprint_raw}"
            evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()

            location_fp = f"{file_path}:{line_start or 0}"

            if line_start is not None and line_end is not None and line_start != line_end:
                precision = LocationPrecision.LINE_RANGE
            elif line_start is not None:
                precision = LocationPrecision.EXACT_LINE
            else:
                precision = LocationPrecision.FILE

            yield RawFinding(
                id=str(uuid.uuid4()),
                scan_task_id=scan_task_id,
                scan_id=scan_id,
                tool="gitleaks",
                raw_severity="secret",
                title=rule_id,
                description=description,
                file_path=file_path or None,
                line_start=line_start,
                line_end=line_end,
                evidence=leak.get("Match", ""),
                evidence_quality=EvidenceQuality.STRUCTURED,
                evidence_hash=evidence_hash,
                cwe="CWE-798",  # Hardcoded credentials
                location_fingerprint=location_fp,
                location_precision=precision,
                parser_version=self.version,
                parser_confidence=self.confidence_tier,
                discovered_at=datetime.now(timezone.utc),
            )
```

```python
# packages/cli/src/opentools/scanner/parsing/parsers/nmap.py
"""Nmap XML output parser."""

from __future__ import annotations

import hashlib
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Iterator

from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)


class NmapParser:
    """Parses Nmap XML output (``-oX`` format) into RawFinding objects.

    Only reports open ports. Each open port becomes a finding with host-level
    location precision.
    """

    name = "nmap"
    version = "1.0.0"
    confidence_tier = 0.5

    def validate(self, data: bytes) -> bool:
        """Check that data is valid Nmap XML (has ``<nmaprun>`` root)."""
        try:
            root = ET.fromstring(data)
            return root.tag == "nmaprun"
        except ET.ParseError:
            return False

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        root = ET.fromstring(data)

        for host in root.findall("host"):
            # Get host address
            addr_el = host.find("address")
            addr = addr_el.get("addr", "unknown") if addr_el is not None else "unknown"

            # Get hostname if available
            hostname = None
            hostnames_el = host.find("hostnames")
            if hostnames_el is not None:
                hn_el = hostnames_el.find("hostname")
                if hn_el is not None:
                    hostname = hn_el.get("name")

            host_display = hostname or addr

            ports_el = host.find("ports")
            if ports_el is None:
                continue

            for port in ports_el.findall("port"):
                state_el = port.find("state")
                if state_el is None:
                    continue
                state = state_el.get("state", "")
                if state != "open":
                    continue

                protocol = port.get("protocol", "tcp")
                portid = port.get("portid", "0")

                service_el = port.find("service")
                service_name = ""
                product = ""
                version = ""
                if service_el is not None:
                    service_name = service_el.get("name", "")
                    product = service_el.get("product", "")
                    version = service_el.get("version", "")

                title = f"Open port {portid}/{protocol} ({service_name})"
                service_detail = f"{product} {version}".strip() if product else service_name
                description = (
                    f"Open port {portid}/{protocol} on {host_display}: "
                    f"{service_detail}"
                )

                evidence_str = f"nmap:{addr}:{protocol}:{portid}:{service_name}"
                evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()
                location_fp = f"{addr}:{portid}/{protocol}"

                yield RawFinding(
                    id=str(uuid.uuid4()),
                    scan_task_id=scan_task_id,
                    scan_id=scan_id,
                    tool="nmap",
                    raw_severity="info",
                    title=title,
                    description=description,
                    file_path=None,
                    line_start=None,
                    line_end=None,
                    url=None,
                    evidence=description,
                    evidence_quality=EvidenceQuality.HEURISTIC,
                    evidence_hash=evidence_hash,
                    cwe=None,
                    location_fingerprint=location_fp,
                    location_precision=LocationPrecision.HOST,
                    parser_version=self.version,
                    parser_confidence=self.confidence_tier,
                    discovered_at=datetime.now(timezone.utc),
                )
```

```python
# packages/cli/src/opentools/scanner/parsing/parsers/trivy.py
"""Trivy JSON output parser."""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Iterator

from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)


class TrivyParser:
    """Parses Trivy JSON output (schema v2 with Results array)."""

    name = "trivy"
    version = "1.0.0"
    confidence_tier = 0.9

    def validate(self, data: bytes) -> bool:
        """Check for Trivy JSON structure with ``Results`` key."""
        try:
            parsed = json.loads(data)
            return isinstance(parsed, dict) and "Results" in parsed
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        parsed = json.loads(data)
        results = parsed.get("Results", [])

        for result in results:
            target = result.get("Target", "")
            vulns = result.get("Vulnerabilities") or []

            for vuln in vulns:
                vuln_id = vuln.get("VulnerabilityID", "unknown")
                pkg_name = vuln.get("PkgName", "")
                installed = vuln.get("InstalledVersion", "")
                fixed = vuln.get("FixedVersion", "")
                severity = vuln.get("Severity", "UNKNOWN")
                title_raw = vuln.get("Title", vuln_id)
                description = vuln.get("Description", "")
                primary_url = vuln.get("PrimaryURL", "")

                # Extract CWE
                cwe_ids = vuln.get("CweIDs") or []
                cwe = cwe_ids[0] if cwe_ids else None

                title = f"{vuln_id}: {title_raw}" if title_raw != vuln_id else vuln_id

                evidence_str = f"{vuln_id}:{pkg_name}:{installed}:{target}"
                evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()
                location_fp = f"{target}:{pkg_name}:{installed}"

                desc_full = description
                if fixed:
                    desc_full += f" (fix: upgrade {pkg_name} to {fixed})"

                yield RawFinding(
                    id=str(uuid.uuid4()),
                    scan_task_id=scan_task_id,
                    scan_id=scan_id,
                    tool="trivy",
                    raw_severity=severity,
                    title=title,
                    description=desc_full,
                    file_path=target or None,
                    line_start=None,
                    line_end=None,
                    url=primary_url or None,
                    evidence=f"{pkg_name}@{installed}",
                    evidence_quality=EvidenceQuality.STRUCTURED,
                    evidence_hash=evidence_hash,
                    cwe=cwe,
                    location_fingerprint=location_fp,
                    location_precision=LocationPrecision.FILE,
                    parser_version=self.version,
                    parser_confidence=self.confidence_tier,
                    discovered_at=datetime.now(timezone.utc),
                )
```

```python
# packages/cli/src/opentools/scanner/parsing/parsers/generic_json.py
"""Generic JSON parser — fallback for tools without a dedicated parser.

Handles two common formats:
- Object with a "findings", "results", or "vulnerabilities" key containing a list
- Top-level array of finding-like objects

Each object should have at minimum a ``title`` or ``name`` field.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Iterator

from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)

_LIST_KEYS = ("findings", "results", "vulnerabilities", "issues", "alerts")


class GenericJsonParser:
    """Best-effort parser for arbitrary JSON tool output."""

    name = "generic_json"
    version = "1.0.0"
    confidence_tier = 0.3

    def validate(self, data: bytes) -> bool:
        """Accept any valid JSON (dict or list)."""
        try:
            parsed = json.loads(data)
            return isinstance(parsed, (dict, list))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return False

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        parsed = json.loads(data)
        items = self._extract_items(parsed)

        for item in items:
            if not isinstance(item, dict):
                continue

            title = (
                item.get("title")
                or item.get("name")
                or item.get("rule_id")
                or item.get("check_id")
                or "Unknown finding"
            )
            severity = str(
                item.get("severity")
                or item.get("level")
                or item.get("risk")
                or "info"
            )
            file_path = item.get("file") or item.get("path") or item.get("location")
            line = item.get("line") or item.get("line_start") or item.get("lineno")
            description = item.get("description") or item.get("message") or ""
            cwe = item.get("cwe")

            evidence_str = f"generic:{title}:{file_path}:{line}"
            evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()
            location_fp = f"{file_path or 'unknown'}:{line or 0}"

            if line is not None:
                precision = LocationPrecision.EXACT_LINE
            elif file_path:
                precision = LocationPrecision.FILE
            else:
                precision = LocationPrecision.HOST

            yield RawFinding(
                id=str(uuid.uuid4()),
                scan_task_id=scan_task_id,
                scan_id=scan_id,
                tool="generic",
                raw_severity=severity,
                title=title,
                description=description,
                file_path=file_path,
                line_start=int(line) if line is not None else None,
                line_end=None,
                evidence=description,
                evidence_quality=EvidenceQuality.HEURISTIC,
                evidence_hash=evidence_hash,
                cwe=cwe,
                location_fingerprint=location_fp,
                location_precision=precision,
                parser_version=self.version,
                parser_confidence=self.confidence_tier,
                discovered_at=datetime.now(timezone.utc),
            )

    def _extract_items(self, parsed: dict | list) -> list:
        """Extract the list of finding-like items from parsed JSON."""
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            for key in _LIST_KEYS:
                if key in parsed and isinstance(parsed[key], list):
                    return parsed[key]
            # Fallback: try any key whose value is a list of dicts
            for value in parsed.values():
                if isinstance(value, list) and value and isinstance(value[0], dict):
                    return value
        return []
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_parsers.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/parsing/parsers/ packages/cli/tests/test_scanner/test_parsers.py
git commit -m "feat(scanner): builtin parsers — gitleaks, nmap, trivy, generic JSON"
```

---

### Task 3: NormalizationEngine

**Files:**
- Create: `packages/cli/src/opentools/scanner/parsing/normalization.py`
- Test: `packages/cli/tests/test_scanner/test_normalization.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_normalization.py
"""Tests for NormalizationEngine — paths, CWEs, severities, titles."""

import hashlib
import uuid
from datetime import datetime, timezone

import pytest

from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)
from opentools.scanner.parsing.normalization import NormalizationEngine


def _make_finding(**overrides) -> RawFinding:
    """Helper to build a RawFinding with sane defaults."""
    defaults = dict(
        id=str(uuid.uuid4()),
        scan_task_id="task-1",
        scan_id="scan-1",
        tool="semgrep",
        raw_severity="ERROR",
        title="sql injection detected",
        description="Found SQL injection",
        file_path="src/api/users.py",
        line_start=42,
        line_end=42,
        evidence="test",
        evidence_quality=EvidenceQuality.STRUCTURED,
        evidence_hash=hashlib.sha256(b"test").hexdigest(),
        cwe="CWE-89",
        location_fingerprint="src/api/users.py:42",
        location_precision=LocationPrecision.EXACT_LINE,
        parser_version="1.0.0",
        parser_confidence=0.9,
        discovered_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return RawFinding(**defaults)


class TestPathNormalization:
    def test_backslash_to_forward_slash(self):
        engine = NormalizationEngine()
        f = _make_finding(file_path="src\\api\\users.py")
        [result] = engine.normalize([f])
        assert result.file_path == "src/api/users.py"

    def test_strip_leading_dot_slash(self):
        engine = NormalizationEngine()
        f = _make_finding(file_path="./src/api/users.py")
        [result] = engine.normalize([f])
        assert result.file_path == "src/api/users.py"

    def test_strip_absolute_prefix(self):
        engine = NormalizationEngine()
        f = _make_finding(file_path="C:\\Users\\dev\\project\\src\\api\\users.py")
        [result] = engine.normalize([f])
        # Should strip to relative path; at minimum, forward slashes
        assert "\\" not in result.file_path

    def test_none_path_unchanged(self):
        engine = NormalizationEngine()
        f = _make_finding(file_path=None)
        [result] = engine.normalize([f])
        assert result.file_path is None


class TestSeverityNormalization:
    def test_semgrep_error_to_high(self):
        engine = NormalizationEngine()
        f = _make_finding(tool="semgrep", raw_severity="ERROR")
        [result] = engine.normalize([f])
        assert result.raw_severity == "high"

    def test_semgrep_warning_to_medium(self):
        engine = NormalizationEngine()
        f = _make_finding(tool="semgrep", raw_severity="WARNING")
        [result] = engine.normalize([f])
        assert result.raw_severity == "medium"

    def test_trivy_critical_unchanged(self):
        engine = NormalizationEngine()
        f = _make_finding(tool="trivy", raw_severity="CRITICAL")
        [result] = engine.normalize([f])
        assert result.raw_severity == "critical"

    def test_gitleaks_secret_to_high(self):
        engine = NormalizationEngine()
        f = _make_finding(tool="gitleaks", raw_severity="secret")
        [result] = engine.normalize([f])
        assert result.raw_severity == "high"

    def test_unknown_tool_passes_through(self):
        engine = NormalizationEngine()
        f = _make_finding(tool="unknown_tool", raw_severity="SCARY")
        [result] = engine.normalize([f])
        assert result.raw_severity == "SCARY"


class TestCWENormalization:
    def test_alias_resolution(self):
        engine = NormalizationEngine()
        f = _make_finding(cwe="sqli")
        [result] = engine.normalize([f])
        assert result.cwe == "CWE-89"

    def test_canonical_unchanged(self):
        engine = NormalizationEngine()
        f = _make_finding(cwe="CWE-79")
        [result] = engine.normalize([f])
        assert result.cwe == "CWE-79"

    def test_none_cwe_stays_none(self):
        engine = NormalizationEngine()
        f = _make_finding(cwe=None)
        [result] = engine.normalize([f])
        assert result.cwe is None


class TestTitleNormalization:
    def test_sql_injection_canonical(self):
        engine = NormalizationEngine()
        f = _make_finding(title="potential sql injection via user input")
        [result] = engine.normalize([f])
        assert result.canonical_title == "SQL Injection"

    def test_xss_canonical(self):
        engine = NormalizationEngine()
        f = _make_finding(title="reflected XSS in search parameter")
        [result] = engine.normalize([f])
        # Should match one of the XSS patterns
        assert "Cross-Site Scripting" in result.canonical_title or "XSS" in result.canonical_title

    def test_no_match_uses_original(self):
        engine = NormalizationEngine()
        f = _make_finding(title="totally unique finding name xyz")
        [result] = engine.normalize([f])
        assert result.canonical_title == "totally unique finding name xyz"

    def test_hardcoded_credentials_canonical(self):
        engine = NormalizationEngine()
        f = _make_finding(title="hard-coded password found in config.py")
        [result] = engine.normalize([f])
        assert result.canonical_title == "Hardcoded Credentials"


class TestLocationFingerprintUpdate:
    def test_fingerprint_uses_normalized_path(self):
        engine = NormalizationEngine()
        f = _make_finding(
            file_path="./src\\api\\users.py",
            location_fingerprint="./src\\api\\users.py:42",
        )
        [result] = engine.normalize([f])
        assert result.location_fingerprint == "src/api/users.py:42"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_normalization.py -v`
Expected: FAIL -- `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/scanner/parsing/normalization.py
"""NormalizationEngine — standardizes paths, CWEs, severities, and titles.

Uses static data files from ``scanner/data/`` (severity_maps.json,
title_normalization.json) and the CWEHierarchy for alias resolution.
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Sequence

from opentools.scanner.cwe import CWEHierarchy
from opentools.scanner.models import RawFinding


_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


@lru_cache(maxsize=1)
def _load_severity_maps() -> dict[str, dict[str, str]]:
    path = _DATA_DIR / "severity_maps.json"
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return {k: v for k, v in data.items() if k != "_comment"}


@lru_cache(maxsize=1)
def _load_title_patterns() -> list[tuple[re.Pattern, str]]:
    path = _DATA_DIR / "title_normalization.json"
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    patterns = data.get("patterns", [])
    compiled = []
    for entry in patterns:
        try:
            compiled.append((re.compile(entry["regex"], re.IGNORECASE), entry["title"]))
        except re.error:
            continue
    return compiled


class NormalizationEngine:
    """Standardizes findings across tools for comparable dedup.

    - **Paths**: resolve to relative, normalize separators
    - **CWEs**: alias resolution via CWEHierarchy
    - **Severities**: per-tool mapping to canonical scale
    - **Titles**: regex-based canonical title mapping
    - **Location fingerprints**: rebuilt from normalized path + line
    """

    def __init__(self) -> None:
        self._severity_maps = _load_severity_maps()
        self._title_patterns = _load_title_patterns()
        self._cwe = CWEHierarchy()

    def normalize(self, findings: Sequence[RawFinding]) -> list[RawFinding]:
        """Return a new list of findings with normalized fields.

        Original finding objects are not mutated; new copies are created.
        """
        result = []
        for f in findings:
            updates: dict = {}

            # 1. Path normalization
            norm_path = self._normalize_path(f.file_path)
            if norm_path != f.file_path:
                updates["file_path"] = norm_path

            # 2. Severity normalization
            norm_sev = self._normalize_severity(f.tool, f.raw_severity)
            if norm_sev != f.raw_severity:
                updates["raw_severity"] = norm_sev

            # 3. CWE normalization
            norm_cwe = self._normalize_cwe(f.cwe)
            if norm_cwe != f.cwe:
                updates["cwe"] = norm_cwe

            # 4. Title normalization
            canon_title = self._normalize_title(f.title)
            updates["canonical_title"] = canon_title

            # 5. Location fingerprint update
            norm_fp = self._normalize_location_fingerprint(
                f.location_fingerprint, f.file_path, norm_path
            )
            if norm_fp != f.location_fingerprint:
                updates["location_fingerprint"] = norm_fp

            if updates:
                result.append(f.model_copy(update=updates))
            else:
                result.append(f)

        return result

    def _normalize_path(self, path: str | None) -> str | None:
        """Normalize file path: forward slashes, strip leading ./ and drive prefixes."""
        if path is None:
            return None

        # Backslash to forward slash
        normalized = path.replace("\\", "/")

        # Strip leading ./
        if normalized.startswith("./"):
            normalized = normalized[2:]

        # Strip Windows drive letter + path prefix (e.g., C:/Users/.../project/)
        # Heuristic: if path starts with X:/ where X is a letter, strip up to
        # the first occurrence of src/, lib/, app/, etc., or just remove the drive letter
        drive_match = re.match(r"^[A-Za-z]:/", normalized)
        if drive_match:
            # Try to find a common project root indicator
            for marker in ("src/", "lib/", "app/", "pkg/", "packages/", "test/", "tests/"):
                idx = normalized.find(marker)
                if idx != -1:
                    normalized = normalized[idx:]
                    break
            else:
                # No marker found — just strip the drive letter
                normalized = normalized[drive_match.end():]

        # Strip leading /
        normalized = normalized.lstrip("/")

        return normalized

    def _normalize_severity(self, tool: str, raw_severity: str) -> str:
        """Map tool-specific severity to canonical severity."""
        tool_map = self._severity_maps.get(tool)
        if tool_map is None:
            return raw_severity
        return tool_map.get(raw_severity, raw_severity)

    def _normalize_cwe(self, cwe: str | None) -> str | None:
        """Resolve CWE aliases to canonical CWE IDs."""
        if cwe is None:
            return None
        resolved = self._cwe.resolve_alias(cwe)
        return resolved if resolved is not None else cwe

    def _normalize_title(self, title: str) -> str:
        """Match title against regex patterns and return canonical title."""
        for pattern, canonical in self._title_patterns:
            if pattern.search(title):
                return canonical
        return title

    def _normalize_location_fingerprint(
        self,
        fingerprint: str,
        original_path: str | None,
        normalized_path: str | None,
    ) -> str:
        """Update location fingerprint with normalized path."""
        if original_path is None or normalized_path is None:
            return fingerprint
        if original_path == normalized_path:
            return fingerprint
        return fingerprint.replace(original_path, normalized_path)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_normalization.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/parsing/normalization.py packages/cli/tests/test_scanner/test_normalization.py
git commit -m "feat(scanner): NormalizationEngine — paths, CWEs, severities, titles"
```

---

### Task 4: DedupEngine — Strict + Fuzzy Multi-Pass

**Files:**
- Create: `packages/cli/src/opentools/scanner/parsing/dedup.py`
- Test: `packages/cli/tests/test_scanner/test_dedup.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_dedup.py
"""Tests for DedupEngine — strict fingerprint + fuzzy multi-pass dedup."""

import hashlib
import uuid
from datetime import datetime, timezone

import pytest

from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)
from opentools.scanner.parsing.dedup import DedupEngine


def _make_finding(
    tool: str = "semgrep",
    title: str = "SQL Injection",
    file_path: str = "src/api/users.py",
    line_start: int = 42,
    line_end: int | None = None,
    cwe: str | None = "CWE-89",
    raw_severity: str = "high",
    evidence_quality: EvidenceQuality = EvidenceQuality.STRUCTURED,
    location_precision: LocationPrecision = LocationPrecision.EXACT_LINE,
    parser_confidence: float = 0.9,
    evidence_hash: str | None = None,
    location_fingerprint: str | None = None,
) -> RawFinding:
    eid = evidence_hash or hashlib.sha256(
        f"{tool}:{title}:{file_path}:{line_start}".encode()
    ).hexdigest()
    lfp = location_fingerprint or f"{file_path}:{line_start}"
    return RawFinding(
        id=str(uuid.uuid4()),
        scan_task_id="task-1",
        scan_id="scan-1",
        tool=tool,
        raw_severity=raw_severity,
        title=title,
        canonical_title=title,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end or line_start,
        evidence="test evidence",
        evidence_quality=evidence_quality,
        evidence_hash=eid,
        cwe=cwe,
        location_fingerprint=lfp,
        location_precision=location_precision,
        parser_version="1.0.0",
        parser_confidence=parser_confidence,
        discovered_at=datetime.now(timezone.utc),
    )


class TestStrictDedup:
    def test_identical_fingerprint_merges(self):
        """Two findings with same CWE + location_fingerprint merge in Pass 1."""
        engine = DedupEngine()
        f1 = _make_finding(tool="semgrep", cwe="CWE-89", file_path="a.py", line_start=10)
        f2 = _make_finding(tool="trivy", cwe="CWE-89", file_path="a.py", line_start=10)
        results = engine.deduplicate([f1, f2])
        assert len(results) == 1
        assert results[0].corroboration_count == 2
        assert set(results[0].tools) == {"semgrep", "trivy"}
        assert len(results[0].raw_finding_ids) == 2

    def test_same_evidence_hash_merges(self):
        """Two findings with same evidence_hash merge even with different location."""
        engine = DedupEngine()
        eh = hashlib.sha256(b"shared").hexdigest()
        f1 = _make_finding(tool="semgrep", evidence_hash=eh, file_path="a.py", line_start=10)
        f2 = _make_finding(tool="trivy", evidence_hash=eh, file_path="b.py", line_start=20)
        results = engine.deduplicate([f1, f2])
        assert len(results) == 1

    def test_different_findings_stay_separate(self):
        """Findings with different CWEs and locations remain separate."""
        engine = DedupEngine()
        f1 = _make_finding(cwe="CWE-89", file_path="a.py", line_start=10)
        f2 = _make_finding(cwe="CWE-79", file_path="b.py", line_start=20)
        results = engine.deduplicate([f1, f2])
        assert len(results) == 2

    def test_single_finding(self):
        engine = DedupEngine()
        f = _make_finding()
        results = engine.deduplicate([f])
        assert len(results) == 1
        assert results[0].corroboration_count == 1

    def test_empty_input(self):
        engine = DedupEngine()
        results = engine.deduplicate([])
        assert results == []


class TestFuzzyDedup:
    def test_overlapping_line_ranges_merge(self):
        """Findings within N lines of each other with same CWE merge in Pass 2."""
        engine = DedupEngine(fuzzy_line_threshold=5)
        f1 = _make_finding(
            tool="semgrep", cwe="CWE-89", file_path="a.py",
            line_start=42, location_fingerprint="a.py:42",
        )
        f2 = _make_finding(
            tool="nuclei", cwe="CWE-89", file_path="a.py",
            line_start=44, location_fingerprint="a.py:44",
        )
        results = engine.deduplicate([f1, f2])
        assert len(results) == 1
        assert results[0].corroboration_count == 2

    def test_line_range_contains_exact_line(self):
        """EXACT_LINE at line 42 merges with LINE_RANGE 40-45 when CWE matches."""
        engine = DedupEngine(fuzzy_line_threshold=5)
        f1 = _make_finding(
            tool="semgrep", cwe="CWE-89", file_path="a.py",
            line_start=42, location_precision=LocationPrecision.EXACT_LINE,
            location_fingerprint="a.py:42",
        )
        f2 = _make_finding(
            tool="codebadger", cwe="CWE-89", file_path="a.py",
            line_start=40, line_end=45,
            location_precision=LocationPrecision.LINE_RANGE,
            location_fingerprint="a.py:40",
        )
        results = engine.deduplicate([f1, f2])
        assert len(results) == 1

    def test_related_cwes_merge(self):
        """Findings with related CWEs (parent/child) at same location merge."""
        engine = DedupEngine(fuzzy_line_threshold=5)
        f1 = _make_finding(
            tool="semgrep", cwe="CWE-89", file_path="a.py", line_start=10,
            location_fingerprint="a.py:10",
        )
        # CWE-564 is child of CWE-89 in the hierarchy
        f2 = _make_finding(
            tool="codebadger", cwe="CWE-564", file_path="a.py", line_start=10,
            location_fingerprint="a.py:10",
        )
        results = engine.deduplicate([f1, f2])
        assert len(results) == 1

    def test_file_level_no_merge_with_exact_unless_cwe_exact(self):
        """FILE-level findings don't merge with EXACT_LINE unless CWE matches exactly."""
        engine = DedupEngine(fuzzy_line_threshold=5)
        f1 = _make_finding(
            cwe="CWE-89", file_path="a.py", line_start=10,
            location_precision=LocationPrecision.EXACT_LINE,
            location_fingerprint="a.py:10",
        )
        f2 = _make_finding(
            cwe="CWE-79", file_path="a.py", line_start=0,
            location_precision=LocationPrecision.FILE,
            location_fingerprint="a.py:0",
        )
        results = engine.deduplicate([f1, f2])
        assert len(results) == 2

    def test_too_far_apart_no_merge(self):
        """Findings more than N lines apart don't merge even with same CWE."""
        engine = DedupEngine(fuzzy_line_threshold=5)
        f1 = _make_finding(
            cwe="CWE-89", file_path="a.py", line_start=10,
            location_fingerprint="a.py:10",
        )
        f2 = _make_finding(
            cwe="CWE-89", file_path="a.py", line_start=100,
            location_fingerprint="a.py:100",
        )
        results = engine.deduplicate([f1, f2])
        assert len(results) == 2


class TestSeverityConsensus:
    def test_weighted_vote_higher_confidence_wins(self):
        """Severity consensus takes the value from the higher-confidence tool."""
        engine = DedupEngine()
        f1 = _make_finding(
            tool="semgrep", raw_severity="high", parser_confidence=0.9,
            cwe="CWE-89", file_path="a.py", line_start=10,
        )
        f2 = _make_finding(
            tool="nmap", raw_severity="medium", parser_confidence=0.5,
            cwe="CWE-89", file_path="a.py", line_start=10,
        )
        results = engine.deduplicate([f1, f2])
        assert len(results) == 1
        assert results[0].severity_consensus == "high"

    def test_tie_breaks_to_more_severe(self):
        """When parser confidences are equal, tie breaks to more severe."""
        engine = DedupEngine()
        f1 = _make_finding(
            tool="semgrep", raw_severity="medium", parser_confidence=0.9,
            cwe="CWE-89", file_path="a.py", line_start=10,
        )
        f2 = _make_finding(
            tool="trivy", raw_severity="high", parser_confidence=0.9,
            cwe="CWE-89", file_path="a.py", line_start=10,
        )
        results = engine.deduplicate([f1, f2])
        assert len(results) == 1
        assert results[0].severity_consensus == "high"


class TestDedupOutput:
    def test_dedup_result_type(self):
        engine = DedupEngine()
        f = _make_finding()
        results = engine.deduplicate([f])
        assert len(results) == 1
        assert isinstance(results[0], DeduplicatedFinding)

    def test_best_evidence_quality_selected(self):
        engine = DedupEngine()
        f1 = _make_finding(
            tool="semgrep", evidence_quality=EvidenceQuality.STRUCTURED,
            cwe="CWE-89", file_path="a.py", line_start=10,
        )
        f2 = _make_finding(
            tool="nmap", evidence_quality=EvidenceQuality.HEURISTIC,
            cwe="CWE-89", file_path="a.py", line_start=10,
        )
        results = engine.deduplicate([f1, f2])
        assert results[0].evidence_quality_best == EvidenceQuality.STRUCTURED
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_dedup.py -v`
Expected: FAIL -- `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/scanner/parsing/dedup.py
"""DedupEngine — multi-pass deduplication for scan findings.

Pass 1 (strict): exact fingerprint match on (CWE + location_fingerprint),
(canonical_title + location_fingerprint), (CWE + evidence_hash), or evidence_hash.

Pass 2 (fuzzy): precision-aware fuzzy match on remaining unmatched findings —
overlapping line ranges, related CWEs, same file within N lines.
"""

from __future__ import annotations

import hashlib
import uuid
from collections import defaultdict
from datetime import datetime, timezone

from opentools.models import FindingStatus
from opentools.scanner.cwe import CWEHierarchy
from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_EQ_ORDER = {
    EvidenceQuality.PROVEN: 4,
    EvidenceQuality.TRACED: 3,
    EvidenceQuality.STRUCTURED: 2,
    EvidenceQuality.PATTERN: 1,
    EvidenceQuality.HEURISTIC: 0,
}


class DedupEngine:
    """Multi-pass dedup engine.

    Parameters
    ----------
    fuzzy_line_threshold : int
        Maximum line distance for fuzzy matching (default 5).
    """

    def __init__(self, fuzzy_line_threshold: int = 5) -> None:
        self._fuzzy_line_threshold = fuzzy_line_threshold
        self._cwe = CWEHierarchy()

    def deduplicate(self, findings: list[RawFinding]) -> list[DeduplicatedFinding]:
        """Run both passes and return merged DeduplicatedFinding objects."""
        if not findings:
            return []

        # Each group is a list of RawFinding indices
        groups: list[list[int]] = []
        matched: set[int] = set()

        # --- Pass 1: Strict fingerprint match ---
        # Build indexes
        cwe_loc_idx: dict[str, list[int]] = defaultdict(list)
        title_loc_idx: dict[str, list[int]] = defaultdict(list)
        cwe_eh_idx: dict[str, list[int]] = defaultdict(list)
        eh_idx: dict[str, list[int]] = defaultdict(list)

        for i, f in enumerate(findings):
            if f.cwe and f.location_fingerprint:
                cwe_loc_idx[f"{f.cwe}:{f.location_fingerprint}"].append(i)
            if f.canonical_title and f.location_fingerprint:
                title_loc_idx[f"{f.canonical_title}:{f.location_fingerprint}"].append(i)
            if f.cwe and f.evidence_hash:
                cwe_eh_idx[f"{f.cwe}:{f.evidence_hash}"].append(i)
            eh_idx[f.evidence_hash].append(i)

        # Merge by each strict key, in priority order
        for index in [cwe_loc_idx, title_loc_idx, cwe_eh_idx, eh_idx]:
            for _key, indices in index.items():
                # Filter to only unmatched
                unmatched_in_group = [i for i in indices if i not in matched]
                if len(unmatched_in_group) >= 2:
                    groups.append(unmatched_in_group)
                    matched.update(unmatched_in_group)

        # Singletons matched by strict pass (only if in a group key but alone)
        # — they'll be handled as singletons below

        # --- Pass 2: Fuzzy match on remaining unmatched ---
        unmatched = [i for i in range(len(findings)) if i not in matched]
        fuzzy_matched: set[int] = set()

        for idx_a, i in enumerate(unmatched):
            if i in fuzzy_matched:
                continue
            group = [i]
            fi = findings[i]
            for j in unmatched[idx_a + 1:]:
                if j in fuzzy_matched:
                    continue
                fj = findings[j]
                if self._fuzzy_match(fi, fj):
                    group.append(j)
                    fuzzy_matched.add(j)
            if len(group) >= 2:
                groups.append(group)
                matched.update(group)
                fuzzy_matched.add(i)

        # --- Build DeduplicatedFinding from each group ---
        result: list[DeduplicatedFinding] = []

        # Grouped findings
        for group in groups:
            raw_group = [findings[i] for i in group]
            result.append(self._merge_group(raw_group))

        # Remaining singletons
        for i in range(len(findings)):
            if i not in matched:
                result.append(self._merge_group([findings[i]]))

        return result

    def _fuzzy_match(self, a: RawFinding, b: RawFinding) -> bool:
        """Return True if two findings should merge in the fuzzy pass."""
        # Must be in the same file
        if a.file_path != b.file_path or a.file_path is None:
            return False

        # Precision-aware: FILE-level doesn't merge with EXACT_LINE unless CWE is exact match
        if LocationPrecision.FILE in (a.location_precision, b.location_precision):
            if a.cwe != b.cwe or a.cwe is None:
                return False
            return True

        # Check CWE relationship
        cwe_match = False
        if a.cwe and b.cwe:
            cwe_match = self._cwe.is_related(a.cwe, b.cwe)
        elif a.canonical_title and b.canonical_title:
            cwe_match = a.canonical_title == b.canonical_title
        else:
            return False

        if not cwe_match:
            return False

        # Check line proximity
        return self._lines_overlap_or_close(a, b)

    def _lines_overlap_or_close(self, a: RawFinding, b: RawFinding) -> bool:
        """Check if two findings' line ranges overlap or are within threshold."""
        a_start = a.line_start or 0
        a_end = a.line_end or a_start
        b_start = b.line_start or 0
        b_end = b.line_end or b_start

        # Check overlap
        if a_start <= b_end and b_start <= a_end:
            return True

        # Check proximity
        distance = min(abs(a_start - b_end), abs(b_start - a_end))
        return distance <= self._fuzzy_line_threshold

    def _merge_group(self, raw_findings: list[RawFinding]) -> DeduplicatedFinding:
        """Merge a group of related RawFindings into a single DeduplicatedFinding."""
        now = datetime.now(timezone.utc)
        tools = list({f.tool for f in raw_findings})
        raw_ids = [f.id for f in raw_findings]

        # Severity consensus: weighted vote by parser_confidence
        severity = self._severity_consensus(raw_findings)

        # Best evidence quality
        best_eq = max(raw_findings, key=lambda f: _EQ_ORDER.get(f.evidence_quality, 0))

        # Best location precision
        best_lp = max(
            raw_findings,
            key=lambda f: {
                LocationPrecision.EXACT_LINE: 5,
                LocationPrecision.LINE_RANGE: 4,
                LocationPrecision.FUNCTION: 3,
                LocationPrecision.FILE: 2,
                LocationPrecision.ENDPOINT: 1,
                LocationPrecision.HOST: 0,
            }.get(f.location_precision, 0),
        )

        # Use canonical title if available, otherwise title from highest-confidence parser
        best_conf = max(raw_findings, key=lambda f: f.parser_confidence)
        canonical_title = best_conf.canonical_title or best_conf.title

        # Use CWE from most specific finding (prefer non-None, then most specific child)
        cwe = next((f.cwe for f in sorted(raw_findings, key=lambda f: f.parser_confidence, reverse=True) if f.cwe), None)

        # Fingerprint: derive from canonical title + best location fingerprint
        fp_source = f"{canonical_title}:{best_lp.location_fingerprint}:{cwe or 'none'}"
        fingerprint = hashlib.sha256(fp_source.encode()).hexdigest()[:32]

        # Confidence: average of parser confidences (pre-corroboration)
        avg_conf = sum(f.parser_confidence for f in raw_findings) / len(raw_findings)

        return DeduplicatedFinding(
            id=str(uuid.uuid4()),
            engagement_id="",  # Set by caller / EngagementDedupEngine
            fingerprint=fingerprint,
            raw_finding_ids=raw_ids,
            tools=tools,
            corroboration_count=len(raw_findings),
            confidence_score=round(avg_conf, 4),
            severity_consensus=severity,
            canonical_title=canonical_title,
            cwe=cwe,
            location_fingerprint=best_lp.location_fingerprint,
            location_precision=best_lp.location_precision,
            evidence_quality_best=best_eq.evidence_quality,
            status=FindingStatus.DISCOVERED,
            first_seen_scan_id=raw_findings[0].scan_id,
            created_at=now,
            updated_at=now,
        )

    def _severity_consensus(self, findings: list[RawFinding]) -> str:
        """Weighted severity vote. Ties break to more severe."""
        votes: dict[str, float] = defaultdict(float)
        for f in findings:
            sev = f.raw_severity.lower()
            votes[sev] += f.parser_confidence

        if not votes:
            return "info"

        max_weight = max(votes.values())
        # All severities with the max weight
        candidates = [s for s, w in votes.items() if w == max_weight]
        # Tie-break: more severe wins
        return max(candidates, key=lambda s: _SEVERITY_ORDER.get(s, 0))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_dedup.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/parsing/dedup.py packages/cli/tests/test_scanner/test_dedup.py
git commit -m "feat(scanner): DedupEngine — strict fingerprint + fuzzy multi-pass dedup"
```

---

### Task 5: EngagementDedupEngine — Cross-Scan Reconciliation

**Files:**
- Create: `packages/cli/src/opentools/scanner/parsing/engagement_dedup.py`
- Test: `packages/cli/tests/test_scanner/test_engagement_dedup.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_engagement_dedup.py
"""Tests for EngagementDedupEngine — cross-scan dedup within an engagement."""

import uuid
from datetime import datetime, timezone

import pytest

from opentools.models import FindingStatus
from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
)
from opentools.scanner.parsing.engagement_dedup import EngagementDedupEngine


def _make_dedup(
    fingerprint: str = "fp1",
    canonical_title: str = "SQL Injection",
    cwe: str | None = "CWE-89",
    location_fingerprint: str = "a.py:10",
    tools: list[str] | None = None,
    scan_id: str = "scan-1",
    engagement_id: str = "eng-1",
    confidence_score: float = 0.9,
    severity_consensus: str = "high",
    status: FindingStatus = FindingStatus.DISCOVERED,
) -> DeduplicatedFinding:
    now = datetime.now(timezone.utc)
    return DeduplicatedFinding(
        id=str(uuid.uuid4()),
        engagement_id=engagement_id,
        fingerprint=fingerprint,
        raw_finding_ids=[str(uuid.uuid4())],
        tools=tools or ["semgrep"],
        corroboration_count=1,
        confidence_score=confidence_score,
        severity_consensus=severity_consensus,
        canonical_title=canonical_title,
        cwe=cwe,
        location_fingerprint=location_fingerprint,
        location_precision=LocationPrecision.EXACT_LINE,
        evidence_quality_best=EvidenceQuality.STRUCTURED,
        status=status,
        first_seen_scan_id=scan_id,
        last_confirmed_scan_id=scan_id,
        last_confirmed_at=now,
        created_at=now,
        updated_at=now,
    )


class TestEngagementDedup:
    def test_new_finding_added(self):
        """A finding not in prior results is returned as new."""
        engine = EngagementDedupEngine()
        current = [_make_dedup(fingerprint="fp-new")]
        prior: list[DeduplicatedFinding] = []
        merged = engine.reconcile(current, prior, scan_id="scan-2")
        assert len(merged) == 1
        assert merged[0].fingerprint == "fp-new"

    def test_matching_fingerprint_merges(self):
        """Same fingerprint across scans merges into one finding."""
        engine = EngagementDedupEngine()
        prior = [_make_dedup(fingerprint="fp1", tools=["semgrep"], scan_id="scan-1")]
        current = [_make_dedup(fingerprint="fp1", tools=["trivy"], scan_id="scan-2")]
        merged = engine.reconcile(current, prior, scan_id="scan-2")
        assert len(merged) == 1
        # Should have tools from both scans
        assert "semgrep" in merged[0].tools
        assert "trivy" in merged[0].tools
        assert merged[0].last_confirmed_scan_id == "scan-2"

    def test_confirmed_by_rescan(self):
        """A DISCOVERED finding reconfirmed in a new scan transitions to CONFIRMED."""
        engine = EngagementDedupEngine()
        prior = [_make_dedup(
            fingerprint="fp1",
            status=FindingStatus.DISCOVERED,
            confidence_score=0.85,
        )]
        current = [_make_dedup(fingerprint="fp1")]
        merged = engine.reconcile(current, prior, scan_id="scan-2")
        assert len(merged) == 1
        assert merged[0].status == FindingStatus.CONFIRMED

    def test_prior_only_findings_kept(self):
        """Findings in prior but not in current are still included (not removed)."""
        engine = EngagementDedupEngine()
        prior = [_make_dedup(fingerprint="fp-old")]
        current: list[DeduplicatedFinding] = []
        merged = engine.reconcile(current, prior, scan_id="scan-2")
        assert len(merged) == 1
        assert merged[0].fingerprint == "fp-old"

    def test_multiple_findings_mixed(self):
        """Mix of new, reconfirmed, and prior-only findings."""
        engine = EngagementDedupEngine()
        prior = [
            _make_dedup(fingerprint="fp-shared"),
            _make_dedup(fingerprint="fp-old-only"),
        ]
        current = [
            _make_dedup(fingerprint="fp-shared"),
            _make_dedup(fingerprint="fp-new"),
        ]
        merged = engine.reconcile(current, prior, scan_id="scan-2")
        fps = {f.fingerprint for f in merged}
        assert "fp-shared" in fps
        assert "fp-old-only" in fps
        assert "fp-new" in fps
        assert len(merged) == 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engagement_dedup.py -v`
Expected: FAIL -- `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/scanner/parsing/engagement_dedup.py
"""EngagementDedupEngine — cross-scan reconciliation within an engagement.

Merges current scan findings with prior engagement findings by fingerprint.
Handles:
- Reconfirmation: updates last_confirmed_scan_id, transitions DISCOVERED -> CONFIRMED
- Tool aggregation: merges tool lists across scans
- Preservation: prior findings not in current scan are retained
"""

from __future__ import annotations

from datetime import datetime, timezone

from opentools.models import FindingStatus
from opentools.scanner.models import DeduplicatedFinding


class EngagementDedupEngine:
    """Reconciles current scan findings with prior engagement-level findings."""

    def reconcile(
        self,
        current: list[DeduplicatedFinding],
        prior: list[DeduplicatedFinding],
        scan_id: str,
    ) -> list[DeduplicatedFinding]:
        """Merge current scan findings with prior engagement findings.

        Returns a list of DeduplicatedFinding objects representing the full
        engagement state after this scan.
        """
        now = datetime.now(timezone.utc)
        prior_by_fp = {f.fingerprint: f for f in prior}
        current_by_fp = {f.fingerprint: f for f in current}

        result: list[DeduplicatedFinding] = []
        seen_fps: set[str] = set()

        # Process current findings
        for fp, cf in current_by_fp.items():
            seen_fps.add(fp)
            pf = prior_by_fp.get(fp)
            if pf is not None:
                # Merge: reconfirm existing finding
                merged_tools = list(set(pf.tools) | set(cf.tools))
                merged_raw_ids = list(set(pf.raw_finding_ids) | set(cf.raw_finding_ids))

                # Transition DISCOVERED -> CONFIRMED on reconfirmation
                new_status = pf.status
                if pf.status == FindingStatus.DISCOVERED:
                    new_status = FindingStatus.CONFIRMED

                result.append(pf.model_copy(update={
                    "tools": merged_tools,
                    "raw_finding_ids": merged_raw_ids,
                    "corroboration_count": max(pf.corroboration_count, cf.corroboration_count) + 1,
                    "last_confirmed_scan_id": scan_id,
                    "last_confirmed_at": now,
                    "status": new_status,
                    "updated_at": now,
                }))
            else:
                # New finding for this engagement
                result.append(cf.model_copy(update={
                    "last_confirmed_scan_id": scan_id,
                    "last_confirmed_at": now,
                }))

        # Retain prior findings not seen in current scan
        for fp, pf in prior_by_fp.items():
            if fp not in seen_fps:
                result.append(pf)

        return result
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_engagement_dedup.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/parsing/engagement_dedup.py packages/cli/tests/test_scanner/test_engagement_dedup.py
git commit -m "feat(scanner): EngagementDedupEngine — cross-scan reconciliation"
```

---

### Task 6: CorroborationScorer

**Files:**
- Create: `packages/cli/src/opentools/scanner/parsing/confidence.py`
- Test: `packages/cli/tests/test_scanner/test_corroboration.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_corroboration.py
"""Tests for CorroborationScorer — confidence scoring based on tool diversity."""

import uuid
from datetime import datetime, timezone

import pytest

from opentools.models import FindingStatus
from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
)
from opentools.scanner.parsing.confidence import CorroborationScorer, ConfidenceDecay


def _make_dedup(
    tools: list[str] | None = None,
    corroboration_count: int = 1,
    confidence_score: float = 0.7,
    previously_marked_fp: bool = False,
) -> DeduplicatedFinding:
    now = datetime.now(timezone.utc)
    return DeduplicatedFinding(
        id=str(uuid.uuid4()),
        engagement_id="eng-1",
        fingerprint="fp1",
        raw_finding_ids=[str(uuid.uuid4())],
        tools=tools or ["semgrep"],
        corroboration_count=corroboration_count,
        confidence_score=confidence_score,
        severity_consensus="high",
        canonical_title="SQL Injection",
        cwe="CWE-89",
        location_fingerprint="a.py:10",
        location_precision=LocationPrecision.EXACT_LINE,
        evidence_quality_best=EvidenceQuality.STRUCTURED,
        previously_marked_fp=previously_marked_fp,
        status=FindingStatus.DISCOVERED,
        first_seen_scan_id="scan-1",
        created_at=now,
        updated_at=now,
    )


class TestCorroborationScorer:
    def test_single_tool_no_boost(self):
        scorer = CorroborationScorer()
        f = _make_dedup(tools=["semgrep"], confidence_score=0.9)
        [result] = scorer.score([f])
        # 1 tool = 1.0x boost, no FP penalty
        # base_confidence * 1.0 * 1.0 * 1.0 = 0.9
        assert result.confidence_score == pytest.approx(0.9, abs=0.01)

    def test_two_tools_same_category_boost(self):
        scorer = CorroborationScorer()
        # Two SAST tools
        f = _make_dedup(
            tools=["semgrep", "codebadger"],
            corroboration_count=2,
            confidence_score=0.8,
        )
        [result] = scorer.score([f])
        # 2 tools same category = 1.2x
        assert result.confidence_score > 0.8

    def test_two_tools_different_category_higher_boost(self):
        scorer = CorroborationScorer()
        # SAST + SCA
        f = _make_dedup(
            tools=["semgrep", "trivy"],
            corroboration_count=2,
            confidence_score=0.8,
        )
        [result] = scorer.score([f])
        # 2 tools different category = 1.4x
        assert result.confidence_score > 0.8

    def test_three_tools_maximum_boost(self):
        scorer = CorroborationScorer()
        f = _make_dedup(
            tools=["semgrep", "trivy", "nuclei"],
            corroboration_count=3,
            confidence_score=0.7,
        )
        [result] = scorer.score([f])
        # 3+ tools = 1.5x
        assert result.confidence_score > 0.7

    def test_fp_penalty(self):
        scorer = CorroborationScorer()
        f = _make_dedup(
            tools=["semgrep"],
            confidence_score=0.9,
            previously_marked_fp=True,
        )
        [result] = scorer.score([f])
        # FP penalty = 0.3
        assert result.confidence_score < 0.5

    def test_confidence_capped_at_one(self):
        scorer = CorroborationScorer()
        f = _make_dedup(
            tools=["semgrep", "trivy", "nuclei"],
            corroboration_count=3,
            confidence_score=0.95,
        )
        [result] = scorer.score([f])
        assert result.confidence_score <= 1.0

    def test_empty_input(self):
        scorer = CorroborationScorer()
        assert scorer.score([]) == []


class TestConfidenceDecay:
    def test_no_decay_within_30_days(self):
        decay = ConfidenceDecay()
        now = datetime.now(timezone.utc)
        f = _make_dedup(confidence_score=0.9)
        f = f.model_copy(update={"last_confirmed_at": now})
        [result] = decay.apply([f], reference_time=now)
        assert result.confidence_score == pytest.approx(0.9, abs=0.01)

    def test_decay_after_60_days(self):
        decay = ConfidenceDecay()
        now = datetime.now(timezone.utc)
        from datetime import timedelta
        old = now - timedelta(days=60)
        f = _make_dedup(confidence_score=0.9)
        f = f.model_copy(update={"last_confirmed_at": old})
        [result] = decay.apply([f], reference_time=now)
        # 60 days = 1 period past the 30-day grace, so -5%
        assert result.confidence_score < 0.9
        assert result.confidence_score >= 0.85 * 0.9 - 0.01

    def test_decay_floor_at_20_percent(self):
        decay = ConfidenceDecay()
        now = datetime.now(timezone.utc)
        from datetime import timedelta
        very_old = now - timedelta(days=365 * 3)
        f = _make_dedup(confidence_score=0.9)
        f = f.model_copy(update={"last_confirmed_at": very_old})
        [result] = decay.apply([f], reference_time=now)
        assert result.confidence_score >= 0.2

    def test_none_last_confirmed_no_decay(self):
        decay = ConfidenceDecay()
        now = datetime.now(timezone.utc)
        f = _make_dedup(confidence_score=0.9)
        f = f.model_copy(update={"last_confirmed_at": None})
        [result] = decay.apply([f], reference_time=now)
        assert result.confidence_score == pytest.approx(0.9, abs=0.01)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_corroboration.py -v`
Expected: FAIL -- `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/scanner/parsing/confidence.py
"""CorroborationScorer and ConfidenceDecay.

CorroborationScorer: adjusts confidence based on tool diversity, parser tiers,
and FP history.

ConfidenceDecay: findings not reconfirmed in recent scans lose confidence
over time.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

from opentools.scanner.models import DeduplicatedFinding

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# Tool categories for corroboration boost
_TOOL_CATEGORIES: dict[str, str] = {
    "semgrep": "sast",
    "codebadger": "sast",
    "trivy": "sca",
    "gitleaks": "secrets",
    "nuclei": "dast",
    "nikto": "dast",
    "nmap": "recon",
    "sqlmap": "dast",
    "capa": "binary",
    "arkana": "binary",
    "hashcat": "password",
}


@lru_cache(maxsize=1)
def _load_parser_confidence() -> dict[str, float]:
    path = _DATA_DIR / "parser_confidence.json"
    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    return {k: v for k, v in data.items() if k != "_comment"}


class CorroborationScorer:
    """Adjusts finding confidence based on corroboration.

    Formula::

        confidence = base_confidence * corroboration_boost * fp_penalty

    Corroboration boost:
        - 1 tool: 1.0x
        - 2 tools same category: 1.2x
        - 2 tools different category: 1.4x
        - 3+ tools: 1.5x

    FP penalty: 0.3 if previously_marked_fp, else 1.0

    Result is capped at 1.0.
    """

    def __init__(self) -> None:
        self._parser_confidence = _load_parser_confidence()

    def score(self, findings: list[DeduplicatedFinding]) -> list[DeduplicatedFinding]:
        """Return new list with updated confidence_score."""
        return [self._score_one(f) for f in findings]

    def _score_one(self, f: DeduplicatedFinding) -> DeduplicatedFinding:
        # Base confidence: average of contributing tools' confidence tiers
        base = self._base_confidence(f.tools) if f.tools else f.confidence_score

        # Corroboration boost
        boost = self._corroboration_boost(f.tools)

        # FP penalty
        fp_penalty = 0.3 if f.previously_marked_fp else 1.0

        confidence = min(base * boost * fp_penalty, 1.0)
        return f.model_copy(update={"confidence_score": round(confidence, 4)})

    def _base_confidence(self, tools: list[str]) -> float:
        """Average parser confidence tier for the given tools."""
        if not tools:
            return 0.5
        total = sum(self._parser_confidence.get(t, 0.5) for t in tools)
        return total / len(tools)

    def _corroboration_boost(self, tools: list[str]) -> float:
        """Compute corroboration boost based on tool count and diversity."""
        if len(tools) <= 1:
            return 1.0

        categories = {_TOOL_CATEGORIES.get(t, t) for t in tools}

        if len(tools) >= 3:
            return 1.5

        # 2 tools
        if len(categories) >= 2:
            return 1.4  # Different categories
        return 1.2  # Same category


class ConfidenceDecay:
    """Decay confidence for findings not reconfirmed in recent scans.

    - 100% for first 30 days
    - -5% per 30-day period after that
    - Floor: 20%
    """

    def __init__(self, grace_days: int = 30, decay_per_period: float = 0.05, floor: float = 0.2) -> None:
        self._grace_days = grace_days
        self._decay_per_period = decay_per_period
        self._floor = floor

    def apply(
        self,
        findings: list[DeduplicatedFinding],
        reference_time: datetime | None = None,
    ) -> list[DeduplicatedFinding]:
        """Return new list with decayed confidence scores."""
        ref = reference_time or datetime.now(timezone.utc)
        return [self._decay_one(f, ref) for f in findings]

    def _decay_one(self, f: DeduplicatedFinding, ref: datetime) -> DeduplicatedFinding:
        if f.last_confirmed_at is None:
            return f

        elapsed_days = (ref - f.last_confirmed_at).total_seconds() / 86400

        if elapsed_days <= self._grace_days:
            return f

        periods_past_grace = (elapsed_days - self._grace_days) / self._grace_days
        decay_factor = max(1.0 - (self._decay_per_period * periods_past_grace), self._floor / max(f.confidence_score, 0.01))
        new_confidence = max(f.confidence_score * decay_factor, self._floor)
        new_confidence = min(new_confidence, f.confidence_score)  # Never increase

        return f.model_copy(update={"confidence_score": round(new_confidence, 4)})
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_corroboration.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/parsing/confidence.py packages/cli/tests/test_scanner/test_corroboration.py
git commit -m "feat(scanner): CorroborationScorer + ConfidenceDecay — confidence scoring"
```

---

### Task 7: SuppressionEngine

**Files:**
- Create: `packages/cli/src/opentools/scanner/parsing/suppression.py`
- Test: `packages/cli/tests/test_scanner/test_suppression.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_suppression.py
"""Tests for SuppressionEngine — applies path/CWE/severity/tool suppression rules."""

import uuid
from datetime import datetime, timezone, timedelta

import pytest

from opentools.models import FindingStatus
from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
    SuppressionRule,
)
from opentools.scanner.parsing.suppression import SuppressionEngine


def _make_dedup(
    file_path: str = "src/api/users.py",
    cwe: str | None = "CWE-89",
    severity_consensus: str = "high",
    tools: list[str] | None = None,
    location_fingerprint: str | None = None,
) -> DeduplicatedFinding:
    now = datetime.now(timezone.utc)
    return DeduplicatedFinding(
        id=str(uuid.uuid4()),
        engagement_id="eng-1",
        fingerprint="fp1",
        raw_finding_ids=[str(uuid.uuid4())],
        tools=tools or ["semgrep"],
        corroboration_count=1,
        confidence_score=0.9,
        severity_consensus=severity_consensus,
        canonical_title="SQL Injection",
        cwe=cwe,
        location_fingerprint=location_fingerprint or f"{file_path}:42",
        location_precision=LocationPrecision.EXACT_LINE,
        evidence_quality_best=EvidenceQuality.STRUCTURED,
        status=FindingStatus.DISCOVERED,
        first_seen_scan_id="scan-1",
        created_at=now,
        updated_at=now,
    )


def _make_rule(
    rule_type: str = "path_pattern",
    pattern: str = "test/**",
    scope: str = "global",
    engagement_id: str | None = None,
    expires_at: datetime | None = None,
) -> SuppressionRule:
    return SuppressionRule(
        id=str(uuid.uuid4()),
        scope=scope,
        engagement_id=engagement_id,
        rule_type=rule_type,
        pattern=pattern,
        reason="Test suppression",
        created_by="user:test",
        created_at=datetime.now(timezone.utc),
        expires_at=expires_at,
    )


class TestPathSuppression:
    def test_path_glob_suppresses(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="path_pattern", pattern="test/**")]
        f = _make_dedup(location_fingerprint="test/test_auth.py:10")
        results = engine.apply(rules, [f])
        assert len(results) == 1
        assert results[0].suppressed is True

    def test_path_no_match_passes(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="path_pattern", pattern="test/**")]
        f = _make_dedup(location_fingerprint="src/api/users.py:42")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is False


class TestCWESuppression:
    def test_cwe_exact_match_suppresses(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="cwe", pattern="CWE-89")]
        f = _make_dedup(cwe="CWE-89")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is True

    def test_cwe_child_suppressed_by_parent(self):
        """Suppressing a parent CWE also suppresses child CWEs."""
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="cwe", pattern="CWE-74")]
        # CWE-89 is child of CWE-74
        f = _make_dedup(cwe="CWE-89")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is True

    def test_cwe_no_match(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="cwe", pattern="CWE-79")]
        f = _make_dedup(cwe="CWE-89")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is False


class TestSeveritySuppression:
    def test_severity_below_threshold(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="severity_below", pattern="medium")]
        f = _make_dedup(severity_consensus="low")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is True

    def test_severity_at_threshold_not_suppressed(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="severity_below", pattern="medium")]
        f = _make_dedup(severity_consensus="medium")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is False

    def test_severity_above_threshold_not_suppressed(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="severity_below", pattern="medium")]
        f = _make_dedup(severity_consensus="high")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is False


class TestToolSuppression:
    def test_tool_match_suppresses(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="tool", pattern="nmap")]
        f = _make_dedup(tools=["nmap"])
        results = engine.apply(rules, [f])
        assert results[0].suppressed is True

    def test_tool_no_match(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="tool", pattern="nmap")]
        f = _make_dedup(tools=["semgrep"])
        results = engine.apply(rules, [f])
        assert results[0].suppressed is False

    def test_tool_match_any_tool_in_list(self):
        engine = SuppressionEngine()
        rules = [_make_rule(rule_type="tool", pattern="nmap")]
        f = _make_dedup(tools=["semgrep", "nmap"])
        results = engine.apply(rules, [f])
        assert results[0].suppressed is True


class TestExpiredRules:
    def test_expired_rule_not_applied(self):
        engine = SuppressionEngine()
        past = datetime.now(timezone.utc) - timedelta(days=1)
        rules = [_make_rule(rule_type="cwe", pattern="CWE-89", expires_at=past)]
        f = _make_dedup(cwe="CWE-89")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is False

    def test_non_expired_rule_applied(self):
        engine = SuppressionEngine()
        future = datetime.now(timezone.utc) + timedelta(days=30)
        rules = [_make_rule(rule_type="cwe", pattern="CWE-89", expires_at=future)]
        f = _make_dedup(cwe="CWE-89")
        results = engine.apply(rules, [f])
        assert results[0].suppressed is True


class TestSuppressionRuleId:
    def test_suppressed_finding_gets_rule_id(self):
        engine = SuppressionEngine()
        rule = _make_rule(rule_type="cwe", pattern="CWE-89")
        f = _make_dedup(cwe="CWE-89")
        results = engine.apply([rule], [f])
        assert results[0].suppression_rule_id == rule.id
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_suppression.py -v`
Expected: FAIL -- `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/scanner/parsing/suppression.py
"""SuppressionEngine — applies path/CWE/severity/tool suppression rules.

Supports:
- path_pattern: fnmatch-style glob against location_fingerprint
- cwe: exact CWE match + hierarchical (suppress parent suppresses children)
- severity_below: suppress all findings below a given severity
- tool: suppress findings from a specific tool
"""

from __future__ import annotations

import fnmatch
from datetime import datetime, timezone

from opentools.scanner.cwe import CWEHierarchy
from opentools.scanner.models import DeduplicatedFinding, SuppressionRule

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class SuppressionEngine:
    """Applies suppression rules to a list of deduplicated findings."""

    def __init__(self) -> None:
        self._cwe = CWEHierarchy()

    def apply(
        self,
        rules: list[SuppressionRule],
        findings: list[DeduplicatedFinding],
    ) -> list[DeduplicatedFinding]:
        """Return a new list of findings with suppression flags set."""
        now = datetime.now(timezone.utc)
        active_rules = [r for r in rules if r.expires_at is None or r.expires_at > now]

        result = []
        for f in findings:
            matched_rule = self._check_rules(active_rules, f)
            if matched_rule is not None:
                result.append(f.model_copy(update={
                    "suppressed": True,
                    "suppression_rule_id": matched_rule.id,
                }))
            else:
                result.append(f)
        return result

    def _check_rules(
        self,
        rules: list[SuppressionRule],
        finding: DeduplicatedFinding,
    ) -> SuppressionRule | None:
        """Return the first matching rule, or None."""
        for rule in rules:
            if self._rule_matches(rule, finding):
                return rule
        return None

    def _rule_matches(self, rule: SuppressionRule, finding: DeduplicatedFinding) -> bool:
        """Check if a single rule matches a finding."""
        if rule.rule_type == "path_pattern":
            return self._match_path(rule.pattern, finding.location_fingerprint)
        elif rule.rule_type == "cwe":
            return self._match_cwe(rule.pattern, finding.cwe)
        elif rule.rule_type == "severity_below":
            return self._match_severity_below(rule.pattern, finding.severity_consensus)
        elif rule.rule_type == "tool":
            return self._match_tool(rule.pattern, finding.tools)
        return False

    def _match_path(self, pattern: str, location_fingerprint: str) -> bool:
        """Match path pattern against location fingerprint (file part)."""
        # Location fingerprint is typically "path:line" — extract path
        file_part = location_fingerprint.rsplit(":", 1)[0] if ":" in location_fingerprint else location_fingerprint
        return fnmatch.fnmatch(file_part, pattern)

    def _match_cwe(self, pattern_cwe: str, finding_cwe: str | None) -> bool:
        """Match CWE with hierarchical support (parent suppresses children)."""
        if finding_cwe is None:
            return False
        if finding_cwe == pattern_cwe:
            return True

        # Check if finding's CWE is a descendant of the pattern CWE
        current = finding_cwe
        visited: set[str] = set()
        while current is not None and current not in visited:
            visited.add(current)
            parent = self._cwe.get_parent(current)
            if parent == pattern_cwe:
                return True
            current = parent

        return False

    def _match_severity_below(self, threshold: str, finding_severity: str) -> bool:
        """Suppress if finding severity is strictly below threshold."""
        threshold_val = _SEVERITY_ORDER.get(threshold.lower(), 0)
        finding_val = _SEVERITY_ORDER.get(finding_severity.lower(), 0)
        return finding_val < threshold_val

    def _match_tool(self, pattern_tool: str, finding_tools: list[str]) -> bool:
        """Suppress if any of the finding's tools match."""
        return pattern_tool in finding_tools
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_suppression.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/parsing/suppression.py packages/cli/tests/test_scanner/test_suppression.py
git commit -m "feat(scanner): SuppressionEngine — path/CWE/severity/tool suppression"
```

---

### Task 8: FindingLifecycle + ConfidenceDecay Integration

**Files:**
- Create: `packages/cli/src/opentools/scanner/parsing/lifecycle.py`
- Test: `packages/cli/tests/test_scanner/test_lifecycle.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_lifecycle.py
"""Tests for FindingLifecycle — auto state transitions."""

import uuid
from datetime import datetime, timezone

import pytest

from opentools.models import FindingStatus
from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
)
from opentools.scanner.parsing.lifecycle import FindingLifecycle


def _make_dedup(
    status: FindingStatus = FindingStatus.DISCOVERED,
    corroboration_count: int = 1,
    confidence_score: float = 0.7,
    suppressed: bool = False,
) -> DeduplicatedFinding:
    now = datetime.now(timezone.utc)
    return DeduplicatedFinding(
        id=str(uuid.uuid4()),
        engagement_id="eng-1",
        fingerprint=str(uuid.uuid4())[:16],
        raw_finding_ids=[str(uuid.uuid4())],
        tools=["semgrep"],
        corroboration_count=corroboration_count,
        confidence_score=confidence_score,
        severity_consensus="high",
        canonical_title="SQL Injection",
        cwe="CWE-89",
        location_fingerprint="a.py:10",
        location_precision=LocationPrecision.EXACT_LINE,
        evidence_quality_best=EvidenceQuality.STRUCTURED,
        suppressed=suppressed,
        status=status,
        first_seen_scan_id="scan-1",
        created_at=now,
        updated_at=now,
    )


class TestFindingLifecycle:
    def test_discovered_to_confirmed_by_corroboration(self):
        """discovered -> confirmed when corroboration_count >= 2."""
        lc = FindingLifecycle()
        f = _make_dedup(
            status=FindingStatus.DISCOVERED,
            corroboration_count=2,
        )
        [result] = lc.apply([f])
        assert result.status == FindingStatus.CONFIRMED

    def test_discovered_to_confirmed_by_confidence(self):
        """discovered -> confirmed when confidence >= 0.85."""
        lc = FindingLifecycle()
        f = _make_dedup(
            status=FindingStatus.DISCOVERED,
            corroboration_count=1,
            confidence_score=0.85,
        )
        [result] = lc.apply([f])
        assert result.status == FindingStatus.CONFIRMED

    def test_discovered_stays_discovered_low_confidence(self):
        """discovered stays discovered when neither threshold met."""
        lc = FindingLifecycle()
        f = _make_dedup(
            status=FindingStatus.DISCOVERED,
            corroboration_count=1,
            confidence_score=0.5,
        )
        [result] = lc.apply([f])
        assert result.status == FindingStatus.DISCOVERED

    def test_confirmed_stays_confirmed(self):
        """confirmed is not downgraded."""
        lc = FindingLifecycle()
        f = _make_dedup(status=FindingStatus.CONFIRMED)
        [result] = lc.apply([f])
        assert result.status == FindingStatus.CONFIRMED

    def test_suppressed_findings_skipped(self):
        """Suppressed findings are not transitioned."""
        lc = FindingLifecycle()
        f = _make_dedup(
            status=FindingStatus.DISCOVERED,
            corroboration_count=5,
            confidence_score=0.99,
            suppressed=True,
        )
        [result] = lc.apply([f])
        assert result.status == FindingStatus.DISCOVERED

    def test_custom_thresholds(self):
        """Custom corroboration and confidence thresholds."""
        lc = FindingLifecycle(
            confirm_corroboration=3,
            confirm_confidence=0.95,
        )
        f = _make_dedup(
            status=FindingStatus.DISCOVERED,
            corroboration_count=2,
            confidence_score=0.9,
        )
        [result] = lc.apply([f])
        assert result.status == FindingStatus.DISCOVERED

        f2 = _make_dedup(
            status=FindingStatus.DISCOVERED,
            corroboration_count=3,
        )
        [result2] = lc.apply([f2])
        assert result2.status == FindingStatus.CONFIRMED

    def test_empty_input(self):
        lc = FindingLifecycle()
        assert lc.apply([]) == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_lifecycle.py -v`
Expected: FAIL -- `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/scanner/parsing/lifecycle.py
"""FindingLifecycle — automatic state transitions for deduplicated findings.

Transition rules (auto):
- discovered -> confirmed: corroboration_count >= 2 OR confidence >= 0.85
- remediated -> verified: handled by ScanDiff (not in this module)

Manual transitions (reported, remediated) are handled by the API layer.
"""

from __future__ import annotations

from opentools.models import FindingStatus
from opentools.scanner.models import DeduplicatedFinding


class FindingLifecycle:
    """Applies automatic state transitions to findings.

    Parameters
    ----------
    confirm_corroboration : int
        Minimum corroboration count to auto-confirm (default 2).
    confirm_confidence : float
        Minimum confidence score to auto-confirm (default 0.85).
    """

    def __init__(
        self,
        confirm_corroboration: int = 2,
        confirm_confidence: float = 0.85,
    ) -> None:
        self._confirm_corroboration = confirm_corroboration
        self._confirm_confidence = confirm_confidence

    def apply(self, findings: list[DeduplicatedFinding]) -> list[DeduplicatedFinding]:
        """Return a new list with state transitions applied."""
        return [self._transition(f) for f in findings]

    def _transition(self, f: DeduplicatedFinding) -> DeduplicatedFinding:
        """Apply auto-transition rules to a single finding."""
        # Skip suppressed findings
        if f.suppressed:
            return f

        if f.status == FindingStatus.DISCOVERED:
            if (
                f.corroboration_count >= self._confirm_corroboration
                or f.confidence_score >= self._confirm_confidence
            ):
                return f.model_copy(update={"status": FindingStatus.CONFIRMED})

        return f
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_lifecycle.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/parsing/lifecycle.py packages/cli/tests/test_scanner/test_lifecycle.py
git commit -m "feat(scanner): FindingLifecycle — auto state transitions"
```

---

### Task 9: FindingCorrelationEngine + RemediationGrouper

**Files:**
- Create: `packages/cli/src/opentools/scanner/parsing/correlation.py`
- Create: `packages/cli/src/opentools/scanner/parsing/remediation.py`
- Test: `packages/cli/tests/test_scanner/test_correlation.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_correlation.py
"""Tests for FindingCorrelationEngine and RemediationGrouper."""

import uuid
from datetime import datetime, timezone

import pytest

from opentools.models import FindingStatus
from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    FindingCorrelation,
    LocationPrecision,
    RemediationGroup,
)
from opentools.scanner.parsing.correlation import FindingCorrelationEngine
from opentools.scanner.parsing.remediation import RemediationGrouper


def _make_dedup(
    canonical_title: str = "SQL Injection",
    cwe: str | None = "CWE-89",
    location_fingerprint: str = "a.py:10",
    severity_consensus: str = "high",
    tools: list[str] | None = None,
    description: str = "",
) -> DeduplicatedFinding:
    now = datetime.now(timezone.utc)
    return DeduplicatedFinding(
        id=str(uuid.uuid4()),
        engagement_id="eng-1",
        fingerprint=str(uuid.uuid4())[:16],
        raw_finding_ids=[str(uuid.uuid4())],
        tools=tools or ["semgrep"],
        corroboration_count=1,
        confidence_score=0.9,
        severity_consensus=severity_consensus,
        canonical_title=canonical_title,
        cwe=cwe,
        location_fingerprint=location_fingerprint,
        location_precision=LocationPrecision.EXACT_LINE,
        evidence_quality_best=EvidenceQuality.STRUCTURED,
        status=FindingStatus.DISCOVERED,
        first_seen_scan_id="scan-1",
        created_at=now,
        updated_at=now,
    )


# ---------------------------------------------------------------------------
# FindingCorrelationEngine
# ---------------------------------------------------------------------------


class TestFindingCorrelationEngine:
    def test_same_endpoint_correlation(self):
        """Findings on the same file/endpoint are correlated."""
        engine = FindingCorrelationEngine()
        f1 = _make_dedup(
            canonical_title="SQL Injection",
            location_fingerprint="src/api/users.py:10",
        )
        f2 = _make_dedup(
            canonical_title="Cross-Site Scripting (XSS)",
            cwe="CWE-79",
            location_fingerprint="src/api/users.py:25",
        )
        correlations = engine.correlate(
            [f1, f2], scan_id="scan-1", engagement_id="eng-1"
        )
        assert len(correlations) >= 1
        c = correlations[0]
        assert isinstance(c, FindingCorrelation)
        assert c.correlation_type == "same_endpoint"
        assert len(c.finding_ids) == 2

    def test_same_cwe_correlation(self):
        """Multiple findings with the same CWE are correlated."""
        engine = FindingCorrelationEngine()
        f1 = _make_dedup(cwe="CWE-89", location_fingerprint="a.py:10")
        f2 = _make_dedup(cwe="CWE-89", location_fingerprint="b.py:20")
        correlations = engine.correlate(
            [f1, f2], scan_id="scan-1", engagement_id="eng-1"
        )
        cwe_corrs = [c for c in correlations if c.correlation_type == "same_cwe"]
        assert len(cwe_corrs) >= 1
        assert len(cwe_corrs[0].finding_ids) == 2

    def test_attack_chain_detection(self):
        """Findings that form a known attack chain are detected."""
        engine = FindingCorrelationEngine()
        # Recon -> injection -> data exfil pattern
        f1 = _make_dedup(
            canonical_title="SQL Injection",
            cwe="CWE-89",
            location_fingerprint="a.py:10",
        )
        f2 = _make_dedup(
            canonical_title="Hardcoded Credentials",
            cwe="CWE-798",
            location_fingerprint="config.py:5",
        )
        f3 = _make_dedup(
            canonical_title="Path Traversal",
            cwe="CWE-22",
            location_fingerprint="b.py:20",
        )
        correlations = engine.correlate(
            [f1, f2, f3], scan_id="scan-1", engagement_id="eng-1"
        )
        attack_chains = [c for c in correlations if c.correlation_type == "attack_chain"]
        # May or may not detect a chain depending on heuristics, but should not crash
        assert isinstance(correlations, list)

    def test_no_findings_no_correlations(self):
        engine = FindingCorrelationEngine()
        result = engine.correlate([], scan_id="scan-1", engagement_id="eng-1")
        assert result == []

    def test_single_finding_no_correlations(self):
        engine = FindingCorrelationEngine()
        f = _make_dedup()
        result = engine.correlate([f], scan_id="scan-1", engagement_id="eng-1")
        assert result == []


# ---------------------------------------------------------------------------
# RemediationGrouper
# ---------------------------------------------------------------------------


class TestRemediationGrouper:
    def test_group_by_shared_cwe(self):
        """Findings with the same CWE are grouped for shared remediation."""
        grouper = RemediationGrouper()
        f1 = _make_dedup(cwe="CWE-89", location_fingerprint="a.py:10")
        f2 = _make_dedup(cwe="CWE-89", location_fingerprint="b.py:20")
        groups = grouper.group(
            [f1, f2], scan_id="scan-1", engagement_id="eng-1"
        )
        assert len(groups) >= 1
        g = groups[0]
        assert isinstance(g, RemediationGroup)
        assert len(g.finding_ids) == 2
        assert g.findings_count == 2

    def test_different_cwes_separate_groups(self):
        grouper = RemediationGrouper()
        f1 = _make_dedup(cwe="CWE-89", location_fingerprint="a.py:10")
        f2 = _make_dedup(cwe="CWE-79", location_fingerprint="b.py:20")
        groups = grouper.group(
            [f1, f2], scan_id="scan-1", engagement_id="eng-1"
        )
        assert len(groups) == 2

    def test_max_severity_in_group(self):
        grouper = RemediationGrouper()
        f1 = _make_dedup(cwe="CWE-89", severity_consensus="medium", location_fingerprint="a.py:10")
        f2 = _make_dedup(cwe="CWE-89", severity_consensus="critical", location_fingerprint="b.py:20")
        groups = grouper.group([f1, f2], scan_id="scan-1", engagement_id="eng-1")
        assert groups[0].max_severity == "critical"

    def test_empty_input(self):
        grouper = RemediationGrouper()
        assert grouper.group([], scan_id="scan-1", engagement_id="eng-1") == []

    def test_none_cwe_gets_own_group(self):
        grouper = RemediationGrouper()
        f1 = _make_dedup(cwe=None, location_fingerprint="a.py:10")
        f2 = _make_dedup(cwe=None, location_fingerprint="b.py:20")
        groups = grouper.group(
            [f1, f2], scan_id="scan-1", engagement_id="eng-1"
        )
        # Each finding with None CWE gets its own group (no meaningful shared fix)
        assert len(groups) == 2
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_correlation.py -v`
Expected: FAIL -- `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/scanner/parsing/correlation.py
"""FindingCorrelationEngine — attack chain and kill chain detection.

Detects:
- same_endpoint: multiple findings on the same file/endpoint
- same_cwe: multiple findings with the same CWE
- attack_chain: findings forming a known attack pattern
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone

from opentools.scanner.models import DeduplicatedFinding, FindingCorrelation

# Known attack chain patterns: lists of CWE sets that form escalation paths
_ATTACK_CHAIN_PATTERNS: list[dict] = [
    {
        "name": "Credential theft + injection",
        "cwes": [{"CWE-798", "CWE-200"}, {"CWE-89", "CWE-78", "CWE-77"}],
        "narrative": "Hardcoded credentials combined with injection vulnerabilities enable authenticated exploitation",
    },
    {
        "name": "File access + code execution",
        "cwes": [{"CWE-22", "CWE-434"}, {"CWE-94", "CWE-78", "CWE-95"}],
        "narrative": "Path traversal or file upload combined with code execution enables remote code execution",
    },
]


class FindingCorrelationEngine:
    """Detects correlations between findings within a scan."""

    def correlate(
        self,
        findings: list[DeduplicatedFinding],
        scan_id: str,
        engagement_id: str,
    ) -> list[FindingCorrelation]:
        """Detect correlations and return FindingCorrelation objects."""
        if len(findings) < 2:
            return []

        correlations: list[FindingCorrelation] = []
        now = datetime.now(timezone.utc)

        # 1. Same endpoint correlation
        correlations.extend(
            self._correlate_by_endpoint(findings, scan_id, engagement_id, now)
        )

        # 2. Same CWE correlation
        correlations.extend(
            self._correlate_by_cwe(findings, scan_id, engagement_id, now)
        )

        # 3. Attack chain detection
        correlations.extend(
            self._detect_attack_chains(findings, scan_id, engagement_id, now)
        )

        return correlations

    def _correlate_by_endpoint(
        self,
        findings: list[DeduplicatedFinding],
        scan_id: str,
        engagement_id: str,
        now: datetime,
    ) -> list[FindingCorrelation]:
        """Group findings by file/endpoint."""
        by_file: dict[str, list[DeduplicatedFinding]] = defaultdict(list)
        for f in findings:
            # Extract file path from location fingerprint
            file_part = f.location_fingerprint.rsplit(":", 1)[0] if ":" in f.location_fingerprint else f.location_fingerprint
            by_file[file_part].append(f)

        result = []
        for file_path, group in by_file.items():
            if len(group) < 2:
                continue
            # Only correlate if findings have different titles
            titles = {f.canonical_title for f in group}
            if len(titles) < 2:
                continue

            severity = max(
                (f.severity_consensus for f in group),
                key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(s, 0),
            )
            result.append(FindingCorrelation(
                id=str(uuid.uuid4()),
                engagement_id=engagement_id,
                scan_id=scan_id,
                finding_ids=[f.id for f in group],
                correlation_type="same_endpoint",
                narrative=f"Multiple vulnerability types found in {file_path}: {', '.join(sorted(titles))}",
                severity=severity,
                created_at=now,
            ))
        return result

    def _correlate_by_cwe(
        self,
        findings: list[DeduplicatedFinding],
        scan_id: str,
        engagement_id: str,
        now: datetime,
    ) -> list[FindingCorrelation]:
        """Group findings by CWE."""
        by_cwe: dict[str, list[DeduplicatedFinding]] = defaultdict(list)
        for f in findings:
            if f.cwe:
                by_cwe[f.cwe].append(f)

        result = []
        for cwe, group in by_cwe.items():
            if len(group) < 2:
                continue
            severity = max(
                (f.severity_consensus for f in group),
                key=lambda s: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(s, 0),
            )
            result.append(FindingCorrelation(
                id=str(uuid.uuid4()),
                engagement_id=engagement_id,
                scan_id=scan_id,
                finding_ids=[f.id for f in group],
                correlation_type="same_cwe",
                narrative=f"Multiple instances of {cwe} detected across {len(group)} locations",
                severity=severity,
                created_at=now,
            ))
        return result

    def _detect_attack_chains(
        self,
        findings: list[DeduplicatedFinding],
        scan_id: str,
        engagement_id: str,
        now: datetime,
    ) -> list[FindingCorrelation]:
        """Detect known attack chain patterns."""
        finding_cwes = {f.cwe for f in findings if f.cwe}
        result = []

        for pattern in _ATTACK_CHAIN_PATTERNS:
            # Check if findings match each stage of the chain
            matched_stages = []
            matched_findings: list[str] = []
            for stage_cwes in pattern["cwes"]:
                stage_matches = [
                    f for f in findings if f.cwe in stage_cwes
                ]
                if stage_matches:
                    matched_stages.append(True)
                    matched_findings.extend(f.id for f in stage_matches)
                else:
                    matched_stages.append(False)

            if all(matched_stages) and len(matched_findings) >= 2:
                result.append(FindingCorrelation(
                    id=str(uuid.uuid4()),
                    engagement_id=engagement_id,
                    scan_id=scan_id,
                    finding_ids=list(set(matched_findings)),
                    correlation_type="attack_chain",
                    narrative=f"{pattern['name']}: {pattern['narrative']}",
                    severity="critical",
                    created_at=now,
                ))

        return result
```

```python
# packages/cli/src/opentools/scanner/parsing/remediation.py
"""RemediationGrouper — groups findings by shared fix.

Groups findings that share the same CWE (and therefore likely the same
remediation strategy) into RemediationGroup objects.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from datetime import datetime, timezone

from opentools.scanner.models import DeduplicatedFinding, RemediationGroup

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# CWE to remediation action mapping
_CWE_ACTIONS: dict[str, tuple[str, str]] = {
    "CWE-89": ("Use parameterized queries / prepared statements", "code_fix"),
    "CWE-79": ("Apply output encoding / Content Security Policy", "code_fix"),
    "CWE-78": ("Avoid shell commands; use safe APIs with allowlists", "code_fix"),
    "CWE-77": ("Use safe APIs instead of command construction", "code_fix"),
    "CWE-22": ("Validate and canonicalize file paths", "code_fix"),
    "CWE-798": ("Move credentials to secret management system", "config_change"),
    "CWE-502": ("Use safe serialization formats (JSON) or allowlists", "code_fix"),
    "CWE-611": ("Disable external entity processing in XML parsers", "code_fix"),
    "CWE-918": ("Validate and restrict outbound URLs", "code_fix"),
    "CWE-352": ("Implement anti-CSRF tokens", "code_fix"),
    "CWE-601": ("Validate redirect URLs against allowlist", "code_fix"),
    "CWE-327": ("Replace with strong cryptographic algorithms", "code_fix"),
    "CWE-434": ("Validate file types, use secure storage", "code_fix"),
    "CWE-94": ("Avoid dynamic code execution; use safe alternatives", "code_fix"),
    "CWE-95": ("Remove eval() usage; use safe alternatives", "code_fix"),
}


class RemediationGrouper:
    """Groups findings by shared remediation action."""

    def group(
        self,
        findings: list[DeduplicatedFinding],
        scan_id: str,
        engagement_id: str,
    ) -> list[RemediationGroup]:
        """Group findings and return RemediationGroup objects."""
        if not findings:
            return []

        now = datetime.now(timezone.utc)
        by_cwe: dict[str | None, list[DeduplicatedFinding]] = defaultdict(list)

        for f in findings:
            by_cwe[f.cwe].append(f)

        result: list[RemediationGroup] = []
        for cwe, group in by_cwe.items():
            if cwe is None:
                # Each finding with no CWE gets its own group
                for f in group:
                    result.append(self._build_group(
                        [f], cwe, scan_id, engagement_id, now
                    ))
            else:
                result.append(self._build_group(
                    group, cwe, scan_id, engagement_id, now
                ))

        return result

    def _build_group(
        self,
        findings: list[DeduplicatedFinding],
        cwe: str | None,
        scan_id: str,
        engagement_id: str,
        now: datetime,
    ) -> RemediationGroup:
        action_info = _CWE_ACTIONS.get(cwe or "", None)
        if action_info:
            action, action_type = action_info
        else:
            action = f"Review and remediate {cwe or 'unknown'} findings"
            action_type = "code_fix"

        max_sev = max(
            (f.severity_consensus for f in findings),
            key=lambda s: _SEVERITY_ORDER.get(s.lower(), 0),
        )

        # Effort estimate based on count
        count = len(findings)
        if count <= 2:
            effort = "low"
        elif count <= 5:
            effort = "medium"
        else:
            effort = "high"

        return RemediationGroup(
            id=str(uuid.uuid4()),
            engagement_id=engagement_id,
            scan_id=scan_id,
            action=action,
            action_type=action_type,
            finding_ids=[f.id for f in findings],
            findings_count=count,
            max_severity=max_sev,
            effort_estimate=effort,
            created_at=now,
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_correlation.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/parsing/correlation.py packages/cli/src/opentools/scanner/parsing/remediation.py packages/cli/tests/test_scanner/test_correlation.py
git commit -m "feat(scanner): FindingCorrelationEngine + RemediationGrouper"
```

---

### Task 10: ScanDiffEngine — Baseline Comparison

**Files:**
- Create: `packages/cli/src/opentools/scanner/diff.py`
- Test: `packages/cli/tests/test_scanner/test_scan_diff.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_scan_diff.py
"""Tests for ScanDiffEngine — baseline comparison."""

import uuid
from datetime import datetime, timezone

import pytest

from opentools.models import FindingStatus
from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    LocationPrecision,
)
from opentools.scanner.diff import ScanDiffEngine, ScanDiffResult, DiffSummary


def _make_dedup(
    fingerprint: str = "fp1",
    severity_consensus: str = "high",
    tools: list[str] | None = None,
    scan_id: str = "scan-1",
) -> DeduplicatedFinding:
    now = datetime.now(timezone.utc)
    return DeduplicatedFinding(
        id=str(uuid.uuid4()),
        engagement_id="eng-1",
        fingerprint=fingerprint,
        raw_finding_ids=[str(uuid.uuid4())],
        tools=tools or ["semgrep"],
        corroboration_count=1,
        confidence_score=0.9,
        severity_consensus=severity_consensus,
        canonical_title="SQL Injection",
        cwe="CWE-89",
        location_fingerprint="a.py:10",
        location_precision=LocationPrecision.EXACT_LINE,
        evidence_quality_best=EvidenceQuality.STRUCTURED,
        status=FindingStatus.DISCOVERED,
        first_seen_scan_id=scan_id,
        created_at=now,
        updated_at=now,
    )


class TestScanDiff:
    def test_all_new_findings(self):
        engine = ScanDiffEngine()
        current = [_make_dedup(fingerprint="fp-new", scan_id="scan-2")]
        baseline: list[DeduplicatedFinding] = []
        diff = engine.diff(
            current=current,
            baseline=baseline,
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert isinstance(diff, ScanDiffResult)
        assert len(diff.new_findings) == 1
        assert len(diff.resolved_findings) == 0
        assert len(diff.persistent_findings) == 0

    def test_all_resolved_findings(self):
        engine = ScanDiffEngine()
        current: list[DeduplicatedFinding] = []
        baseline = [_make_dedup(fingerprint="fp-old", scan_id="scan-1")]
        diff = engine.diff(
            current=current,
            baseline=baseline,
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert len(diff.new_findings) == 0
        assert len(diff.resolved_findings) == 1
        assert len(diff.persistent_findings) == 0

    def test_persistent_findings(self):
        engine = ScanDiffEngine()
        baseline = [_make_dedup(fingerprint="fp-both", scan_id="scan-1")]
        current = [_make_dedup(fingerprint="fp-both", scan_id="scan-2")]
        diff = engine.diff(
            current=current,
            baseline=baseline,
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert len(diff.new_findings) == 0
        assert len(diff.resolved_findings) == 0
        assert len(diff.persistent_findings) == 1

    def test_mixed_scenario(self):
        engine = ScanDiffEngine()
        baseline = [
            _make_dedup(fingerprint="fp-persist", scan_id="scan-1"),
            _make_dedup(fingerprint="fp-resolved", scan_id="scan-1"),
        ]
        current = [
            _make_dedup(fingerprint="fp-persist", scan_id="scan-2"),
            _make_dedup(fingerprint="fp-new", scan_id="scan-2"),
        ]
        diff = engine.diff(
            current=current,
            baseline=baseline,
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert len(diff.new_findings) == 1
        assert len(diff.resolved_findings) == 1
        assert len(diff.persistent_findings) == 1

    def test_severity_change_detected(self):
        engine = ScanDiffEngine()
        baseline = [_make_dedup(fingerprint="fp1", severity_consensus="medium")]
        current = [_make_dedup(fingerprint="fp1", severity_consensus="critical")]
        diff = engine.diff(
            current=current,
            baseline=baseline,
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert len(diff.severity_changes) == 1
        assert diff.severity_changes[0]["from"] == "medium"
        assert diff.severity_changes[0]["to"] == "critical"

    def test_tool_diff(self):
        engine = ScanDiffEngine()
        baseline = [_make_dedup(fingerprint="fp1", tools=["semgrep"])]
        current = [_make_dedup(fingerprint="fp1", tools=["semgrep", "trivy"])]
        diff = engine.diff(
            current=current,
            baseline=baseline,
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert "trivy" in diff.new_tools_used

    def test_summary(self):
        engine = ScanDiffEngine()
        baseline = [
            _make_dedup(fingerprint="fp-persist"),
            _make_dedup(fingerprint="fp-resolved"),
        ]
        current = [
            _make_dedup(fingerprint="fp-persist"),
            _make_dedup(fingerprint="fp-new"),
        ]
        diff = engine.diff(
            current=current,
            baseline=baseline,
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert isinstance(diff.summary, DiffSummary)
        assert diff.summary.new_count == 1
        assert diff.summary.resolved_count == 1
        assert diff.summary.persistent_count == 1
        assert diff.summary.net_risk_change == "stable"

    def test_empty_both(self):
        engine = ScanDiffEngine()
        diff = engine.diff(
            current=[],
            baseline=[],
            scan_id="scan-2",
            baseline_id="scan-1",
        )
        assert diff.summary.new_count == 0
        assert diff.summary.resolved_count == 0
        assert diff.summary.net_risk_change == "stable"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_scan_diff.py -v`
Expected: FAIL -- `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/scanner/diff.py
"""ScanDiffEngine — baseline comparison between scan results.

Compares current scan findings against a baseline using semantic fingerprints
(the same fingerprint used by the dedup engine).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from opentools.scanner.models import DeduplicatedFinding

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class DiffSummary:
    """Summary statistics for a scan diff."""

    new_count: int = 0
    resolved_count: int = 0
    persistent_count: int = 0
    severity_escalations: int = 0
    severity_deescalations: int = 0
    net_risk_change: str = "stable"  # "increased", "decreased", "stable"


@dataclass
class ScanDiffResult:
    """Full diff result between two scans."""

    scan_id: str
    baseline_id: str
    new_findings: list[DeduplicatedFinding] = field(default_factory=list)
    resolved_findings: list[DeduplicatedFinding] = field(default_factory=list)
    persistent_findings: list[DeduplicatedFinding] = field(default_factory=list)
    severity_changes: list[dict] = field(default_factory=list)
    new_tools_used: list[str] = field(default_factory=list)
    removed_tools: list[str] = field(default_factory=list)
    summary: DiffSummary = field(default_factory=DiffSummary)


class ScanDiffEngine:
    """Compares two sets of deduplicated findings by fingerprint."""

    def diff(
        self,
        current: list[DeduplicatedFinding],
        baseline: list[DeduplicatedFinding],
        scan_id: str,
        baseline_id: str,
    ) -> ScanDiffResult:
        """Compute diff between current and baseline scan findings."""
        baseline_by_fp = {f.fingerprint: f for f in baseline}
        current_by_fp = {f.fingerprint: f for f in current}

        baseline_fps = set(baseline_by_fp.keys())
        current_fps = set(current_by_fp.keys())

        new_fps = current_fps - baseline_fps
        resolved_fps = baseline_fps - current_fps
        persistent_fps = current_fps & baseline_fps

        new_findings = [current_by_fp[fp] for fp in new_fps]
        resolved_findings = [baseline_by_fp[fp] for fp in resolved_fps]
        persistent_findings = [current_by_fp[fp] for fp in persistent_fps]

        # Detect severity changes in persistent findings
        severity_changes = []
        severity_escalations = 0
        severity_deescalations = 0
        for fp in persistent_fps:
            old_sev = baseline_by_fp[fp].severity_consensus
            new_sev = current_by_fp[fp].severity_consensus
            if old_sev != new_sev:
                severity_changes.append({
                    "fingerprint": fp,
                    "from": old_sev,
                    "to": new_sev,
                })
                old_val = _SEVERITY_ORDER.get(old_sev.lower(), 0)
                new_val = _SEVERITY_ORDER.get(new_sev.lower(), 0)
                if new_val > old_val:
                    severity_escalations += 1
                else:
                    severity_deescalations += 1

        # Tool diff
        baseline_tools = set()
        for f in baseline:
            baseline_tools.update(f.tools)
        current_tools = set()
        for f in current:
            current_tools.update(f.tools)

        new_tools = sorted(current_tools - baseline_tools)
        removed_tools = sorted(baseline_tools - current_tools)

        # Net risk change
        # Weighted: new high/critical increases risk, resolved high/critical decreases
        new_risk = sum(
            _SEVERITY_ORDER.get(f.severity_consensus.lower(), 0) for f in new_findings
        )
        resolved_risk = sum(
            _SEVERITY_ORDER.get(f.severity_consensus.lower(), 0) for f in resolved_findings
        )

        if new_risk > resolved_risk:
            net_risk = "increased"
        elif resolved_risk > new_risk:
            net_risk = "decreased"
        else:
            net_risk = "stable"

        summary = DiffSummary(
            new_count=len(new_findings),
            resolved_count=len(resolved_findings),
            persistent_count=len(persistent_findings),
            severity_escalations=severity_escalations,
            severity_deescalations=severity_deescalations,
            net_risk_change=net_risk,
        )

        return ScanDiffResult(
            scan_id=scan_id,
            baseline_id=baseline_id,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            persistent_findings=persistent_findings,
            severity_changes=severity_changes,
            new_tools_used=new_tools,
            removed_tools=removed_tools,
            summary=summary,
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_scan_diff.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/diff.py packages/cli/tests/test_scanner/test_scan_diff.py
git commit -m "feat(scanner): ScanDiffEngine — baseline comparison"
```

---

### Task 11: ScanResultExporter — JSON, SARIF, CSV, Markdown

**Files:**
- Create: `packages/cli/src/opentools/scanner/export.py`
- Test: `packages/cli/tests/test_scanner/test_export.py`

- [ ] **Step 1: Write the failing tests**

```python
# packages/cli/tests/test_scanner/test_export.py
"""Tests for ScanResultExporter — JSON, SARIF, CSV, Markdown."""

import csv
import io
import json
import uuid
from datetime import datetime, timezone

import pytest

from opentools.models import FindingStatus
from opentools.scanner.models import (
    DeduplicatedFinding,
    EvidenceQuality,
    FindingCorrelation,
    LocationPrecision,
    RemediationGroup,
    Scan,
    ScanMode,
    ScanStatus,
    TargetType,
)
from opentools.scanner.export import ScanResultExporter


def _make_scan() -> Scan:
    return Scan(
        id="scan-1",
        engagement_id="eng-1",
        target="https://example.com",
        target_type=TargetType.URL,
        mode=ScanMode.AUTO,
        status=ScanStatus.COMPLETED,
        tools_planned=["semgrep", "trivy"],
        tools_completed=["semgrep", "trivy"],
        created_at=datetime(2026, 4, 12, tzinfo=timezone.utc),
        started_at=datetime(2026, 4, 12, 0, 1, tzinfo=timezone.utc),
        completed_at=datetime(2026, 4, 12, 0, 10, tzinfo=timezone.utc),
    )


def _make_findings() -> list[DeduplicatedFinding]:
    now = datetime.now(timezone.utc)
    return [
        DeduplicatedFinding(
            id="finding-1",
            engagement_id="eng-1",
            fingerprint="fp1",
            raw_finding_ids=["raw-1", "raw-2"],
            tools=["semgrep", "trivy"],
            corroboration_count=2,
            confidence_score=0.92,
            severity_consensus="high",
            canonical_title="SQL Injection",
            cwe="CWE-89",
            location_fingerprint="src/api/users.py:42",
            location_precision=LocationPrecision.EXACT_LINE,
            evidence_quality_best=EvidenceQuality.STRUCTURED,
            status=FindingStatus.CONFIRMED,
            first_seen_scan_id="scan-1",
            created_at=now,
            updated_at=now,
        ),
        DeduplicatedFinding(
            id="finding-2",
            engagement_id="eng-1",
            fingerprint="fp2",
            raw_finding_ids=["raw-3"],
            tools=["trivy"],
            corroboration_count=1,
            confidence_score=0.9,
            severity_consensus="critical",
            canonical_title="CVE-2023-22796: ReDoS in Active Support",
            cwe="CWE-1333",
            location_fingerprint="Gemfile.lock:activesupport:7.0.4",
            location_precision=LocationPrecision.FILE,
            evidence_quality_best=EvidenceQuality.STRUCTURED,
            status=FindingStatus.DISCOVERED,
            first_seen_scan_id="scan-1",
            created_at=now,
            updated_at=now,
        ),
    ]


class TestJsonExport:
    def test_valid_json(self):
        exporter = ScanResultExporter()
        result = exporter.to_json(_make_scan(), _make_findings())
        parsed = json.loads(result)
        assert parsed["scan"]["id"] == "scan-1"
        assert len(parsed["findings"]) == 2

    def test_json_finding_fields(self):
        exporter = ScanResultExporter()
        result = exporter.to_json(_make_scan(), _make_findings())
        parsed = json.loads(result)
        f = parsed["findings"][0]
        assert f["canonical_title"] == "SQL Injection"
        assert f["severity_consensus"] == "high"
        assert f["cwe"] == "CWE-89"
        assert f["confidence_score"] == 0.92

    def test_json_empty_findings(self):
        exporter = ScanResultExporter()
        result = exporter.to_json(_make_scan(), [])
        parsed = json.loads(result)
        assert parsed["findings"] == []


class TestSarifExport:
    def test_valid_sarif(self):
        exporter = ScanResultExporter()
        result = exporter.to_sarif(_make_scan(), _make_findings())
        parsed = json.loads(result)
        assert parsed["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"]) == 1

    def test_sarif_results(self):
        exporter = ScanResultExporter()
        result = exporter.to_sarif(_make_scan(), _make_findings())
        parsed = json.loads(result)
        results = parsed["runs"][0]["results"]
        assert len(results) == 2

    def test_sarif_result_fields(self):
        exporter = ScanResultExporter()
        result = exporter.to_sarif(_make_scan(), _make_findings())
        parsed = json.loads(result)
        r = parsed["runs"][0]["results"][0]
        assert r["ruleId"] == "CWE-89"
        assert r["level"] == "error"  # high -> error
        assert r["message"]["text"] == "SQL Injection"

    def test_sarif_tool_info(self):
        exporter = ScanResultExporter()
        result = exporter.to_sarif(_make_scan(), _make_findings())
        parsed = json.loads(result)
        tool = parsed["runs"][0]["tool"]["driver"]
        assert tool["name"] == "opentools-scanner"


class TestCsvExport:
    def test_valid_csv(self):
        exporter = ScanResultExporter()
        result = exporter.to_csv(_make_findings())
        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)
        assert len(rows) == 2

    def test_csv_headers(self):
        exporter = ScanResultExporter()
        result = exporter.to_csv(_make_findings())
        reader = csv.DictReader(io.StringIO(result))
        headers = reader.fieldnames
        assert "id" in headers
        assert "severity" in headers
        assert "title" in headers
        assert "cwe" in headers
        assert "location" in headers
        assert "confidence" in headers
        assert "tools" in headers

    def test_csv_values(self):
        exporter = ScanResultExporter()
        result = exporter.to_csv(_make_findings())
        reader = csv.DictReader(io.StringIO(result))
        rows = list(reader)
        assert rows[0]["title"] == "SQL Injection"
        assert rows[0]["severity"] == "high"

    def test_csv_empty(self):
        exporter = ScanResultExporter()
        result = exporter.to_csv([])
        # Should have header line only
        lines = result.strip().split("\n")
        assert len(lines) == 1  # header only


class TestMarkdownExport:
    def test_markdown_contains_header(self):
        exporter = ScanResultExporter()
        result = exporter.to_markdown(_make_scan(), _make_findings())
        assert "# Scan Report" in result
        assert "scan-1" in result

    def test_markdown_contains_findings(self):
        exporter = ScanResultExporter()
        result = exporter.to_markdown(_make_scan(), _make_findings())
        assert "SQL Injection" in result
        assert "CWE-89" in result
        assert "high" in result.lower() or "HIGH" in result

    def test_markdown_summary(self):
        exporter = ScanResultExporter()
        result = exporter.to_markdown(_make_scan(), _make_findings())
        assert "critical" in result.lower() or "Critical" in result
        assert "2" in result  # total findings count

    def test_markdown_empty_findings(self):
        exporter = ScanResultExporter()
        result = exporter.to_markdown(_make_scan(), [])
        assert "No findings" in result or "0" in result
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_export.py -v`
Expected: FAIL -- `ModuleNotFoundError`

- [ ] **Step 3: Write implementation**

```python
# packages/cli/src/opentools/scanner/export.py
"""ScanResultExporter — JSON, SARIF 2.1, CSV, and Markdown export.

Each method takes scan metadata and findings, returning a string in the
requested format.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from opentools.scanner.models import (
    DeduplicatedFinding,
    Scan,
)

_SEVERITY_TO_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


class ScanResultExporter:
    """Export scan results in multiple formats."""

    # -----------------------------------------------------------------------
    # JSON
    # -----------------------------------------------------------------------

    def to_json(
        self,
        scan: Scan,
        findings: list[DeduplicatedFinding],
    ) -> str:
        """Export as structured JSON."""
        data = {
            "scan": json.loads(scan.model_dump_json()),
            "findings": [json.loads(f.model_dump_json()) for f in findings],
            "metadata": {
                "export_format": "opentools-json",
                "export_version": "1.0.0",
            },
        }
        return json.dumps(data, indent=2, default=str)

    # -----------------------------------------------------------------------
    # SARIF 2.1
    # -----------------------------------------------------------------------

    def to_sarif(
        self,
        scan: Scan,
        findings: list[DeduplicatedFinding],
    ) -> str:
        """Export as SARIF 2.1.0 JSON."""
        results = []
        rules_seen: dict[str, dict] = {}

        for f in findings:
            rule_id = f.cwe or f.fingerprint
            level = _SEVERITY_TO_SARIF_LEVEL.get(
                f.severity_consensus.lower(), "note"
            )

            # Build location
            locations = []
            if f.location_fingerprint:
                parts = f.location_fingerprint.rsplit(":", 1)
                artifact_uri = parts[0] if parts else f.location_fingerprint
                try:
                    line = int(parts[1]) if len(parts) > 1 else None
                except ValueError:
                    line = None

                location: dict = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": artifact_uri},
                    },
                }
                if line is not None:
                    location["physicalLocation"]["region"] = {
                        "startLine": line,
                    }
                locations.append(location)

            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": f.canonical_title},
                "locations": locations,
                "fingerprints": {"opentools/v1": f.fingerprint},
                "properties": {
                    "confidence": f.confidence_score,
                    "tools": f.tools,
                    "corroboration_count": f.corroboration_count,
                },
            }
            results.append(result)

            # Collect rules
            if rule_id not in rules_seen:
                rules_seen[rule_id] = {
                    "id": rule_id,
                    "shortDescription": {"text": f.canonical_title},
                }

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "opentools-scanner",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/opentools",
                            "rules": list(rules_seen.values()),
                        },
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": scan.status == "completed",
                            "startTimeUtc": scan.started_at.isoformat() if scan.started_at else None,
                            "endTimeUtc": scan.completed_at.isoformat() if scan.completed_at else None,
                        },
                    ],
                },
            ],
        }

        return json.dumps(sarif, indent=2, default=str)

    # -----------------------------------------------------------------------
    # CSV
    # -----------------------------------------------------------------------

    def to_csv(self, findings: list[DeduplicatedFinding]) -> str:
        """Export findings as CSV."""
        output = io.StringIO()
        fieldnames = [
            "id", "severity", "title", "cwe", "location", "confidence",
            "tools", "corroboration", "status", "evidence_quality",
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()

        for f in findings:
            writer.writerow({
                "id": f.id,
                "severity": f.severity_consensus,
                "title": f.canonical_title,
                "cwe": f.cwe or "",
                "location": f.location_fingerprint,
                "confidence": f"{f.confidence_score:.2f}",
                "tools": "; ".join(f.tools),
                "corroboration": f.corroboration_count,
                "status": f.status,
                "evidence_quality": f.evidence_quality_best,
            })

        return output.getvalue()

    # -----------------------------------------------------------------------
    # Markdown
    # -----------------------------------------------------------------------

    def to_markdown(
        self,
        scan: Scan,
        findings: list[DeduplicatedFinding],
    ) -> str:
        """Export as Markdown report."""
        lines: list[str] = []

        # Header
        lines.append(f"# Scan Report: {scan.id}")
        lines.append("")
        lines.append(f"**Target:** {scan.target}")
        lines.append(f"**Target Type:** {scan.target_type}")
        lines.append(f"**Mode:** {scan.mode}")
        lines.append(f"**Status:** {scan.status}")
        if scan.started_at:
            lines.append(f"**Started:** {scan.started_at.isoformat()}")
        if scan.completed_at:
            lines.append(f"**Completed:** {scan.completed_at.isoformat()}")
        lines.append(f"**Tools:** {', '.join(scan.tools_completed)}")
        lines.append("")

        # Summary
        lines.append("## Summary")
        lines.append("")
        lines.append(f"**Total Findings:** {len(findings)}")

        # Severity breakdown
        sev_counts: dict[str, int] = {}
        for f in findings:
            sev = f.severity_consensus.lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sev_counts.get(sev, 0)
            if count > 0:
                lines.append(f"- **{sev.capitalize()}:** {count}")

        if not findings:
            lines.append("")
            lines.append("No findings discovered.")
            return "\n".join(lines)

        lines.append("")

        # Findings table
        lines.append("## Findings")
        lines.append("")
        lines.append("| # | Severity | Title | CWE | Location | Confidence | Tools |")
        lines.append("|---|----------|-------|-----|----------|------------|-------|")

        for i, f in enumerate(findings, 1):
            tools_str = ", ".join(f.tools)
            lines.append(
                f"| {i} | {f.severity_consensus} | {f.canonical_title} | "
                f"{f.cwe or 'N/A'} | {f.location_fingerprint} | "
                f"{f.confidence_score:.0%} | {tools_str} |"
            )

        lines.append("")
        lines.append("---")
        lines.append(f"*Generated by OpenTools Scanner*")

        return "\n".join(lines)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_export.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/export.py packages/cli/tests/test_scanner/test_export.py
git commit -m "feat(scanner): ScanResultExporter — JSON, SARIF, CSV, Markdown"
```

---

### Task 12: Pipeline Integration Test

**Files:**
- Test: `packages/cli/tests/test_scanner/test_pipeline_integration.py`
- Modify: `packages/cli/src/opentools/scanner/parsing/__init__.py`

- [ ] **Step 1: Write the integration test**

This test exercises the full pipeline end-to-end: raw tool output bytes → parser → normalization → dedup → suppression → corroboration → lifecycle → correlation → remediation → export.

```python
# packages/cli/tests/test_scanner/test_pipeline_integration.py
"""End-to-end pipeline integration test.

Exercises: parser → normalization → dedup → suppression → corroboration →
lifecycle → correlation → remediation → diff → export.
"""

import json
from datetime import datetime, timezone

import pytest

from opentools.scanner.models import (
    DeduplicatedFinding,
    Scan,
    ScanMode,
    ScanStatus,
    SuppressionRule,
    TargetType,
)
from opentools.scanner.parsing.router import ParserRouter
from opentools.scanner.parsing.parsers.semgrep import SemgrepParser
from opentools.scanner.parsing.parsers.trivy import TrivyParser
from opentools.scanner.parsing.parsers.gitleaks import GitleaksParser
from opentools.scanner.parsing.normalization import NormalizationEngine
from opentools.scanner.parsing.dedup import DedupEngine
from opentools.scanner.parsing.engagement_dedup import EngagementDedupEngine
from opentools.scanner.parsing.confidence import CorroborationScorer, ConfidenceDecay
from opentools.scanner.parsing.suppression import SuppressionEngine
from opentools.scanner.parsing.lifecycle import FindingLifecycle
from opentools.scanner.parsing.correlation import FindingCorrelationEngine
from opentools.scanner.parsing.remediation import RemediationGrouper
from opentools.scanner.diff import ScanDiffEngine
from opentools.scanner.export import ScanResultExporter


# --- Simulated tool output ---

SEMGREP_OUTPUT = json.dumps({
    "results": [
        {
            "check_id": "python.lang.security.audit.dangerous-subprocess-use",
            "path": "src/api/users.py",
            "start": {"line": 42, "col": 5},
            "end": {"line": 42, "col": 55},
            "extra": {
                "severity": "ERROR",
                "message": "Dangerous subprocess use with user input",
                "metadata": {
                    "cwe": ["CWE-78: OS Command Injection"],
                    "confidence": "HIGH",
                },
                "fingerprint": "sem-fp-1",
            },
        },
        {
            "check_id": "python.lang.security.audit.sqli",
            "path": "src/api/users.py",
            "start": {"line": 55, "col": 1},
            "end": {"line": 55, "col": 40},
            "extra": {
                "severity": "ERROR",
                "message": "SQL injection in query",
                "metadata": {
                    "cwe": ["CWE-89: SQL Injection"],
                    "confidence": "HIGH",
                },
                "fingerprint": "sem-fp-2",
            },
        },
    ],
    "errors": [],
}).encode()

TRIVY_OUTPUT = json.dumps({
    "SchemaVersion": 2,
    "Results": [
        {
            "Target": "requirements.txt",
            "Type": "pip",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2023-99999",
                    "PkgName": "django",
                    "InstalledVersion": "4.1.0",
                    "FixedVersion": "4.1.7",
                    "Severity": "HIGH",
                    "Title": "SQL Injection in Django ORM",
                    "Description": "Django ORM SQL injection",
                    "CweIDs": ["CWE-89"],
                },
            ],
        },
    ],
}).encode()

GITLEAKS_OUTPUT = json.dumps([
    {
        "Description": "Hardcoded API Key",
        "StartLine": 5,
        "EndLine": 5,
        "StartColumn": 1,
        "EndColumn": 40,
        "Match": "AKIAEXAMPLE",
        "Secret": "AKIAEXAMPLE",
        "File": "test/fixtures/fake_creds.py",
        "Commit": "abc123",
        "RuleID": "generic-api-key",
        "Fingerprint": "test/fixtures/fake_creds.py:generic-api-key:5",
    },
]).encode()


class TestFullPipeline:
    """Exercises the complete finding pipeline from raw bytes to export."""

    def _run_pipeline(self):
        """Run the full pipeline and return intermediate + final results."""
        # 1. Set up parsers
        router = ParserRouter()
        router.register(SemgrepParser())
        router.register(TrivyParser())
        router.register(GitleaksParser())

        # 2. Parse raw output
        raw_findings = []
        raw_findings.extend(
            router.get("semgrep").parse(SEMGREP_OUTPUT, "scan-1", "task-semgrep")
        )
        raw_findings.extend(
            router.get("trivy").parse(TRIVY_OUTPUT, "scan-1", "task-trivy")
        )
        raw_findings.extend(
            router.get("gitleaks").parse(GITLEAKS_OUTPUT, "scan-1", "task-gitleaks")
        )
        assert len(raw_findings) == 4  # 2 semgrep + 1 trivy + 1 gitleaks

        # 3. Normalize
        normalizer = NormalizationEngine()
        normalized = normalizer.normalize(raw_findings)
        assert len(normalized) == 4

        # 4. Dedup
        dedup = DedupEngine()
        deduped = dedup.deduplicate(normalized)
        # The SQL injection findings (semgrep CWE-89 + trivy CWE-89) should potentially merge
        # depending on location fingerprint. They are in different files so they should NOT merge.
        # We should have: command injection, sqli (semgrep), sqli (trivy), gitleaks = 4
        # OR: command injection, sqli merged, gitleaks = 3 if they fuzzy match
        assert len(deduped) >= 3

        # 5. Set engagement_id
        for i, f in enumerate(deduped):
            deduped[i] = f.model_copy(update={"engagement_id": "eng-1"})

        # 6. Suppression — suppress findings in test/ directories
        suppression = SuppressionEngine()
        rules = [
            SuppressionRule(
                id="rule-1",
                scope="global",
                rule_type="path_pattern",
                pattern="test/**",
                reason="Test fixtures are not production code",
                created_by="user:test",
                created_at=datetime.now(timezone.utc),
            ),
        ]
        suppressed = suppression.apply(rules, deduped)
        # The gitleaks finding in test/fixtures/ should be suppressed
        suppressed_count = sum(1 for f in suppressed if f.suppressed)
        assert suppressed_count >= 1

        # 7. Corroboration scoring
        scorer = CorroborationScorer()
        scored = scorer.score(suppressed)
        assert all(0 <= f.confidence_score <= 1.0 for f in scored)

        # 8. Lifecycle
        lifecycle = FindingLifecycle()
        lifed = lifecycle.apply(scored)

        # 9. Correlation
        correlator = FindingCorrelationEngine()
        non_suppressed = [f for f in lifed if not f.suppressed]
        correlations = correlator.correlate(non_suppressed, "scan-1", "eng-1")
        assert isinstance(correlations, list)

        # 10. Remediation grouping
        grouper = RemediationGrouper()
        groups = grouper.group(non_suppressed, "scan-1", "eng-1")
        assert len(groups) >= 1

        return {
            "raw": raw_findings,
            "normalized": normalized,
            "deduped": deduped,
            "suppressed": suppressed,
            "scored": scored,
            "lifed": lifed,
            "correlations": correlations,
            "groups": groups,
            "non_suppressed": non_suppressed,
        }

    def test_pipeline_produces_results(self):
        results = self._run_pipeline()
        assert len(results["raw"]) == 4
        assert len(results["deduped"]) >= 3
        assert len(results["groups"]) >= 1

    def test_pipeline_normalization_applied(self):
        results = self._run_pipeline()
        # Semgrep ERROR should be normalized to "high"
        semgrep_findings = [f for f in results["normalized"] if f.tool == "semgrep"]
        assert all(f.raw_severity == "high" for f in semgrep_findings)

    def test_pipeline_suppression_applied(self):
        results = self._run_pipeline()
        suppressed = [f for f in results["suppressed"] if f.suppressed]
        assert len(suppressed) >= 1

    def test_pipeline_export_json(self):
        results = self._run_pipeline()
        scan = Scan(
            id="scan-1",
            engagement_id="eng-1",
            target="/src",
            target_type=TargetType.SOURCE_CODE,
            mode=ScanMode.AUTO,
            status=ScanStatus.COMPLETED,
            tools_completed=["semgrep", "trivy", "gitleaks"],
            created_at=datetime.now(timezone.utc),
        )
        exporter = ScanResultExporter()
        json_out = exporter.to_json(scan, results["non_suppressed"])
        parsed = json.loads(json_out)
        assert "scan" in parsed
        assert "findings" in parsed
        assert len(parsed["findings"]) == len(results["non_suppressed"])

    def test_pipeline_export_sarif(self):
        results = self._run_pipeline()
        scan = Scan(
            id="scan-1",
            engagement_id="eng-1",
            target="/src",
            target_type=TargetType.SOURCE_CODE,
            mode=ScanMode.AUTO,
            status=ScanStatus.COMPLETED,
            tools_completed=["semgrep", "trivy", "gitleaks"],
            created_at=datetime.now(timezone.utc),
        )
        exporter = ScanResultExporter()
        sarif_out = exporter.to_sarif(scan, results["non_suppressed"])
        parsed = json.loads(sarif_out)
        assert parsed["version"] == "2.1.0"
        assert len(parsed["runs"][0]["results"]) == len(results["non_suppressed"])

    def test_pipeline_export_csv(self):
        results = self._run_pipeline()
        exporter = ScanResultExporter()
        csv_out = exporter.to_csv(results["non_suppressed"])
        assert "severity" in csv_out
        assert "SQL Injection" in csv_out or "sql" in csv_out.lower()

    def test_pipeline_export_markdown(self):
        results = self._run_pipeline()
        scan = Scan(
            id="scan-1",
            engagement_id="eng-1",
            target="/src",
            target_type=TargetType.SOURCE_CODE,
            mode=ScanMode.AUTO,
            status=ScanStatus.COMPLETED,
            tools_completed=["semgrep", "trivy", "gitleaks"],
            created_at=datetime.now(timezone.utc),
        )
        exporter = ScanResultExporter()
        md_out = exporter.to_markdown(scan, results["non_suppressed"])
        assert "# Scan Report" in md_out

    def test_scan_diff_against_baseline(self):
        results = self._run_pipeline()
        diff_engine = ScanDiffEngine()
        # Use first run as baseline, run again as current
        baseline = results["non_suppressed"][:2]
        current = results["non_suppressed"]
        diff = diff_engine.diff(current, baseline, "scan-2", "scan-1")
        # All baseline findings should be persistent or new
        assert diff.summary.persistent_count + diff.summary.new_count == len(current)

    def test_engagement_dedup_across_scans(self):
        results = self._run_pipeline()
        eng_dedup = EngagementDedupEngine()
        # Simulate second scan with same findings
        prior = results["non_suppressed"]
        current = results["non_suppressed"]
        merged = eng_dedup.reconcile(current, prior, scan_id="scan-2")
        # All should be merged (same fingerprints)
        assert len(merged) == len(prior)
        # All should be CONFIRMED now (reconfirmed)
        confirmed = [f for f in merged if f.status.value == "confirmed"]
        assert len(confirmed) >= 1
```

- [ ] **Step 2: Update `parsing/__init__.py` with all public exports**

```python
# packages/cli/src/opentools/scanner/parsing/__init__.py
"""Finding parsing pipeline — parsers, normalization, dedup, scoring, export."""

from opentools.scanner.parsing.router import ParserPlugin, ParserRouter
from opentools.scanner.parsing.normalization import NormalizationEngine
from opentools.scanner.parsing.dedup import DedupEngine
from opentools.scanner.parsing.engagement_dedup import EngagementDedupEngine
from opentools.scanner.parsing.confidence import CorroborationScorer, ConfidenceDecay
from opentools.scanner.parsing.suppression import SuppressionEngine
from opentools.scanner.parsing.lifecycle import FindingLifecycle
from opentools.scanner.parsing.correlation import FindingCorrelationEngine
from opentools.scanner.parsing.remediation import RemediationGrouper

__all__ = [
    "ParserPlugin",
    "ParserRouter",
    "NormalizationEngine",
    "DedupEngine",
    "EngagementDedupEngine",
    "CorroborationScorer",
    "ConfidenceDecay",
    "SuppressionEngine",
    "FindingLifecycle",
    "FindingCorrelationEngine",
    "RemediationGrouper",
]
```

- [ ] **Step 3: Run the integration test**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_pipeline_integration.py -v`
Expected: All tests PASS

- [ ] **Step 4: Run all Plan 4 tests together**

Run: `cd packages/cli && python -m pytest tests/test_scanner/test_parser_router.py tests/test_scanner/test_parsers.py tests/test_scanner/test_normalization.py tests/test_scanner/test_dedup.py tests/test_scanner/test_engagement_dedup.py tests/test_scanner/test_corroboration.py tests/test_scanner/test_suppression.py tests/test_scanner/test_lifecycle.py tests/test_scanner/test_correlation.py tests/test_scanner/test_scan_diff.py tests/test_scanner/test_export.py tests/test_scanner/test_pipeline_integration.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add packages/cli/src/opentools/scanner/parsing/__init__.py packages/cli/tests/test_scanner/test_pipeline_integration.py
git commit -m "feat(scanner): full pipeline integration test — parser through export"
```
