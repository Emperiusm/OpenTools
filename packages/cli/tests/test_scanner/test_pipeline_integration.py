"""End-to-end pipeline integration test.

Exercises: parser -> normalization -> dedup -> suppression -> corroboration ->
lifecycle -> correlation -> remediation -> diff -> export.
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
