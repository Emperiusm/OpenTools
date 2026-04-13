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
