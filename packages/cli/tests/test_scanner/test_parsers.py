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
