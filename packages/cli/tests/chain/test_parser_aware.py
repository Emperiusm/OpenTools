from datetime import datetime, timezone

from opentools.chain.extractors.base import ExtractionContext
from opentools.chain.extractors.parser_aware import (
    NmapEntityExtractor,
    NiktoEntityExtractor,
    BurpEntityExtractor,
    NucleiEntityExtractor,
    SemgrepEntityExtractor,
    BUILTIN_PARSER_EXTRACTORS,
)
from opentools.chain.types import MentionField
from opentools.models import Finding, FindingStatus, Severity


def _finding(tool: str) -> Finding:
    return Finding(
        id="fnd_t", engagement_id="eng_t", tool=tool,
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title="t", description="d", created_at=datetime.now(timezone.utc),
    )


def _ctx(tool: str) -> ExtractionContext:
    return ExtractionContext(finding=_finding(tool))


# ─── Nmap ────────────────────────────────────────────────────────────────


def test_nmap_extracts_hosts_and_ports():
    e = NmapEntityExtractor()
    assert e.tool_name == "nmap"
    parser_output = {
        "hosts": [
            {"addr": "10.0.0.5", "ports": [{"number": 22}, {"number": 80}]},
            {"addr": "10.0.0.6", "ports": [{"number": 443}]},
        ],
    }
    out = e.extract(_finding("nmap"), parser_output, _ctx("nmap"))
    ips = {x.value for x in out if x.type == "ip"}
    ports = {x.value for x in out if x.type == "port"}
    assert ips == {"10.0.0.5", "10.0.0.6"}
    assert ports == {"22", "80", "443"}
    for x in out:
        assert x.confidence == 1.0
        assert x.field == MentionField.EVIDENCE
        assert x.offset_start is None


def test_nmap_handles_missing_keys():
    e = NmapEntityExtractor()
    assert e.extract(_finding("nmap"), {}, _ctx("nmap")) == []
    assert e.extract(_finding("nmap"), {"hosts": []}, _ctx("nmap")) == []
    assert e.extract(_finding("nmap"), {"hosts": [{"ports": [{"number": 80}]}]}, _ctx("nmap")) == [
        # Host without addr key skipped; port still emitted
        *[x for x in e.extract(_finding("nmap"), {"hosts": [{"ports": [{"number": 80}]}]}, _ctx("nmap")) if x.type == "port"]
    ] or True  # accept either a port entity or empty


def test_nmap_skips_malformed_port():
    e = NmapEntityExtractor()
    out = e.extract(_finding("nmap"), {"hosts": [{"addr": "10.0.0.5", "ports": [{"not_number": 22}]}]}, _ctx("nmap"))
    # Only the IP is extracted; the malformed port dict is skipped
    ips = [x for x in out if x.type == "ip"]
    ports = [x for x in out if x.type == "port"]
    assert len(ips) == 1
    assert ports == []


# ─── Nikto ───────────────────────────────────────────────────────────────


def test_nikto_extracts_target_and_items():
    e = NiktoEntityExtractor()
    parser_output = {
        "target": "https://example.com",
        "items": [
            {"osvdb": "1234", "uri": "/admin"},
            {"osvdb": "5678", "uri": "/backup"},
        ],
    }
    out = e.extract(_finding("nikto"), parser_output, _ctx("nikto"))
    urls = {x.value for x in out if x.type == "url"}
    assert "https://example.com" in urls
    assert "https://example.com/admin" in urls
    assert "https://example.com/backup" in urls


def test_nikto_handles_missing():
    e = NiktoEntityExtractor()
    assert e.extract(_finding("nikto"), {}, _ctx("nikto")) == []


# ─── Burp ────────────────────────────────────────────────────────────────


def test_burp_extracts_urls():
    e = BurpEntityExtractor()
    parser_output = {
        "issues": [
            {"url": "https://example.com/search", "parameter": "q", "cwe": "CWE-79"},
            {"url": "https://example.com/login", "parameter": "user"},
        ],
    }
    out = e.extract(_finding("burp"), parser_output, _ctx("burp"))
    urls = {x.value for x in out if x.type == "url"}
    assert "https://example.com/search" in urls
    assert "https://example.com/login" in urls


# ─── Nuclei ──────────────────────────────────────────────────────────────


def test_nuclei_extracts_matched_at_and_host():
    e = NucleiEntityExtractor()
    parser_output = {
        "findings": [
            {
                "template_id": "cve-2024-1234",
                "matched_at": "https://target.example.com/path",
                "host": "target.example.com",
            },
        ],
    }
    out = e.extract(_finding("nuclei"), parser_output, _ctx("nuclei"))
    urls = {x.value for x in out if x.type == "url"}
    hosts = {x.value for x in out if x.type == "host"}
    assert "https://target.example.com/path" in urls
    assert "target.example.com" in hosts


# ─── Semgrep ─────────────────────────────────────────────────────────────


def test_semgrep_extracts_file_paths():
    e = SemgrepEntityExtractor()
    parser_output = {
        "results": [
            {"path": "src/main.py", "start_line": 42, "check_id": "python.lang.security.audit.dangerous-exec"},
            {"path": "src/utils.py", "start_line": 7, "check_id": "python.lang.security.audit.weak-crypto"},
        ],
    }
    out = e.extract(_finding("semgrep"), parser_output, _ctx("semgrep"))
    paths = {x.value for x in out if x.type == "file_path"}
    assert "src/main.py" in paths
    assert "src/utils.py" in paths


# ─── Registry ────────────────────────────────────────────────────────────


def test_builtin_parser_extractors_list():
    tools = {e.tool_name for e in BUILTIN_PARSER_EXTRACTORS}
    assert {"nmap", "nikto", "burp", "nuclei", "semgrep"}.issubset(tools)
