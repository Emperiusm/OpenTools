import json
import pytest
from opentools.parsers import get_parser, list_parsers


SEMGREP_OUTPUT = json.dumps({
    "results": [
        {
            "check_id": "python.lang.security.audit.dangerous-system-call",
            "path": "app.py",
            "start": {"line": 42, "col": 1},
            "end": {"line": 42, "col": 30},
            "extra": {
                "message": "Detected dangerous system call",
                "severity": "ERROR",
                "metadata": {"cwe": ["CWE-78: OS Command Injection"]},
            },
        }
    ]
})

NUCLEI_OUTPUT = (
    json.dumps({
        "template-id": "cve-2021-44228",
        "info": {"name": "Log4Shell RCE", "severity": "critical",
                 "classification": {"cwe-id": ["CWE-502"]}},
        "matched-at": "https://target.com/api",
        "host": "target.com",
    })
)

TRIVY_OUTPUT = json.dumps({
    "Results": [{
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2023-1234",
            "PkgName": "openssl",
            "Severity": "HIGH",
            "Title": "OpenSSL buffer overflow",
            "Description": "A buffer overflow in OpenSSL allows...",
        }]
    }]
})

GITLEAKS_OUTPUT = json.dumps([{
    "Description": "AWS Access Key",
    "File": "config/settings.py",
    "StartLine": 15,
    "EndLine": 15,
    "Secret": "AKIA***",
    "RuleID": "aws-access-key",
}])

CAPA_OUTPUT = json.dumps({
    "rules": {
        "create mutex": {
            "meta": {"name": "create mutex", "att&ck": [{"technique": "Synchronization", "id": "T1559"}]},
        },
        "encrypt data": {
            "meta": {"name": "encrypt data using AES", "att&ck": [{"technique": "Encrypted Channel", "id": "T1573"}]},
        },
    }
})


def test_list_parsers():
    parsers = list_parsers()
    assert "semgrep" in parsers
    assert "nuclei" in parsers
    assert "trivy" in parsers
    assert "gitleaks" in parsers
    assert "capa" in parsers


def test_semgrep_parser():
    parser = get_parser("semgrep")
    assert parser is not None
    findings = parser(SEMGREP_OUTPUT)
    assert len(findings) == 1
    assert findings[0].file_path == "app.py"
    assert findings[0].line_start == 42
    assert findings[0].tool == "semgrep"


def test_nuclei_parser():
    parser = get_parser("nuclei")
    assert parser is not None
    findings = parser(NUCLEI_OUTPUT)
    assert len(findings) == 1
    assert findings[0].severity.value == "critical"
    assert findings[0].tool == "nuclei"


def test_trivy_parser():
    parser = get_parser("trivy")
    assert parser is not None
    findings = parser(TRIVY_OUTPUT)
    assert len(findings) == 1
    assert "openssl" in findings[0].title.lower() or "openssl" in findings[0].description.lower()
    assert findings[0].severity.value == "high"


def test_gitleaks_parser():
    parser = get_parser("gitleaks")
    assert parser is not None
    findings = parser(GITLEAKS_OUTPUT)
    assert len(findings) == 1
    assert findings[0].cwe == "CWE-798"
    assert findings[0].file_path == "config/settings.py"


def test_capa_parser():
    parser = get_parser("capa")
    assert parser is not None
    findings = parser(CAPA_OUTPUT)
    assert len(findings) == 2
    assert all(f.tool == "capa" for f in findings)


def test_get_parser_unknown():
    parser = get_parser("nonexistent_tool_xyz")
    assert parser is None


def test_empty_input():
    parser = get_parser("semgrep")
    findings = parser(json.dumps({"results": []}))
    assert findings == []
