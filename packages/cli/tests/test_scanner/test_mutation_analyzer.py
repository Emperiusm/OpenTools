"""Tests for OutputAnalyzer protocol, NmapAnalyzer, NucleiAnalyzer, and AnalyzerRegistry."""
from __future__ import annotations

import pytest

from opentools.scanner.mutation.analyzer import (
    AnalyzerRegistry,
    NmapAnalyzer,
    NucleiAnalyzer,
    OutputAnalyzer,
)
from opentools.scanner.mutation.models import IntelBundle


# ---------------------------------------------------------------------------
# Fixtures — Nmap XML
# ---------------------------------------------------------------------------

NMAP_TWO_OPEN_ONE_CLOSED = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX - 10.0.0.1" start="1700000000" version="7.94">
  <host starttime="1700000001" endtime="1700000002">
    <status state="up" reason="echo-reply"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <hostnames>
      <hostname name="target.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="closed" reason="reset"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="Apache httpd" version="2.4.54"/>
      </port>
      <port protocol="tcp" portid="6379">
        <state state="open" reason="syn-ack"/>
        <service name="redis" product="Redis key-value store" version="7.0.8"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NMAP_NO_OPEN_PORTS = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="filtered" reason="no-response"/>
        <service name="https"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

NMAP_MULTI_HOST = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="3306">
        <state state="open" reason="syn-ack"/>
        <service name="mysql" product="MySQL" version="8.0.31"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""

# ---------------------------------------------------------------------------
# Fixtures — Nuclei JSON-lines
# ---------------------------------------------------------------------------

NUCLEI_TWO_VULNS = """\
{"template-id":"CVE-2021-44228","host":"https://example.com","port":443,"matched-at":"https://example.com/log4shell","info":{"severity":"critical","name":"Log4Shell"},"extracted-results":["jndi:ldap://attacker.com/a"]}
{"template-id":"exposed-git","host":"https://example.com","port":80,"matched-at":"https://example.com/.git/config","info":{"severity":"medium","name":"Exposed Git"}}
"""


# ---------------------------------------------------------------------------
# TestNmapAnalyzer
# ---------------------------------------------------------------------------


class TestNmapAnalyzer:
    def setup_method(self):
        self.analyzer = NmapAnalyzer()

    def test_tool_name(self):
        assert self.analyzer.tool == "nmap"

    def test_implements_protocol(self):
        assert isinstance(self.analyzer, OutputAnalyzer)

    def test_extracts_open_services(self):
        bundle = self.analyzer.analyze(NMAP_TWO_OPEN_ONE_CLOSED, "")
        assert len(bundle.services) == 2

        # Check both ports are present
        ports = {svc.port for svc in bundle.services}
        assert ports == {80, 6379}

    def test_service_fields_http(self):
        bundle = self.analyzer.analyze(NMAP_TWO_OPEN_ONE_CLOSED, "")
        http_svcs = [s for s in bundle.services if s.port == 80]
        assert len(http_svcs) == 1
        svc = http_svcs[0]
        assert svc.host == "10.0.0.1"
        assert svc.protocol == "tcp"
        assert svc.service == "http"
        assert svc.product == "Apache httpd"
        assert svc.version == "2.4.54"

    def test_service_fields_redis(self):
        bundle = self.analyzer.analyze(NMAP_TWO_OPEN_ONE_CLOSED, "")
        redis_svcs = [s for s in bundle.services if s.port == 6379]
        assert len(redis_svcs) == 1
        svc = redis_svcs[0]
        assert svc.host == "10.0.0.1"
        assert svc.service == "redis"
        assert svc.product == "Redis key-value store"
        assert svc.version == "7.0.8"

    def test_skips_closed_ports(self):
        bundle = self.analyzer.analyze(NMAP_TWO_OPEN_ONE_CLOSED, "")
        # SSH port 22 is closed — must not appear
        ssh_ports = [s for s in bundle.services if s.port == 22]
        assert ssh_ports == []

    def test_no_open_ports_returns_empty(self):
        bundle = self.analyzer.analyze(NMAP_NO_OPEN_PORTS, "")
        assert bundle.services == []
        assert isinstance(bundle, IntelBundle)

    def test_multi_host(self):
        bundle = self.analyzer.analyze(NMAP_MULTI_HOST, "")
        assert len(bundle.services) == 2
        hosts = {svc.host for svc in bundle.services}
        assert hosts == {"10.0.0.1", "10.0.0.2"}
        services = {svc.service for svc in bundle.services}
        assert services == {"ssh", "mysql"}

    def test_invalid_xml_returns_empty(self):
        bundle = self.analyzer.analyze("this is not xml <<<", "")
        assert bundle.services == []
        assert isinstance(bundle, IntelBundle)

    def test_empty_stdout_returns_empty(self):
        bundle = self.analyzer.analyze("", "")
        assert bundle.services == []
        assert isinstance(bundle, IntelBundle)

    def test_whitespace_only_stdout_returns_empty(self):
        bundle = self.analyzer.analyze("   \n\t  ", "")
        assert bundle.services == []

    def test_wrong_root_tag_returns_empty(self):
        bundle = self.analyzer.analyze("<scanresult><host/></scanresult>", "")
        assert bundle.services == []

    def test_no_vulns_or_urls_in_nmap_bundle(self):
        bundle = self.analyzer.analyze(NMAP_TWO_OPEN_ONE_CLOSED, "")
        assert bundle.vulns == []
        assert bundle.urls == []


# ---------------------------------------------------------------------------
# TestNucleiAnalyzer
# ---------------------------------------------------------------------------


class TestNucleiAnalyzer:
    def setup_method(self):
        self.analyzer = NucleiAnalyzer()

    def test_tool_name(self):
        assert self.analyzer.tool == "nuclei"

    def test_implements_protocol(self):
        assert isinstance(self.analyzer, OutputAnalyzer)

    def test_extracts_vulns_count(self):
        bundle = self.analyzer.analyze(NUCLEI_TWO_VULNS, "")
        assert len(bundle.vulns) == 2

    def test_extracts_template_ids(self):
        bundle = self.analyzer.analyze(NUCLEI_TWO_VULNS, "")
        template_ids = {v.template_id for v in bundle.vulns}
        assert template_ids == {"CVE-2021-44228", "exposed-git"}

    def test_vuln_fields_log4shell(self):
        bundle = self.analyzer.analyze(NUCLEI_TWO_VULNS, "")
        log4 = next(v for v in bundle.vulns if v.template_id == "CVE-2021-44228")
        assert log4.host == "https://example.com"
        assert log4.port == 443
        assert log4.severity == "critical"
        assert log4.matched_at == "https://example.com/log4shell"

    def test_vuln_fields_exposed_git(self):
        bundle = self.analyzer.analyze(NUCLEI_TWO_VULNS, "")
        git = next(v for v in bundle.vulns if v.template_id == "exposed-git")
        assert git.port == 80
        assert git.severity == "medium"
        assert git.matched_at == "https://example.com/.git/config"

    def test_port_is_int(self):
        bundle = self.analyzer.analyze(NUCLEI_TWO_VULNS, "")
        for vuln in bundle.vulns:
            assert isinstance(vuln.port, int)

    def test_extracts_urls_from_matched_at(self):
        bundle = self.analyzer.analyze(NUCLEI_TWO_VULNS, "")
        assert "https://example.com/log4shell" in bundle.urls
        assert "https://example.com/.git/config" in bundle.urls

    def test_extracted_results_stored(self):
        bundle = self.analyzer.analyze(NUCLEI_TWO_VULNS, "")
        log4 = next(v for v in bundle.vulns if v.template_id == "CVE-2021-44228")
        assert "extracted_results" in log4.extracted_data
        assert log4.extracted_data["extracted_results"] == ["jndi:ldap://attacker.com/a"]

    def test_empty_output_returns_empty(self):
        bundle = self.analyzer.analyze("", "")
        assert bundle.vulns == []
        assert bundle.urls == []
        assert isinstance(bundle, IntelBundle)

    def test_whitespace_only_returns_empty(self):
        bundle = self.analyzer.analyze("   \n   ", "")
        assert bundle.vulns == []

    def test_invalid_json_lines_skipped(self):
        mixed = 'not json at all\n{"template-id":"test-id","host":"h","matched-at":"http://h","info":{"severity":"low"}}\nbad line'
        bundle = self.analyzer.analyze(mixed, "")
        assert len(bundle.vulns) == 1
        assert bundle.vulns[0].template_id == "test-id"

    def test_all_invalid_json_returns_empty(self):
        bad = "garbage\nnot json\n{broken"
        bundle = self.analyzer.analyze(bad, "")
        assert bundle.vulns == []
        assert bundle.urls == []

    def test_no_services_in_nuclei_bundle(self):
        bundle = self.analyzer.analyze(NUCLEI_TWO_VULNS, "")
        assert bundle.services == []

    def test_extracted_results_string_ignored(self):
        line = '{"template-id":"test-str","host":"h","matched-at":"http://h","info":{"severity":"low"},"extracted-results":"single string"}'
        bundle = self.analyzer.analyze(line, "")
        assert len(bundle.vulns) == 1
        assert "extracted_results" not in bundle.vulns[0].extracted_data

    def test_extracted_results_null_ignored(self):
        line = '{"template-id":"test-null","host":"h","matched-at":"http://h","info":{"severity":"low"},"extracted-results":null}'
        bundle = self.analyzer.analyze(line, "")
        assert len(bundle.vulns) == 1
        assert "extracted_results" not in bundle.vulns[0].extracted_data


# ---------------------------------------------------------------------------
# TestAnalyzerRegistry
# ---------------------------------------------------------------------------


class TestAnalyzerRegistry:
    def setup_method(self):
        self.registry = AnalyzerRegistry()

    def test_register_and_get(self):
        analyzer = NmapAnalyzer()
        self.registry.register(analyzer)
        result = self.registry.get("nmap")
        assert result is analyzer

    def test_get_missing_returns_none(self):
        result = self.registry.get("nonexistent_tool")
        assert result is None

    def test_register_overwrites_existing(self):
        a1 = NmapAnalyzer()
        a2 = NmapAnalyzer()
        self.registry.register(a1)
        self.registry.register(a2)
        assert self.registry.get("nmap") is a2

    def test_get_builtin_analyzers(self):
        self.registry.register_builtins()
        nmap_analyzer = self.registry.get("nmap")
        nuclei_analyzer = self.registry.get("nuclei")
        assert nmap_analyzer is not None
        assert nuclei_analyzer is not None
        assert isinstance(nmap_analyzer, NmapAnalyzer)
        assert isinstance(nuclei_analyzer, NucleiAnalyzer)

    def test_builtins_are_functional(self):
        self.registry.register_builtins()
        nmap = self.registry.get("nmap")
        bundle = nmap.analyze(NMAP_TWO_OPEN_ONE_CLOSED, "")
        assert len(bundle.services) == 2

        nuclei = self.registry.get("nuclei")
        bundle = nuclei.analyze(NUCLEI_TWO_VULNS, "")
        assert len(bundle.vulns) == 2

    def test_registry_starts_empty(self):
        assert self.registry.get("nmap") is None
        assert self.registry.get("nuclei") is None
