"""Tests for mutation layer data models: KillChainState, IntelBundle, etc."""
from __future__ import annotations

import pytest

from opentools.scanner.mutation.models import (
    DiscoveredService,
    DiscoveredVuln,
    IntelBundle,
    KillChainState,
)


# ---------------------------------------------------------------------------
# DiscoveredService
# ---------------------------------------------------------------------------


class TestDiscoveredService:
    def test_construction_required_fields(self):
        svc = DiscoveredService(host="10.0.0.1", port=22, protocol="tcp", service="ssh")
        assert svc.host == "10.0.0.1"
        assert svc.port == 22
        assert svc.protocol == "tcp"
        assert svc.service == "ssh"

    def test_optional_fields_default_none(self):
        svc = DiscoveredService(host="10.0.0.1", port=80, protocol="tcp", service="http")
        assert svc.product is None
        assert svc.version is None
        assert svc.banner is None

    def test_optional_fields_populated(self):
        svc = DiscoveredService(
            host="10.0.0.1",
            port=6379,
            protocol="tcp",
            service="redis",
            product="Redis",
            version="7.0.5",
            banner="*1\r\n$7\r\nCOMMAND\r\n",
        )
        assert svc.product == "Redis"
        assert svc.version == "7.0.5"
        assert svc.banner == "*1\r\n$7\r\nCOMMAND\r\n"

    def test_udp_protocol(self):
        svc = DiscoveredService(host="10.0.0.1", port=53, protocol="udp", service="dns")
        assert svc.protocol == "udp"

    def test_immutable_model(self):
        """Pydantic v2 models are mutable by default; just verify round-trip works."""
        svc = DiscoveredService(host="1.2.3.4", port=443, protocol="tcp", service="https")
        data = svc.model_dump()
        svc2 = DiscoveredService(**data)
        assert svc == svc2


# ---------------------------------------------------------------------------
# DiscoveredVuln
# ---------------------------------------------------------------------------


class TestDiscoveredVuln:
    def test_construction_required_fields(self):
        vuln = DiscoveredVuln(
            host="10.0.0.1",
            port=6379,
            template_id="redis-unauth",
            severity="critical",
            matched_at="redis://10.0.0.1:6379",
        )
        assert vuln.host == "10.0.0.1"
        assert vuln.port == 6379
        assert vuln.template_id == "redis-unauth"
        assert vuln.severity == "critical"
        assert vuln.matched_at == "redis://10.0.0.1:6379"

    def test_port_optional_none(self):
        vuln = DiscoveredVuln(
            host="10.0.0.1",
            port=None,
            template_id="generic-header-check",
            severity="info",
            matched_at="http://10.0.0.1/",
        )
        assert vuln.port is None

    def test_extracted_data_defaults_empty(self):
        vuln = DiscoveredVuln(
            host="10.0.0.1",
            port=80,
            template_id="xss-reflected",
            severity="medium",
            matched_at="http://10.0.0.1/search?q=test",
        )
        assert vuln.extracted_data == {}

    def test_extracted_data_populated(self):
        vuln = DiscoveredVuln(
            host="10.0.0.1",
            port=8080,
            template_id="sqli-error-based",
            severity="high",
            matched_at="http://10.0.0.1/api/users",
            extracted_data={"payload": "' OR '1'='1", "error": "syntax error"},
        )
        assert vuln.extracted_data["payload"] == "' OR '1'='1"

    def test_round_trip(self):
        vuln = DiscoveredVuln(
            host="1.2.3.4",
            port=443,
            template_id="ssl-weak-cipher",
            severity="low",
            matched_at="https://1.2.3.4/",
        )
        assert DiscoveredVuln(**vuln.model_dump()) == vuln


# ---------------------------------------------------------------------------
# IntelBundle
# ---------------------------------------------------------------------------


class TestIntelBundle:
    def test_empty_defaults(self):
        bundle = IntelBundle()
        assert bundle.services == []
        assert bundle.vulns == []
        assert bundle.urls == []
        assert bundle.metadata == {}

    def test_with_services(self):
        svc = DiscoveredService(host="10.0.0.1", port=22, protocol="tcp", service="ssh")
        bundle = IntelBundle(services=[svc])
        assert len(bundle.services) == 1
        assert bundle.services[0].service == "ssh"

    def test_with_vulns(self):
        vuln = DiscoveredVuln(
            host="10.0.0.1",
            port=80,
            template_id="cve-2023-12345",
            severity="high",
            matched_at="http://10.0.0.1/vuln",
        )
        bundle = IntelBundle(vulns=[vuln])
        assert len(bundle.vulns) == 1

    def test_with_urls(self):
        bundle = IntelBundle(urls=["http://10.0.0.1/admin", "http://10.0.0.1/api"])
        assert len(bundle.urls) == 2

    def test_with_metadata(self):
        bundle = IntelBundle(metadata={"task_id": "nmap-001", "duration_s": 12.3})
        assert bundle.metadata["task_id"] == "nmap-001"

    def test_independent_default_factories(self):
        """Each IntelBundle instance must get its own list objects."""
        b1 = IntelBundle()
        b2 = IntelBundle()
        b1.services.append(
            DiscoveredService(host="1.2.3.4", port=80, protocol="tcp", service="http")
        )
        assert b2.services == []


# ---------------------------------------------------------------------------
# KillChainState
# ---------------------------------------------------------------------------


class TestKillChainState:
    def test_empty_defaults(self):
        state = KillChainState()
        assert state.services == {}
        assert state.vulns == {}
        assert state.urls == set()
        assert state.tasks_spawned == {}
        assert state.total_spawned == 0

    def test_ingest_services(self):
        state = KillChainState()
        bundle = IntelBundle(
            services=[
                DiscoveredService(host="10.0.0.1", port=22, protocol="tcp", service="ssh"),
                DiscoveredService(host="10.0.0.1", port=80, protocol="tcp", service="http"),
            ]
        )
        state.ingest(bundle)
        assert len(state.services) == 2
        assert "10.0.0.1:22/tcp" in state.services
        assert "10.0.0.1:80/tcp" in state.services

    def test_ingest_deduplicates_services(self):
        """Re-ingesting the same host:port/proto should overwrite, not duplicate."""
        state = KillChainState()
        svc_v1 = DiscoveredService(
            host="10.0.0.1", port=6379, protocol="tcp", service="redis", version="6.0"
        )
        svc_v2 = DiscoveredService(
            host="10.0.0.1", port=6379, protocol="tcp", service="redis", version="7.0"
        )
        state.ingest(IntelBundle(services=[svc_v1]))
        state.ingest(IntelBundle(services=[svc_v2]))
        assert len(state.services) == 1
        assert state.services["10.0.0.1:6379/tcp"].version == "7.0"

    def test_ingest_vulns(self):
        state = KillChainState()
        vuln = DiscoveredVuln(
            host="10.0.0.1",
            port=80,
            template_id="xss-reflected",
            severity="medium",
            matched_at="http://10.0.0.1/",
        )
        state.ingest(IntelBundle(vulns=[vuln]))
        assert "10.0.0.1:xss-reflected" in state.vulns

    def test_ingest_deduplicates_vulns(self):
        state = KillChainState()
        vuln1 = DiscoveredVuln(
            host="10.0.0.1",
            port=80,
            template_id="sqli",
            severity="high",
            matched_at="http://10.0.0.1/a",
        )
        vuln2 = DiscoveredVuln(
            host="10.0.0.1",
            port=80,
            template_id="sqli",
            severity="high",
            matched_at="http://10.0.0.1/b",  # same template_id, updated matched_at
        )
        state.ingest(IntelBundle(vulns=[vuln1]))
        state.ingest(IntelBundle(vulns=[vuln2]))
        assert len(state.vulns) == 1
        assert state.vulns["10.0.0.1:sqli"].matched_at == "http://10.0.0.1/b"

    def test_ingest_urls(self):
        state = KillChainState()
        state.ingest(IntelBundle(urls=["http://10.0.0.1/admin", "http://10.0.0.1/login"]))
        assert "http://10.0.0.1/admin" in state.urls
        assert "http://10.0.0.1/login" in state.urls

    def test_ingest_urls_deduplicates(self):
        state = KillChainState()
        state.ingest(IntelBundle(urls=["http://10.0.0.1/admin"]))
        state.ingest(IntelBundle(urls=["http://10.0.0.1/admin", "http://10.0.0.1/api"]))
        assert len(state.urls) == 2

    def test_has_service_true(self):
        state = KillChainState()
        state.ingest(
            IntelBundle(
                services=[DiscoveredService(host="10.0.0.1", port=6379, protocol="tcp", service="redis")]
            )
        )
        assert state.has_service("redis") is True

    def test_has_service_false(self):
        state = KillChainState()
        state.ingest(
            IntelBundle(
                services=[DiscoveredService(host="10.0.0.1", port=22, protocol="tcp", service="ssh")]
            )
        )
        assert state.has_service("redis") is False

    def test_has_service_empty_state(self):
        state = KillChainState()
        assert state.has_service("ssh") is False

    def test_get_services_returns_matching(self):
        state = KillChainState()
        bundle = IntelBundle(
            services=[
                DiscoveredService(host="10.0.0.1", port=6379, protocol="tcp", service="redis"),
                DiscoveredService(host="10.0.0.2", port=6380, protocol="tcp", service="redis"),
                DiscoveredService(host="10.0.0.3", port=22, protocol="tcp", service="ssh"),
            ]
        )
        state.ingest(bundle)
        redis_svcs = state.get_services("redis")
        assert len(redis_svcs) == 2
        assert all(s.service == "redis" for s in redis_svcs)

    def test_get_services_returns_empty_when_none(self):
        state = KillChainState()
        state.ingest(
            IntelBundle(
                services=[DiscoveredService(host="10.0.0.1", port=22, protocol="tcp", service="ssh")]
            )
        )
        assert state.get_services("redis") == []

    def test_record_spawn_single(self):
        state = KillChainState()
        state.record_spawn("nmap-service-scan")
        assert state.tasks_spawned["nmap-service-scan"] == 1
        assert state.total_spawned == 1

    def test_record_spawn_accumulates(self):
        state = KillChainState()
        state.record_spawn("nuclei-scan", count=3)
        state.record_spawn("nuclei-scan", count=2)
        assert state.tasks_spawned["nuclei-scan"] == 5
        assert state.total_spawned == 5

    def test_record_spawn_multiple_strategies(self):
        state = KillChainState()
        state.record_spawn("nmap-scan", count=1)
        state.record_spawn("nuclei-scan", count=4)
        state.record_spawn("nmap-scan", count=2)
        assert state.tasks_spawned["nmap-scan"] == 3
        assert state.tasks_spawned["nuclei-scan"] == 4
        assert state.total_spawned == 7

    def test_ingest_combined_bundle(self):
        """Ingest a bundle with services, vulns, and URLs all at once."""
        state = KillChainState()
        bundle = IntelBundle(
            services=[DiscoveredService(host="10.0.0.1", port=80, protocol="tcp", service="http")],
            vulns=[
                DiscoveredVuln(
                    host="10.0.0.1",
                    port=80,
                    template_id="http-title",
                    severity="info",
                    matched_at="http://10.0.0.1/",
                )
            ],
            urls=["http://10.0.0.1/admin"],
            metadata={"scanner": "nuclei"},
        )
        state.ingest(bundle)
        assert len(state.services) == 1
        assert len(state.vulns) == 1
        assert len(state.urls) == 1
