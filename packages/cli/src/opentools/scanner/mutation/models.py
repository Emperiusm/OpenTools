"""Data models for kill-chain state accumulation and per-task intel extraction."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class DiscoveredService(BaseModel):
    """A network service discovered by a scanning tool."""

    host: str
    port: int
    protocol: str  # "tcp" | "udp"
    service: str  # e.g., "redis", "http", "ssh"
    product: str | None = None
    version: str | None = None
    banner: str | None = None


class DiscoveredVuln(BaseModel):
    """A vulnerability discovered by a scanning tool."""

    host: str
    port: int | None
    template_id: str
    severity: str
    matched_at: str
    extracted_data: dict[str, Any] = Field(default_factory=dict)


class IntelBundle(BaseModel):
    """Structured intelligence extracted from a single task's output."""

    services: list[DiscoveredService] = Field(default_factory=list)
    vulns: list[DiscoveredVuln] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class KillChainState(BaseModel):
    """Accumulated attack surface knowledge across all completed tasks."""

    services: dict[str, DiscoveredService] = Field(default_factory=dict)
    vulns: dict[str, DiscoveredVuln] = Field(default_factory=dict)
    urls: set[str] = Field(default_factory=set)
    tasks_spawned: dict[str, int] = Field(default_factory=dict)
    total_spawned: int = 0

    def ingest(self, bundle: IntelBundle) -> None:
        for svc in bundle.services:
            key = f"{svc.host}:{svc.port}/{svc.protocol}"
            self.services[key] = svc
        for vuln in bundle.vulns:
            port_part = str(vuln.port) if vuln.port is not None else "noport"
            key = f"{vuln.host}:{port_part}:{vuln.template_id}"
            self.vulns[key] = vuln
        self.urls.update(bundle.urls)

    def has_service(self, service_name: str) -> bool:
        return any(s.service == service_name for s in self.services.values())

    def get_services(self, service_name: str) -> list[DiscoveredService]:
        return [s for s in self.services.values() if s.service == service_name]

    def record_spawn(self, strategy_name: str, count: int = 1) -> None:
        self.tasks_spawned[strategy_name] = self.tasks_spawned.get(strategy_name, 0) + count
        self.total_spawned += count
