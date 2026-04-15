"""Generate per-plugin Docker Compose projects with sandbox injection."""

from __future__ import annotations
from typing import Any, Optional
from opentools_plugin_core.models import PluginManifest
from opentools_plugin_core.sandbox import DEFAULT_SECURITY


def generate_compose(
    manifest: PluginManifest,
    hub_network: str = "mcp-security-hub_default",
) -> dict[str, Any] | None:
    if not manifest.provides.containers:
        return None

    services: dict[str, Any] = {}
    networks: dict[str, Any] = {
        "plugin-net": {"name": f"opentools-plugin-{manifest.name}"},
    }

    needs_hub = bool(manifest.requires.containers)
    service_networks = ["plugin-net"]
    if needs_hub:
        networks["hub"] = {"name": hub_network, "external": True}
        service_networks.append("hub")

    for container in manifest.provides.containers:
        svc: dict[str, Any] = {
            "image": container.image,
            "networks": list(service_networks),
            "labels": {
                "com.opentools.plugin": manifest.name,
                "com.opentools.version": manifest.version,
                "com.opentools.sandbox": "enforced",
            },
        }
        svc.update(DEFAULT_SECURITY)
        if manifest.sandbox.capabilities:
            svc["cap_add"] = list(manifest.sandbox.capabilities)
        if manifest.sandbox.network_mode:
            svc["network_mode"] = manifest.sandbox.network_mode
        if manifest.sandbox.volumes:
            svc["volumes"] = list(manifest.sandbox.volumes)
        services[container.name] = svc

    return {"version": "3.8", "services": services, "networks": networks}
