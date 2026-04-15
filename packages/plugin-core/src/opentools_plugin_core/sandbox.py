"""Container sandbox policy: mount blocklist, capability checks, org policy."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Violation:
    severity: str  # "red" | "yellow" | "info"
    message: str
    detail: str = ""
    path: str = ""


_BLOCKED_MOUNTS: list[str] = [
    "/var/run/docker.sock",
    "/",
    "/etc/shadow",
    "/etc/passwd",
    "/proc",
    "/sys",
    "~/.ssh",
    "~/.opentools/plugins.db",
]


def check_volumes(volumes: list[str]) -> list[Violation]:
    violations: list[Violation] = []
    for vol in volumes:
        parts = vol.split(":")
        source = parts[0].rstrip("/") or "/"
        for blocked in _BLOCKED_MOUNTS:
            blocked_norm = blocked.rstrip("/") or "/"
            # For the root "/" block, only match exactly "/" not sub-paths
            if blocked_norm == "/":
                if source == "/":
                    violations.append(Violation(
                        severity="red",
                        message=f"Blocked volume mount: {blocked}",
                        detail=f"Volume '{vol}' maps blocked path '{blocked}'",
                        path=source,
                    ))
                    break
            else:
                if source == blocked_norm or source.startswith(blocked_norm + "/"):
                    violations.append(Violation(
                        severity="red",
                        message=f"Blocked volume mount: {blocked}",
                        detail=f"Volume '{vol}' maps blocked path '{blocked}'",
                        path=source,
                    ))
                    break
    return violations


def check_capabilities(compose_caps: list[str], declared_caps: list[str]) -> list[Violation]:
    declared_set = set(declared_caps)
    violations: list[Violation] = []
    for cap in compose_caps:
        if cap not in declared_set:
            violations.append(Violation(
                severity="red",
                message=f"Undeclared capability: {cap}",
                detail=f"Compose uses cap_add '{cap}' not declared in manifest sandbox.capabilities",
            ))
    return violations


def validate_compose_service(
    service: dict,
    declared_caps: list[str],
    declared_network_mode: Optional[str] = None,
) -> list[Violation]:
    violations: list[Violation] = []
    if service.get("privileged"):
        violations.append(Violation(
            severity="red",
            message="Container runs in privileged mode",
            detail="'privileged: true' grants full host access",
        ))
    net_mode = service.get("network_mode")
    if net_mode == "host":
        if declared_network_mode == "host":
            violations.append(Violation(
                severity="yellow",
                message="Container uses host networking",
                detail="network_mode: host bypasses Docker network isolation",
            ))
        else:
            violations.append(Violation(
                severity="red",
                message="Undeclared host networking",
                detail="Compose uses network_mode: host but manifest does not declare it",
            ))
    vols = service.get("volumes", [])
    if vols:
        vol_strings = [v if isinstance(v, str) else v.get("source", "") for v in vols]
        violations.extend(check_volumes(vol_strings))
    caps = service.get("cap_add", [])
    if caps:
        violations.extend(check_capabilities(caps, declared_caps))
    return violations


@dataclass
class OrgPolicy:
    blocked_capabilities: list[str] = field(default_factory=list)
    blocked_network_modes: list[str] = field(default_factory=list)
    require_egress_allowlist: bool = False
    max_volume_mounts: Optional[int] = None
    enforced_by: str = ""


def apply_org_policy(
    policy: OrgPolicy, declared_caps: list[str], network_mode: Optional[str],
) -> list[Violation]:
    violations: list[Violation] = []
    for cap in declared_caps:
        if cap in policy.blocked_capabilities:
            violations.append(Violation(
                severity="red",
                message=f"Org policy blocks capability: {cap}",
                detail=f"Capability '{cap}' is blocked by org policy"
                       + (f" ({policy.enforced_by})" if policy.enforced_by else ""),
            ))
    if network_mode and network_mode in policy.blocked_network_modes:
        violations.append(Violation(
            severity="red",
            message=f"Org policy blocks network mode: {network_mode}",
            detail=f"Network mode '{network_mode}' is blocked by org policy",
        ))
    return violations


CAPABILITY_SECCOMP_MAP: dict[str, str] = {
    "NET_RAW": "profiles/net-raw.json",
    "NET_ADMIN": "profiles/net-admin.json",
    "SYS_PTRACE": "profiles/ptrace.json",
}

DEFAULT_SECURITY: dict = {
    "security_opt": ["no-new-privileges:true"],
    "read_only": True,
    "tmpfs": ["/tmp:size=256m"],
    "mem_limit": "2g",
    "cpus": 2.0,
    "pids_limit": 256,
}
