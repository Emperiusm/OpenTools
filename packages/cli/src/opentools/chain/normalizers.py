"""Canonical-form normalizers per entity type and built-in type registration."""
from __future__ import annotations

import ipaddress
import sys

import tldextract

from opentools.chain.types import (
    EntityTypeCategory,
    ENTITY_TYPE_REGISTRY,
    register_entity_type,
)


# ─── individual normalizers ───────────────────────────────────────────────


def _norm_ip(value: str) -> str:
    stripped = value.strip().strip("[]")
    return str(ipaddress.ip_address(stripped))


def _norm_domain(value: str) -> str:
    return value.strip().rstrip(".").lower()


_TLD = tldextract.TLDExtract(suffix_list_urls=())


def _norm_registered_domain(value: str) -> str:
    parts = _TLD(value.strip().rstrip(".").lower())
    if parts.domain and parts.suffix:
        return f"{parts.domain}.{parts.suffix}"
    return value.strip().lower()


def _norm_cve(value: str) -> str:
    return value.upper().replace("_", "-")


def _norm_mitre(value: str) -> str:
    return value.upper().strip()


def _norm_email(value: str) -> str:
    return value.strip().lower()


def _norm_path(value: str) -> str:
    if sys.platform == "win32":
        return value.lower()
    return value


def _norm_hash(value: str) -> str:
    return value.strip().lower()


def _norm_user(value: str) -> str:
    return value.strip().lower()


def _norm_process(value: str) -> str:
    return value.strip()


def _norm_host(value: str) -> str:
    return value.strip().rstrip(".").lower()


def _norm_port(value: str) -> str:
    return value.strip().lstrip("0") or "0"


def _norm_registry_key(value: str) -> str:
    return value.strip().upper()


def _norm_package(value: str) -> str:
    return value.strip()


def _norm_url(value: str) -> str:
    return value.strip()


NORMALIZERS: dict = {
    "host": _norm_host,
    "ip": _norm_ip,
    "user": _norm_user,
    "process": _norm_process,
    "cve": _norm_cve,
    "mitre_technique": _norm_mitre,
    "domain": _norm_domain,
    "registered_domain": _norm_registered_domain,
    "email": _norm_email,
    "url": _norm_url,
    "file_path": _norm_path,
    "port": _norm_port,
    "registry_key": _norm_registry_key,
    "package": _norm_package,
    "hash_md5": _norm_hash,
    "hash_sha1": _norm_hash,
    "hash_sha256": _norm_hash,
}


def normalize(entity_type: str, raw: str) -> str:
    fn = NORMALIZERS.get(entity_type)
    if fn is None:
        return raw
    return fn(raw)


# ─── built-in type registration (runs once on import) ────────────────────


_BUILTIN_STRONG = {
    "host", "ip", "user", "process", "cve", "mitre_technique",
    "domain", "registered_domain", "email", "url",
    "hash_md5", "hash_sha1", "hash_sha256",
}
_BUILTIN_WEAK = {"file_path", "port", "registry_key", "package"}


def _register_builtins() -> None:
    for t in _BUILTIN_STRONG:
        if t not in ENTITY_TYPE_REGISTRY:
            register_entity_type(
                t, category=EntityTypeCategory.STRONG, normalizer=NORMALIZERS[t]
            )
    for t in _BUILTIN_WEAK:
        if t not in ENTITY_TYPE_REGISTRY:
            register_entity_type(
                t, category=EntityTypeCategory.WEAK, normalizer=NORMALIZERS[t]
            )


_register_builtins()
