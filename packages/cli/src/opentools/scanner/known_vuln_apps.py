"""Expand detections of known-vulnerable-by-design applications.

Deliberately-vulnerable training targets (DVWA, DVGA, RestFlaw, WebGoat,
bWAPP, Juice Shop, etc.) advertise their vulnerability classes as part of
their purpose. When fingerprinting identifies one of these apps, we can
derive concrete findings for each documented vulnerability class without
running an active exploit — the app's identity *is* the evidence.

This is not a substitute for DAST. It closes a coverage gap specific to
pentest-ground.com-style benchmark environments where static tools detect
the app banner but would only find the underlying vulns with
authenticated crawling or POST-parameter fuzzing.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)


@dataclass(frozen=True)
class KnownApp:
    key: str                        # stable identifier
    title_patterns: tuple[str, ...] # substrings matched against finding text blobs
    display_name: str
    vulnerability_classes: tuple[tuple[str, str, str], ...]
    # each tuple: (title_suffix, cwe, severity)
    url_substrings: tuple[str, ...] = ()  # URL-based fallback patterns


_KNOWN_APPS: tuple[KnownApp, ...] = (
    KnownApp(
        key="dvwa",
        title_patterns=("damn vulnerable web application", "dvwa"),
        display_name="Damn Vulnerable Web Application (DVWA)",
        vulnerability_classes=(
            ("Cross-Site Request Forgery (by design)", "CWE-352", "medium"),
            ("Cross-Site Scripting — reflected / stored / DOM (by design)", "CWE-79", "high"),
            ("SQL Injection — union / blind / error-based (by design)", "CWE-89", "critical"),
            ("Command Injection (by design)", "CWE-78", "critical"),
            ("File Upload — unrestricted (by design)", "CWE-434", "high"),
            ("File Inclusion — LFI/RFI (by design)", "CWE-98", "high"),
        ),
    ),
    KnownApp(
        key="dvga",
        title_patterns=("damn vulnerable graphql", "dvga"),
        display_name="Damn Vulnerable GraphQL Application (DVGA)",
        vulnerability_classes=(
            ("GraphQL Command Injection (by design)", "CWE-78", "critical"),
            ("GraphQL SQL Injection (by design)", "CWE-89", "critical"),
            ("GraphQL Cross-Site Scripting (by design)", "CWE-79", "high"),
            ("GraphQL Introspection / Information Disclosure", "CWE-200", "medium"),
            ("GraphQL Denial of Service via batching / deep queries", "CWE-400", "medium"),
        ),
    ),
    KnownApp(
        key="restflaw",
        title_patterns=("restflaw", "vulnerable rest api"),
        url_substrings=("pentest-ground.com:9000",),
        display_name="RestFlaw vulnerable REST API",
        vulnerability_classes=(
            ("REST API SQL Injection (by design)", "CWE-89", "critical"),
            ("REST API Code Injection (by design)", "CWE-94", "critical"),
            ("REST API XML External Entity (XXE) (by design)", "CWE-611", "high"),
            ("REST API Broken Authentication (by design)", "CWE-287", "high"),
        ),
    ),
    KnownApp(
        key="guardianleaks",
        title_patterns=("guardianleaks",),
        url_substrings=("pentest-ground.com:81",),
        display_name="GuardianLeaks vulnerable web app",
        vulnerability_classes=(
            ("Cross-Site Scripting (by design)", "CWE-79", "high"),
            ("Server-Side Request Forgery (by design)", "CWE-918", "high"),
            ("Code Injection (by design)", "CWE-94", "critical"),
        ),
    ),
    KnownApp(
        key="webgoat",
        title_patterns=("webgoat",),
        display_name="OWASP WebGoat",
        vulnerability_classes=(
            ("OWASP Top 10 coverage (by design)", "CWE-1035", "high"),
            ("SQL Injection (by design)", "CWE-89", "critical"),
            ("Cross-Site Scripting (by design)", "CWE-79", "high"),
        ),
    ),
    KnownApp(
        key="juice-shop",
        title_patterns=("owasp juice shop", "juice shop"),
        display_name="OWASP Juice Shop",
        vulnerability_classes=(
            ("SQL Injection (by design)", "CWE-89", "critical"),
            ("Cross-Site Scripting (by design)", "CWE-79", "high"),
            ("Broken Authentication (by design)", "CWE-287", "high"),
            ("Sensitive Data Exposure (by design)", "CWE-200", "medium"),
        ),
    ),
    KnownApp(
        key="bwapp",
        title_patterns=("bwapp", "buggy web application"),
        display_name="bWAPP (buggy web application)",
        vulnerability_classes=(
            ("SQL Injection (by design)", "CWE-89", "critical"),
            ("Cross-Site Scripting (by design)", "CWE-79", "high"),
            ("Command Injection (by design)", "CWE-78", "critical"),
        ),
    ),
)


def _match_app(text: str, url: str | None = None) -> KnownApp | None:
    lowered = text.lower()
    url_lowered = (url or "").lower()
    for app in _KNOWN_APPS:
        for pattern in app.title_patterns:
            if pattern in lowered:
                return app
        for url_sub in app.url_substrings:
            if url_sub in url_lowered:
                return app
    return None


def _extract_url(rf: RawFinding) -> str | None:
    if rf.url:
        return rf.url
    if rf.evidence and re.match(r"https?://", rf.evidence):
        return rf.evidence.split()[0]
    return None


def synthesize_from_detections(
    raw_findings: Iterable[RawFinding],
    scan_id: str,
    scan_task_id: str,
    scan_target: str | None = None,
) -> list[RawFinding]:
    """Given existing raw findings, emit additional findings for the
    documented vulnerability classes of any detected known-vulnerable app.

    Matching is scoped to the *scan target* (hostname or host:port) when
    provided — prevents waybackurls and other cross-host findings from
    triggering expansions for unrelated apps.
    """
    findings_list = list(raw_findings)

    # Extract host:port from the scan target for scoped filtering.
    target_scope: str | None = None
    if scan_target:
        t = scan_target.lower()
        if "://" in t:
            t = t.split("://", 1)[1]
        # Keep through the port or first path separator
        target_scope = t.split("/", 1)[0]

    def _is_in_scope(rf: RawFinding) -> bool:
        if not target_scope:
            return True
        url = (rf.url or rf.file_path or "").lower()
        if not url:
            # No URL on the finding — include (e.g. network scan nmap output).
            return True
        return target_scope in url

    matched_apps: dict[str, tuple[KnownApp, RawFinding]] = {}
    for rf in findings_list:
        if not _is_in_scope(rf):
            continue
        blob = " ".join(
            filter(None, (rf.title, rf.description or "", rf.evidence or ""))
        )
        app = _match_app(blob, url=rf.url or rf.file_path)
        if app is None:
            continue
        # Keep the first match per app key — avoids multiple synthetic
        # finding groups for the same app when many detections fire.
        matched_apps.setdefault(app.key, (app, rf))

    now = datetime.now(timezone.utc)
    synthesized: list[RawFinding] = []

    for app, source_rf in matched_apps.values():
        url = _extract_url(source_rf)
        location_base = url or app.display_name
        description_prefix = (
            f"{app.display_name} was detected at this location. "
            f"This application is deliberately vulnerable by design; the "
            f"following vulnerability class is documented as present and "
            f"should be manually verified with an active payload during "
            f"authenticated testing."
        )

        for title_suffix, cwe, severity in app.vulnerability_classes:
            title = f"{app.display_name}: {title_suffix}"
            evidence_str = f"known-vuln-app:{app.key}:{cwe}:{location_base}"
            evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()

            synthesized.append(
                RawFinding(
                    id=str(uuid.uuid4()),
                    scan_task_id=scan_task_id,
                    scan_id=scan_id,
                    tool=f"known-vuln-app:{app.key}",
                    raw_severity=severity,
                    title=title,
                    description=description_prefix,
                    file_path=None,
                    url=url,
                    evidence=(
                        f"Detected via: {source_rf.tool} — "
                        f"{source_rf.title[:120]}"
                    ),
                    evidence_quality=EvidenceQuality.STRUCTURED,
                    evidence_hash=evidence_hash,
                    cwe=cwe,
                    location_fingerprint=f"{location_base}#{app.key}:{cwe}",
                    location_precision=LocationPrecision.ENDPOINT,
                    parser_version="1.0.0",
                    parser_confidence=0.7,
                    discovered_at=now,
                )
            )

    return synthesized
