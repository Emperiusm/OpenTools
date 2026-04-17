"""WhatWeb JSON output parser.

WhatWeb outputs an array of target objects, each listing detected plugins/
technologies. Each detected plugin becomes an informational RawFinding —
technology fingerprinting is low-risk on its own but feeds vulnerability
correlation downstream.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Iterator

import orjson

from opentools.scanner.models import (
    EvidenceQuality,
    LocationPrecision,
    RawFinding,
)


class WhatWebParser:
    name = "whatweb"
    version = "1.0.0"
    confidence_tier = 0.9

    def validate(self, data: bytes) -> bool:
        """Accept if at least one target block parses as a JSON array of dicts.

        WhatWeb outputs one JSON array per invocation; when multiple targets
        are scanned back-to-back, the stdout contains multiple arrays
        concatenated line-by-line which is not valid single-document JSON.
        """
        return any(True for _ in self._iter_targets(data))

    @staticmethod
    def _iter_targets(data: bytes):
        """Yield each target dict across possibly-concatenated JSON arrays.

        Strategy: extract balanced-bracket top-level arrays and parse each.
        Falls back to parsing the whole blob as a single array if that works.
        """
        text = data.decode("utf-8", errors="replace")

        # Fast path: single array
        try:
            parsed = orjson.loads(text)
            if isinstance(parsed, list):
                for item in parsed:
                    if isinstance(item, dict):
                        yield item
                return
        except orjson.JSONDecodeError:
            pass

        # Slow path: find each top-level `[...]` block by bracket-counting
        depth = 0
        start = -1
        in_string = False
        escape = False
        for i, ch in enumerate(text):
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "[":
                if depth == 0:
                    start = i
                depth += 1
            elif ch == "]":
                depth -= 1
                if depth == 0 and start >= 0:
                    block = text[start : i + 1]
                    try:
                        parsed = orjson.loads(block)
                    except orjson.JSONDecodeError:
                        start = -1
                        continue
                    if isinstance(parsed, list):
                        for item in parsed:
                            if isinstance(item, dict):
                                yield item
                    start = -1

    def parse(
        self,
        data: bytes,
        scan_id: str,
        scan_task_id: str,
    ) -> Iterator[RawFinding]:
        for target in self._iter_targets(data):
            if not isinstance(target, dict):
                continue
            url = target.get("target") or target.get("uri") or "unknown"
            plugins = target.get("plugins", {}) or {}

            for plugin_name, details in plugins.items():
                # Skip noisy structural plugins
                if plugin_name in ("HTTPServer", "IP", "Country", "RedirectLocation"):
                    continue

                versions: list[str] = []
                accounts: list[str] = []
                if isinstance(details, dict):
                    raw_versions = details.get("version") or details.get("string") or []
                    if isinstance(raw_versions, list):
                        versions = [str(v) for v in raw_versions]
                    elif raw_versions:
                        versions = [str(raw_versions)]
                    if isinstance(details.get("account"), list):
                        accounts = [str(a) for a in details["account"]]

                version_str = f" {versions[0]}" if versions else ""
                title = f"Detected: {plugin_name}{version_str}"
                description_parts = [f"WhatWeb identified {plugin_name} at {url}"]
                if versions:
                    description_parts.append(f"Version(s): {', '.join(versions)}")
                if accounts:
                    description_parts.append(f"Account: {', '.join(accounts)}")
                description = ". ".join(description_parts)

                evidence_str = f"whatweb:{plugin_name}:{url}:{','.join(versions)}"
                evidence_hash = hashlib.sha256(evidence_str.encode()).hexdigest()

                yield RawFinding(
                    id=str(uuid.uuid4()),
                    scan_task_id=scan_task_id,
                    scan_id=scan_id,
                    tool="whatweb",
                    raw_severity="info",
                    title=title,
                    description=description,
                    file_path=None,
                    url=url,
                    evidence=str(versions) if versions else plugin_name,
                    evidence_quality=EvidenceQuality.STRUCTURED,
                    evidence_hash=evidence_hash,
                    cwe=None,
                    location_fingerprint=f"{url}#{plugin_name}",
                    location_precision=LocationPrecision.ENDPOINT,
                    parser_version=self.version,
                    parser_confidence=self.confidence_tier,
                    discovered_at=datetime.now(timezone.utc),
                )
