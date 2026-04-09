"""Parse hashcat potfile output into Finding models."""

import re
from datetime import datetime, timezone
from uuid import uuid4

from opentools.models import Finding, Severity


def _detect_hash_type(hash_str: str) -> str:
    """Detect hash type from format heuristics."""
    if hash_str.startswith("$2"):
        return "bcrypt"
    if hash_str.startswith("$6$"):
        return "SHA-512 crypt"
    if hash_str.startswith("$5$"):
        return "SHA-256 crypt"
    if hash_str.startswith("$1$"):
        return "MD5 crypt"
    if re.match(r'^[a-fA-F0-9]{32}$', hash_str):
        return "MD5"
    if re.match(r'^[a-fA-F0-9]{40}$', hash_str):
        return "SHA-1"
    if re.match(r'^[a-fA-F0-9]{64}$', hash_str):
        return "SHA-256"
    if re.match(r'^[a-fA-F0-9]{128}$', hash_str):
        return "SHA-512"
    return "Unknown"


def parse(raw_output: str) -> list[Finding]:
    """Parse hashcat potfile output (hash:plaintext per line)."""
    findings = []
    if not raw_output.strip():
        return []

    now = datetime.now(timezone.utc)

    for line in raw_output.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(":")

        # Machine-readable format: type:hash:plaintext (3+ fields)
        if len(parts) >= 3 and parts[0].isdigit():
            hash_type_code = parts[0]
            hash_val = parts[1]
            plaintext = ":".join(parts[2:])
            hash_type = f"Mode {hash_type_code}"
        elif len(parts) >= 2:
            # Standard potfile: hash:plaintext
            hash_val = parts[0]
            plaintext = ":".join(parts[1:])
            hash_type = _detect_hash_type(hash_val)
        else:
            continue

        findings.append(Finding(
            id=str(uuid4()),
            engagement_id="",
            tool="hashcat",
            title=f"Weak password cracked ({hash_type})",
            severity=Severity.HIGH,
            cwe="CWE-521",
            file_path=hash_type,
            evidence=f"{hash_val}:{plaintext}",
            description=f"Password cracked from {hash_type} hash. Original hash: {hash_val}",
            created_at=now,
        ))
    return findings
