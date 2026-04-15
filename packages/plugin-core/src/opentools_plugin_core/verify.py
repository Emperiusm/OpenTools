"""Sigstore signature and SHA256 verification."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from opentools_plugin_core.errors import VerificationError


@dataclass
class VerifyResult:
    verified: bool
    identity: str = ""
    error: str = ""


def verify_sha256(data: bytes, expected_hash: str) -> None:
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_hash:
        raise VerificationError(
            "SHA256 mismatch",
            detail=f"Expected {expected_hash[:16]}..., got {actual[:16]}...",
            hint="The plugin content may have been tampered with.",
        )


def verify_sigstore_bundle(
    artifact_path: str,
    bundle_path: str,
    expected_identity: str,
) -> VerifyResult:
    try:
        from sigstore.verify import Verifier
        from sigstore.verify.policy import Identity

        verifier = Verifier.production()
        identity = Identity(
            identity=expected_identity,
            issuer="https://accounts.google.com",
        )
        artifact = Path(artifact_path)
        bundle = Path(bundle_path)
        if not artifact.exists():
            return VerifyResult(verified=False, error=f"Artifact not found: {artifact_path}")
        if not bundle.exists():
            return VerifyResult(verified=False, error=f"Bundle not found: {bundle_path}")
        result = verifier.verify(
            artifact.read_bytes(), bundle=bundle.read_bytes(), policy=identity,
        )
        return VerifyResult(verified=True, identity=expected_identity)
    except ImportError:
        return VerifyResult(
            verified=False,
            error="sigstore not installed. Install with: pip install opentools-plugin-core[sigstore]",
        )
    except Exception as e:
        return VerifyResult(verified=False, error=str(e))
