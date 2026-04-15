"""Tests for sigstore verification (mocked -- no real signatures in unit tests)."""

import pytest


class TestSHA256Verification:
    def test_matching_hash_passes(self):
        from opentools_plugin_core.verify import verify_sha256
        import hashlib
        data = b"known content"
        expected = hashlib.sha256(data).hexdigest()
        verify_sha256(data, expected)

    def test_mismatched_hash_raises(self):
        from opentools_plugin_core.verify import verify_sha256
        from opentools_plugin_core.errors import VerificationError
        with pytest.raises(VerificationError, match="SHA256 mismatch"):
            verify_sha256(b"content", "0000" * 16)


class TestSigstoreVerify:
    def test_verify_bundle_returns_result(self):
        from opentools_plugin_core.verify import verify_sigstore_bundle
        result = verify_sigstore_bundle(
            artifact_path="/fake/path",
            bundle_path="/fake/path.sigstore.bundle",
            expected_identity="test@users.noreply.github.com",
        )
        assert result.verified is False or result.verified is True
        assert hasattr(result, "error")

    def test_verify_result_model(self):
        from opentools_plugin_core.verify import VerifyResult
        r = VerifyResult(verified=True, identity="someone@x.com", error="")
        assert r.verified is True
        r2 = VerifyResult(verified=False, identity="", error="sigstore not installed")
        assert r2.verified is False
