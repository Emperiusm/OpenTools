"""Tests for PluginError hierarchy."""

import pytest


class TestPluginError:
    def test_base_error_is_exception(self):
        from opentools_plugin_core.errors import PluginError

        err = PluginError("something broke")
        assert isinstance(err, Exception)
        assert "something broke" in str(err)

    def test_error_with_hint(self):
        from opentools_plugin_core.errors import PluginError

        err = PluginError(
            "Plugin not found",
            hint="opentools plugin search wifi",
        )
        assert err.message == "Plugin not found"
        assert err.hint == "opentools plugin search wifi"

    def test_error_with_detail(self):
        from opentools_plugin_core.errors import PluginError

        err = PluginError(
            "Install failed",
            detail="git clone returned exit code 128",
            hint="Check your network connection",
        )
        assert err.detail == "git clone returned exit code 128"

    def test_not_found_error(self):
        from opentools_plugin_core.errors import PluginNotFoundError

        err = PluginNotFoundError("wifi-hacking")
        assert isinstance(err, Exception)
        assert "wifi-hacking" in str(err)

    def test_install_error(self):
        from opentools_plugin_core.errors import PluginInstallError

        err = PluginInstallError("SHA256 mismatch")
        assert isinstance(err, Exception)

    def test_sandbox_violation_error(self):
        from opentools_plugin_core.errors import SandboxViolationError

        err = SandboxViolationError(
            "Undeclared capability: SYS_ADMIN",
            hint="Declare SYS_ADMIN in sandbox.capabilities",
        )
        assert "SYS_ADMIN" in err.message

    def test_resolve_error(self):
        from opentools_plugin_core.errors import DependencyResolveError

        err = DependencyResolveError("Circular dependency detected")
        assert isinstance(err, Exception)

    def test_verification_error(self):
        from opentools_plugin_core.errors import VerificationError

        err = VerificationError("Signature invalid")
        assert isinstance(err, Exception)

    def test_registry_error(self):
        from opentools_plugin_core.errors import RegistryError

        err = RegistryError(
            "Catalog fetch failed",
            detail="HTTP 503",
            hint="opentools plugin search --refresh",
        )
        assert err.hint == "opentools plugin search --refresh"
