"""Plugin error hierarchy with user-facing messages and hints."""

from __future__ import annotations


class PluginError(Exception):
    """Base error for all plugin operations.

    Every fixable error includes a ``hint`` with the exact CLI command
    the user should run to resolve the problem.
    """

    def __init__(
        self,
        message: str,
        detail: str = "",
        hint: str = "",
    ) -> None:
        self.message = message
        self.detail = detail
        self.hint = hint
        super().__init__(message)


class PluginNotFoundError(PluginError):
    """Plugin not found in any registry."""

    def __init__(self, name: str, **kwargs):
        super().__init__(
            f"Plugin not found: {name}",
            hint=kwargs.pop("hint", f"opentools plugin search {name}"),
            **kwargs,
        )


class PluginInstallError(PluginError):
    """Install pipeline failure."""


class SandboxViolationError(PluginError):
    """Compose fragment or manifest violates sandbox policy."""


class DependencyResolveError(PluginError):
    """Dependency resolution failed (conflict, cycle, missing)."""


class VerificationError(PluginError):
    """Sigstore or SHA256 verification failed."""


class RegistryError(PluginError):
    """Registry communication or catalog parsing error."""


class IntegrityError(PluginError):
    """Installed file integrity check failed."""
