"""Threat intel enrichment provider registry."""

import importlib
import pkgutil
from opentools.correlation.enrichment.base import EnrichmentProvider

_PROVIDERS: dict[str, EnrichmentProvider] = {}


def _discover_providers() -> None:
    import opentools.correlation.enrichment as pkg
    for importer, modname, ispkg in pkgutil.iter_modules(pkg.__path__):
        if modname.startswith("_") or modname in ("base", "manager"):
            continue
        module = importlib.import_module(f"opentools.correlation.enrichment.{modname}")
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if (isinstance(attr, type) and issubclass(attr, EnrichmentProvider)
                    and attr is not EnrichmentProvider and hasattr(attr, 'name')
                    and attr.name):
                try:
                    instance = attr()
                    _PROVIDERS[instance.name] = instance
                except Exception:
                    pass


def get_providers() -> list[EnrichmentProvider]:
    if not _PROVIDERS:
        _discover_providers()
    return list(_PROVIDERS.values())


def get_provider(name: str) -> EnrichmentProvider | None:
    if not _PROVIDERS:
        _discover_providers()
    return _PROVIDERS.get(name)
