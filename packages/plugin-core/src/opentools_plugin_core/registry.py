"""Registry client: catalog fetch with ETag caching, multi-registry, offline."""

from __future__ import annotations
import json
from pathlib import Path
from typing import Optional
from opentools_plugin_core.errors import RegistryError
from opentools_plugin_core.models import Catalog, CatalogEntry


class RegistryClient:
    def __init__(self, cache_dir: Path, registries: list[dict] | None = None, catalog_ttl: int = 3600) -> None:
        self._cache_dir = Path(cache_dir)
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        self._registries = registries or []
        self._catalog_ttl = catalog_ttl
        self._catalog: Catalog | None = None

    @property
    def _cache_path(self) -> Path:
        return self._cache_dir / "catalog.json"

    @property
    def _etag_path(self) -> Path:
        return self._cache_dir / "catalog.etag"

    def load_cached_catalog(self) -> Catalog | None:
        if not self._cache_path.exists():
            return None
        try:
            raw = json.loads(self._cache_path.read_text(encoding="utf-8"))
            self._catalog = Catalog(**raw)
            return self._catalog
        except Exception:
            return None

    def save_catalog(self, catalog: Catalog, etag: str = "") -> None:
        self._cache_path.write_text(catalog.model_dump_json(indent=2), encoding="utf-8")
        if etag:
            self._etag_path.write_text(etag, encoding="utf-8")
        self._catalog = catalog

    async def fetch_catalog(self, url: str, force: bool = False) -> Catalog:
        import httpx
        headers: dict[str, str] = {}
        if not force and self._etag_path.exists():
            headers["If-None-Match"] = self._etag_path.read_text(encoding="utf-8").strip()
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, headers=headers, timeout=30)
            if resp.status_code == 304:
                cached = self.load_cached_catalog()
                if cached:
                    return cached
                raise RegistryError("304 Not Modified but no local cache", hint="opentools plugin search --refresh")
            resp.raise_for_status()
            raw = resp.json()
            catalog = Catalog(**raw)
            self.save_catalog(catalog, resp.headers.get("ETag", ""))
            return catalog
        except Exception as e:
            if not isinstance(e, RegistryError):
                cached = self.load_cached_catalog()
                if cached:
                    return cached
            raise RegistryError("Catalog fetch failed", detail=str(e), hint="Check your network or add a local registry path") from e

    def _ensure_catalog(self) -> Catalog:
        if self._catalog is None:
            self._catalog = self.load_cached_catalog()
        if self._catalog is None:
            raise RegistryError("No catalog available", hint="opentools plugin search --refresh")
        return self._catalog

    def search(self, query: str, domain: str | None = None) -> list[CatalogEntry]:
        catalog = self._ensure_catalog()
        query_lower = query.lower()
        results: list[CatalogEntry] = []
        for entry in catalog.plugins:
            if domain and entry.domain != domain:
                continue
            if not query:
                results.append(entry)
                continue
            searchable = entry.name.lower() + " " + entry.description.lower() + " " + " ".join(t.lower() for t in entry.tags)
            if query_lower in searchable:
                results.append(entry)
        return results

    def lookup(self, name: str) -> CatalogEntry | None:
        catalog = self._ensure_catalog()
        for entry in catalog.plugins:
            if entry.name == name:
                return entry
        return None
