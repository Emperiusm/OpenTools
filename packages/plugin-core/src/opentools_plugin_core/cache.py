"""Content-addressable download cache for plugin tarballs."""

from __future__ import annotations

import hashlib
from pathlib import Path


class PluginCache:
    """SHA256-addressed file cache at ``~/.opentools/cache/``."""

    def __init__(self, cache_dir: Path) -> None:
        self._dir = Path(cache_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self, sha256: str) -> Path:
        return self._dir / f"{sha256}.tar.gz"

    def store(self, sha256: str, data: bytes) -> Path:
        actual = hashlib.sha256(data).hexdigest()
        if actual != sha256:
            raise ValueError(
                f"Content hash mismatch: expected {sha256[:16]}..., got {actual[:16]}..."
            )
        path = self._path(sha256)
        path.write_bytes(data)
        return path

    def retrieve(self, sha256: str) -> bytes | None:
        path = self._path(sha256)
        if not path.exists():
            return None
        return path.read_bytes()

    def has(self, sha256: str) -> bool:
        return self._path(sha256).exists()

    def evict(self, sha256: str) -> None:
        path = self._path(sha256)
        if path.exists():
            path.unlink()

    def size_bytes(self) -> int:
        return sum(f.stat().st_size for f in self._dir.iterdir() if f.is_file())

    def clear(self) -> None:
        for f in self._dir.iterdir():
            if f.is_file():
                f.unlink()
