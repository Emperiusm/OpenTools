"""OutputBuffer — backpressure buffer with disk spillover."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Self


class OutputBuffer:
    """Buffer for streaming tool output with automatic disk spillover.

    Accumulates output in memory up to ``memory_limit`` bytes. Once exceeded,
    all data (existing + new) is flushed to a temporary file on disk. Reads
    always return the complete accumulated output.

    The ``disk_spill_limit`` caps total size on disk. Exceeding it raises
    ``OverflowError`` so the caller can abort the tool.
    """

    def __init__(
        self,
        memory_limit: int = 10 * 1024 * 1024,  # 10 MB
        disk_spill_limit: int = 500 * 1024 * 1024,  # 500 MB
    ) -> None:
        self._memory_limit = memory_limit
        self._disk_spill_limit = disk_spill_limit
        self._chunks: list[bytes] = []
        self._memory_size = 0
        self._spill_path: str | None = None
        self._spill_file = None
        self._total_size = 0

    @property
    def size(self) -> int:
        return self._total_size

    @property
    def spilled(self) -> bool:
        return self._spill_path is not None

    def write(self, data: bytes) -> None:
        """Append data to the buffer. Spills to disk if memory limit exceeded."""
        self._total_size += len(data)

        if self._spill_path is not None:
            if self._total_size > self._disk_spill_limit:
                raise OverflowError(
                    f"Output exceeds disk spill limit "
                    f"({self._total_size} > {self._disk_spill_limit})"
                )
            assert self._spill_file is not None
            self._spill_file.write(data)
            self._spill_file.flush()
            return

        self._chunks.append(data)
        self._memory_size += len(data)

        if self._memory_size > self._memory_limit:
            self._spill_to_disk()

    def read(self) -> bytes:
        """Return all accumulated output."""
        if self._spill_path is not None:
            return Path(self._spill_path).read_bytes()
        return b"".join(self._chunks)

    def cleanup(self) -> None:
        """Remove temporary spill file if one was created."""
        if self._spill_file is not None:
            try:
                self._spill_file.close()
            except Exception:
                pass
            self._spill_file = None
        if self._spill_path is not None:
            try:
                os.unlink(self._spill_path)
            except FileNotFoundError:
                pass
            self._spill_path = None

    def _spill_to_disk(self) -> None:
        """Flush in-memory chunks to a temporary file."""
        fd, path = tempfile.mkstemp(prefix="opentools_output_", suffix=".buf")
        self._spill_path = path
        self._spill_file = os.fdopen(fd, "wb")
        for chunk in self._chunks:
            self._spill_file.write(chunk)
        self._spill_file.flush()
        self._chunks.clear()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc) -> None:
        self.cleanup()
