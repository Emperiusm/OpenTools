"""File-based advisory lock for concurrent linker run protection."""
from __future__ import annotations

import os
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class LinkerLockHeld(RuntimeError):
    """Raised when another linker process holds the lock and wait=False."""


class LinkerLockTimeout(RuntimeError):
    """Raised when wait=True times out waiting for the lock."""


@contextmanager
def chain_lock(
    db_path: Path,
    *,
    scope_key: str = "global",
    wait: bool = False,
    timeout_sec: float = 30.0,
) -> Iterator[None]:
    """File-based advisory lock keyed by (db_path, scope_key)."""
    lock_path = Path(f"{db_path}.{scope_key}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)

    # Open/create the lock file
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o644)

    try:
        acquired = _try_acquire(fd, wait=wait, timeout_sec=timeout_sec)
        if not acquired:
            os.close(fd)
            if wait:
                raise LinkerLockTimeout(
                    f"timed out waiting {timeout_sec}s for chain lock: {lock_path}"
                )
            raise LinkerLockHeld(
                f"chain lock already held: {lock_path}"
            )
        yield
    finally:
        try:
            _release(fd)
        except Exception:
            pass
        try:
            os.close(fd)
        except Exception:
            pass


def _try_acquire(fd: int, *, wait: bool, timeout_sec: float) -> bool:
    if sys.platform == "win32":
        import msvcrt
        if wait:
            deadline = time.monotonic() + timeout_sec
            while time.monotonic() < deadline:
                try:
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    return True
                except OSError:
                    time.sleep(0.1)
            return False
        else:
            try:
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                return True
            except OSError:
                return False
    else:
        import fcntl
        flags = fcntl.LOCK_EX
        if not wait:
            flags |= fcntl.LOCK_NB
        try:
            if wait:
                deadline = time.monotonic() + timeout_sec
                while time.monotonic() < deadline:
                    try:
                        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        return True
                    except BlockingIOError:
                        time.sleep(0.1)
                return False
            fcntl.flock(fd, flags)
            return True
        except BlockingIOError:
            return False


def _release(fd: int) -> None:
    if sys.platform == "win32":
        import msvcrt
        try:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)
