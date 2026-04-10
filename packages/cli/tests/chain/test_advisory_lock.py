import pytest

from opentools.chain.linker.advisory_lock import (
    LinkerLockHeld,
    chain_lock,
)


def test_lock_acquire_and_release(tmp_path):
    db_path = tmp_path / "test.db"
    db_path.touch()
    with chain_lock(db_path, scope_key="s1"):
        pass  # lock released on exit


def test_lock_second_acquisition_fails_without_wait(tmp_path):
    db_path = tmp_path / "test.db"
    db_path.touch()
    with chain_lock(db_path, scope_key="s2"):
        with pytest.raises(LinkerLockHeld):
            with chain_lock(db_path, scope_key="s2", wait=False):
                pass


def test_different_scopes_do_not_conflict(tmp_path):
    db_path = tmp_path / "test.db"
    db_path.touch()
    with chain_lock(db_path, scope_key="scopeA"):
        # Different scope should succeed
        with chain_lock(db_path, scope_key="scopeB"):
            pass


def test_lock_released_after_block(tmp_path):
    db_path = tmp_path / "test.db"
    db_path.touch()
    with chain_lock(db_path, scope_key="reuse"):
        pass
    # Should be able to acquire again
    with chain_lock(db_path, scope_key="reuse"):
        pass
