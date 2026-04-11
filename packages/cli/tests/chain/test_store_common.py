"""Tests for chain/stores/_common.py — decorators, errors, helpers."""
import asyncio

import pytest

from opentools.chain.stores._common import (
    ScopingViolation,
    StoreNotInitialized,
    pad_in_clause,
    require_initialized,
)


def test_store_not_initialized_is_runtime_error():
    assert issubclass(StoreNotInitialized, RuntimeError)


def test_scoping_violation_is_runtime_error():
    assert issubclass(ScopingViolation, RuntimeError)


def test_pad_in_clause_empty():
    assert pad_in_clause([]) == []


def test_pad_in_clause_power_of_two_padding():
    assert len(pad_in_clause(["a"])) == 4      # min 4
    assert len(pad_in_clause(["a", "b", "c"])) == 4
    assert len(pad_in_clause(["a"] * 5)) == 8
    assert len(pad_in_clause(["a"] * 17)) == 32


def test_pad_in_clause_preserves_values_and_pads_with_none():
    padded = pad_in_clause(["x", "y", "z"])
    assert padded[:3] == ["x", "y", "z"]
    assert padded[3:] == [None]


def test_require_initialized_raises_when_not_initialized():
    class _Dummy:
        _initialized = False

        @require_initialized
        async def do_thing(self):
            return "ok"

    d = _Dummy()
    with pytest.raises(StoreNotInitialized, match="do_thing"):
        asyncio.run(d.do_thing())


def test_require_initialized_allows_when_initialized():
    class _Dummy:
        _initialized = True

        @require_initialized
        async def do_thing(self):
            return "ok"

    d = _Dummy()
    assert asyncio.run(d.do_thing()) == "ok"
