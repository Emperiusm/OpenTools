"""Tests for OutputBuffer — backpressure with disk spillover."""

import tempfile
from pathlib import Path

import pytest

from opentools.scanner.output_buffer import OutputBuffer


class TestOutputBuffer:
    def test_small_output_stays_in_memory(self):
        buf = OutputBuffer(memory_limit=1024)
        buf.write(b"hello world")
        assert buf.size == 11
        assert buf.spilled is False
        assert buf.read() == b"hello world"

    def test_multiple_writes(self):
        buf = OutputBuffer(memory_limit=1024)
        buf.write(b"aaa")
        buf.write(b"bbb")
        assert buf.size == 6
        assert buf.read() == b"aaabbb"

    def test_spills_to_disk_above_memory_limit(self):
        buf = OutputBuffer(memory_limit=10)
        buf.write(b"12345")
        buf.write(b"67890")
        assert buf.spilled is False  # exactly at limit

        buf.write(b"X")  # exceeds limit
        assert buf.spilled is True
        assert buf.size == 11
        assert buf.read() == b"1234567890X"

    def test_read_after_spill(self):
        buf = OutputBuffer(memory_limit=5)
        buf.write(b"abcde")
        buf.write(b"fghij")
        data = buf.read()
        assert data == b"abcdefghij"

    def test_cleanup_removes_temp_file(self):
        buf = OutputBuffer(memory_limit=5)
        buf.write(b"abcdefghij")  # triggers spill
        assert buf.spilled is True
        spill_path = buf._spill_path
        assert spill_path is not None
        assert Path(spill_path).exists()

        buf.cleanup()
        assert not Path(spill_path).exists()

    def test_cleanup_no_spill_is_noop(self):
        buf = OutputBuffer(memory_limit=1024)
        buf.write(b"small")
        buf.cleanup()  # should not raise

    def test_empty_buffer(self):
        buf = OutputBuffer()
        assert buf.size == 0
        assert buf.read() == b""
        assert buf.spilled is False

    def test_as_callback(self):
        buf = OutputBuffer(memory_limit=1024)
        callback = buf.write
        callback(b"chunk1")
        callback(b"chunk2")
        assert buf.read() == b"chunk1chunk2"

    def test_disk_spill_limit_raises(self):
        buf = OutputBuffer(memory_limit=5, disk_spill_limit=20)
        buf.write(b"123456")  # spills to disk (6 > 5)
        buf.write(b"1234567890")  # 16 total, still ok
        with pytest.raises(OverflowError, match="spill limit"):
            buf.write(b"123456")  # 22 > 20, exceeds disk limit

    def test_context_manager(self):
        with OutputBuffer(memory_limit=5) as buf:
            buf.write(b"abcdefghij")
            assert buf.spilled is True
            spill_path = buf._spill_path
        if spill_path:
            assert not Path(spill_path).exists()
