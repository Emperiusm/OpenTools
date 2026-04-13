"""Tests for TaskExecutor protocol and TaskOutput model."""

from opentools.scanner.executor.base import TaskExecutor, TaskOutput


class TestTaskOutput:
    def test_defaults(self):
        output = TaskOutput()
        assert output.exit_code is None
        assert output.stdout == ""
        assert output.stderr == ""
        assert output.duration_ms == 0
        assert output.cached is False

    def test_success_output(self):
        output = TaskOutput(exit_code=0, stdout="result", duration_ms=150)
        assert output.exit_code == 0
        assert output.stdout == "result"
        assert output.duration_ms == 150

    def test_failure_output(self):
        output = TaskOutput(exit_code=1, stderr="error msg", duration_ms=50)
        assert output.exit_code == 1
        assert output.stderr == "error msg"

    def test_cached_output(self):
        output = TaskOutput(exit_code=0, stdout="cached", cached=True, duration_ms=0)
        assert output.cached is True

    def test_serialization_round_trip(self):
        output = TaskOutput(exit_code=0, stdout="hello", stderr="warn", duration_ms=99)
        restored = TaskOutput.model_validate_json(output.model_dump_json())
        assert restored == output


class TestTaskExecutorProtocol:
    def test_protocol_structural_subtyping(self):
        """A class with the right method signature satisfies the protocol."""

        class FakeExecutor:
            async def execute(self, task, on_output, cancellation):
                return TaskOutput(exit_code=0)

        assert isinstance(FakeExecutor(), TaskExecutor)

    def test_non_conforming_class_rejected(self):
        """A class missing the execute method does not satisfy the protocol."""

        class NotAnExecutor:
            pass

        assert not isinstance(NotAnExecutor(), TaskExecutor)
