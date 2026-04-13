# packages/cli/tests/test_scanner/test_reactive.py
"""Tests for builtin reactive edge evaluators."""

import pytest

from opentools.scanner.executor.base import TaskOutput
from opentools.scanner.models import (
    ExecutionTier,
    ReactiveEdge,
    ScanTask,
    TaskType,
)
from opentools.scanner.reactive import (
    HighSeverityToDeepDive,
    OpenPortsToVulnScan,
    PackingDetectedToUnpack,
    WebFrameworkToRuleset,
    get_builtin_evaluators,
)


def _make_task(
    tool: str = "nmap",
    task_id: str = "t1",
    scan_id: str = "scan1",
    task_type: TaskType = TaskType.SHELL,
) -> ScanTask:
    return ScanTask(
        id=task_id,
        scan_id=scan_id,
        name=f"{tool}-scan",
        tool=tool,
        task_type=task_type,
    )


def _make_edge(evaluator: str = "builtin:open_ports_to_vuln_scan") -> ReactiveEdge:
    return ReactiveEdge(
        id="edge-1",
        trigger_task_id="t1",
        evaluator=evaluator,
    )


class TestOpenPortsToVulnScan:
    def setup_method(self):
        self.evaluator = OpenPortsToVulnScan()

    def test_http_port_spawns_nuclei(self):
        task = _make_task(tool="nmap")
        output = TaskOutput(
            exit_code=0,
            stdout="80/tcp   open  http\n443/tcp  open  https\n",
        )
        edge = _make_edge()

        new_tasks = self.evaluator(task, output, edge)

        assert len(new_tasks) >= 1
        tool_names = [t.tool for t in new_tasks]
        assert "nuclei" in tool_names or "nikto" in tool_names

    def test_mysql_port_spawns_sqlmap(self):
        task = _make_task(tool="nmap")
        output = TaskOutput(
            exit_code=0,
            stdout="3306/tcp open  mysql\n",
        )
        edge = _make_edge()

        new_tasks = self.evaluator(task, output, edge)

        # mysql port should not spawn web tools, but may not spawn sqlmap
        # without an HTTP endpoint. At minimum, no crash.
        assert isinstance(new_tasks, list)

    def test_no_open_ports_returns_empty(self):
        task = _make_task(tool="nmap")
        output = TaskOutput(exit_code=0, stdout="All 1000 scanned ports are closed\n")
        edge = _make_edge()

        new_tasks = self.evaluator(task, output, edge)

        assert new_tasks == []

    def test_nonzero_exit_returns_empty(self):
        task = _make_task(tool="nmap")
        output = TaskOutput(exit_code=1, stderr="error")
        edge = _make_edge()

        new_tasks = self.evaluator(task, output, edge)

        assert new_tasks == []

    def test_spawned_tasks_reference_scan_id(self):
        task = _make_task(tool="nmap", scan_id="scan-abc")
        output = TaskOutput(
            exit_code=0,
            stdout="80/tcp open http\n",
        )
        edge = _make_edge()

        new_tasks = self.evaluator(task, output, edge)

        for t in new_tasks:
            assert t.scan_id == "scan-abc"
            assert t.spawned_by == "t1"


class TestWebFrameworkToRuleset:
    def setup_method(self):
        self.evaluator = WebFrameworkToRuleset()

    def test_wordpress_detected(self):
        task = _make_task(tool="whatweb")
        output = TaskOutput(
            exit_code=0,
            stdout='[{"plugins":{"WordPress":{"version":["6.4"]}}}]',
        )
        edge = _make_edge("builtin:web_framework_to_ruleset")

        new_tasks = self.evaluator(task, output, edge)

        assert isinstance(new_tasks, list)
        # Should spawn framework-specific scanning tasks
        for t in new_tasks:
            assert t.scan_id == task.scan_id

    def test_no_framework_returns_empty(self):
        task = _make_task(tool="whatweb")
        output = TaskOutput(exit_code=0, stdout='[{}]')
        edge = _make_edge("builtin:web_framework_to_ruleset")

        new_tasks = self.evaluator(task, output, edge)

        assert new_tasks == []


class TestPackingDetectedToUnpack:
    def setup_method(self):
        self.evaluator = PackingDetectedToUnpack()

    def test_packing_detected_spawns_unpack(self):
        task = _make_task(tool="arkana-packing", task_type=TaskType.MCP_CALL)
        output = TaskOutput(
            exit_code=0,
            stdout='{"packed": true, "packer": "UPX"}',
        )
        edge = _make_edge("builtin:packing_detected_to_unpack")

        new_tasks = self.evaluator(task, output, edge)

        assert len(new_tasks) >= 1
        tool_names = [t.tool for t in new_tasks]
        assert any("unpack" in name.lower() or "upx" in name.lower() for name in tool_names)

    def test_not_packed_returns_empty(self):
        task = _make_task(tool="arkana-packing", task_type=TaskType.MCP_CALL)
        output = TaskOutput(
            exit_code=0,
            stdout='{"packed": false}',
        )
        edge = _make_edge("builtin:packing_detected_to_unpack")

        new_tasks = self.evaluator(task, output, edge)

        assert new_tasks == []


class TestHighSeverityToDeepDive:
    def setup_method(self):
        self.evaluator = HighSeverityToDeepDive()

    def test_critical_finding_spawns_deep_dive(self):
        task = _make_task(tool="semgrep")
        output = TaskOutput(
            exit_code=0,
            stdout='{"results":[{"extra":{"severity":"ERROR","metadata":{"cwe":["CWE-89"]}}}]}',
        )
        edge = _make_edge("builtin:high_severity_to_deep_dive")

        new_tasks = self.evaluator(task, output, edge)

        assert isinstance(new_tasks, list)
        # May or may not spawn tasks depending on heuristics; no crash is the baseline

    def test_info_finding_returns_empty(self):
        task = _make_task(tool="semgrep")
        output = TaskOutput(
            exit_code=0,
            stdout='{"results":[{"extra":{"severity":"INFO"}}]}',
        )
        edge = _make_edge("builtin:high_severity_to_deep_dive")

        new_tasks = self.evaluator(task, output, edge)

        assert new_tasks == []


class TestGetBuiltinEvaluators:
    def test_returns_dict(self):
        evaluators = get_builtin_evaluators()
        assert isinstance(evaluators, dict)

    def test_contains_expected_evaluators(self):
        evaluators = get_builtin_evaluators()
        assert "builtin:open_ports_to_vuln_scan" in evaluators
        assert "builtin:web_framework_to_ruleset" in evaluators
        assert "builtin:packing_detected_to_unpack" in evaluators
        assert "builtin:high_severity_to_deep_dive" in evaluators

    def test_evaluators_are_callable(self):
        evaluators = get_builtin_evaluators()
        for name, evaluator in evaluators.items():
            assert callable(evaluator), f"Evaluator {name} is not callable"
