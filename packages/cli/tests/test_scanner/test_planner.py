# packages/cli/tests/test_scanner/test_planner.py
"""Tests for ScanPlanner — profile resolution and task DAG building."""

import pytest

from opentools.scanner.models import (
    ReactiveEdge,
    ScanConfig,
    ScanMode,
    ScanTask,
    TargetType,
    TaskStatus,
    TaskType,
)
from opentools.scanner.planner import ScanPlanner
from opentools.scanner.profiles import (
    ProfilePhase,
    ProfileTool,
    ReactiveEdgeTemplate,
    ScanProfile,
    load_builtin_profile,
)
from opentools.scanner.target import DetectedTarget


class TestScanPlannerBasic:
    def setup_method(self):
        self.planner = ScanPlanner()

    def test_plan_returns_scan_tasks(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="test-scan-1",
            engagement_id="eng-1",
        )
        assert isinstance(tasks, list)
        assert len(tasks) >= 1
        for t in tasks:
            assert isinstance(t, ScanTask)
            assert t.scan_id == "test-scan-1"

    def test_plan_sets_correct_scan_id(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="my-scan",
            engagement_id="eng-1",
        )
        for t in tasks:
            assert t.scan_id == "my-scan"

    def test_plan_tasks_are_pending(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="test-1",
            engagement_id="eng-1",
        )
        for t in tasks:
            assert t.status == TaskStatus.PENDING

    def test_plan_includes_expected_tools(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="test-1",
            engagement_id="eng-1",
        )
        tool_names = [t.tool for t in tasks]
        assert "semgrep" in tool_names
        assert "gitleaks" in tool_names


class TestScanPlannerPhaseOrdering:
    """Verify that tasks from later phases depend on all tasks from earlier phases."""

    def setup_method(self):
        self.planner = ScanPlanner()

    def test_multiphase_dependencies(self):
        """Tasks in phase 2 should depend on all tasks in phase 1."""
        profile = ScanProfile(
            id="test-multiphase",
            name="Test Multi-Phase",
            description="Test profile with two phases",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="phase-1",
                    tools=[
                        ProfileTool(tool="tool-a", task_type=TaskType.SHELL, command_template="echo a"),
                        ProfileTool(tool="tool-b", task_type=TaskType.SHELL, command_template="echo b"),
                    ],
                ),
                ProfilePhase(
                    name="phase-2",
                    tools=[
                        ProfileTool(tool="tool-c", task_type=TaskType.SHELL, command_template="echo c"),
                    ],
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/tmp/test",
            original_target="/tmp/test",
            metadata={"languages": ["python"]},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        # Find phase-2 task
        phase2_tasks = [t for t in tasks if t.tool == "tool-c"]
        phase1_tasks = [t for t in tasks if t.tool in {"tool-a", "tool-b"}]

        assert len(phase2_tasks) == 1
        assert len(phase1_tasks) == 2

        phase1_ids = {t.id for t in phase1_tasks}
        # Phase 2 task should depend on ALL phase 1 tasks
        assert set(phase2_tasks[0].depends_on) == phase1_ids

    def test_parallel_phase_no_internal_deps(self):
        """Tasks within a parallel phase should not depend on each other."""
        profile = ScanProfile(
            id="test-parallel",
            name="Test Parallel",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="phase-1",
                    parallel=True,
                    tools=[
                        ProfileTool(tool="tool-a", task_type=TaskType.SHELL, command_template="echo a"),
                        ProfileTool(tool="tool-b", task_type=TaskType.SHELL, command_template="echo b"),
                    ],
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/tmp/test",
            original_target="/tmp/test",
            metadata={"languages": ["python"]},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        # No task in phase 1 depends on another task in phase 1
        task_ids = {t.id for t in tasks}
        for t in tasks:
            for dep in t.depends_on:
                assert dep not in task_ids or any(
                    other.id == dep and other.tool not in {"tool-a", "tool-b"}
                    for other in tasks
                )

    def test_sequential_phase_creates_chain(self):
        """Tasks in a sequential phase should form a dependency chain."""
        profile = ScanProfile(
            id="test-sequential",
            name="Test Sequential",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="phase-1",
                    parallel=False,
                    tools=[
                        ProfileTool(tool="tool-a", task_type=TaskType.SHELL, command_template="echo a"),
                        ProfileTool(tool="tool-b", task_type=TaskType.SHELL, command_template="echo b"),
                        ProfileTool(tool="tool-c", task_type=TaskType.SHELL, command_template="echo c"),
                    ],
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/tmp/test",
            original_target="/tmp/test",
            metadata={"languages": ["python"]},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        # tool-b depends on tool-a, tool-c depends on tool-b
        task_map = {t.tool: t for t in tasks}
        assert task_map["tool-a"].depends_on == []
        assert task_map["tool-b"].depends_on == [task_map["tool-a"].id]
        assert task_map["tool-c"].depends_on == [task_map["tool-b"].id]


class TestScanPlannerConditions:
    """Verify that tool conditions are evaluated correctly."""

    def setup_method(self):
        self.planner = ScanPlanner()

    def test_condition_met_includes_tool(self):
        profile = ScanProfile(
            id="test-cond",
            name="Test Condition",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="analysis",
                    tools=[
                        ProfileTool(
                            tool="trivy",
                            task_type=TaskType.SHELL,
                            command_template="trivy fs {target}",
                            condition="has_package_lock",
                        ),
                    ],
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/tmp/test",
            original_target="/tmp/test",
            metadata={"languages": ["javascript"], "has_package_lock": True},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        assert any(t.tool == "trivy" for t in tasks)

    def test_condition_not_met_excludes_tool(self):
        profile = ScanProfile(
            id="test-cond",
            name="Test Condition",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="analysis",
                    tools=[
                        ProfileTool(
                            tool="trivy",
                            task_type=TaskType.SHELL,
                            command_template="trivy fs {target}",
                            condition="has_package_lock",
                        ),
                    ],
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/tmp/test",
            original_target="/tmp/test",
            metadata={"languages": ["python"], "has_package_lock": False},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        assert not any(t.tool == "trivy" for t in tasks)

    def test_language_condition(self):
        profile = ScanProfile(
            id="test-lang",
            name="Test Language",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="analysis",
                    tools=[
                        ProfileTool(
                            tool="semgrep-python",
                            task_type=TaskType.SHELL,
                            command_template="semgrep --config p/python {target}",
                            condition="'python' in languages",
                        ),
                        ProfileTool(
                            tool="semgrep-java",
                            task_type=TaskType.SHELL,
                            command_template="semgrep --config p/java {target}",
                            condition="'java' in languages",
                        ),
                    ],
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/tmp/test",
            original_target="/tmp/test",
            metadata={"languages": ["python"]},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        tool_names = [t.tool for t in tasks]
        assert "semgrep-python" in tool_names
        assert "semgrep-java" not in tool_names


class TestScanPlannerReactiveEdges:
    """Verify that reactive edge templates are instantiated on tasks."""

    def setup_method(self):
        self.planner = ScanPlanner()

    def test_reactive_edges_attached_to_trigger_task(self):
        profile = ScanProfile(
            id="test-edges",
            name="Test Edges",
            description="Test",
            target_types=[TargetType.NETWORK],
            phases=[
                ProfilePhase(
                    name="discovery",
                    tools=[
                        ProfileTool(tool="nmap", task_type=TaskType.SHELL, command_template="nmap {target}"),
                    ],
                ),
            ],
            reactive_edges=[
                ReactiveEdgeTemplate(
                    evaluator="builtin:open_ports_to_vuln_scan",
                    trigger_tool="nmap",
                    max_spawns=20,
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.NETWORK,
            original_target="192.168.1.0/24",
            metadata={},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        nmap_tasks = [t for t in tasks if t.tool == "nmap"]
        assert len(nmap_tasks) == 1
        assert len(nmap_tasks[0].reactive_edges) >= 1
        assert nmap_tasks[0].reactive_edges[0].evaluator == "builtin:open_ports_to_vuln_scan"

    def test_wildcard_trigger_attaches_to_all(self):
        profile = ScanProfile(
            id="test-wildcard",
            name="Test Wildcard",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="analysis",
                    tools=[
                        ProfileTool(tool="semgrep", task_type=TaskType.SHELL, command_template="semgrep {target}"),
                        ProfileTool(tool="gitleaks", task_type=TaskType.SHELL, command_template="gitleaks {target}"),
                    ],
                ),
            ],
            reactive_edges=[
                ReactiveEdgeTemplate(
                    evaluator="builtin:high_severity_to_deep_dive",
                    trigger_tool="*",
                    max_spawns=5,
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/tmp/test",
            original_target="/tmp/test",
            metadata={"languages": ["python"]},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        # Both tasks should have the wildcard edge attached
        for t in tasks:
            assert len(t.reactive_edges) >= 1
            assert any(
                e.evaluator == "builtin:high_severity_to_deep_dive"
                for e in t.reactive_edges
            )


class TestScanPlannerProfileInheritance:
    """Verify that profile inheritance (extends) works correctly."""

    def setup_method(self):
        self.planner = ScanPlanner()

    def test_extends_merges_parent_phases(self):
        parent = ScanProfile(
            id="parent",
            name="Parent",
            description="Parent profile",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="analysis",
                    tools=[
                        ProfileTool(tool="semgrep", task_type=TaskType.SHELL, command_template="semgrep {target}"),
                        ProfileTool(tool="gitleaks", task_type=TaskType.SHELL, command_template="gitleaks {target}"),
                    ],
                ),
            ],
        )

        child = ScanProfile(
            id="child",
            name="Child",
            description="Child profile extending parent",
            target_types=[TargetType.SOURCE_CODE],
            extends="parent",
            add_tools=[
                ProfileTool(tool="trivy", task_type=TaskType.SHELL, command_template="trivy {target}"),
            ],
            remove_tools=["gitleaks"],
        )

        resolved = self.planner.resolve_inheritance(child, {"parent": parent})

        all_tools = [t.tool for phase in resolved.phases for t in phase.tools]
        assert "semgrep" in all_tools
        assert "trivy" in all_tools
        assert "gitleaks" not in all_tools

    def test_no_extends_returns_unchanged(self):
        profile = ScanProfile(
            id="standalone",
            name="Standalone",
            description="No parent",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="analysis",
                    tools=[
                        ProfileTool(tool="semgrep", task_type=TaskType.SHELL, command_template="semgrep {target}"),
                    ],
                ),
            ],
        )

        resolved = self.planner.resolve_inheritance(profile, {})
        assert len(resolved.phases) == 1
        assert resolved.phases[0].tools[0].tool == "semgrep"


class TestScanPlannerCommandTemplates:
    """Verify that command templates are resolved with target metadata."""

    def setup_method(self):
        self.planner = ScanPlanner()

    def test_target_placeholder_resolved(self):
        profile = ScanProfile(
            id="test-template",
            name="Test Template",
            description="Test",
            target_types=[TargetType.SOURCE_CODE],
            phases=[
                ProfilePhase(
                    name="analysis",
                    tools=[
                        ProfileTool(
                            tool="semgrep",
                            task_type=TaskType.SHELL,
                            command_template="semgrep --config auto --json {target}",
                        ),
                    ],
                ),
            ],
        )

        detected = DetectedTarget(
            target_type=TargetType.SOURCE_CODE,
            resolved_path="/home/user/myapp",
            original_target="/home/user/myapp",
            metadata={"languages": ["python"]},
        )

        tasks = self.planner.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id="test-1",
            engagement_id="eng-1",
            mode=ScanMode.AUTO,
        )

        assert len(tasks) == 1
        assert "/home/user/myapp" in tasks[0].command


class TestScanPlannerAutoDetect:
    """Verify auto-detection selects the correct default profile."""

    def setup_method(self):
        self.planner = ScanPlanner()

    def test_auto_detect_source(self, tmp_path):
        (tmp_path / "main.py").write_text("import flask\napp = flask.Flask(__name__)")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name=None,  # auto-detect
            mode=ScanMode.AUTO,
            scan_id="test-1",
            engagement_id="eng-1",
        )
        assert len(tasks) >= 1
        # Should use source-full by default
        tool_names = [t.tool for t in tasks]
        assert "semgrep" in tool_names

    def test_explicit_profile_overrides_auto(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="test-1",
            engagement_id="eng-1",
        )
        tool_names = [t.tool for t in tasks]
        assert "semgrep" in tool_names
        assert "gitleaks" in tool_names


class TestScanPlannerConfigOverrides:
    """Verify that ScanConfig overrides are applied."""

    def setup_method(self):
        self.planner = ScanPlanner()

    def test_add_tools(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="test-1",
            engagement_id="eng-1",
            add_tools=["bandit"],
        )
        # add_tools should not crash; tool may or may not appear
        # since we only support named additions from profile
        assert isinstance(tasks, list)

    def test_remove_tools(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="test-1",
            engagement_id="eng-1",
            remove_tools=["gitleaks"],
        )
        tool_names = [t.tool for t in tasks]
        assert "gitleaks" not in tool_names
        assert "semgrep" in tool_names

    def test_unique_task_ids(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        tasks = self.planner.plan(
            target=str(tmp_path),
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="test-1",
            engagement_id="eng-1",
        )
        task_ids = [t.id for t in tasks]
        assert len(task_ids) == len(set(task_ids)), "Task IDs must be unique"
