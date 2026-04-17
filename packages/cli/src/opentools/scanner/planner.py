# packages/cli/src/opentools/scanner/planner.py
"""ScanPlanner — builds a task DAG from a profile + detected target.

The planner is the integration point between target detection, profile
resolution, and the ScanEngine. It takes a target string and optional
profile name, runs detection, resolves profile inheritance, evaluates
tool conditions against target metadata, and produces a list of
ScanTask objects ready for ScanEngine.load_tasks().
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from typing import Optional

from opentools.scanner.models import (
    ReactiveEdge,
    ScanConfig,
    ScanMode,
    ScanTask,
    TargetType,
    TaskStatus,
    TaskType,
)
from opentools.scanner.profiles import (
    DEFAULT_PROFILES,
    ProfilePhase,
    ProfileTool,
    ReactiveEdgeTemplate,
    ScanProfile,
    load_builtin_profile,
)
from opentools.scanner.target import DetectedTarget, TargetDetector

# ---------------------------------------------------------------------------
# Safe condition evaluator — replaces eval() for profile conditions
# ---------------------------------------------------------------------------

import ast
import operator

_SAFE_OPS = {
    ast.And: lambda vals: all(vals),
    ast.Or: lambda vals: any(vals),
}

_SAFE_COMPARE = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
}

_SAFE_UNARY = {
    ast.Not: operator.not_,
    ast.USub: operator.neg,
}


def _safe_eval(expr: str, variables: dict) -> object:
    """Evaluate a simple boolean expression safely (no code execution).

    Supports: variable lookup, ``in``/``not in``, boolean operators,
    comparisons, literals (str, int, float, bool, None, list, tuple).
    Does NOT support function calls, attribute access, or subscripts.
    """
    tree = ast.parse(expr, mode="eval")
    return _eval_node(tree.body, variables)


def _eval_node(node: ast.AST, variables: dict) -> object:
    if isinstance(node, ast.Expression):
        return _eval_node(node.body, variables)
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        if node.id in variables:
            return variables[node.id]
        raise NameError(f"Undefined variable: {node.id}")
    if isinstance(node, ast.List):
        return [_eval_node(e, variables) for e in node.elts]
    if isinstance(node, ast.Tuple):
        return tuple(_eval_node(e, variables) for e in node.elts)
    if isinstance(node, ast.BoolOp):
        op_fn = _SAFE_OPS.get(type(node.op))
        if op_fn is None:
            raise ValueError(f"Unsupported bool op: {type(node.op).__name__}")
        return op_fn([_eval_node(v, variables) for v in node.values])
    if isinstance(node, ast.UnaryOp):
        op_fn = _SAFE_UNARY.get(type(node.op))
        if op_fn is None:
            raise ValueError(f"Unsupported unary op: {type(node.op).__name__}")
        return op_fn(_eval_node(node.operand, variables))
    if isinstance(node, ast.Compare):
        left = _eval_node(node.left, variables)
        for op, comparator in zip(node.ops, node.comparators):
            op_fn = _SAFE_COMPARE.get(type(op))
            if op_fn is None:
                raise ValueError(f"Unsupported compare op: {type(op).__name__}")
            right = _eval_node(comparator, variables)
            if not op_fn(left, right):
                return False
            left = right
        return True
    raise ValueError(f"Unsupported expression: {type(node).__name__}")


class ScanPlanner:
    """Builds a task DAG from a profile + detected target.

    Usage::

        planner = ScanPlanner()
        tasks = planner.plan(
            target="/path/to/source",
            profile_name="source-quick",
            mode=ScanMode.AUTO,
            scan_id="scan-123",
            engagement_id="eng-456",
        )
        engine.load_tasks(tasks)
    """

    def __init__(self) -> None:
        self._detector = TargetDetector()

    def plan(
        self,
        target: str,
        profile_name: Optional[str],
        mode: ScanMode,
        scan_id: str,
        engagement_id: str,
        config: Optional[ScanConfig] = None,
        override_type: Optional[TargetType] = None,
        add_tools: Optional[list[str]] = None,
        remove_tools: Optional[list[str]] = None,
    ) -> list[ScanTask]:
        """Plan a scan: detect target, load profile, build task DAG.

        Args:
            target: Target string (path, URL, IP, image name, etc.)
            profile_name: Profile name, or None for auto-detect.
            mode: Scan mode (auto or assisted).
            scan_id: Unique scan identifier.
            engagement_id: Engagement to bind scan to.
            config: Optional scan configuration overrides.
            override_type: Force a specific target type.
            add_tools: Tool names to add (appended to last phase).
            remove_tools: Tool names to remove from profile.

        Returns:
            List of ScanTask objects ready for ScanEngine.load_tasks().

        Raises:
            ValueError: If target type cannot be determined.
            FileNotFoundError: If profile does not exist.
        """
        # 1. Detect target
        detected = self._detector.detect(target, override_type=override_type)

        # 2. Resolve profile
        if profile_name is None:
            profile_name = DEFAULT_PROFILES.get(detected.target_type)
            if profile_name is None:
                raise ValueError(
                    f"No default profile for target type {detected.target_type}. "
                    "Specify a profile explicitly with --profile."
                )

        profile = load_builtin_profile(profile_name)

        # 3. Resolve inheritance
        profile = self.resolve_inheritance(profile, self._load_parent_profiles(profile))

        # 4. Apply add/remove tool overrides
        if remove_tools:
            profile = self._remove_tools_from_profile(profile, remove_tools)

        # 5. Build task DAG
        return self.plan_from_profile(
            profile=profile,
            detected=detected,
            scan_id=scan_id,
            engagement_id=engagement_id,
            mode=mode,
            config=config,
        )

    def plan_from_profile(
        self,
        profile: ScanProfile,
        detected: DetectedTarget,
        scan_id: str,
        engagement_id: str,
        mode: ScanMode,
        config: Optional[ScanConfig] = None,
    ) -> list[ScanTask]:
        """Build a task DAG from a resolved profile and detected target.

        This is the core graph-building method. It:
        1. Iterates through profile phases in order
        2. Evaluates tool conditions against target metadata
        3. Creates ScanTask instances with proper dependencies
        4. Attaches reactive edges from profile-level templates

        Args:
            profile: Resolved ScanProfile (inheritance already applied).
            detected: Detected target information.
            scan_id: Unique scan identifier.
            engagement_id: Engagement identifier.
            mode: Scan mode.
            config: Optional scan configuration.

        Returns:
            List of ScanTask objects.
        """
        target_str = detected.resolved_path or detected.original_target
        metadata = detected.metadata
        all_tasks: list[ScanTask] = []
        previous_phase_ids: list[str] = []

        for phase in profile.phases:
            phase_task_ids: list[str] = []

            # Filter tools by condition
            eligible_tools = [
                tool for tool in phase.tools
                if self._evaluate_condition(tool.condition, metadata)
            ]

            # Build tasks for this phase
            prev_in_phase: Optional[str] = None
            for tool_def in eligible_tools:
                task_id = f"{scan_id}-{tool_def.tool}-{uuid.uuid4().hex[:8]}"

                # Compute dependencies
                if phase.parallel:
                    # Parallel: depend on all tasks from previous phase
                    depends_on = list(previous_phase_ids)
                else:
                    # Sequential: depend on previous task in this phase,
                    # or previous phase if first task
                    if prev_in_phase is not None:
                        depends_on = [prev_in_phase]
                    else:
                        depends_on = list(previous_phase_ids)

                # Resolve command template
                command = self._resolve_template(
                    tool_def.command_template, target_str, scan_id, metadata
                )

                # Resolve MCP args template
                mcp_args = None
                if tool_def.mcp_args_template:
                    mcp_args = {
                        k: self._resolve_template(str(v), target_str, scan_id, metadata)
                        if isinstance(v, str) else v
                        for k, v in tool_def.mcp_args_template.items()
                    }

                task = ScanTask(
                    id=task_id,
                    scan_id=scan_id,
                    name=f"{tool_def.tool}",
                    tool=tool_def.tool,
                    task_type=tool_def.task_type,
                    command=command,
                    mcp_server=tool_def.mcp_server,
                    mcp_tool=tool_def.mcp_tool,
                    mcp_args=mcp_args,
                    depends_on=depends_on,
                    status=TaskStatus.PENDING,
                    priority=tool_def.priority,
                    tier=tool_def.tier,
                    resource_group=tool_def.resource_group,
                    retry_policy=tool_def.retry_policy,
                    cache_key=self._resolve_template(
                        tool_def.cache_key_template, target_str, scan_id, metadata
                    ) if tool_def.cache_key_template else None,
                    parser=tool_def.parser,
                    isolation=tool_def.isolation,
                )

                all_tasks.append(task)
                phase_task_ids.append(task_id)
                prev_in_phase = task_id

            previous_phase_ids = phase_task_ids

        # Build tool → task index for O(1) lookup
        tasks_by_tool: dict[str, list[ScanTask]] = defaultdict(list)
        for task in all_tasks:
            tasks_by_tool[task.tool].append(task)

        # Attach reactive edges from profile-level templates
        for template in profile.reactive_edges:
            if template.trigger_tool == "*":
                for task in all_tasks:
                    self._attach_reactive_edges_to_task(task, [template])
            else:
                for task in tasks_by_tool.get(template.trigger_tool, []):
                    self._attach_reactive_edges_to_task(task, [template])

        # Attach per-tool reactive edges
        for phase in profile.phases:
            for tool_def in phase.tools:
                if tool_def.reactive_edges:
                    for task in tasks_by_tool.get(tool_def.tool, []):
                        self._attach_reactive_edges_to_task(task, tool_def.reactive_edges)

        return all_tasks

    def resolve_inheritance(
        self,
        profile: ScanProfile,
        parent_profiles: dict[str, ScanProfile],
    ) -> ScanProfile:
        """Resolve profile inheritance by merging parent phases.

        Args:
            profile: The child profile.
            parent_profiles: Mapping of profile ID → ScanProfile for lookup.

        Returns:
            A new ScanProfile with parent phases merged in.
        """
        if profile.extends is None:
            return profile

        parent = parent_profiles.get(profile.extends)
        if parent is None:
            return profile

        # Recursively resolve parent inheritance first
        parent = self.resolve_inheritance(parent, parent_profiles)

        # Start with parent phases
        merged_phases: list[ProfilePhase] = []
        remove_set = set(profile.remove_tools)

        for phase in parent.phases:
            filtered_tools = [
                t for t in phase.tools if t.tool not in remove_set
            ]
            if filtered_tools:
                merged_phases.append(
                    ProfilePhase(
                        name=phase.name,
                        tools=filtered_tools,
                        parallel=phase.parallel,
                    )
                )

        # Add child's own phases
        for phase in profile.phases:
            merged_phases.append(phase)

        # Append add_tools to last phase (or create new phase)
        if profile.add_tools:
            if merged_phases:
                last_phase = merged_phases[-1]
                merged_phases[-1] = ProfilePhase(
                    name=last_phase.name,
                    tools=last_phase.tools + profile.add_tools,
                    parallel=last_phase.parallel,
                )
            else:
                merged_phases.append(
                    ProfilePhase(
                        name="added-tools",
                        tools=profile.add_tools,
                        parallel=True,
                    )
                )

        # Merge reactive edges
        merged_edges = list(parent.reactive_edges) + list(profile.reactive_edges)

        return ScanProfile(
            id=profile.id,
            name=profile.name,
            description=profile.description,
            target_types=profile.target_types or parent.target_types,
            phases=merged_phases,
            reactive_edges=merged_edges,
            default_config=profile.default_config or parent.default_config,
            override_config=profile.override_config,
        )

    def _load_parent_profiles(self, profile: ScanProfile) -> dict[str, ScanProfile]:
        """Recursively load parent profiles for inheritance resolution."""
        parents: dict[str, ScanProfile] = {}
        current = profile
        visited: set[str] = {current.id}

        while current.extends is not None:
            parent_name = current.extends
            if parent_name in visited:
                break  # Cycle detection
            try:
                parent = load_builtin_profile(parent_name)
                parents[parent_name] = parent
                visited.add(parent_name)
                current = parent
            except FileNotFoundError:
                break

        return parents

    def _remove_tools_from_profile(
        self, profile: ScanProfile, remove_tools: list[str]
    ) -> ScanProfile:
        """Remove tools from all phases in a profile."""
        remove_set = set(remove_tools)
        new_phases = []
        for phase in profile.phases:
            filtered_tools = [t for t in phase.tools if t.tool not in remove_set]
            if filtered_tools:
                new_phases.append(
                    ProfilePhase(
                        name=phase.name,
                        tools=filtered_tools,
                        parallel=phase.parallel,
                    )
                )
        return profile.model_copy(update={"phases": new_phases})

    def _evaluate_condition(
        self, condition: Optional[str], metadata: dict
    ) -> bool:
        """Evaluate a tool condition against target metadata.

        Conditions are simple Python expressions evaluated against
        the metadata dictionary as local variables. Supports:
        - ``has_package_lock`` (bool check)
        - ``'python' in languages`` (membership check)
        - ``language in ['python', 'java']`` (value check)
        - Complex boolean expressions with ``and``/``or``

        Args:
            condition: Condition string, or None (always included).
            metadata: Target metadata dictionary.

        Returns:
            True if the condition is met (or if no condition).
        """
        if condition is None:
            return True

        try:
            # Provide metadata keys as local variables
            local_vars = dict(metadata)
            # Also provide common computed variables
            local_vars.setdefault("languages", [])
            local_vars.setdefault("framework_hints", [])
            local_vars.setdefault("has_dockerfile", False)
            local_vars.setdefault("has_package_lock", False)

            result = _safe_eval(condition, local_vars)
            return bool(result)
        except Exception:
            # If condition evaluation fails, skip the tool
            return False

    def _resolve_template(
        self,
        template: Optional[str],
        target: str,
        scan_id: str,
        metadata: dict,
    ) -> Optional[str]:
        """Resolve placeholders in a command/args template.

        Supported placeholders:
        - ``{target}`` — resolved target path/URL
        - ``{scan_id}`` — scan identifier
        - ``{target_host}`` — hostname extracted from URL (if applicable)
        - ``{target_hash}`` — content hash from metadata (if available)

        Args:
            template: Template string with placeholders.
            target: Resolved target path or URL.
            scan_id: Scan identifier.
            metadata: Target metadata.

        Returns:
            Resolved string, or None if template is None.
        """
        if template is None:
            return None

        # Extract host and port for substitution placeholders.
        target_host = target
        target_port = ""
        if "://" in target:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            target_host = parsed.hostname or target
            target_port = str(parsed.port) if parsed.port else ""
        elif ":" in target and "/" not in target:
            # host:port form (e.g. "pentest-ground.com:6379")
            host_part, _, port_part = target.rpartition(":")
            if port_part.isdigit():
                target_host = host_part
                target_port = port_part

        # Default to a common port range when no explicit port was given —
        # avoids producing a syntactically invalid `-p ` argument for nmap.
        port_or_range = target_port or "1-10000"

        replacements = {
            "{target}": target,
            "{scan_id}": scan_id,
            "{target_host}": target_host,
            "{target_port}": port_or_range,
            "{target_hash}": metadata.get("content_hash", "unknown"),
            "{tool}": "",  # filled per-tool if needed
        }

        result = template
        for placeholder, value in replacements.items():
            result = result.replace(placeholder, str(value))

        return result

    def _attach_reactive_edges(
        self,
        tasks: list[ScanTask],
        edge_templates: list[ReactiveEdgeTemplate],
    ) -> None:
        """Attach reactive edges from profile-level templates to tasks."""
        for template in edge_templates:
            if template.trigger_tool == "*":
                # Wildcard: attach to all tasks
                for task in tasks:
                    self._attach_reactive_edges_to_task(task, [template])
            else:
                # Attach to matching tool tasks
                matching = [t for t in tasks if t.tool == template.trigger_tool]
                for task in matching:
                    self._attach_reactive_edges_to_task(task, [template])

    def _attach_reactive_edges_to_task(
        self,
        task: ScanTask,
        templates: list[ReactiveEdgeTemplate],
    ) -> None:
        """Instantiate reactive edge templates into concrete ReactiveEdge instances."""
        new_edges: list[ReactiveEdge] = list(task.reactive_edges)
        for template in templates:
            edge = ReactiveEdge(
                id=f"edge-{uuid.uuid4().hex[:12]}",
                trigger_task_id=task.id,
                evaluator=template.evaluator,
                condition=template.condition,
                max_spawns=template.max_spawns,
                max_spawns_per_trigger=template.max_spawns_per_trigger,
                cooldown_seconds=int(template.cooldown_seconds),
                budget_group=template.budget_group,
                min_upstream_confidence=template.min_upstream_confidence,
            )
            new_edges.append(edge)

        # ScanTask is a Pydantic model — use direct assignment
        task.reactive_edges = new_edges
