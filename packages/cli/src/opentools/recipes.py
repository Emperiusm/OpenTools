"""Recipe loading, validation, and async execution engine."""

import asyncio
import json
import re
import shlex
import sys
import time
from pathlib import Path
from typing import Optional

from opentools.models import (
    Recipe, RecipeStep, RecipeVariable, StepType,
    FailureAction, StepResult, RecipeResult, ToolkitConfig,
)


class RecipeRunner:
    """Load, validate, and execute security workflow recipes."""

    def __init__(self, config: ToolkitConfig, recipes_path: Path) -> None:
        self._config = config
        self._recipes_path = recipes_path
        self._recipes: dict[str, Recipe] = {}
        self._load_recipes()

    def _load_recipes(self) -> None:
        """Load recipes from recipes.json."""
        if not self._recipes_path.exists():
            return
        with open(self._recipes_path) as f:
            data = json.load(f)
        for entry in data.get("recipes", []):
            # Parse variables
            variables = {}
            for vname, vspec in entry.get("variables", {}).items():
                variables[vname] = RecipeVariable(
                    description=vspec.get("description", ""),
                    required=vspec.get("required", True),
                    default=vspec.get("default"),
                )
            # Parse steps
            steps = []
            for s in entry.get("steps", []):
                steps.append(RecipeStep(
                    name=s["name"],
                    tool=s.get("tool", ""),
                    command=s.get("command", ""),
                    timeout=s.get("timeout", 300),
                    step_type=StepType(s.get("step_type", "shell")),
                    on_failure=FailureAction(s.get("on_failure", "continue")),
                    depends_on=s.get("depends_on"),
                ))
            recipe = Recipe(
                id=entry["id"],
                name=entry["name"],
                description=entry.get("description", ""),
                requires=entry.get("requires", []),
                variables=variables,
                steps=steps,
                parallel=entry.get("parallel", False),
                output=entry.get("output", "consolidated-findings-table"),
            )
            self._recipes[recipe.id] = recipe

    def list_recipes(self) -> list[Recipe]:
        """Return all loaded recipes."""
        return list(self._recipes.values())

    def get_recipe(self, recipe_id: str) -> Recipe:
        """Get a recipe by ID. Raises KeyError if not found."""
        if recipe_id not in self._recipes:
            raise KeyError(f"Recipe not found: {recipe_id}")
        return self._recipes[recipe_id]

    def validate_recipe(self, recipe_id: str) -> list[str]:
        """Validate a recipe. Returns list of issues (empty = valid)."""
        try:
            recipe = self.get_recipe(recipe_id)
        except KeyError:
            return [f"Recipe '{recipe_id}' not found"]

        issues = []
        if not recipe.steps:
            issues.append("Recipe has no steps")

        # Check for depends_on referencing nonexistent steps
        step_names = {s.name for s in recipe.steps}
        for step in recipe.steps:
            if step.depends_on:
                for dep in step.depends_on:
                    if dep not in step_names:
                        issues.append(f"Step '{step.name}' depends on '{dep}' which doesn't exist")

        return issues

    def substitute_variables(self, command: str, variables: dict[str, str]) -> str:
        """Replace {{var}} placeholders in a command string."""
        result = command
        for key, value in variables.items():
            result = result.replace(f"{{{{{key}}}}}", value)
        return result

    async def run(
        self,
        recipe_id: str,
        variables: dict[str, str],
        dry_run: bool = False,
        quiet: bool = False,
    ) -> RecipeResult:
        """Execute a recipe. Returns RecipeResult with all step outcomes."""
        recipe = self.get_recipe(recipe_id)

        # Validate required variables and apply defaults for all variables
        for vname, vspec in recipe.variables.items():
            if vname not in variables:
                if vspec.default is not None:
                    variables[vname] = vspec.default
                elif vspec.required:
                    return RecipeResult(
                        recipe_id=recipe_id,
                        recipe_name=recipe.name,
                        status="failed",
                        steps=[StepResult(step_name="validation", status="error",
                                         stderr=f"Missing required variable: {vname}")],
                    )

        # Substitute variables in all step commands
        resolved_steps: list[tuple[RecipeStep, str]] = []
        for step in recipe.steps:
            resolved_cmd = self.substitute_variables(step.command, variables)
            resolved_steps.append((step, resolved_cmd))

        if dry_run:
            dry_results = []
            for step, cmd in resolved_steps:
                dry_results.append(StepResult(
                    step_name=step.name,
                    status="dry_run",
                    stdout=f"Would execute: {cmd}",
                ))
            return RecipeResult(
                recipe_id=recipe_id,
                recipe_name=recipe.name,
                status="dry_run",
                steps=dry_results,
            )

        start_time = time.monotonic()

        if recipe.parallel:
            step_results = await self._run_parallel(resolved_steps, quiet)
        else:
            step_results = await self._run_sequential(resolved_steps, quiet)

        duration_ms = int((time.monotonic() - start_time) * 1000)

        failed = any(r.status == "error" for r in step_results)
        status = "failed" if failed else "success"
        if failed and any(r.status == "success" for r in step_results):
            status = "partial"

        return RecipeResult(
            recipe_id=recipe_id,
            recipe_name=recipe.name,
            status=status,
            steps=step_results,
            duration_ms=duration_ms,
        )

    async def _run_sequential(
        self, steps: list[tuple[RecipeStep, str]], quiet: bool,
    ) -> list[StepResult]:
        """Execute steps one at a time."""
        results: list[StepResult] = []
        for step, cmd in steps:
            result = await self._run_step(step, cmd, quiet)
            results.append(result)
            if result.status == "error" and step.on_failure == FailureAction.ABORT:
                # Skip remaining steps
                for remaining_step, _ in steps[len(results):]:
                    results.append(StepResult(step_name=remaining_step.name, status="skipped"))
                break
        return results

    async def _run_parallel(
        self, steps: list[tuple[RecipeStep, str]], quiet: bool,
    ) -> list[StepResult]:
        """Execute steps in parallel with DAG dependency support."""
        events: dict[str, asyncio.Event] = {step.name: asyncio.Event() for step, _ in steps}
        results: dict[str, StepResult] = {}

        async def run_with_deps(step: RecipeStep, cmd: str) -> None:
            if step.depends_on:
                for dep in step.depends_on:
                    if dep in events:
                        await events[dep].wait()
            result = await self._run_step(step, cmd, quiet)
            results[step.name] = result
            events[step.name].set()

        async with asyncio.TaskGroup() as tg:
            for step, cmd in steps:
                tg.create_task(run_with_deps(step, cmd))

        return [results[step.name] for step, _ in steps]

    async def run_with_progress(self, recipe_id: str, variables: dict[str, str],
                                dry_run: bool = False):
        """Execute recipe yielding per-step progress events.

        Yields tuples: (event_type, step_name, result_or_none)
        - ("started", step_name, None)
        - ("completed", step_name, StepResult)
        - ("error", "validation", StepResult)  — on missing required variable
        """
        recipe = self.get_recipe(recipe_id)

        # Apply defaults and validate required variables
        for vname, vspec in recipe.variables.items():
            if vname not in variables:
                if vspec.default is not None:
                    variables[vname] = vspec.default
                elif vspec.required:
                    yield ("error", "validation", StepResult(
                        step_name="validation", status="error",
                        stderr=f"Missing required variable: {vname}"))
                    return

        resolved_steps = []
        for step in recipe.steps:
            resolved_cmd = self.substitute_variables(step.command, variables)
            resolved_steps.append((step, resolved_cmd))

        if dry_run:
            for step, cmd in resolved_steps:
                yield ("completed", step.name, StepResult(
                    step_name=step.name, status="dry_run",
                    stdout=f"Would execute: {cmd}"))
            return

        for step, cmd in resolved_steps:
            yield ("started", step.name, None)
            result = await self._run_step(step, cmd, quiet=True)
            yield ("completed", step.name, result)

    async def _run_step(self, step: RecipeStep, command: str, quiet: bool) -> StepResult:
        """Execute a single recipe step."""
        if step.step_type == StepType.MANUAL:
            return StepResult(step_name=step.name, status="manual", stdout=command)

        if step.step_type == StepType.MCP_TOOL:
            return StepResult(step_name=step.name, status="manual",
                            stdout=f"MCP tool step (execute in Claude): {command}")

        # Shell step — delegate to shared subprocess
        from opentools.shared.subprocess import run_streaming

        args = shlex.split(command, posix=(sys.platform != "win32"))
        result = await run_streaming(
            args,
            on_output=lambda chunk: None,
            timeout=step.timeout,
        )

        if result.timed_out:
            return StepResult(
                step_name=step.name, status="timeout",
                duration_ms=result.duration_ms,
                stderr=f"Timed out after {step.timeout}s",
            )

        status = "success" if result.exit_code == 0 else "error"
        return StepResult(
            step_name=step.name,
            status=status,
            exit_code=result.exit_code,
            stdout=result.stdout,
            stderr=result.stderr,
            duration_ms=result.duration_ms,
        )
