import asyncio
import json
import pytest
from pathlib import Path
from opentools.recipes import RecipeRunner
from opentools.models import ToolkitConfig, StepType


@pytest.fixture
def recipes_file(tmp_path):
    recipes_data = {
        "version": "1.0.0",
        "recipes": [
            {
                "id": "test-recipe",
                "name": "Test Recipe",
                "description": "A test recipe",
                "requires": [],
                "variables": {
                    "target": {"description": "Target", "required": True},
                    "mode": {"description": "Mode", "required": False, "default": "fast"},
                },
                "steps": [
                    {"name": "step1", "tool": "echo", "command": "echo {{target}} {{mode}}", "timeout": 10},
                    {"name": "step2", "tool": "echo", "command": "echo done", "timeout": 10},
                ],
                "parallel": False,
                "output": "test-output",
            },
            {
                "id": "parallel-recipe",
                "name": "Parallel Recipe",
                "description": "Runs steps in parallel",
                "requires": [],
                "variables": {},
                "steps": [
                    {"name": "a", "tool": "echo", "command": "echo a", "timeout": 10},
                    {"name": "b", "tool": "echo", "command": "echo b", "timeout": 10, "depends_on": ["a"]},
                ],
                "parallel": True,
                "output": "test-output",
            },
            {
                "id": "empty-recipe",
                "name": "Empty Recipe",
                "description": "No steps",
                "requires": [],
                "variables": {},
                "steps": [],
                "parallel": False,
            },
        ],
    }
    path = tmp_path / "recipes.json"
    path.write_text(json.dumps(recipes_data))
    return path


@pytest.fixture
def runner(recipes_file):
    config = ToolkitConfig()
    return RecipeRunner(config, recipes_file)


def test_list_recipes(runner):
    recipes = runner.list_recipes()
    assert len(recipes) == 3
    ids = {r.id for r in recipes}
    assert "test-recipe" in ids


def test_get_recipe(runner):
    recipe = runner.get_recipe("test-recipe")
    assert recipe.name == "Test Recipe"
    assert len(recipe.steps) == 2


def test_get_recipe_not_found(runner):
    with pytest.raises(KeyError, match="not found"):
        runner.get_recipe("nonexistent")


def test_validate_empty_recipe(runner):
    issues = runner.validate_recipe("empty-recipe")
    assert any("no steps" in i.lower() for i in issues)


def test_validate_good_recipe(runner):
    issues = runner.validate_recipe("test-recipe")
    assert issues == []


def test_substitute_variables(runner):
    result = runner.substitute_variables("echo {{target}} --mode {{mode}}", {"target": "192.168.1.1", "mode": "fast"})
    assert result == "echo 192.168.1.1 --mode fast"


def test_dry_run(runner):
    result = asyncio.run(runner.run("test-recipe", {"target": "example.com"}, dry_run=True))
    assert result.status == "dry_run"
    assert len(result.steps) == 2
    assert "example.com" in result.steps[0].stdout
    assert "fast" in result.steps[0].stdout  # default variable


def test_run_sequential(runner):
    result = asyncio.run(runner.run("test-recipe", {"target": "hello"}))
    assert result.status == "success"
    assert len(result.steps) == 2
    assert result.steps[0].status == "success"
    assert "hello" in result.steps[0].stdout


def test_run_missing_required_variable(runner):
    result = asyncio.run(runner.run("test-recipe", {}))
    assert result.status == "failed"


def test_run_parallel_with_deps(runner):
    result = asyncio.run(runner.run("parallel-recipe", {}))
    assert result.status == "success"
    assert len(result.steps) == 2
    # Both should succeed — b depends on a but both are echo commands
    assert all(s.status == "success" for s in result.steps)


def test_run_with_progress(recipes_file):
    import asyncio
    config = ToolkitConfig()
    runner = RecipeRunner(config, recipes_file)

    events = []
    async def collect():
        async for event_type, step_name, result in runner.run_with_progress(
            "test-recipe", {"target": "hello"}
        ):
            events.append((event_type, step_name))

    asyncio.run(collect())
    assert len(events) == 4  # 2 steps x (started + completed)
    assert events[0] == ("started", "step1")
    assert events[1][0] == "completed"
