"""Recipe execution service wrapping the CLI recipe runner."""

import uuid
from typing import Any, Optional

from app.models import User


# In-memory task store (adequate for single-process deployment)
_tasks: dict[str, dict[str, Any]] = {}


class RecipeService:
    def __init__(self, user: User):
        self.user = user

    async def list_recipes(self) -> list[dict]:
        try:
            from opentools.recipes import RecipeRunner
            from opentools.plugin import discover_plugin_dir
            from opentools.config import ConfigLoader

            plugin_dir = discover_plugin_dir()
            config = ConfigLoader(plugin_dir).load()
            runner = RecipeRunner(config=config, recipes_path=plugin_dir / "recipes")
            recipes = runner.list_recipes()
            return [
                {"id": r.id, "name": r.name, "description": r.description}
                for r in recipes
            ]
        except Exception as exc:
            return [{"error": str(exc)}]

    async def run(
        self,
        recipe_id: str,
        variables: Optional[dict] = None,
        dry_run: bool = False,
    ) -> str:
        task_id = str(uuid.uuid4())
        _tasks[task_id] = {"status": "pending", "result": None, "error": None}

        try:
            from opentools.recipes import RecipeRunner
            from opentools.plugin import discover_plugin_dir
            from opentools.config import ConfigLoader

            plugin_dir = discover_plugin_dir()
            config = ConfigLoader(plugin_dir).load()
            runner = RecipeRunner(config=config, recipes_path=plugin_dir / "recipes")

            _tasks[task_id]["status"] = "running"
            result = runner.run(recipe_id, variables=variables or {}, dry_run=dry_run)
            _tasks[task_id]["status"] = "completed"
            _tasks[task_id]["result"] = result
        except Exception as exc:
            _tasks[task_id]["status"] = "failed"
            _tasks[task_id]["error"] = str(exc)

        return task_id

    async def get_task_status(self, task_id: str) -> Optional[dict]:
        return _tasks.get(task_id)
