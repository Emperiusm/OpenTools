"""Recipe execution API routes."""

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from app.dependencies import get_current_user
from app.models import User
from app.services.recipe_service import RecipeService

router = APIRouter(prefix="/api/v1/recipes", tags=["recipes"])


class RecipeRunRequest(BaseModel):
    recipe_id: str
    variables: Optional[dict] = None
    dry_run: bool = False


@router.get("")
async def list_recipes(
    user: User = Depends(get_current_user),
):
    service = RecipeService(user)
    recipes = await service.list_recipes()
    return {"items": recipes}


@router.get("/{recipe_id}")
async def get_recipe(
    recipe_id: str,
    user: User = Depends(get_current_user),
):
    service = RecipeService(user)
    recipes = await service.list_recipes()
    recipe = next((r for r in recipes if r.get("id") == recipe_id), None)
    if not recipe:
        raise HTTPException(status_code=404, detail="Recipe not found")
    return recipe


@router.post("/{recipe_id}/run")
async def run_recipe_by_id(
    recipe_id: str,
    body: dict | None = None,
    user: User = Depends(get_current_user),
):
    service = RecipeService(user)
    variables = (body or {}).get("variables", {})
    dry_run = (body or {}).get("dry_run", False)
    task_id = await service.run(
        recipe_id=recipe_id,
        variables=variables,
        dry_run=dry_run,
    )
    return {"task_id": task_id, "status": "submitted"}


@router.post("/run")
async def run_recipe(
    body: RecipeRunRequest,
    background_tasks: BackgroundTasks,
    user: User = Depends(get_current_user),
):
    service = RecipeService(user)

    # Schedule the recipe run as a background task
    task_id: Optional[str] = None

    async def _run():
        nonlocal task_id
        task_id = await service.run(
            recipe_id=body.recipe_id,
            variables=body.variables,
            dry_run=body.dry_run,
        )

    # We need the task_id immediately, so run inline (service stores state)
    task_id = await service.run(
        recipe_id=body.recipe_id,
        variables=body.variables,
        dry_run=body.dry_run,
    )
    return {"task_id": task_id, "status": "submitted"}


@router.get("/tasks/{task_id}")
async def get_task_status(
    task_id: str,
    user: User = Depends(get_current_user),
):
    service = RecipeService(user)
    status = await service.get_task_status(task_id)
    if not status:
        raise HTTPException(status_code=404, detail="Task not found")
    return status
