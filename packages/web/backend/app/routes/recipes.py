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
