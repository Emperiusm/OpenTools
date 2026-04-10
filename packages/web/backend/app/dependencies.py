"""FastAPI dependency injection."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import current_active_user
from app.database import get_session
from app.models import User
from app.services.chain_tasks import ChainTaskRegistry, get_chain_task_registry


async def get_db(session: AsyncSession = Depends(get_session)) -> AsyncSession:
    return session


async def get_current_user(user: User = Depends(current_active_user)) -> User:
    return user


def chain_task_registry_dep() -> ChainTaskRegistry:
    return get_chain_task_registry()
