"""FastAPI-Users authentication setup."""

import uuid

from fastapi import Depends
from fastapi_users import BaseUserManager, FastAPIUsers, UUIDIDMixin
from fastapi_users.authentication import (
    AuthenticationBackend,
    CookieTransport,
    JWTStrategy,
)
from fastapi_users.db import SQLAlchemyUserDatabase
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_session
from app.models import User


class UserManager(UUIDIDMixin, BaseUserManager[User, uuid.UUID]):
    reset_password_token_secret = settings.secret_key
    verification_token_secret = settings.secret_key


async def get_user_db(session: AsyncSession = Depends(get_session)):
    yield SQLAlchemyUserDatabase(session, User)


async def get_user_manager(user_db=Depends(get_user_db)):
    yield UserManager(user_db)


cookie_transport = CookieTransport(
    cookie_name="opentools_session",
    cookie_httponly=True,
    cookie_secure=(settings.environment == "production"),
    cookie_samesite="lax",
    cookie_max_age=86400,
)


def get_jwt_strategy() -> JWTStrategy:
    return JWTStrategy(secret=settings.secret_key, lifetime_seconds=86400)


auth_backend = AuthenticationBackend(
    name="cookie",
    transport=cookie_transport,
    get_strategy=get_jwt_strategy,
)

fastapi_users = FastAPIUsers[User, uuid.UUID](get_user_manager, [auth_backend])

current_active_user = fastapi_users.current_user(active=True)
