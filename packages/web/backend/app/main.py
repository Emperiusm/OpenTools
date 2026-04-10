"""FastAPI application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware

from app.auth import fastapi_users, auth_backend
from app.config import settings
from app.models import UserRead, UserCreate
from app.routes import (
    engagements,
    findings,
    iocs,
    containers,
    recipes,
    reports,
    exports,
    system,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title="OpenTools Web Dashboard",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(GZipMiddleware, minimum_size=1000)

if settings.allowed_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins.split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# Auth routes
app.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/api/v1/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix="/api/v1/auth",
    tags=["auth"],
)

# API routes
app.include_router(engagements.router)
app.include_router(findings.router)
app.include_router(iocs.router)
app.include_router(containers.router)
app.include_router(recipes.router)
app.include_router(reports.router)
app.include_router(exports.router)
app.include_router(system.router)
