"""FastAPI application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware

from app.auth import fastapi_users, auth_backend
from app.config import settings
from app.models import UserRead, UserCreate


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


@app.get("/api/v1/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}


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
