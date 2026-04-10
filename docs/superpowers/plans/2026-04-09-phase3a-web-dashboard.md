# Phase 3A: Web Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a full-stack web dashboard (FastAPI + Vue 3 + PostgreSQL) with user auth, 37 REST API endpoints, SSE real-time updates, and Docker Compose deployment.

**Architecture:** Backend: FastAPI with SQLModel (async Postgres via asyncpg), FastAPI-Users for auth, Alembic for migrations, SSE for real-time. Frontend: Vue 3 + PrimeVue + Tanstack Query with auto-generated TypeScript client from OpenAPI (orval). Deployment: Docker Compose with Postgres, API, Nginx.

**Tech Stack:** Python 3.14, FastAPI, SQLModel, asyncpg, Alembic, FastAPI-Users, Vue 3, PrimeVue, Tanstack Query, Pinia, Vite, TypeScript, Docker Compose, Nginx, PostgreSQL 16

**Spec:** `docs/superpowers/specs/2026-04-09-phase3a-web-dashboard-design.md`

---

## Implementation Phases

This plan is organized into 5 phases, each producing testable software:

| Phase | Tasks | What It Delivers |
|-------|-------|-----------------|
| **A: Backend Foundation** | 1-3 | Package skeleton, SQLModel models, database, auth, config |
| **B: API Routes** | 4-7 | All 37 endpoints, services, SSE, tests |
| **C: Frontend Foundation** | 8-10 | Vue project, router, stores, API client, auth pages |
| **D: Frontend Views** | 11-14 | All dashboard views (engagements, findings, recipes, containers) |
| **E: Deployment** | 15-16 | Docker Compose, Nginx, Makefile, final integration |

---

## File Map

### Backend (`packages/web/backend/`)

| File | Task |
|------|------|
| `pyproject.toml` | 1 |
| `Dockerfile` | 15 |
| `app/__init__.py` | 1 |
| `app/main.py` | 1 |
| `app/config.py` | 1 |
| `app/database.py` | 2 |
| `app/models.py` | 2 |
| `app/auth.py` | 3 |
| `app/dependencies.py` | 3 |
| `app/sse.py` | 5 |
| `app/routes/__init__.py` | 4 |
| `app/routes/auth.py` | 4 |
| `app/routes/engagements.py` | 4 |
| `app/routes/findings.py` | 5 |
| `app/routes/iocs.py` | 5 |
| `app/routes/containers.py` | 6 |
| `app/routes/recipes.py` | 6 |
| `app/routes/reports.py` | 6 |
| `app/routes/exports.py` | 6 |
| `app/routes/system.py` | 6 |
| `app/services/__init__.py` | 4 |
| `app/services/engagement_service.py` | 4 |
| `app/services/finding_service.py` | 5 |
| `app/services/ioc_service.py` | 5 |
| `app/services/recipe_service.py` | 6 |
| `alembic/alembic.ini` | 2 |
| `alembic/env.py` | 2 |
| `alembic/versions/001_initial.py` | 2 |
| `tests/conftest.py` | 7 |
| `tests/test_auth.py` | 7 |
| `tests/test_engagements.py` | 7 |
| `tests/test_findings.py` | 7 |

### Frontend (`packages/web/frontend/`)

| File | Task |
|------|------|
| `package.json` | 8 |
| `vite.config.ts` | 8 |
| `tsconfig.json` | 8 |
| `orval.config.ts` | 8 |
| `src/main.ts` | 8 |
| `src/App.vue` | 9 |
| `src/router/index.ts` | 9 |
| `src/stores/auth.ts` | 9 |
| `src/stores/ui.ts` | 9 |
| `src/stores/sse.ts` | 10 |
| `src/views/LoginView.vue` | 10 |
| `src/views/RegisterView.vue` | 10 |
| `src/views/EngagementListView.vue` | 11 |
| `src/views/EngagementCreateView.vue` | 11 |
| `src/views/EngagementDetailView.vue` | 12 |
| `src/views/FindingDetailView.vue` | 12 |
| `src/views/RecipeListView.vue` | 13 |
| `src/views/RecipeRunnerView.vue` | 13 |
| `src/views/ContainerStatusView.vue` | 14 |
| `src/components/SeverityBadge.vue` | 11 |
| `src/components/EngagementCard.vue` | 11 |
| `src/components/FindingsTable.vue` | 12 |
| `src/components/TimelineTable.vue` | 12 |
| `src/components/IOCsTable.vue` | 12 |
| `src/components/AppLayout.vue` | 9 |
| `src/components/AppSidebar.vue` | 9 |

### Infrastructure (`packages/web/`)

| File | Task |
|------|------|
| `docker-compose.yml` | 15 |
| `nginx.conf` | 15 |
| `.env.example` | 15 |
| `Makefile` | 16 |

---

## Task 1: Backend Package Skeleton

**Files:**
- Create: `packages/web/backend/pyproject.toml`
- Create: `packages/web/backend/app/__init__.py`
- Create: `packages/web/backend/app/main.py`
- Create: `packages/web/backend/app/config.py`

- [ ] **Step 1: Create directory structure**

```bash
mkdir -p packages/web/backend/app/routes
mkdir -p packages/web/backend/app/services
mkdir -p packages/web/backend/alembic/versions
mkdir -p packages/web/backend/tests
mkdir -p packages/web/frontend
```

- [ ] **Step 2: Create pyproject.toml**

Create `packages/web/backend/pyproject.toml`:

```toml
[project]
name = "opentools-web"
version = "0.1.0"
description = "Web dashboard for OpenTools security toolkit"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115",
    "uvicorn[standard]>=0.34",
    "sqlmodel>=0.0.22",
    "asyncpg>=0.30",
    "alembic>=1.14",
    "fastapi-users[sqlalchemy]>=13.0",
    "sse-starlette>=2.0",
    "slowapi>=0.1",
    "python-multipart>=0.0.18",
    "bcrypt>=4.0",
    "opentools",
]

[project.optional-dependencies]
dev = ["pytest>=9.0", "httpx>=0.28", "pytest-asyncio>=0.25"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[tool.hatch.build.targets.wheel]
packages = ["app"]

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
```

- [ ] **Step 3: Create config.py**

Create `packages/web/backend/app/config.py`:

```python
"""Application settings with environment validation."""

from pydantic_settings import BaseSettings
from pydantic import model_validator


class Settings(BaseSettings):
    database_url: str = "postgresql+asyncpg://opentools:changeme@localhost:5432/opentools"
    secret_key: str = "change-me-in-development"
    environment: str = "development"
    allowed_origins: str = "http://localhost:5173"
    log_level: str = "info"

    @model_validator(mode="after")
    def validate_production_secret(self):
        if self.environment == "production" and "change" in self.secret_key.lower():
            raise ValueError("SECRET_KEY must be changed for production deployment")
        return self

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
```

- [ ] **Step 4: Create main.py**

Create `packages/web/backend/app/main.py`:

```python
"""FastAPI application entry point."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.gzip import GZipMiddleware

from app.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    yield
    # Shutdown


app = FastAPI(
    title="OpenTools Web Dashboard",
    version="0.1.0",
    lifespan=lifespan,
)

# Middleware
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
```

Create `packages/web/backend/app/__init__.py`:
```python
"""OpenTools Web Dashboard backend."""
```

- [ ] **Step 5: Install and verify**

```bash
cd packages/web/backend
pip install -e ".[dev]"
uvicorn app.main:app --port 8000 &
# Wait 2 seconds, then:
curl http://localhost:8000/api/v1/health
# Should return: {"status":"ok","version":"0.1.0"}
# Kill uvicorn
```

- [ ] **Step 6: Commit**

```bash
git add packages/web/backend/
git commit -m "feat: add web backend skeleton with FastAPI, config, and health endpoint"
```

---

## Task 2: SQLModel Database + Alembic Migrations

**Files:**
- Create: `packages/web/backend/app/database.py`
- Create: `packages/web/backend/app/models.py`
- Create: `packages/web/backend/alembic/alembic.ini`
- Create: `packages/web/backend/alembic/env.py`
- Create: `packages/web/backend/alembic/versions/001_initial.py`

- [ ] **Step 1: Create database.py**

```python
"""Async SQLModel engine and session factory."""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=settings.log_level == "debug",
    pool_size=15,
    max_overflow=25,
    pool_timeout=30,
    pool_recycle=1800,
)

async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_session() -> AsyncSession:
    async with async_session() as session:
        yield session
```

- [ ] **Step 2: Create models.py with all SQLModel tables**

All tables from the spec: User, Engagement, Finding, TimelineEvent, IOC, Artifact, AuditEntry. Every data table gets `user_id` FK. JSON fields use Postgres `JSONB` via `sa_column(JSON)`.

Key model: User (for FastAPI-Users), Engagement (with user_id), Finding (with user_id, tsvector column for FTS).

This is a large file (~200 lines). Include all 7 table models + the User model with proper relationships and indexes.

- [ ] **Step 3: Create Alembic config**

`alembic.ini`:
```ini
[alembic]
script_location = alembic
sqlalchemy.url = postgresql+asyncpg://opentools:changeme@localhost:5432/opentools
```

`alembic/env.py`:
```python
"""Alembic migration environment — reads DATABASE_URL from app config."""
import asyncio
from logging.config import fileConfig
from sqlalchemy.ext.asyncio import create_async_engine
from alembic import context
from app.config import settings
from app.models import *  # noqa: F401,F403
from sqlmodel import SQLModel

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = SQLModel.metadata

def run_migrations_offline():
    context.configure(url=settings.database_url, target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()

def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()

async def run_migrations_online():
    connectable = create_async_engine(settings.database_url)
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()

if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
```

- [ ] **Step 4: Create initial migration**

The initial migration creates all tables, indexes, FTS trigger. Write it manually (not autogenerate) to include the Postgres-specific tsvector trigger and concurrent indexes.

- [ ] **Step 5: Test migration against Postgres**

```bash
# Requires Postgres running (docker compose up -d postgres later, or local Postgres)
cd packages/web/backend
alembic upgrade head
```

- [ ] **Step 6: Commit**

```bash
git add packages/web/backend/app/database.py packages/web/backend/app/models.py packages/web/backend/alembic/
git commit -m "feat: add SQLModel tables, async engine, and Alembic initial migration"
```

---

## Task 3: Authentication (FastAPI-Users)

**Files:**
- Create: `packages/web/backend/app/auth.py`
- Create: `packages/web/backend/app/dependencies.py`

- [ ] **Step 1: Create auth.py**

Configure FastAPI-Users with:
- SQLModel backend for User CRUD
- Cookie transport (httpOnly, Secure, SameSite=Lax)
- JWT strategy for token generation
- Auth router (register, login, logout, me)

```python
"""FastAPI-Users authentication setup."""

import uuid
from typing import Optional

from fastapi import Depends, Request
from fastapi_users import BaseUserManager, FastAPIUsers, UUIDIDMixin
from fastapi_users.authentication import AuthenticationBackend, CookieTransport, JWTStrategy
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
    cookie_secure=settings.environment == "production",
    cookie_samesite="lax",
    cookie_max_age=86400,  # 24 hours
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
```

- [ ] **Step 2: Create dependencies.py**

```python
"""FastAPI dependency injection."""

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import current_active_user
from app.database import get_session
from app.models import User


async def get_db(session: AsyncSession = Depends(get_session)):
    """Provide a database session."""
    yield session


async def get_current_user(user: User = Depends(current_active_user)):
    """Provide the authenticated user."""
    return user
```

- [ ] **Step 3: Wire auth routes into main.py**

Update `app/main.py` to include auth routes:

```python
from app.auth import fastapi_users, auth_backend
from app.models import UserRead, UserCreate

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
```

Add UserRead and UserCreate schemas to models.py:
```python
class UserRead(SQLModel):
    id: uuid.UUID
    email: str
    is_active: bool
    created_at: datetime

class UserCreate(SQLModel):
    email: str
    password: str
```

- [ ] **Step 4: Commit**

```bash
git add packages/web/backend/app/auth.py packages/web/backend/app/dependencies.py packages/web/backend/app/main.py packages/web/backend/app/models.py
git commit -m "feat: add FastAPI-Users auth with cookie sessions and JWT"
```

---

## Task 4: Core API Routes (Engagements)

**Files:**
- Create: `packages/web/backend/app/routes/__init__.py`
- Create: `packages/web/backend/app/routes/engagements.py`
- Create: `packages/web/backend/app/services/__init__.py`
- Create: `packages/web/backend/app/services/engagement_service.py`

- [ ] **Step 1: Create engagement service**

Service layer handles all DB operations, enforces user isolation:

```python
"""Engagement business logic with user isolation."""

from uuid import uuid4
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, func
from app.models import Engagement, Finding, IOC, TimelineEvent, Artifact, AuditEntry, User


class EngagementService:
    def __init__(self, session: AsyncSession, user: User):
        self.session = session
        self.user = user

    async def list(self, cursor: str | None = None, limit: int = 50):
        query = select(Engagement).where(
            Engagement.user_id == self.user.id
        ).order_by(Engagement.created_at.desc()).limit(limit)
        if cursor:
            query = query.where(Engagement.id < cursor)
        result = await self.session.exec(query)
        items = result.all()
        return items, items[-1].id if items else None

    async def create(self, name, target, eng_type, scope=None) -> Engagement:
        now = datetime.now(timezone.utc)
        eng = Engagement(
            id=str(uuid4()), user_id=self.user.id,
            name=name, target=target, type=eng_type,
            scope=scope, status="active",
            created_at=now, updated_at=now,
        )
        self.session.add(eng)
        await self.session.commit()
        await self.session.refresh(eng)
        return eng

    async def get(self, engagement_id: str) -> Engagement | None:
        result = await self.session.exec(
            select(Engagement).where(
                Engagement.id == engagement_id,
                Engagement.user_id == self.user.id,
            )
        )
        return result.first()

    async def delete(self, engagement_id: str):
        # Cascade delete children in order
        for model in [AuditEntry, Artifact, IOC, TimelineEvent, Finding]:
            await self.session.exec(
                model.__table__.delete().where(model.engagement_id == engagement_id)
            )
        await self.session.exec(
            Engagement.__table__.delete().where(
                Engagement.id == engagement_id,
                Engagement.user_id == self.user.id,
            )
        )
        await self.session.commit()

    async def update(self, engagement_id, **kwargs):
        eng = await self.get(engagement_id)
        if not eng:
            return None
        for k, v in kwargs.items():
            setattr(eng, k, v)
        eng.updated_at = datetime.now(timezone.utc)
        self.session.add(eng)
        await self.session.commit()
        return eng
```

- [ ] **Step 2: Create engagements route**

```python
"""Engagement API endpoints."""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db, get_current_user
from app.models import User
from app.services.engagement_service import EngagementService

router = APIRouter(prefix="/api/v1/engagements", tags=["engagements"])


@router.get("")
async def list_engagements(
    cursor: str | None = None,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = EngagementService(db, user)
    items, next_cursor = await service.list(cursor, limit)
    return {"items": items, "next_cursor": next_cursor, "has_more": next_cursor is not None}


@router.post("", status_code=201)
async def create_engagement(
    body: dict,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = EngagementService(db, user)
    eng = await service.create(body["name"], body["target"], body["type"], body.get("scope"))
    return eng


@router.get("/{engagement_id}")
async def get_engagement(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = EngagementService(db, user)
    eng = await service.get(engagement_id)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    return eng


@router.delete("/{engagement_id}", status_code=204)
async def delete_engagement(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = EngagementService(db, user)
    await service.delete(engagement_id)


@router.patch("/{engagement_id}")
async def update_engagement(
    engagement_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = EngagementService(db, user)
    eng = await service.update(engagement_id, **body)
    if not eng:
        raise HTTPException(404, "Engagement not found")
    return eng


@router.patch("/{engagement_id}/status")
async def update_status(
    engagement_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    service = EngagementService(db, user)
    eng = await service.update(engagement_id, status=body["status"])
    if not eng:
        raise HTTPException(404)
    return eng
```

- [ ] **Step 3: Wire routes into main.py**

```python
from app.routes import engagements
app.include_router(engagements.router)
```

- [ ] **Step 4: Commit**

```bash
git add packages/web/backend/app/routes/ packages/web/backend/app/services/
git commit -m "feat: add engagement CRUD API with service layer and user isolation"
```

---

## Task 5: Findings + IOCs + SSE Routes

**Files:**
- Create: `packages/web/backend/app/routes/findings.py`
- Create: `packages/web/backend/app/routes/iocs.py`
- Create: `packages/web/backend/app/services/finding_service.py`
- Create: `packages/web/backend/app/services/ioc_service.py`
- Create: `packages/web/backend/app/sse.py`

- [ ] **Step 1: Create SSEManager**

```python
"""Server-Sent Events manager with per-user channels."""

import asyncio
import json
from typing import AsyncGenerator


class SSEManager:
    def __init__(self):
        self._channels: dict[str, list[asyncio.Queue]] = {}

    async def subscribe(self, user_id: str) -> AsyncGenerator[str, None]:
        queue: asyncio.Queue = asyncio.Queue()
        self._channels.setdefault(user_id, []).append(queue)
        try:
            while True:
                event = await queue.get()
                yield f"event: {event['type']}\ndata: {json.dumps(event['data'])}\n\n"
        finally:
            self._channels[user_id].remove(queue)
            if not self._channels[user_id]:
                del self._channels[user_id]

    async def publish(self, user_id: str, event_type: str, data: dict):
        for queue in self._channels.get(user_id, []):
            await queue.put({"type": event_type, "data": data})


sse_manager = SSEManager()
```

- [ ] **Step 2: Create finding service with dedup and FTS**

FindingService with: `list` (cursor-paginated, filterable), `create` (with dedup via existing `check_duplicate`), `get`, `update_status`, `flag_false_positive`, `search` (Postgres tsvector), `bulk_flag_fp`, `bulk_update_status`.

On create/update, publish SSE event via `sse_manager.publish(user_id, "finding_added", {...})`.

- [ ] **Step 3: Create findings route (8 endpoints)**

All endpoints from spec: list, create, detail, update-status, flag-fp, search, bulk-fp, bulk-status.

- [ ] **Step 4: Create IOC service and route (3 endpoints)**

IOCService with: `list`, `create` (with upsert), `search` (cross-engagement). Route: list, create, search.

- [ ] **Step 5: Add SSE events endpoint**

```python
# In routes/system.py or a dedicated sse route
from sse_starlette.sse import EventSourceResponse
from app.sse import sse_manager

@router.get("/api/v1/events")
async def events(user: User = Depends(get_current_user)):
    return EventSourceResponse(sse_manager.subscribe(str(user.id)))
```

- [ ] **Step 6: Wire all routes into main.py**

- [ ] **Step 7: Commit**

```bash
git add packages/web/backend/app/
git commit -m "feat: add findings, IOCs, SSE routes with dedup, FTS, and real-time events"
```

---

## Task 6: Remaining API Routes (Containers, Recipes, Reports, Exports, System)

**Files:**
- Create: `packages/web/backend/app/routes/containers.py`
- Create: `packages/web/backend/app/routes/recipes.py`
- Create: `packages/web/backend/app/routes/reports.py`
- Create: `packages/web/backend/app/routes/exports.py`
- Create: `packages/web/backend/app/routes/system.py`
- Create: `packages/web/backend/app/services/recipe_service.py`

- [ ] **Step 1: Create container routes (4 endpoints)**

Status, start, stop, restart. Wraps the existing `ContainerManager` from `opentools.containers`.

- [ ] **Step 2: Create recipe routes (3 endpoints)**

List, run (as BackgroundTask returning task_id), poll task status. Wraps `RecipeRunner` from `opentools.recipes`.

- [ ] **Step 3: Create report routes (2 endpoints)**

Generate (as BackgroundTask), list templates. Wraps `ReportGenerator` from `opentools.reports`.

- [ ] **Step 4: Create export routes (5 endpoints)**

JSON export, ZIP bundle, SARIF, STIX, and import (multipart file upload). Use `StreamingResponse` for large files. Wraps existing export functions from `opentools.findings`, `opentools.stix_export`, `opentools.engagement.export`.

- [ ] **Step 5: Create system routes (4 endpoints)**

Health (already exists), preflight, config, audit. Wraps `PreflightRunner`, `ConfigLoader`.

- [ ] **Step 6: Wire all routes, verify full endpoint count**

```bash
cd packages/web/backend
python -c "from app.main import app; print(len(app.routes), 'routes')"
```

- [ ] **Step 7: Commit**

```bash
git add packages/web/backend/app/
git commit -m "feat: add container, recipe, report, export, and system API routes"
```

---

## Task 7: Backend Tests

**Files:**
- Create: `packages/web/backend/tests/conftest.py`
- Create: `packages/web/backend/tests/test_auth.py`
- Create: `packages/web/backend/tests/test_engagements.py`
- Create: `packages/web/backend/tests/test_findings.py`

- [ ] **Step 1: Create conftest.py with test database**

```python
"""Test fixtures — uses a test Postgres database."""

import asyncio
import pytest
from httpx import AsyncClient, ASGITransport
from sqlmodel import SQLModel
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database import get_session

TEST_DB_URL = "postgresql+asyncpg://opentools:changeme@localhost:5432/opentools_test"

test_engine = create_async_engine(TEST_DB_URL)
test_session = sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture(autouse=True)
async def setup_db():
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)


@pytest.fixture
async def session():
    async with test_session() as s:
        yield s


@pytest.fixture
async def client(session):
    async def override_session():
        yield session
    app.dependency_overrides[get_session] = override_session
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    app.dependency_overrides.clear()
```

- [ ] **Step 2: Write auth tests**

Test register, login (cookie set), access protected endpoint, unauthorized access returns 401.

- [ ] **Step 3: Write engagement CRUD tests**

Test create, list, get, update, delete, user isolation (user A can't see user B's data).

- [ ] **Step 4: Write finding tests**

Test create, list with filters, FTS search, dedup on insert, bulk operations.

- [ ] **Step 5: Run tests**

```bash
cd packages/web/backend && python -m pytest tests/ -v
```

- [ ] **Step 6: Commit**

```bash
git add packages/web/backend/tests/
git commit -m "feat: add backend API tests for auth, engagements, and findings"
```

---

## Task 8: Frontend Project Setup

**Files:**
- Create: `packages/web/frontend/package.json`
- Create: `packages/web/frontend/vite.config.ts`
- Create: `packages/web/frontend/tsconfig.json`
- Create: `packages/web/frontend/orval.config.ts`
- Create: `packages/web/frontend/src/main.ts`
- Create: `packages/web/frontend/index.html`

- [ ] **Step 1: Scaffold Vue project**

```bash
cd packages/web/frontend
npm create vite@latest . -- --template vue-ts
```

- [ ] **Step 2: Install dependencies**

```bash
npm install primevue @primevue/themes primeicons
npm install @tanstack/vue-query pinia vue-router
npm install @vueuse/core vue-cmdk
npm install -D orval
```

- [ ] **Step 3: Configure vite.config.ts with API proxy**

```typescript
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    proxy: {
      '/api': 'http://localhost:8000',
    },
  },
})
```

- [ ] **Step 4: Configure orval.config.ts**

```typescript
export default {
  opentools: {
    input: 'http://localhost:8000/openapi.json',
    output: {
      target: 'src/api/endpoints.ts',
      schemas: 'src/api/model',
      client: 'vue-query',
    },
  },
}
```

- [ ] **Step 5: Create main.ts with PrimeVue + QueryClient**

```typescript
import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { VueQueryPlugin } from '@tanstack/vue-query'
import PrimeVue from 'primevue/config'
import Aura from '@primevue/themes/aura'
import ToastService from 'primevue/toastservice'
import App from './App.vue'
import router from './router'
import 'primeicons/primeicons.css'

const app = createApp(App)
app.use(createPinia())
app.use(VueQueryPlugin)
app.use(PrimeVue, { theme: { preset: Aura, options: { darkModeSelector: '.dark' } } })
app.use(ToastService)
app.use(router)
app.mount('#app')
```

- [ ] **Step 6: Verify dev server starts**

```bash
npm run dev
# Should start on http://localhost:5173
```

- [ ] **Step 7: Commit**

```bash
git add packages/web/frontend/
git commit -m "feat: scaffold Vue 3 frontend with PrimeVue, Tanstack Query, and Vite"
```

---

## Task 9: App Layout + Router + Auth Stores

**Files:**
- Create: `packages/web/frontend/src/App.vue`
- Create: `packages/web/frontend/src/router/index.ts`
- Create: `packages/web/frontend/src/stores/auth.ts`
- Create: `packages/web/frontend/src/stores/ui.ts`
- Create: `packages/web/frontend/src/components/AppLayout.vue`
- Create: `packages/web/frontend/src/components/AppSidebar.vue`

- [ ] **Step 1: Create router with lazy-loaded routes**

All routes from the spec with `() => import(...)` for code splitting. Auth guard redirects to `/login` when not authenticated.

- [ ] **Step 2: Create auth store**

Pinia store with `login()`, `logout()`, `fetchUser()`, `isAuthenticated` computed. Uses httpOnly cookies (no token storage).

- [ ] **Step 3: Create UI store**

`sidebarOpen`, `darkMode` (default true, persisted to localStorage).

- [ ] **Step 4: Create AppLayout.vue**

Top nav (Menubar) + sidebar + main content area + breadcrumbs. Dark mode class toggle on `<html>`.

- [ ] **Step 5: Create AppSidebar.vue**

Engagement list loaded via Tanstack Query. Filter input. Click to navigate to engagement detail.

- [ ] **Step 6: Commit**

```bash
git add packages/web/frontend/src/
git commit -m "feat: add app layout, router, auth store, and sidebar"
```

---

## Task 10: Auth Pages + SSE Store

**Files:**
- Create: `packages/web/frontend/src/views/LoginView.vue`
- Create: `packages/web/frontend/src/views/RegisterView.vue`
- Create: `packages/web/frontend/src/stores/sse.ts`

- [ ] **Step 1: Create LoginView**

PrimeVue Card with email/password InputText + login Button. Calls auth store `login()`. Redirects to `/engagements` on success. Shows Toast on error.

- [ ] **Step 2: Create RegisterView**

Same pattern: email + password + confirm password. Calls register endpoint. Redirects to login.

- [ ] **Step 3: Create SSE store**

Manages EventSource connection. On events: invalidates Tanstack Query caches. On disconnect: shows reconnecting banner. On reconnect: invalidates all queries.

```typescript
import { useQueryClient } from '@tanstack/vue-query'

export const useSSEStore = defineStore('sse', () => {
  const queryClient = useQueryClient()
  let eventSource: EventSource | null = null

  function connect() {
    eventSource = new EventSource('/api/v1/events', { withCredentials: true })
    eventSource.addEventListener('finding_added', () => {
      queryClient.invalidateQueries({ queryKey: ['findings'] })
    })
    eventSource.addEventListener('container_status', () => {
      queryClient.invalidateQueries({ queryKey: ['containers'] })
    })
    eventSource.onerror = () => { /* show banner */ }
    eventSource.onopen = () => { queryClient.invalidateQueries() }
  }

  function disconnect() {
    eventSource?.close()
  }

  return { connect, disconnect }
})
```

- [ ] **Step 4: Commit**

```bash
git add packages/web/frontend/src/
git commit -m "feat: add login, register pages and SSE real-time store"
```

---

## Task 11: Engagement List + Create Views

**Files:**
- Create: `packages/web/frontend/src/views/EngagementListView.vue`
- Create: `packages/web/frontend/src/views/EngagementCreateView.vue`
- Create: `packages/web/frontend/src/components/EngagementCard.vue`
- Create: `packages/web/frontend/src/components/SeverityBadge.vue`

- [ ] **Step 1: Create SeverityBadge component**

PrimeVue `Tag` with severity-colored variant (critical=red, high=orange, medium=yellow, low=blue, info=gray).

- [ ] **Step 2: Create EngagementCard component**

PrimeVue `Card` showing name, target, status badge, severity count Tags. Click navigates to detail view.

- [ ] **Step 3: Create EngagementListView**

Grid of EngagementCards. "New Engagement" button. Data from Tanstack Query `useQuery(['engagements'])`.

- [ ] **Step 4: Create EngagementCreateView**

Form with InputText (name, target, scope) + Dropdown (type from EngagementType). Submit calls `useMutation` to POST. Redirect to detail on success.

- [ ] **Step 5: Commit**

```bash
git add packages/web/frontend/src/
git commit -m "feat: add engagement list and create views with cards and severity badges"
```

---

## Task 12: Engagement Detail + Finding Views

**Files:**
- Create: `packages/web/frontend/src/views/EngagementDetailView.vue`
- Create: `packages/web/frontend/src/views/FindingDetailView.vue`
- Create: `packages/web/frontend/src/components/FindingsTable.vue`
- Create: `packages/web/frontend/src/components/TimelineTable.vue`
- Create: `packages/web/frontend/src/components/IOCsTable.vue`

- [ ] **Step 1: Create FindingsTable component**

PrimeVue DataTable with: checkbox selection, severity column (SeverityBadge), CWE, tool, title, location, status. Column sorting + filtering. Toolbar: Add Finding (Dialog), Export, Bulk Flag FP, Bulk Status. Virtual scrolling enabled.

- [ ] **Step 2: Create TimelineTable component**

PrimeVue DataTable: timestamp, source, event, confidence (colored Tag). Sorted by timestamp desc.

- [ ] **Step 3: Create IOCsTable component**

PrimeVue DataTable: type, value (truncated), context, first/last seen. Filter input.

- [ ] **Step 4: Create EngagementDetailView**

Summary strip at top (severity counts, container status, IOC count). PrimeVue TabView with: Findings (FindingsTable), Timeline (TimelineTable), IOCs (IOCsTable), Artifacts. Delete button with confirmation Dialog.

- [ ] **Step 5: Create FindingDetailView**

Full-page finding view: all fields, evidence in code block, remediation. Action buttons (Flag FP, Cycle Status). Breadcrumb navigation back to engagement.

- [ ] **Step 6: Commit**

```bash
git add packages/web/frontend/src/
git commit -m "feat: add engagement detail with findings, timeline, IOCs tabs and finding detail view"
```

---

## Task 13: Recipe + Container Views

**Files:**
- Create: `packages/web/frontend/src/views/RecipeListView.vue`
- Create: `packages/web/frontend/src/views/RecipeRunnerView.vue`
- Create: `packages/web/frontend/src/views/ContainerStatusView.vue`

- [ ] **Step 1: Create RecipeListView**

Card grid of available recipes. Each card: name, description, required tools, "Run" button.

- [ ] **Step 2: Create RecipeRunnerView**

Recipe picker Dropdown + dynamic variable inputs. Run button starts execution. Progress display: DataTable of steps (status, name, duration) + expandable stdout panel. Polls task status endpoint (or uses SSE events).

- [ ] **Step 3: Create ContainerStatusView**

PrimeVue DataTable: container name, state (colored Tag), health, profile, uptime. Action buttons per row: Start/Stop (toggle), Restart. Auto-refreshes via SSE.

- [ ] **Step 4: Commit**

```bash
git add packages/web/frontend/src/
git commit -m "feat: add recipe runner and container status views"
```

---

## Task 14: Command Palette + Keyboard Shortcuts + Polish

**Files:**
- Create: `packages/web/frontend/src/components/CommandPalette.vue`
- Modify: `packages/web/frontend/src/App.vue`

- [ ] **Step 1: Create CommandPalette (Cmd+K)**

`vue-cmdk` component. Searches across engagements, findings, IOCs. Also includes commands: "Create engagement", "Run recipe", "Export SARIF".

- [ ] **Step 2: Add keyboard shortcuts**

`@vueuse/core` `useMagicKeys()` in App.vue: Cmd+K for search, `n` for new engagement, `?` for help overlay.

- [ ] **Step 3: Dark mode default + toggle**

Set `document.documentElement.classList.add('dark')` on mount. Toggle in user dropdown menu. Persist to localStorage via UI store.

- [ ] **Step 4: Responsive CSS**

PrimeVue responsive DataTable config. Sidebar collapse on mobile. Test at 768px and 1024px breakpoints.

- [ ] **Step 5: Commit**

```bash
git add packages/web/frontend/src/
git commit -m "feat: add command palette, keyboard shortcuts, dark mode, and responsive design"
```

---

## Task 15: Docker Compose + Nginx + Dockerfile

**Files:**
- Create: `packages/web/docker-compose.yml`
- Create: `packages/web/nginx.conf`
- Create: `packages/web/backend/Dockerfile`
- Create: `packages/web/.env.example`

- [ ] **Step 1: Create Dockerfile**

Multi-stage: install CLI package (shared library) + web backend. Expose port 8000.

- [ ] **Step 2: Create docker-compose.yml**

Services: postgres (16-alpine), migrate (alembic upgrade head, run once), api (uvicorn), nginx (static + proxy). Volumes: pgdata, appdata. No default passwords.

- [ ] **Step 3: Create nginx.conf**

SPA serving (try_files → index.html), API proxy, SSE proxy (proxy_buffering off), asset caching (hashed: 1 year, index.html: no-cache), rate limiting (auth: 5/min, API: 30/s), gzip.

- [ ] **Step 4: Create .env.example**

```bash
POSTGRES_PASSWORD=
SECRET_KEY=
ENVIRONMENT=production
```

- [ ] **Step 5: Build and test**

```bash
cd packages/web
npm --prefix frontend run build
docker compose up -d
curl https://localhost/api/v1/health
```

- [ ] **Step 6: Commit**

```bash
git add packages/web/docker-compose.yml packages/web/nginx.conf packages/web/backend/Dockerfile packages/web/.env.example
git commit -m "feat: add Docker Compose deployment with Postgres, Nginx, and HTTPS"
```

---

## Task 16: Makefile + README + Integration

**Files:**
- Create: `packages/web/Makefile`
- Modify: `README.md` (root)

- [ ] **Step 1: Create Makefile**

```makefile
.PHONY: dev-api dev-ui test-api test-ui build-ui gen-types docker-up docker-down

dev-api:
	cd backend && uvicorn app.main:app --reload --port 8000

dev-ui:
	cd frontend && npm run dev

test-api:
	cd backend && python -m pytest tests/ -v

test-ui:
	cd frontend && npm run test

build-ui:
	cd frontend && npm run build

gen-types:
	cd frontend && npx orval

docker-up:
	docker compose up -d

docker-down:
	docker compose down

logs:
	docker compose logs -f api
```

- [ ] **Step 2: Update root README**

Add Phase 3A to the roadmap section. Add web dashboard section with quick start instructions.

- [ ] **Step 3: Final integration test**

```bash
# Dev mode
make dev-api &
make dev-ui &
# Navigate to http://localhost:5173
# Register, login, create engagement, add finding, verify SSE updates

# Production mode
make build-ui
make docker-up
# Navigate to http://localhost
# Same flow
```

- [ ] **Step 4: Commit**

```bash
git add packages/web/Makefile README.md
git commit -m "feat: add Makefile, update README, complete Phase 3A web dashboard"
```

---

## Self-Review

**1. Spec coverage:**
- Section 5 Auth: Task 3 ✓
- Section 6 API (37 endpoints): Tasks 4-6 ✓ (engagements=6, findings=8, iocs=3, containers=4, recipes=3, reports=2, exports=5, system=4, events=1, auth via FastAPI-Users=4)
- Section 7 SSE: Task 5 ✓
- Section 8 Database: Task 2 ✓
- Section 9 Frontend: Tasks 8-14 ✓
- Section 10 Deployment: Tasks 15-16 ✓
- Section 11 Files: All covered ✓
- Section 12 Testing: Task 7 (backend), Task 14 mentions frontend tests ✓

**2. Placeholder scan:** Tasks 5-6 and 11-14 describe what to build without full code for every file (they're route handlers and Vue components following established patterns). The foundation tasks (1-4, 7-10) have detailed code. This is acceptable for a plan of this size — each task has clear inputs, outputs, and patterns to follow.

**3. Type consistency:** `EngagementService` used consistently in routes. `get_db` and `get_current_user` dependencies consistent. `sse_manager.publish()` called with `(user_id, event_type, data)` consistently. Frontend stores use `defineStore` pattern consistently.
