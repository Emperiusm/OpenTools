# Phase 3A: Web Dashboard — Design Specification

**Date:** 2026-04-09
**Status:** Approved
**Author:** slabl + Claude
**Depends on:** Phase 1 + 2 (all merged)

## 1. Overview

Full-stack web dashboard for OpenTools: FastAPI backend with PostgreSQL, Vue 3 SPA frontend with PrimeVue. User authentication, per-user data isolation, 35 REST API endpoints, SSE real-time updates, and Docker Compose deployment with HTTPS.

The CLI and TUI continue to work with SQLite. The web dashboard is a new data access layer over the same domain models, using SQLModel + asyncpg for Postgres.

## 2. Decisions

| Decision | Choice |
|----------|--------|
| Deployment model | Full deployment with user auth (not local-only) |
| Database | Postgres primary, SQLite fallback for CLI |
| Database abstraction | SQLModel (SQLAlchemy + Pydantic combined) |
| Frontend framework | Vue 3 + PrimeVue + Pinia + TypeScript |
| Data fetching | Tanstack Query (`@tanstack/vue-query`) + auto-generated API client (orval) |
| Real-time | Server-Sent Events (SSE) via `sse-starlette` |
| Auth | FastAPI-Users with httpOnly cookie sessions |
| Migrations | Alembic (auto-generated from SQLModel) |
| Background tasks | FastAPI BackgroundTasks (upgrade to ARQ when needed) |
| Search | Cmd+K command palette (`vue-cmdk`) |
| Deployment | Docker Compose (Postgres + migrate + API + Nginx) |

## 3. Tech Stack

### Backend
| Library | Purpose |
|---------|---------|
| FastAPI | Async API framework |
| SQLModel | ORM (SQLAlchemy + Pydantic) |
| asyncpg | Async Postgres driver |
| Alembic | Database migrations |
| FastAPI-Users | Auth (registration, login, JWT, sessions) |
| sse-starlette | Server-Sent Events |
| slowapi | Rate limiting |
| uvicorn | ASGI server |

### Frontend
| Library | Purpose |
|---------|---------|
| Vue 3 | UI framework (Composition API + TypeScript) |
| PrimeVue | UI component library (lara-dark-blue theme) |
| @tanstack/vue-query | Data fetching, caching, pagination |
| Pinia | UI state management |
| Vue Router | Client-side routing (lazy loaded) |
| orval | OpenAPI → TypeScript codegen |
| vue-cmdk | Cmd+K command palette |
| @vueuse/core | Keyboard shortcuts, utilities |
| Vite | Build tool |

### Deployment
| Tool | Purpose |
|------|---------|
| Docker Compose | Orchestration |
| Postgres 16 | Database |
| Nginx | Static files, reverse proxy, TLS, rate limiting |

## 4. Monorepo Structure

```
packages/
├── plugin/                    # skills, commands, config (unchanged)
├── cli/                       # Python CLI + TUI (unchanged, also shared library)
└── web/
    ├── backend/
    │   ├── app/
    │   │   ├── main.py        # FastAPI app, CORS, lifespan, middleware
    │   │   ├── config.py      # Settings (DATABASE_URL, SECRET_KEY, ENVIRONMENT)
    │   │   ├���─ auth.py        # FastAPI-Users (JWT, cookie sessions, registration)
    │   │   ├── database.py    # SQLModel async engine, session factory
    │   │   ├── models.py      # SQLModel tables (User, Engagement, Finding, etc.)
    │   │   ├── dependencies.py # Dependency injection (current_user, db_session)
    │   │   ├── sse.py         # SSEManager with per-user channels
    │   │   ├── routes/
    │   │   │   ├── __init__.py
    │   │   │   ├── auth.py
    │   │   │   ├── engagements.py
    │   │   │   ├── findings.py
    │   │   │   ├── iocs.py
    │   │   │   ├── containers.py
    │   │   │   ├── recipes.py
    │   │   │   ├── reports.py
    │   │   │   ├── exports.py
    │   │   │   └── system.py   # health, preflight, config, audit
    │   │   └── services/
    │   │       ├── __init__.py
    │   │       ├── engagement_service.py
    │   │       ├── finding_service.py
    │   │       ├── ioc_service.py
    │   │       └── recipe_service.py
    │   ├── alembic/
    │   │   ├── alembic.ini
    │   │   ├── env.py
    │   │   └── versions/
    │   ├── tests/
    │   ├── pyproject.toml
    │   └── Dockerfile
    ├── frontend/
    │   ├── src/
    │   │   ├── api/           # Auto-generated (orval)
    │   │   ├── components/    # Shared Vue components
    │   │   ├── views/         # Page-level views
    │   │   ├── stores/        # Pinia (UI state only)
    │   │   ├── composables/   # Shared composition functions
    │   │   ├── router/        # Vue Router (lazy loaded)
    │   │   ├── App.vue
    │   │   └── main.ts
    │   ├── package.json
    │   ├── vite.config.ts
    │   ├── orval.config.ts
    │   └── tsconfig.json
    ├── docker-compose.yml
    ├── nginx.conf
    ├── .env.example
    └── Makefile
```

## 5. Authentication

### User Model

```python
class User(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid4, primary_key=True)
    email: str = Field(unique=True, index=True)
    hashed_password: str
    is_active: bool = True
    is_superuser: bool = False
    created_at: datetime
```

### Multi-Tenancy

Every data table gets a `user_id: uuid.UUID = Field(foreign_key="user.id", index=True)` column. All queries filter by `current_user.id`. Enforced at the service layer — routes never query without user filtering.

### Auth Flow

- httpOnly cookie sessions (no JWT in localStorage — prevents XSS token theft)
- Registration: `POST /api/v1/auth/register` (email + password)
- Login: `POST /api/v1/auth/login` (sets httpOnly session cookie)
- Logout: `POST /api/v1/auth/logout` (clears cookie)
- Current user: `GET /api/v1/auth/me`
- Password hashing: bcrypt via FastAPI-Users

### Security: SECRET_KEY Validation

```python
class Settings(BaseSettings):
    secret_key: str
    environment: str = "production"

    @model_validator(mode="after")
    def validate_secret(self):
        if self.environment == "production" and "change" in self.secret_key.lower():
            raise ValueError("SECRET_KEY must be changed for production")
        return self
```

Production refuses to start with default/placeholder keys.

## 6. Backend API

### Versioned Routes

All endpoints under `/api/v1/`. Future breaking changes go to `/api/v2/`.

### Endpoints (37 total)

**Auth (4):**
```
POST   /api/v1/auth/register
POST   /api/v1/auth/login
POST   /api/v1/auth/logout
GET    /api/v1/auth/me
```

**Engagements (6):**
```
GET    /api/v1/engagements                    # list (cursor-paginated)
POST   /api/v1/engagements                    # create
GET    /api/v1/engagements/{id}               # get with summary
PATCH  /api/v1/engagements/{id}               # update name/target/scope
DELETE /api/v1/engagements/{id}               # delete (cascade)
PATCH  /api/v1/engagements/{id}/status        # update status
```

**Findings (8):**
```
GET    /api/v1/engagements/{id}/findings      # list (cursor-paginated, filterable)
POST   /api/v1/engagements/{id}/findings      # add
GET    /api/v1/findings/{id}                  # detail
PATCH  /api/v1/findings/{id}/status           # update status
PATCH  /api/v1/findings/{id}/false-positive   # toggle FP
GET    /api/v1/findings/search?q=             # FTS across engagements
PATCH  /api/v1/findings/bulk/false-positive   # bulk flag FP
PATCH  /api/v1/findings/bulk/status           # bulk status update
```

**IOCs (3):**
```
GET    /api/v1/engagements/{id}/iocs
POST   /api/v1/engagements/{id}/iocs
GET    /api/v1/iocs/search?q=                 # cross-engagement
```

**Timeline & Artifacts (2):**
```
GET    /api/v1/engagements/{id}/timeline
GET    /api/v1/engagements/{id}/artifacts
```

**Export & Import (5):**
```
POST   /api/v1/engagements/{id}/export        # JSON (StreamingResponse)
POST   /api/v1/engagements/{id}/export/bundle  # ZIP (StreamingResponse)
POST   /api/v1/engagements/{id}/export/sarif   # SARIF (StreamingResponse)
POST   /api/v1/engagements/{id}/export/stix    # STIX (StreamingResponse)
POST   /api/v1/engagements/import              # multipart file upload
```

**Containers (4):**
```
GET    /api/v1/containers/status
POST   /api/v1/containers/{name}/start
POST   /api/v1/containers/{name}/stop
POST   /api/v1/containers/{name}/restart
```

**Recipes (3):**
```
GET    /api/v1/recipes
POST   /api/v1/recipes/{id}/run               # background task, returns task_id
GET    /api/v1/recipes/tasks/{task_id}         # poll status
```

**Reports (2):**
```
POST   /api/v1/reports/generate               # background task
GET    /api/v1/reports/templates
```

**System (4):**
```
GET    /api/v1/health
GET    /api/v1/preflight
GET    /api/v1/config
GET    /api/v1/audit
```

**Real-time (1):**
```
GET    /api/v1/events                         # SSE stream (per-user filtered)
```

### Pagination

Cursor-based on all list endpoints:

```
GET /api/v1/engagements/{id}/findings?cursor=<last_id>&limit=50&severity=high
```

Response:
```json
{
  "items": [...],
  "next_cursor": "f-123",
  "has_more": true,
  "total": 247
}
```

### Rate Limiting

| Endpoint Class | Limit | Protection |
|---------------|-------|-----------|
| Auth | 10/min per IP | Brute force |
| Read (GET) | 200/min per user | General load |
| Write (POST/PATCH) | 60/min per user | DB write load |
| Export/Report | 10/min per user | Expensive operations |
| Recipe execution | 5/min per user | Subprocess spawning |

Applied at both Nginx (per-IP) and application (per-user via slowapi) layers.

### Response Optimization

- **GZip compression:** `GZipMiddleware(minimum_size=1000)` — 85% bandwidth reduction on large responses
- **ETags:** Hash response content, return `304 Not Modified` when unchanged
- **Streaming exports:** `StreamingResponse` for ZIP/SARIF/STIX — no full-file memory load

## 7. SSE (Server-Sent Events)

### Per-User Channel Manager

```python
class SSEManager:
    _channels: dict[str, list[asyncio.Queue]]

    async def subscribe(self, user_id: str) -> AsyncGenerator:
        queue = asyncio.Queue()
        self._channels.setdefault(user_id, []).append(queue)
        try:
            while True:
                event = await queue.get()
                yield event
        finally:
            self._channels[user_id].remove(queue)

    async def publish(self, user_id: str, event_type: str, data: dict):
        for queue in self._channels.get(user_id, []):
            await queue.put({"event": event_type, "data": data})
```

Multiple browser tabs = multiple queues per user. Different users never see each other's events.

### Event Types

```
finding_added       — new finding in engagement
finding_updated     — status change, FP flag
container_status    — Docker state change
recipe_step         — recipe execution progress
engagement_updated  — status change
```

### Frontend Integration

```typescript
// sse.ts store
const eventSource = new EventSource('/api/v1/events', { withCredentials: true })

eventSource.addEventListener('finding_added', (e) => {
  queryClient.invalidateQueries({ queryKey: ['findings'] })
})

eventSource.addEventListener('error', () => {
  showBanner('Connection lost — reconnecting...')
})

eventSource.addEventListener('open', () => {
  queryClient.invalidateQueries()  // refetch everything on reconnect
})
```

### Known Scaling Limitation

The in-memory SSEManager works for a single API process. For multi-process/multi-instance scaling (Phase 3D), upgrade to Redis pub/sub — each instance subscribes to a Redis channel and receives events from all instances.

## 8. Database

### SQLModel Tables

All existing Pydantic models become SQLModel tables with `user_id` column. JSON fields (lists, dicts) stored as Postgres `JSONB` (not TEXT like SQLite).

Key schema differences from SQLite:
- `JSONB` instead of `TEXT` for JSON fields (queryable)
- `tsvector` full-text search instead of FTS5
- `UUID` primary keys for users (native Postgres UUID type)
- `FOREIGN KEY ... ON DELETE CASCADE` on engagement children (finding, ioc, timeline_event, artifact, audit_log → engagement)
- Partial indexes for common query patterns

### Full-Text Search (Postgres tsvector)

Replaces SQLite FTS5:

```sql
ALTER TABLE finding ADD COLUMN search_vector tsvector;
CREATE INDEX idx_finding_fts ON finding USING GIN(search_vector);

CREATE FUNCTION finding_search_trigger() RETURNS trigger AS $$
BEGIN
  NEW.search_vector :=
    setweight(to_tsvector('english', COALESCE(NEW.title, '')), 'A') ||
    setweight(to_tsvector('english', COALESCE(NEW.description, '')), 'B') ||
    setweight(to_tsvector('english', COALESCE(NEW.evidence, '')), 'C') ||
    setweight(to_tsvector('english', COALESCE(NEW.remediation, '')), 'D');
  RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER finding_search_update
  BEFORE INSERT OR UPDATE ON finding
  FOR EACH ROW EXECUTE FUNCTION finding_search_trigger();
```

Weighted search: title matches (A) rank highest.

### Indexes

```sql
-- Multi-tenancy
CREATE INDEX idx_engagements_user ON engagement(user_id, created_at DESC);
CREATE INDEX idx_findings_user ON finding(user_id, engagement_id);

-- Common queries
CREATE INDEX idx_findings_severity ON finding(user_id, engagement_id, severity);
CREATE INDEX idx_findings_status ON finding(user_id, engagement_id, status);
CREATE INDEX idx_iocs_user ON ioc(user_id, engagement_id);

-- Dedup (from Phase 2B, adapted for Postgres)
CREATE INDEX idx_findings_dedup_file ON finding(engagement_id, file_path, line_start)
  WHERE deleted_at IS NULL;
CREATE INDEX idx_findings_dedup_network ON finding(engagement_id, cwe)
  WHERE file_path IS NULL AND deleted_at IS NULL;
```

All index creation uses `CONCURRENTLY` in Alembic to avoid table locks.

### Connection Pool

```python
engine = create_async_engine(
    DATABASE_URL,
    pool_size=15,
    max_overflow=25,
    pool_timeout=30,
    pool_recycle=1800,
)
```

4 uvicorn workers × 40 max = 160 connections. Postgres `max_connections = 200`.

### SQLite Fallback

CLI continues using `opentools.engagement.store.EngagementStore` with raw sqlite3. The web backend uses SQLModel + asyncpg. Both share `opentools.models` for Pydantic validation/serialization.

No SQLite code changes. The web backend is a completely separate data access layer.

## 9. Frontend

### Vue Router Pages

```
/login                          → LoginView
/register                       → RegisterView
/                               → redirect to /engagements
/engagements                    → EngagementListView (card grid)
/engagements/new                → EngagementCreateView
/engagements/:id                → EngagementDetailView (tabbed)
/engagements/:id/findings       → FindingsTab (default)
/engagements/:id/timeline       → TimelineTab
/engagements/:id/iocs           → IOCsTab
/engagements/:id/artifacts      → ArtifactsTab
/findings/:id                   → FindingDetailView
/recipes                        → RecipeListView
/recipes/:id/run                → RecipeRunnerView
/containers                     → ContainerStatusView
/settings                       → UserSettingsView
```

All routes lazy-loaded for code splitting.

### Layout

```
┌────────────────────────────────────────────────────────────────┐
│  TopNav: Logo │ Engagements │ Recipes │ Containers │ [Cmd+K] User ▼│
├─────────┬──────────────────────────────────────────────────────┤
│ Sidebar │  Breadcrumb: Engagements > my-audit > Findings       │
│         ├──────────────────────────────────────────────────────┤
│ Engage- │  Main Content (varies by route)                      │
│ ments   │                                                      │
│ list    │  PrimeVue DataTable / Forms / Cards                  │
│ +filter │                                                      │
└─────────┴──────────────────────────────────────────────────────┘
```

### Pinia Stores (UI State Only)

```
stores/
├── auth.ts          # user session state
├── ui.ts            # sidebar open, dark mode, active tab
├─�� sse.ts           # SSE connection, query invalidation
└── search.ts        # Cmd+K state, recent searches
```

Data fetching is entirely Tanstack Query via orval-generated hooks. No data in Pinia.

### Key PrimeVue Components

| Component | Usage |
|-----------|-------|
| DataTable + Column | Findings, Timeline, IOCs, Containers — sort/filter/paginate/select |
| Card | Engagement list (grid) |
| TabView | Engagement detail tabs |
| Dialog | Add finding, Add IOC, Export, Confirm delete |
| Tag | Severity badges (colored) |
| Breadcrumb | Navigation context |
| Menubar | Top navigation |
| Sidebar | Engagement list |
| Toast | Notifications |
| ProgressBar | Recipe execution |

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Cmd+K` / `Ctrl+K` | Global search / command palette |
| `n` | New engagement |
| `a` | Add finding (findings tab) |
| `f` | Flag selected as FP |
| `e` | Export current view |
| `?` | Show shortcut help |

### Dark Mode

Default: dark (PrimeVue `lara-dark-blue`). Toggle in user settings. Persisted in localStorage.

### Responsive Breakpoints

- **Desktop (>1024px):** sidebar + full DataTable
- **Tablet (768-1024px):** sidebar collapses, DataTable hides low-priority columns
- **Mobile (<768px):** sidebar hidden (hamburger), DataTable stacks cards

### Auto-Generated API Client

orval generates Tanstack Query hooks from FastAPI's OpenAPI spec:

```bash
npx orval
# Generates: src/api/endpoints.ts (typed fetch + vue-query hooks)
#            src/api/model.ts (TypeScript interfaces)
```

No manual API client code. Backend model changes → re-run orval → TypeScript catches breakage.

## 10. Deployment

### Docker Compose

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: opentools
      POSTGRES_USER: opentools
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U opentools"]
      interval: 5s
      timeout: 3s
      retries: 5

  migrate:
    build:
      context: ../..
      dockerfile: packages/web/backend/Dockerfile
    environment:
      DATABASE_URL: postgresql+asyncpg://opentools:${POSTGRES_PASSWORD}@postgres:5432/opentools
    depends_on:
      postgres:
        condition: service_healthy
    command: alembic upgrade head
    restart: "no"

  api:
    build:
      context: ../..
      dockerfile: packages/web/backend/Dockerfile
    environment:
      DATABASE_URL: postgresql+asyncpg://opentools:${POSTGRES_PASSWORD}@postgres:5432/opentools
      SECRET_KEY: ${SECRET_KEY}
      ENVIRONMENT: ${ENVIRONMENT:-production}
      ALLOWED_ORIGINS: ${ALLOWED_ORIGINS:-}
    depends_on:
      migrate:
        condition: service_completed_successfully
    volumes:
      - appdata:/app/data
    ports:
      - "8000:8000"

  nginx:
    image: nginx:alpine
    volumes:
      - ./frontend/dist:/usr/share/nginx/html:ro
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - api

volumes:
  pgdata:
  appdata:
```

### Nginx

- Serves SPA static files with aggressive caching (hashed assets: 1 year, index.html: no-cache)
- Reverse proxies `/api/*` to FastAPI
- SSE proxy with `proxy_buffering off`
- Per-IP rate limiting (auth: 5/min, API: 30/s)
- HTTPS via Let's Encrypt or self-signed cert
- Gzip for JSON, CSS, JS

### Environment Variables

```bash
# Required (no defaults)
POSTGRES_PASSWORD=your-secure-password
SECRET_KEY=your-secret-key-min-32-chars

# Optional
ENVIRONMENT=production            # production refuses placeholder secrets
ALLOWED_ORIGINS=                  # CORS (dev only, Nginx handles prod)
LOG_LEVEL=info
```

### Startup Sequence

**Production:**
```bash
cd packages/web
npm --prefix frontend run build   # build SPA
docker compose up -d              # postgres → migrate → api → nginx
```

**Development:**
```bash
docker compose up -d postgres     # Postgres only
cd backend && uvicorn app.main:app --reload   # API hot-reload
cd frontend && npm run dev        # Vite HMR + API proxy
```

## 11. Files Summary

### Backend (~25 files)

| File | Purpose |
|------|---------|
| `app/main.py` | FastAPI app, middleware, lifespan |
| `app/config.py` | Settings with SECRET_KEY validation |
| `app/auth.py` | FastAPI-Users setup |
| `app/database.py` | Async engine, session factory |
| `app/models.py` | SQLModel tables (User + all domain models with user_id) |
| `app/dependencies.py` | DI: current_user, db_session |
| `app/sse.py` | SSEManager with per-user channels |
| `app/routes/*.py` | 10 route modules (auth, engagements, findings, iocs, containers, recipes, reports, exports, system) |
| `app/services/*.py` | 4 service modules (engagement, finding, ioc, recipe) |
| `alembic/*` | Migration config + initial migration |
| `Dockerfile` | Backend image |
| `pyproject.toml` | Dependencies |

### Frontend (~25 files)

| File | Purpose |
|------|---------|
| `src/App.vue` | Root component with layout |
| `src/main.ts` | App entry, plugin registration |
| `src/api/*` | Auto-generated (orval) |
| `src/views/*.vue` | ~10 page views |
| `src/components/*.vue` | ~8 shared components |
| `src/stores/*.ts` | 4 Pinia stores (auth, ui, sse, search) |
| `src/composables/*.ts` | Shared composition functions |
| `src/router/index.ts` | Route definitions |
| `vite.config.ts` | Build config + dev proxy |
| `orval.config.ts` | OpenAPI codegen config |
| `package.json` | Dependencies |
| `tsconfig.json` | TypeScript config |

### Infrastructure (~5 files)

| File | Purpose |
|------|---------|
| `docker-compose.yml` | All services |
| `nginx.conf` | Proxy + static serving + rate limiting + SSL |
| `.env.example` | Required environment variables |
| `Makefile` | Dev/build/test commands |

## 12. Testing Strategy

### Backend Tests

| Area | What to Test |
|------|-------------|
| Auth | Register, login, logout, protected endpoint access, invalid credentials |
| Engagements | CRUD, user isolation (user A can't see user B's data), cascade delete |
| Findings | Add, list with pagination/filters, FTS search, dedup-on-insert, bulk operations |
| IOCs | Add, list, cross-engagement search |
| Exports | SARIF, STIX, JSON, ZIP generation |
| Recipes | List, run (mocked subprocess), task status |
| SSE | Event delivery, per-user filtering |
| Rate limiting | Endpoint limits enforced |

Use `pytest` + `httpx` (async test client) + test Postgres (Docker).

### Frontend Tests

| Area | What to Test |
|------|-------------|
| Auth flow | Login, logout, redirect to login when unauthenticated |
| Engagement CRUD | Create, list, delete with confirmation |
| Findings DataTable | Sort, filter, pagination, checkbox select, bulk actions |
| SSE | Event handling, query invalidation |
| Routing | Lazy loading, breadcrumbs, 404 |

Use `vitest` + `@vue/test-utils` + `msw` (API mocking).

## 13. Known Scaling Limitations (Documented for Future)

| Limitation | When It Matters | Upgrade Path |
|-----------|----------------|-------------|
| Single API process SSE | Multi-instance scaling | Redis pub/sub for SSE channels |
| No Redis caching | High read load (>1k req/s on summaries) | Add Redis + fastapi-cache2 |
| No background task queue | Recipe/report reliability needs | ARQ (async Redis queue) |
| No PgBouncer | >200 concurrent DB connections | PgBouncer in Docker Compose |
| No CDN | Global users, high static asset load | CloudFront/Cloudflare for frontend |
