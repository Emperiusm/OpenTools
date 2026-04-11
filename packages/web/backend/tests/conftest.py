"""Test fixtures with SQLite backend (no Postgres required)."""

import asyncio
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

from app.main import app
from app.database import get_session

# Use SQLite for tests (async via aiosqlite)
TEST_DB_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(TEST_DB_URL, echo=False)
test_session_factory = sessionmaker(test_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture(autouse=True)
async def setup_db():
    """Create all tables before each test, drop after."""
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)


async def override_get_session():
    async with test_session_factory() as session:
        yield session


@pytest.fixture
async def client():
    """Async HTTP client with overridden DB session."""
    app.dependency_overrides[get_session] = override_get_session
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture
def test_session_factory_fixture():
    """Provide the test session factory as a pytest fixture.

    Tests that need to call ``async with session_factory() as session: ...``
    directly (e.g. the chain rebuild worker tests) should use this fixture.
    """
    return test_session_factory


@pytest.fixture
async def auth_client(client):
    """Client that's registered and logged in."""
    # Register
    await client.post("/api/v1/auth/register", json={
        "email": "test@example.com",
        "password": "testpassword123",
    })
    # Login — FastAPI-Users uses OAuth2 form data, not JSON
    response = await client.post("/api/v1/auth/login", data={
        "username": "test@example.com",
        "password": "testpassword123",
    })
    # httpx AsyncClient does not auto-store cookies from responses; copy them manually
    if response.status_code in (200, 204):
        for name, value in response.cookies.items():
            client.cookies.set(name, value)
    return client
