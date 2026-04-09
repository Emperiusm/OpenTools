import sqlite3
from datetime import datetime, timezone
import pytest
from opentools.engagement.schema import migrate
from opentools.engagement.store import EngagementStore
from opentools.models import Engagement, EngagementType, EngagementStatus


@pytest.fixture
def db_conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    migrate(conn)
    yield conn
    conn.close()


@pytest.fixture
def store(db_conn):
    return EngagementStore(conn=db_conn)


@pytest.fixture
def sample_engagement():
    now = datetime.now(timezone.utc)
    return Engagement(
        id="eng-001",
        name="test-pentest",
        target="192.168.1.0/24",
        type=EngagementType.PENTEST,
        status=EngagementStatus.ACTIVE,
        skills_used=["pentest"],
        created_at=now,
        updated_at=now,
    )
