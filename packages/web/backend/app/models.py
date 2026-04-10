"""SQLModel table definitions for the web dashboard."""

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi_users import schemas as fu_schemas
from sqlalchemy import Column, Index, Text, JSON
from sqlmodel import Field, SQLModel


# --- User -----------------------------------------------------------------

class User(SQLModel, table=True):
    __tablename__ = "user"
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    email: str = Field(unique=True, index=True, max_length=320)
    hashed_password: str = Field(default="")
    is_active: bool = Field(default=True)
    is_superuser: bool = Field(default=False)
    is_verified: bool = Field(default=False)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class UserRead(fu_schemas.BaseUser[uuid.UUID]):
    pass


class UserCreate(fu_schemas.BaseUserCreate):
    pass


# --- Engagement -----------------------------------------------------------

class Engagement(SQLModel, table=True):
    __tablename__ = "engagement"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    name: str
    target: str
    type: str
    scope: Optional[str] = None
    status: str = Field(default="active")
    skills_used: Optional[str] = Field(default=None, sa_column=Column(JSON))
    created_at: datetime
    updated_at: datetime


# --- Finding --------------------------------------------------------------

class Finding(SQLModel, table=True):
    __tablename__ = "finding"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    engagement_id: str = Field(foreign_key="engagement.id")
    tool: str
    corroborated_by: Optional[str] = Field(default=None, sa_column=Column(JSON))
    cwe: Optional[str] = None
    severity: str
    severity_by_tool: Optional[str] = Field(default=None, sa_column=Column(JSON))
    status: str = Field(default="discovered")
    phase: Optional[str] = None
    title: str
    description: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    evidence: Optional[str] = Field(default=None, sa_column=Column(Text))
    remediation: Optional[str] = Field(default=None, sa_column=Column(Text))
    cvss: Optional[float] = None
    false_positive: bool = Field(default=False)
    dedup_confidence: Optional[str] = None
    created_at: datetime
    deleted_at: Optional[datetime] = None

    # Note: search_vector (tsvector) added via migration, not SQLModel field


# --- TimelineEvent --------------------------------------------------------

class TimelineEvent(SQLModel, table=True):
    __tablename__ = "timeline_event"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    engagement_id: str = Field(foreign_key="engagement.id")
    timestamp: datetime
    source: str
    event: str
    details: Optional[str] = None
    confidence: str = Field(default="medium")
    finding_id: Optional[str] = Field(default=None, foreign_key="finding.id")


# --- IOC ------------------------------------------------------------------

class IOC(SQLModel, table=True):
    __tablename__ = "ioc"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    engagement_id: str = Field(foreign_key="engagement.id")
    ioc_type: str
    value: str
    context: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source_finding_id: Optional[str] = Field(default=None, foreign_key="finding.id")


# --- Artifact -------------------------------------------------------------

class Artifact(SQLModel, table=True):
    __tablename__ = "artifact"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    engagement_id: str = Field(foreign_key="engagement.id")
    file_path: str
    artifact_type: str
    description: Optional[str] = None
    source_tool: Optional[str] = None
    created_at: datetime


# --- AuditEntry -----------------------------------------------------------

class AuditEntry(SQLModel, table=True):
    __tablename__ = "audit_entry"
    id: str = Field(primary_key=True)
    user_id: uuid.UUID = Field(foreign_key="user.id", index=True)
    timestamp: datetime
    command: str
    args: Optional[str] = Field(default=None, sa_column=Column(JSON))
    engagement_id: Optional[str] = None
    result: str
    details: Optional[str] = None
