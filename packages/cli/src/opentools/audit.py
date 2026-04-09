"""Audit trail for CLI command invocations."""

from datetime import datetime, timezone
from uuid import uuid4

from opentools.models import AuditEntry
from opentools.engagement.store import EngagementStore


def log_command(
    store: EngagementStore,
    command: str,
    args: dict | None = None,
    engagement_id: str | None = None,
    result: str = "success",
    details: str | None = None,
) -> None:
    """Log a CLI command invocation to the audit trail."""
    entry = AuditEntry(
        id=str(uuid4()),
        timestamp=datetime.now(timezone.utc),
        command=command,
        args=args,
        engagement_id=engagement_id,
        result=result,
        details=details,
    )
    store.log_action(entry)
