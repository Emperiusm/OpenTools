from opentools.chain.events import StoreEventBus, get_event_bus, reset_event_bus


def test_event_bus_dispatches_to_subscribers():
    bus = StoreEventBus()
    calls = []

    def handler_a(**kwargs):
        calls.append(("a", kwargs))

    def handler_b(**kwargs):
        calls.append(("b", kwargs))

    bus.subscribe("finding.created", handler_a)
    bus.subscribe("finding.created", handler_b)
    bus.emit("finding.created", finding_id="fnd_1", extra=42)

    assert ("a", {"finding_id": "fnd_1", "extra": 42}) in calls
    assert ("b", {"finding_id": "fnd_1", "extra": 42}) in calls


def test_event_bus_swallows_handler_exceptions():
    bus = StoreEventBus()
    ok = []

    def broken(**kwargs):
        raise RuntimeError("boom")

    def fine(**kwargs):
        ok.append(kwargs)

    bus.subscribe("finding.updated", broken)
    bus.subscribe("finding.updated", fine)
    bus.emit("finding.updated", finding_id="fnd_2")
    assert ok == [{"finding_id": "fnd_2"}]


def test_event_bus_ignores_unknown_events():
    bus = StoreEventBus()
    bus.emit("finding.nonsense", finding_id="fnd_x")  # must not raise


def test_event_bus_singleton_shared():
    reset_event_bus()
    a = get_event_bus()
    b = get_event_bus()
    assert a is b
    reset_event_bus()


def test_store_emits_finding_created(tmp_path):
    """Smoke test: adding a finding via the real store emits finding.created."""
    from datetime import datetime, timezone
    from opentools.chain.events import get_event_bus, reset_event_bus
    from opentools.engagement.store import EngagementStore
    from opentools.models import (
        Engagement,
        EngagementStatus,
        EngagementType,
        Finding,
        FindingStatus,
        Severity,
    )

    reset_event_bus()
    received = []
    get_event_bus().subscribe("finding.created", lambda **kw: received.append(kw))

    db_path = tmp_path / "test.db"
    store = EngagementStore(db_path=db_path)

    now = datetime.now(timezone.utc)
    engagement = Engagement(
        id="eng_test",
        name="test",
        target="example.com",
        type=EngagementType.PENTEST,
        status=EngagementStatus.ACTIVE,
        created_at=now,
        updated_at=now,
    )
    store.create(engagement)

    finding = Finding(
        id="fnd_test1",
        engagement_id="eng_test",
        tool="nmap",
        severity=Severity.HIGH,
        status=FindingStatus.DISCOVERED,
        title="Open port 22",
        description="SSH exposed on 10.0.0.5",
        created_at=now,
    )
    store.add_finding(finding)

    assert any(e.get("finding_id") == "fnd_test1" for e in received)
    reset_event_bus()
