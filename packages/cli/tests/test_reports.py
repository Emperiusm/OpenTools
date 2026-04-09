import pytest
from datetime import datetime, timezone
from pathlib import Path
from opentools.reports import ReportGenerator
from opentools.models import Engagement, EngagementType, EngagementStatus, Finding, Severity


def test_list_templates(tmp_path):
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "pentest-report.md.j2").write_text("# Report")
    (template_dir / "incident-report.md.j2").write_text("# IR")
    (template_dir / "not-a-template.txt").write_text("nope")

    from opentools.engagement.store import EngagementStore
    store = EngagementStore(db_path=tmp_path / "test.db")
    gen = ReportGenerator(template_dir, store)
    templates = gen.list_templates()
    assert "pentest-report" in templates
    assert "incident-report" in templates
    assert "not-a-template" not in templates


def test_generate_renders_template(tmp_path):
    # Setup store with data
    from opentools.engagement.store import EngagementStore
    store = EngagementStore(db_path=tmp_path / "test.db")
    now = datetime.now(timezone.utc)
    eng = Engagement(
        id="e-1", name="test", target="10.0.0.1",
        type=EngagementType.PENTEST, status=EngagementStatus.ACTIVE,
        skills_used=["pentest"], created_at=now, updated_at=now,
    )
    store.create(eng)
    store.add_finding(Finding(
        id="f-1", engagement_id="e-1", tool="semgrep",
        title="SQL Injection", severity=Severity.HIGH, created_at=now,
    ))

    # Create template
    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "simple.md.j2").write_text(
        "# Report: {{ engagement.name }}\n"
        "Findings: {{ findings | length }}\n"
        "{% for f in findings %}\n"
        "- {{ f.title }} ({{ f.severity }})\n"
        "{% endfor %}\n"
    )

    gen = ReportGenerator(template_dir, store)
    result = gen.generate("e-1", "simple")
    assert "test" in result
    assert "SQL Injection" in result
    assert "Findings: 1" in result


def test_generate_writes_to_file(tmp_path):
    from opentools.engagement.store import EngagementStore
    store = EngagementStore(db_path=tmp_path / "test.db")
    now = datetime.now(timezone.utc)
    eng = Engagement(
        id="e-1", name="test", target="10.0.0.1",
        type=EngagementType.PENTEST, status=EngagementStatus.ACTIVE,
        created_at=now, updated_at=now,
    )
    store.create(eng)

    template_dir = tmp_path / "templates"
    template_dir.mkdir()
    (template_dir / "minimal.md.j2").write_text("# {{ engagement.name }}")

    output_path = tmp_path / "output" / "report.md"
    gen = ReportGenerator(template_dir, store)
    gen.generate("e-1", "minimal", output_path=output_path)
    assert output_path.exists()
    assert "test" in output_path.read_text()


def test_list_templates_empty_dir(tmp_path):
    template_dir = tmp_path / "empty"
    template_dir.mkdir()
    from opentools.engagement.store import EngagementStore
    store = EngagementStore(db_path=tmp_path / "test.db")
    gen = ReportGenerator(template_dir, store)
    assert gen.list_templates() == []
