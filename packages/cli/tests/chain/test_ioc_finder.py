from datetime import datetime, timezone

from opentools.chain.extractors.base import ExtractionContext
from opentools.chain.extractors.ioc_finder import IocFinderExtractor
from opentools.chain.types import MentionField
from opentools.models import Finding, FindingStatus, Severity


def _finding() -> Finding:
    return Finding(
        id="fnd_t", engagement_id="eng_t", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title="t", description="d", created_at=datetime.now(timezone.utc),
    )


def _ctx() -> ExtractionContext:
    return ExtractionContext(finding=_finding())


def test_extractor_metadata():
    e = IocFinderExtractor()
    assert e.name == "ioc_finder"
    # Applies to every finding (stage-2 extractor)
    assert e.applies_to(_finding()) is True


def test_extracts_ipv4():
    e = IocFinderExtractor()
    out = e.extract("see 10.0.0.5 please", MentionField.DESCRIPTION, _ctx())
    types = {(x.type, x.value) for x in out}
    assert ("ip", "10.0.0.5") in types


def test_extracts_domain_and_email():
    e = IocFinderExtractor()
    out = e.extract("contact admin@example.com at example.com", MentionField.DESCRIPTION, _ctx())
    types = {(x.type, x.value) for x in out}
    assert ("email", "admin@example.com") in types
    assert ("domain", "example.com") in types


def test_extracts_cve():
    e = IocFinderExtractor()
    out = e.extract("affected by CVE-2024-1234", MentionField.DESCRIPTION, _ctx())
    types = {(x.type, x.value) for x in out}
    assert ("cve", "CVE-2024-1234") in types


def test_extracts_url():
    e = IocFinderExtractor()
    out = e.extract("visit https://example.com/path", MentionField.DESCRIPTION, _ctx())
    types = {(x.type, x.value) for x in out}
    assert ("url", "https://example.com/path") in types


def test_extracts_hashes():
    e = IocFinderExtractor()
    text = (
        "md5 d41d8cd98f00b204e9800998ecf8427e "
        "sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709 "
        "sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    out = e.extract(text, MentionField.EVIDENCE, _ctx())
    types = {x.type for x in out}
    assert "hash_md5" in types
    assert "hash_sha1" in types
    assert "hash_sha256" in types


def test_defanged_ip_detected():
    e = IocFinderExtractor()
    out = e.extract("defanged 10[.]0[.]0[.]5", MentionField.DESCRIPTION, _ctx())
    types = {(x.type, x.value) for x in out}
    assert ("ip", "10.0.0.5") in types


def test_all_entities_have_expected_metadata():
    e = IocFinderExtractor()
    out = e.extract("10.0.0.5 and CVE-2024-1234", MentionField.DESCRIPTION, _ctx())
    for x in out:
        assert x.extractor == "ioc_finder"
        assert x.confidence == 0.9
        assert x.offset_start is None
        assert x.offset_end is None
        assert x.field == MentionField.DESCRIPTION


def test_empty_text_returns_empty_list():
    e = IocFinderExtractor()
    out = e.extract("", MentionField.DESCRIPTION, _ctx())
    assert out == []


def test_no_iocs_returns_empty_list():
    e = IocFinderExtractor()
    out = e.extract("this text has no indicators", MentionField.DESCRIPTION, _ctx())
    assert out == []
