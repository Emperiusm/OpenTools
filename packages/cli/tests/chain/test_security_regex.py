from datetime import datetime, timezone

from opentools.chain.extractors.base import ExtractionContext
from opentools.chain.extractors.security_regex import (
    MitreTechniqueExtractor,
    WindowsUserExtractor,
    ProcessNameExtractor,
    WindowsPathExtractor,
    RegistryKeyExtractor,
    PortExtractor,
    PackageVersionExtractor,
)
from opentools.chain.types import MentionField
from opentools.models import Finding, FindingStatus, Severity


def _finding() -> Finding:
    return Finding(
        id="fnd_t", engagement_id="eng_t", tool="nmap",
        severity=Severity.HIGH, status=FindingStatus.DISCOVERED,
        title="t", description="d", created_at=datetime.now(timezone.utc),
    )


def _ctx(**kwargs) -> ExtractionContext:
    return ExtractionContext(finding=_finding(), **kwargs)


# ─── MitreTechniqueExtractor ────────────────────────────────────────────


def test_mitre_extracts_valid_technique():
    e = MitreTechniqueExtractor()
    text = "uses T1566.001 for initial access"
    out = e.extract(text, MentionField.DESCRIPTION, _ctx())
    assert len(out) == 1
    assert out[0].type == "mitre_technique"
    assert out[0].value == "T1566.001"
    assert out[0].confidence == 0.95


def test_mitre_rejects_unknown_technique():
    e = MitreTechniqueExtractor()
    out = e.extract("uses T9999 which isn't real", MentionField.DESCRIPTION, _ctx())
    assert out == []


def test_mitre_extracts_tactic():
    e = MitreTechniqueExtractor()
    out = e.extract("mapped to TA0001", MentionField.DESCRIPTION, _ctx())
    assert len(out) == 1
    assert out[0].value == "TA0001"


def test_mitre_offsets_tracked():
    e = MitreTechniqueExtractor()
    text = "uses T1566.001 here"
    out = e.extract(text, MentionField.DESCRIPTION, _ctx())
    assert out[0].offset_start == 5
    assert out[0].offset_end == 14


# ─── WindowsPathExtractor ───────────────────────────────────────────────


def test_windows_path_extracts():
    e = WindowsPathExtractor()
    text = r"file at C:\Users\Admin\file.txt found"
    out = e.extract(text, MentionField.EVIDENCE, _ctx())
    assert any("C:\\Users\\Admin\\file.txt" in x.value for x in out)
    assert all(x.confidence == 0.9 for x in out)


def test_windows_path_skips_on_linux_engagement():
    e = WindowsPathExtractor()
    ctx = _ctx(engagement_metadata={"platform": "linux"})
    assert e.applies_to(_finding()) is True  # default
    # applies_to doesn't see ctx, so we document via test that extract still runs
    # but we test applies_to_context too
    # Instead, test that a direct platform check on the extractor returns False
    from opentools.chain.extractors.security_regex import WindowsPathExtractor as WPE
    assert WPE().platform_allows({"platform": "linux"}) is False
    assert WPE().platform_allows({"platform": "windows"}) is True
    assert WPE().platform_allows({}) is True  # auto


# ─── RegistryKeyExtractor ───────────────────────────────────────────────


def test_registry_key_extracts():
    e = RegistryKeyExtractor()
    text = r"key HKLM\Software\Microsoft\Windows set"
    out = e.extract(text, MentionField.DESCRIPTION, _ctx())
    assert any("HKLM\\Software\\Microsoft\\Windows" in x.value for x in out)
    assert out[0].confidence == 0.95


def test_registry_key_hkcu():
    e = RegistryKeyExtractor()
    out = e.extract(r"stored in HKCU\Environment", MentionField.EVIDENCE, _ctx())
    assert len(out) == 1
    assert out[0].value == "HKCU\\Environment"


# ─── ProcessNameExtractor ───────────────────────────────────────────────


def test_process_extracts_exe():
    e = ProcessNameExtractor()
    out = e.extract("spawned lsass.exe and cmd.exe", MentionField.DESCRIPTION, _ctx())
    values = {x.value for x in out}
    assert "lsass.exe" in values
    assert "cmd.exe" in values


def test_process_extracts_unix_binary():
    e = ProcessNameExtractor()
    out = e.extract("executed /usr/bin/wget", MentionField.DESCRIPTION, _ctx())
    assert any("/usr/bin/wget" in x.value for x in out)


# ─── PortExtractor ──────────────────────────────────────────────────────


def test_port_extracts_named_port():
    e = PortExtractor()
    out = e.extract("open port 22 and port 443", MentionField.DESCRIPTION, _ctx())
    values = {x.value for x in out}
    assert "22" in values
    assert "443" in values


def test_port_rejects_year_number():
    """PortExtractor requires a port context keyword; years in dates must not match."""
    e = PortExtractor()
    out = e.extract("found in 2024 documentation", MentionField.DESCRIPTION, _ctx())
    assert out == []


# ─── WindowsUserExtractor ───────────────────────────────────────────────


def test_windows_user_extracts_domain_backslash():
    e = WindowsUserExtractor()
    out = e.extract(r"CORP\alice logged in", MentionField.DESCRIPTION, _ctx())
    values = {x.value for x in out}
    assert "CORP\\alice" in values


# ─── PackageVersionExtractor ────────────────────────────────────────────


def test_package_version_at_syntax():
    e = PackageVersionExtractor()
    out = e.extract("affected: lodash@4.17.15 (CVE-2019-10744)", MentionField.DESCRIPTION, _ctx())
    values = {x.value for x in out}
    assert "lodash@4.17.15" in values
