import pytest

from opentools.chain.normalizers import normalize
from opentools.chain.types import (
    ENTITY_TYPE_REGISTRY,
    is_strong_entity_type,
    is_weak_entity_type,
)


def test_builtins_registered_on_import():
    # Importing normalizers has the side effect of registering built-in types.
    import opentools.chain.normalizers  # noqa: F401
    for t in [
        "host", "ip", "user", "process", "cve", "mitre_technique",
        "domain", "registered_domain", "email", "url",
        "file_path", "port", "registry_key", "package",
        "hash_md5", "hash_sha1", "hash_sha256",
    ]:
        assert t in ENTITY_TYPE_REGISTRY, f"missing built-in: {t}"


def test_strong_vs_weak_categories():
    import opentools.chain.normalizers  # noqa: F401
    assert is_strong_entity_type("host")
    assert is_strong_entity_type("cve")
    assert is_strong_entity_type("mitre_technique")
    assert is_strong_entity_type("domain")
    assert is_strong_entity_type("url")
    assert is_weak_entity_type("file_path")
    assert is_weak_entity_type("port")
    assert is_weak_entity_type("registry_key")
    assert is_weak_entity_type("package")


def test_ip_canonicalizes():
    assert normalize("ip", "10.0.0.5") == "10.0.0.5"
    assert normalize("ip", "[::1]") == "::1"
    with pytest.raises(ValueError):
        normalize("ip", "not-an-ip")


def test_cve_uppercases_and_dashes():
    assert normalize("cve", "cve-2024-1234") == "CVE-2024-1234"
    assert normalize("cve", "cve_2024_1234") == "CVE-2024-1234"


def test_mitre_uppercases():
    assert normalize("mitre_technique", "t1566.001") == "T1566.001"
    assert normalize("mitre_technique", "ta0001") == "TA0001"


def test_email_lowercases():
    assert normalize("email", "Admin@Example.COM") == "admin@example.com"


def test_domain_strips_trailing_dot_and_lowercases():
    assert normalize("domain", "Example.COM.") == "example.com"


def test_registered_domain_via_psl():
    assert normalize("registered_domain", "mail.google.com") == "google.com"
    assert normalize("registered_domain", "sub.example.co.uk") == "example.co.uk"


def test_file_path_windows_lowercases(monkeypatch):
    import sys
    monkeypatch.setattr(sys, "platform", "win32")
    # Re-import normalize since it closes over sys.platform
    from opentools.chain.normalizers import normalize as n
    assert n("file_path", "C:\\Users\\Admin\\File.TXT") == "c:\\users\\admin\\file.txt"


def test_hash_lowercases():
    assert normalize("hash_sha256", "ABCDEF") == "abcdef"


def test_registry_key_uppercases():
    assert normalize("registry_key", "HKLM\\Software\\Foo") == "HKLM\\SOFTWARE\\FOO"


def test_url_preserved_stripped():
    assert normalize("url", "  https://example.com/path  ") == "https://example.com/path"


def test_unknown_type_passes_through():
    assert normalize("unknown_type_xyz", "some value") == "some value"
