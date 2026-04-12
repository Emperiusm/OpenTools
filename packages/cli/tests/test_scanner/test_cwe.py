"""Tests for CWEHierarchy — parent/child, alias resolution, OWASP mapping."""

from __future__ import annotations

import pytest

from opentools.scanner.cwe import CWEHierarchy


@pytest.fixture(scope="module")
def hierarchy() -> CWEHierarchy:
    return CWEHierarchy()


# ===========================================================================
# get_name
# ===========================================================================


class TestGetName:
    def test_get_name(self, hierarchy: CWEHierarchy) -> None:
        assert hierarchy.get_name("CWE-89") == "SQL Injection"

    def test_get_name_unknown(self, hierarchy: CWEHierarchy) -> None:
        assert hierarchy.get_name("CWE-99999") is None


# ===========================================================================
# get_parent
# ===========================================================================


class TestGetParent:
    def test_get_parent(self, hierarchy: CWEHierarchy) -> None:
        assert hierarchy.get_parent("CWE-564") == "CWE-89"

    def test_get_parent_root(self, hierarchy: CWEHierarchy) -> None:
        # CWE-190 has null parent — should return None
        assert hierarchy.get_parent("CWE-190") is None


# ===========================================================================
# get_children
# ===========================================================================


class TestGetChildren:
    def test_get_children(self, hierarchy: CWEHierarchy) -> None:
        children = hierarchy.get_children("CWE-89")
        assert "CWE-564" in children


# ===========================================================================
# is_related
# ===========================================================================


class TestIsRelated:
    def test_is_related_parent_child(self, hierarchy: CWEHierarchy) -> None:
        # CWE-89 is the parent of CWE-564
        assert hierarchy.is_related("CWE-89", "CWE-564") is True

    def test_is_related_siblings(self, hierarchy: CWEHierarchy) -> None:
        # CWE-89 and CWE-79 both have parent CWE-74
        assert hierarchy.is_related("CWE-89", "CWE-79") is True

    def test_is_related_unrelated(self, hierarchy: CWEHierarchy) -> None:
        # CWE-89 (SQL Injection, tree under CWE-74) and CWE-416 (Use After Free, root)
        assert hierarchy.is_related("CWE-89", "CWE-416") is False


# ===========================================================================
# resolve_alias
# ===========================================================================


class TestResolveAlias:
    def test_resolve_alias(self, hierarchy: CWEHierarchy) -> None:
        assert hierarchy.resolve_alias("sqli") == "CWE-89"
        assert hierarchy.resolve_alias("xss") == "CWE-79"
        assert hierarchy.resolve_alias("use after free") == "CWE-416"

    def test_resolve_alias_canonical_passthrough(self, hierarchy: CWEHierarchy) -> None:
        # Already a canonical CWE ID — should return it directly
        assert hierarchy.resolve_alias("CWE-89") == "CWE-89"

    def test_resolve_alias_unknown(self, hierarchy: CWEHierarchy) -> None:
        assert hierarchy.resolve_alias("unknown-thing") is None


# ===========================================================================
# get_owasp_category
# ===========================================================================


class TestGetOwaspCategory:
    def test_get_owasp_category(self, hierarchy: CWEHierarchy) -> None:
        category = hierarchy.get_owasp_category("CWE-89")
        assert category is not None
        assert "Injection" in category

    def test_get_owasp_category_unknown(self, hierarchy: CWEHierarchy) -> None:
        assert hierarchy.get_owasp_category("CWE-99999") is None

    def test_get_owasp_category_via_parent(self, hierarchy: CWEHierarchy) -> None:
        # CWE-564 (SQL Injection: Hibernate) has parent CWE-89 which maps to Injection
        category = hierarchy.get_owasp_category("CWE-564")
        assert category is not None
        assert "Injection" in category
