import pytest
from opentools.chain.cypher.builtins import (
    builtin_collect, builtin_has_entity, builtin_has_mitre,
    builtin_length, builtin_nodes, builtin_relationships,
    get_builtin, list_builtins,
)

def test_builtin_length():
    path = {"nodes": [1, 2, 3], "edges": [10, 20]}
    assert builtin_length(path) == 2

def test_builtin_length_empty_path():
    path = {"nodes": [1], "edges": []}
    assert builtin_length(path) == 0

def test_builtin_nodes():
    path = {"nodes": ["a", "b", "c"], "edges": [1, 2]}
    assert builtin_nodes(path) == ["a", "b", "c"]

def test_builtin_relationships():
    path = {"nodes": ["a", "b"], "edges": ["r1"]}
    assert builtin_relationships(path) == ["r1"]

def test_builtin_has_entity():
    node = {"entities": [{"type": "host", "canonical_value": "10.0.0.1"}, {"type": "cve", "canonical_value": "CVE-2024-1234"}]}
    assert builtin_has_entity(node, "host", "10.0.0.1") is True
    assert builtin_has_entity(node, "host", "10.0.0.2") is False
    assert builtin_has_entity(node, "cve", "CVE-2024-1234") is True

def test_builtin_has_entity_no_entities():
    node = {"entities": []}
    assert builtin_has_entity(node, "host", "anything") is False

def test_builtin_has_mitre():
    node = {"entities": [{"type": "mitre_technique", "canonical_value": "T1059"}]}
    assert builtin_has_mitre(node, "T1059") is True
    assert builtin_has_mitre(node, "T1078") is False

def test_builtin_collect():
    values = [1, 2, 3, 4]
    assert builtin_collect(values) == [1, 2, 3, 4]

def test_get_builtin():
    fn = get_builtin("length")
    assert fn is builtin_length
    assert get_builtin("nonexistent") is None

def test_list_builtins():
    builtins = list_builtins()
    assert "length" in builtins
    assert "has_entity" in builtins
    assert "collect" in builtins
    assert len(builtins) >= 6
