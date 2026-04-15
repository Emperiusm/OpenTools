import pytest
from opentools.chain.cypher.plugins import PluginFunctionRegistry

@pytest.fixture
def registry():
    return PluginFunctionRegistry()

def test_register_scalar_function(registry):
    registry.register_function("my_plugin.risk_score", fn=lambda node: 0.9, help="Risk score", arg_types=["node"], return_type="float")
    assert registry.get_function("my_plugin.risk_score") is not None

def test_register_aggregation(registry):
    registry.register_aggregation("my_plugin.combined_risk", fn=lambda values: max(values), help="Max risk", input_type="float", return_type="float")
    assert registry.get_aggregation("my_plugin.combined_risk") is not None

def test_reject_undotted_plugin_name(registry):
    with pytest.raises(ValueError, match="dotted"):
        registry.register_function("no_dot", fn=lambda x: x, help="bad", arg_types=["node"], return_type="float")

def test_reject_duplicate_name(registry):
    registry.register_function("my_plugin.f", fn=lambda x: x, help="first", arg_types=["node"], return_type="float")
    with pytest.raises(ValueError, match="already registered"):
        registry.register_function("my_plugin.f", fn=lambda x: x, help="second", arg_types=["node"], return_type="float")

def test_list_all_functions(registry):
    registry.register_function("a.one", fn=lambda x: x, help="h1", arg_types=["node"], return_type="float")
    registry.register_aggregation("a.two", fn=lambda v: sum(v), help="h2", input_type="float", return_type="float")
    all_fns = registry.list_all()
    assert "a.one" in all_fns
    assert "a.two" in all_fns
    assert all_fns["a.one"]["kind"] == "scalar"
    assert all_fns["a.two"]["kind"] == "aggregation"

def test_resolve_returns_none_for_unknown(registry):
    assert registry.get_function("nonexistent.fn") is None
    assert registry.get_aggregation("nonexistent.fn") is None
