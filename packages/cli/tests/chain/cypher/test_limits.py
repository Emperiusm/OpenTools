from opentools.chain.cypher.limits import QueryLimits


def test_query_limits_defaults():
    limits = QueryLimits()
    assert limits.timeout_seconds == 30.0
    assert limits.max_rows == 1000
    assert limits.intermediate_binding_cap == 10_000
    assert limits.max_var_length_hops == 10


def test_query_limits_custom():
    limits = QueryLimits(timeout_seconds=60.0, max_rows=500)
    assert limits.timeout_seconds == 60.0
    assert limits.max_rows == 500
    assert limits.intermediate_binding_cap == 10_000  # unchanged default


def test_query_limits_frozen():
    limits = QueryLimits()
    try:
        limits.timeout_seconds = 99.0
        assert False, "should be frozen"
    except Exception:
        pass
