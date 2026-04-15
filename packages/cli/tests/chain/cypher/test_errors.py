from opentools.chain.cypher.errors import (
    QueryParseError,
    QueryResourceError,
    QueryValidationError,
)


def test_query_parse_error_is_exception():
    err = QueryParseError("unexpected token", line=3, column=12)
    assert isinstance(err, Exception)
    assert err.line == 3
    assert err.column == 12
    assert "unexpected token" in str(err)


def test_query_validation_error_is_exception():
    err = QueryValidationError("unknown function: foo.bar")
    assert isinstance(err, Exception)
    assert "foo.bar" in str(err)


def test_query_resource_error_is_exception():
    err = QueryResourceError("binding cap exceeded", limit_name="intermediate_binding_cap", limit_value=10_000)
    assert isinstance(err, Exception)
    assert err.limit_name == "intermediate_binding_cap"
    assert err.limit_value == 10_000
