from opentools.chain.cypher.result import QueryResult, QueryStats
from opentools.chain.cypher.session import QuerySession


def test_session_store_and_get():
    session = QuerySession()
    result = QueryResult(columns=["a"], rows=[{"a": 1}, {"a": 2}], stats=QueryStats())
    session.store("my_results", result)
    retrieved = session.get("my_results")
    assert retrieved is result


def test_session_get_unknown():
    session = QuerySession()
    assert session.get("nonexistent") is None


def test_session_list_variables():
    session = QuerySession()
    r1 = QueryResult(columns=["a"], rows=[], stats=QueryStats())
    r2 = QueryResult(columns=["b"], rows=[], stats=QueryStats())
    session.store("first", r1)
    session.store("second", r2)
    assert set(session.list_variables()) == {"first", "second"}


def test_session_clear():
    session = QuerySession()
    session.store("x", QueryResult(columns=[], rows=[], stats=QueryStats()))
    session.clear()
    assert session.get("x") is None
    assert session.list_variables() == []


def test_session_overwrite():
    session = QuerySession()
    r1 = QueryResult(columns=["a"], rows=[{"a": 1}], stats=QueryStats())
    r2 = QueryResult(columns=["a"], rows=[{"a": 2}], stats=QueryStats())
    session.store("x", r1)
    session.store("x", r2)
    assert session.get("x") is r2
