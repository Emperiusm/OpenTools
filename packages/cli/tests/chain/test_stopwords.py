from opentools.chain.stopwords import is_stopword, STATIC_STOPWORDS


def test_builtin_stopwords_present():
    assert is_stopword("host", "localhost")
    assert is_stopword("ip", "127.0.0.1")
    assert is_stopword("ip", "::1")
    assert is_stopword("ip", "0.0.0.0")
    assert is_stopword("user", "root")
    assert is_stopword("user", "admin")
    assert is_stopword("port", "80")
    assert is_stopword("port", "443")
    assert is_stopword("port", "22")


def test_non_stopword():
    assert not is_stopword("host", "10.0.0.5")
    assert not is_stopword("user", "alice")
    assert not is_stopword("port", "8443")


def test_extras_extend_list():
    extras = ["host:test.local", "user:svc_bot"]
    assert is_stopword("host", "test.local", extras=extras)
    assert is_stopword("user", "svc_bot", extras=extras)
    assert not is_stopword("host", "real.example.com", extras=extras)


def test_static_stopwords_is_dict_of_sets():
    assert isinstance(STATIC_STOPWORDS, dict)
    for v in STATIC_STOPWORDS.values():
        assert isinstance(v, set)


def test_unknown_type_has_no_stopwords():
    assert not is_stopword("docker_container", "localhost")
