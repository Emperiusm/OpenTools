from opentools.chain.mitre_catalog import is_valid_technique, validate_technique_ids


def test_valid_techniques():
    assert is_valid_technique("T1566")
    assert is_valid_technique("T1566.001")
    assert is_valid_technique("T1003")


def test_valid_tactics():
    assert is_valid_technique("TA0001")
    assert is_valid_technique("TA0043")


def test_invalid_technique():
    # T9999 is not in the baked-in catalog
    assert not is_valid_technique("T9999")
    assert not is_valid_technique("T12345")   # wrong digit count
    assert not is_valid_technique("not-a-technique")
    assert not is_valid_technique("TA9999")   # out of range


def test_case_insensitive():
    assert is_valid_technique("t1566")
    assert is_valid_technique("ta0001")


def test_validate_technique_ids_filters():
    candidates = ["T1566", "T9999", "T1003.001", "foo", "TA0001"]
    valid = validate_technique_ids(candidates)
    assert "T1566" in valid
    assert "T1003.001" in valid
    assert "TA0001" in valid
    assert "T9999" not in valid
    assert "foo" not in valid
