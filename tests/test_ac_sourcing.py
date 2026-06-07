"""
Tests for endpoint sourcing (path templating) and the ID classifier — the logic
that decides the SAFE enumeration strategy per identifier type.
"""

from modules.accesscontrol.idparams import classify_id, is_id_name
from modules.accesscontrol.sourcing import templatize_path


# --- path templating -------------------------------------------------------
def test_templatize_collapses_numeric_and_uuid_segments():
    assert templatize_path("/api/users/1/orders/42") == "/api/users/{id}/orders/{id}"
    u = "/api/objects/f47ac10b-58cc-4372-a567-0e02b2c3d479"
    assert templatize_path(u) == "/api/objects/{uuid}"


def test_templatize_leaves_words_alone():
    assert templatize_path("/api/users/me") == "/api/users/me"


# --- id name heuristic -----------------------------------------------------
def test_is_id_name():
    assert is_id_name("id")
    assert is_id_name("userId")
    assert is_id_name("order_id")
    assert is_id_name("uuid")
    assert not is_id_name("name")
    assert not is_id_name("color")


# --- id classifier (drives the enumeration STRATEGY) -----------------------
def test_classify_sequential():
    cls, strat = classify_id("1042")
    assert cls == "sequential"
    assert "READ-ONLY" in strat


def test_classify_uuidv4_says_do_not_bruteforce():
    cls, strat = classify_id("f47ac10b-58cc-4372-a567-0e02b2c3d479")  # version 4
    assert cls == "uuidv4"
    assert "DO NOT brute force" in strat


def test_classify_uuidv1_says_sandwich():
    cls, strat = classify_id("a8098c1a-f86e-11da-bd1a-00112444be1e")  # version 1
    assert cls == "uuidv1"
    assert "sandwich" in strat.lower()


def test_classify_base64_encoded():
    # base64("user-1042") = "dXNlci0xMDQy" (>= 8 chars; short strings are ignored
    # on purpose to avoid false positives).
    cls, strat = classify_id("dXNlci0xMDQy")
    assert cls == "encoded"
    assert "decode" in strat.lower()
    assert "user-1042" in strat


def test_classify_hex_hash():
    cls, strat = classify_id("5f4dcc3b5aa765d61d8327deb882cf99")  # md5-length hex
    assert cls == "encoded"
