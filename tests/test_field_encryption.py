"""
Proof of field-level encryption at rest for the high-sensitivity fields ONLY.

The platform encrypts JUST the crown-jewel fields — captured request/response
headers+bodies, finding request/response blocks (which carry harvested
tokens/heapdump secrets), and identity auth material — and leaves lower-
sensitivity metadata (urls, titles, severities, …) in plaintext so the dashboard
and reporter can still filter and group on it.

Each test proves both halves of the contract:
  * CIPHERTEXT AT REST — the secret bytes are absent from the .db file on disk.
  * PLAINTEXT ON READ  — the datastore's read methods transparently decrypt.

And, to prove it is NOT a blanket pass, that the low-sensitivity fields remain
readable as plaintext in the raw file.
"""

from __future__ import annotations

import sqlite3

from core.datastore import Datastore, Finding
from core.governance import FieldCipher, SecretsStore, get_data_cipher


# Distinctive secret markers we can grep for in the raw database bytes.
REQ_SECRET = "REQ-MARKER-1a2b3c-secret"
RESP_SECRET = "AKIAZ7HEAPDUMPLEAK99 secret-in-response"     # heapdump-style leak
COOKIE_SECRET = "Cookie: session=SUPERSECRETSESSION-xyz789"
BODY_SECRET = "password=HUNTER2-in-body"
RESP_BODY_SECRET = "RESP-BODY-MARKER-deadbeef"
AUTH_SECRET = "bearer eyJSECRETJWTpayload.sig(214)"


def _new_store(tmp_path):
    cipher = FieldCipher(FieldCipher.generate_key())
    return Datastore(db_path=tmp_path / "enc.db", cipher=cipher), cipher


def _raw_bytes(path) -> bytes:
    # Read the main db file AND its WAL sidecar (rows may still be in the WAL).
    data = b""
    for suffix in ("", "-wal", "-shm"):
        p = path.with_name(path.name + suffix) if suffix else path
        if p.exists():
            data += p.read_bytes()
    return data


# ---------------------------------------------------------------------------
# Findings: request/response carry harvested secrets -> encrypted at rest.
# ---------------------------------------------------------------------------
def test_finding_request_response_encrypted_at_rest_plaintext_on_read(tmp_path):
    store, _ = _new_store(tmp_path)
    pid = store.upsert_program("enc", "local", "enc", "x")
    fid = store.record_finding(pid, Finding(
        type="ssrf", subtype="internal-service", severity="critical",
        url="https://app.example.com/fetch", parameter="u",
        title="Internal service reachable via SSRF",   # low-sensitivity metadata
        request=REQ_SECRET, response=RESP_SECRET,
    ))
    store.close()

    raw = _raw_bytes((tmp_path / "enc.db"))
    # CIPHERTEXT AT REST: the harvested secrets are not in the file.
    assert REQ_SECRET.encode() not in raw
    assert RESP_SECRET.encode() not in raw
    # NOT a blanket pass: low-sensitivity metadata stays plaintext (greppable).
    assert b"app.example.com" in raw
    assert b"Internal service reachable via SSRF" in raw

    # PLAINTEXT ON READ: both the list and single-finding read paths decrypt.
    store2 = Datastore(db_path=tmp_path / "enc.db", cipher=_reopen_cipher(store))
    got = store2.get_finding(fid)
    assert got["request"] == REQ_SECRET
    assert got["response"] == RESP_SECRET
    assert store2.get_findings(pid)[0]["response"] == RESP_SECRET
    store2.close()


def test_finding_instances_also_encrypted_at_rest(tmp_path):
    """The per-instance copy of request/response must be encrypted too."""
    store, _ = _new_store(tmp_path)
    pid = store.upsert_program("enc", "local", "enc", "x")
    store.record_finding(pid, Finding(type="ssrf", url="https://h/x", parameter="u",
                                      request=REQ_SECRET, response=RESP_SECRET))
    store.close()
    raw = _raw_bytes((tmp_path / "enc.db"))
    assert REQ_SECRET.encode() not in raw
    assert RESP_SECRET.encode() not in raw
    # Prove the data really is in finding_instances (as ciphertext, not absent).
    con = sqlite3.connect(tmp_path / "enc.db")
    stored = con.execute("SELECT request, response FROM finding_instances").fetchone()
    con.close()
    assert stored[0] and stored[0] != REQ_SECRET      # present but encrypted
    assert stored[1] and stored[1] != RESP_SECRET


# ---------------------------------------------------------------------------
# Captured traffic: headers (auth) + bodies -> encrypted at rest.
# ---------------------------------------------------------------------------
def test_captured_traffic_headers_and_bodies_encrypted(tmp_path):
    store, _ = _new_store(tmp_path)
    pid = store.upsert_program("enc", "local", "enc", "x")
    store.add_captured(
        pid, "POST", "https://app.example.com/api/redeem", host="app.example.com",
        req_headers={"Cookie": "session=SUPERSECRETSESSION-xyz789"},
        req_body=BODY_SECRET, status_code=200,
        resp_headers={"Set-Cookie": "session=SUPERSECRETSESSION-xyz789"},
        resp_body=RESP_BODY_SECRET, captured_as="userA",
    )
    store.close()

    raw = _raw_bytes((tmp_path / "enc.db"))
    assert b"SUPERSECRETSESSION-xyz789" not in raw   # auth material in headers
    assert BODY_SECRET.encode() not in raw
    assert RESP_BODY_SECRET.encode() not in raw
    # Low-sensitivity routing metadata stays plaintext.
    assert b"app.example.com" in raw

    store2 = Datastore(db_path=tmp_path / "enc.db", cipher=_reopen_cipher(store))
    row = store2.get_captured(pid)[0]
    assert "SUPERSECRETSESSION-xyz789" in row["req_headers"]
    assert "SUPERSECRETSESSION-xyz789" in row["resp_headers"]
    assert row["req_body"] == BODY_SECRET
    assert row["resp_body"] == RESP_BODY_SECRET
    store2.close()


# ---------------------------------------------------------------------------
# Identity auth material -> encrypted at rest.
# ---------------------------------------------------------------------------
def test_identity_auth_summary_encrypted(tmp_path):
    store, _ = _new_store(tmp_path)
    pid = store.upsert_program("enc", "local", "enc", "x")
    store.upsert_identity(pid, "userA", role="high_priv", auth_type="bearer",
                          auth_summary=AUTH_SECRET, description="my own test account")
    store.close()

    raw = _raw_bytes((tmp_path / "enc.db"))
    assert AUTH_SECRET.encode() not in raw
    # Non-secret identity metadata stays plaintext.
    assert b"userA" in raw
    assert b"high_priv" in raw

    store2 = Datastore(db_path=tmp_path / "enc.db", cipher=_reopen_cipher(store))
    idn = store2.get_identities(pid)[0]
    assert idn["auth_summary"] == AUTH_SECRET
    assert idn["auth_type"] == "bearer"        # untouched low-sensitivity field
    store2.close()


# ---------------------------------------------------------------------------
# Key provenance: the key comes from the SecretsStore, never committed.
# ---------------------------------------------------------------------------
def test_key_resolves_from_secrets_store_env(monkeypatch, tmp_path):
    key = FieldCipher.generate_key().decode()
    monkeypatch.setenv("BBP_SECRET_DATA_KEY", key)
    cipher = get_data_cipher(SecretsStore(), key_path=str(tmp_path / ".data_key"))
    # Key came from the env secret -> NO key file was written to disk.
    assert not (tmp_path / ".data_key").exists()
    token = cipher.encrypt("hello")
    assert FieldCipher.from_key_b64(key).decrypt(token) == "hello"


def test_local_key_file_is_created_0600_and_gitignored(tmp_path):
    # With no secret set, a fresh key file is minted with owner-only perms.
    import os
    import stat

    monkey_dir = tmp_path / "data"
    cipher = get_data_cipher(SecretsStore(secrets_path=tmp_path / "nope.yml"),
                             key_path=str(monkey_dir / ".data_key"))
    keyfile = monkey_dir / ".data_key"
    assert keyfile.exists()
    mode = stat.S_IMODE(os.stat(keyfile).st_mode)
    assert mode == 0o600, f"key file perms should be 0600, got {oct(mode)}"
    # And it round-trips.
    token = cipher.encrypt("secret")
    assert cipher.decrypt(token) == "secret"


def test_no_cipher_means_plaintext_passthrough(tmp_path):
    """Without a cipher (e.g. legacy/raw stores) nothing is encrypted — and
    reads still work, so enabling encryption later is non-breaking."""
    store = Datastore(db_path=tmp_path / "plain.db")  # no cipher
    pid = store.upsert_program("p", "local", "p", "x")
    fid = store.record_finding(pid, Finding(type="xss", url="https://h/x",
                                            parameter="q", request=REQ_SECRET))
    assert store.get_finding(fid)["request"] == REQ_SECRET
    store.close()
    raw = _raw_bytes((tmp_path / "plain.db"))
    assert REQ_SECRET.encode() in raw  # genuinely plaintext when no cipher


# ---------------------------------------------------------------------------
# helper: recover the in-memory cipher from a store so a re-opened store can
# decrypt what the first one wrote.
# ---------------------------------------------------------------------------
def _reopen_cipher(store):
    return store.cipher
