"""
vulnerable_api.py — a small, intentionally-broken REST API for LOCAL testing.

It deliberately has classic Broken Access Control flaws so we can validate the
access-control module end-to-end against a target we own (Juice Shop needs
Docker; this is the no-Docker stand-in). Accounts are pre-seeded — they are all
"ours".

Accounts (username / password):
  userA / passA   id=1  role=user   (high-value data)
  userB / passB   id=2  role=user
  admin / passAdmin id=99 role=admin

Intentional flaws:
  * IDOR/BOLA   GET /api/users/<id>            — no ownership check
  * nested IDOR GET /api/users/<id>/orders     — no ownership check
  * BFLA        GET /admin/stats               — any logged-in user, no role check
  * BOPLA       POST /api/profile  {role:...}  — mass-assignment of any field
  * Race        POST /api/redeem   {code}      — single-use coupon, not atomic
  * 403 bypass  GET /admin/secret              — 403, but bypassable via header/case
  * JWT         HS256 with weak secret "secret"; ALSO accepts alg:none

Run:  python tests/fixtures/vulnerable_api.py 8100
"""

from __future__ import annotations

import base64
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import jwt  # PyJWT

SECRET = "secret"  # intentionally weak

USERS = {
    "userA": {"id": 1, "password": "passA", "role": "user", "name": "Alice",
              "email": "alice@mine.test", "secret": "A-private-SSN-111"},
    "userB": {"id": 2, "password": "passB", "role": "user", "name": "Bob",
              "email": "bob@mine.test", "secret": "B-private-SSN-222"},
    "admin": {"id": 99, "password": "passAdmin", "role": "admin", "name": "Admin",
              "email": "admin@mine.test", "secret": "ADMIN-master-key"},
}
BY_ID = {u["id"]: {"username": k, **u} for k, u in USERS.items()}
ORDERS = {1: [{"order": "A-1001", "total": 50}], 2: [{"order": "B-2002", "total": 70}],
          99: [{"order": "ADM-9", "total": 0}]}

# Single-use coupon: redeeming should only ever succeed ONCE (race target).
_coupon_lock = threading.Lock()
COUPON = {"WELCOME50": {"used": False, "value": 50}}
_balance = {"value": 0}


def issue_token(user: dict) -> str:
    # sub must be a string per RFC 7519 (PyJWT enforces this on decode).
    return jwt.encode({"sub": str(user["id"]), "role": user["role"], "name": user["name"]},
                      SECRET, algorithm="HS256")


def _b64url(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def parse_token(token: str):
    """INTENTIONALLY WEAK: accepts alg:none, and HS256 with the weak secret."""
    try:
        parts = token.split(".")
        header = json.loads(_b64url(parts[0]))
        if str(header.get("alg", "")).lower() == "none":  # VULN: alg:none accepted
            return json.loads(_b64url(parts[1]))
        return jwt.decode(token, SECRET, algorithms=["HS256"])  # VULN: weak secret
    except Exception:
        return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    # -- helpers --
    def _send(self, code: int, obj, headers=None):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _identity(self):
        """Return the user dict from the Authorization bearer or session cookie."""
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.lower().startswith("bearer ") else ""
        if not token:
            cookie = self.headers.get("Cookie", "")
            for part in cookie.split(";"):
                if part.strip().startswith("session="):
                    token = part.strip()[8:]
        if not token:
            return None
        claims = parse_token(token)
        if not claims:
            return None
        return BY_ID.get(int(claims.get("sub", -1)))

    def _graphql(self, query: str):
        """A tiny, INTENTIONALLY-VULNERABLE GraphQL endpoint (regex-parsed)."""
        import re as _re
        # Introspection is enabled (info disclosure + schema recovery).
        if "__schema" in query or "__type" in query:
            return self._send(200, {"data": {"__schema": {
                "queryType": {"name": "Query"},
                "types": [
                    {"name": "Query", "fields": [
                        {"name": "me", "args": []},
                        {"name": "user", "args": [{"name": "id"}]}]},
                    {"name": "User", "fields": [
                        {"name": "id"}, {"name": "name"}, {"name": "email"},
                        {"name": "secret"}, {"name": "role"}]},
                ]}}})
        # VULN BOLA: user(id: N) returns ANY user's private data, no auth/ownership
        # check. Supports aliases (so batching/aliasing is unrestricted).
        data = {}
        for m in _re.finditer(r"(?:(\w+)\s*:\s*)?user\s*\(\s*id\s*:\s*(\d+)\s*\)", query):
            alias = m.group(1) or "user"
            uid = int(m.group(2))
            u = BY_ID.get(uid)
            data[alias] = _private(u) if u else None
        if data:
            return self._send(200, {"data": data})
        if "me" in query:
            me = self._identity()
            return self._send(200, {"data": {"me": _public(me) if me else None}})
        return self._send(200, {"data": None, "errors": [{"message": "unknown query"}]})

    def _body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            return json.loads(raw or b"{}")
        except Exception:
            return {}

    # -- routing --
    def do_GET(self):
        path = urlparse(self.path).path
        me = self._identity()

        if path == "/api/me":
            if not me:
                return self._send(401, {"error": "auth required"})
            return self._send(200, _public(me))

        if path.startswith("/api/users/") and path.endswith("/orders"):
            uid = _intpart(path, 2)
            if not me:
                return self._send(401, {"error": "auth required"})
            # VULN nested IDOR: no check that uid belongs to `me`.
            return self._send(200, {"userId": uid, "orders": ORDERS.get(uid, [])})

        if path.startswith("/api/users/"):
            uid = _intpart(path, 2)
            if not me:
                return self._send(401, {"error": "auth required"})
            target = BY_ID.get(uid)
            if not target:
                return self._send(404, {"error": "not found"})
            # VULN IDOR/BOLA: returns private data of ANY user id.
            return self._send(200, _private(target))

        if path == "/admin/stats":
            if not me:
                return self._send(401, {"error": "auth required"})
            # VULN BFLA: no role check — any logged-in user reaches admin function.
            return self._send(200, {"users": len(USERS), "revenue": 120,
                                    "note": "admin-only stats (but not enforced)"})

        if path == "/admin/secret":
            # 403 normally, but bypassable: header spoof or path-case.
            spoofed = self.headers.get("X-Forwarded-For") == "127.0.0.1" or \
                self.headers.get("X-Original-URL") or \
                self.headers.get("X-Custom-IP-Authorization") == "127.0.0.1"
            if spoofed:
                return self._send(200, {"secret": "flag{403-bypassed-via-header}"})
            return self._send(403, {"error": "forbidden"})

        if path == "/Admin/secret":  # VULN: case-variation bypass
            return self._send(200, {"secret": "flag{403-bypassed-via-case}"})

        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._body()

        if path == "/graphql":
            return self._graphql(body.get("query", ""))

        if path == "/login":
            user = USERS.get(body.get("username", ""))
            if not user or user["password"] != body.get("password"):
                return self._send(401, {"error": "bad credentials"})
            token = issue_token(user)
            return self._send(200, {"token": token, "id": user["id"], "role": user["role"]},
                              headers={"Set-Cookie": f"session={token}; Path=/"})

        me = self._identity()

        if path == "/api/profile":
            if not me:
                return self._send(401, {"error": "auth required"})
            # VULN BOPLA/mass-assignment: blindly applies every field, incl. role.
            for k, v in body.items():
                BY_ID[me["id"]][k] = v
            return self._send(200, {"updated": _public(BY_ID[me["id"]])})

        if path == "/api/redeem":
            code = body.get("code", "")
            # VULN race: check-then-act without holding the lock across both.
            coupon = COUPON.get(code)
            if not coupon or coupon["used"]:
                return self._send(400, {"error": "invalid or used"})
            # (no lock here on purpose -> TOCTOU window)
            import time
            time.sleep(0.05)
            coupon["used"] = True
            _balance["value"] += coupon["value"]
            return self._send(200, {"redeemed": code, "balance": _balance["value"]})

        return self._send(404, {"error": "not found"})


def _public(u):
    return {"id": u["id"], "name": u["name"], "role": u["role"]}


def _private(u):
    return {"id": u["id"], "name": u["name"], "email": u["email"],
            "role": u["role"], "secret": u["secret"]}


def _intpart(path: str, idx: int) -> int:
    try:
        return int(path.strip("/").split("/")[idx])
    except Exception:
        return -1


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8100
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Vulnerable API on http://127.0.0.1:{port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
