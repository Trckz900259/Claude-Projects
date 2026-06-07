"""
vulnerable_ssrf.py — a local, intentionally-vulnerable SSRF app for testing.

The server-side fetcher will retrieve any URL you give it. To simulate a cloud
environment WITHOUT real metadata endpoints, the fetcher intercepts the metadata
IPs and a couple of "internal services" and returns canned (fake) responses — so
SSRF to 169.254.169.254 or an internal Actuator is reachable only THROUGH the
SSRF, exactly like a real deployment. Everything else is fetched for real (so
injecting your OOB collaborator URL produces a genuine callback).

Endpoints:
  GET  /fetch?url=        full SSRF  (response body reflected)
  POST /webhook {url}     blind SSRF ("test webhook" — returns only ok)
  GET  /fetch-safe?url=   filtered SSRF (blocks obvious internals; bypassable)
  GET  /                  links page (for discovery)

Run:  python tests/fixtures/vulnerable_ssrf.py 8300
"""

from __future__ import annotations

import ipaddress
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import requests

# Fake cloud + internal responses, reachable only via SSRF.
_FAKE_AWS_ROLE = "ssrf-lab-role"
_FAKE_CREDS = {"AccessKeyId": "ASIAFAKE0000EXAMPLE", "Type": "AWS-HMAC",
               "SecretAccessKey": "FAKEwJalrXUtnFEMI/EXAMPLEKEY",
               "Token": "FAKE-SESSION-TOKEN", "Expiration": "2030-01-01T00:00:00Z"}
_FAKE_HEAPDUMP = (
    "....binary-heap....\x00AWS_SECRET_ACCESS_KEY=AKIAFAKEINTERNALKEY00\x00"
    "spring.datasource.password=Sup3rSecretDbPass\x00jdbc:mysql://db.internal:3306/app\x00"
    "Authorization: Basic YWRtaW46YWRtaW4=\x00....")


def _norm_host(host: str) -> str:
    """Normalise decimal/hex/octal IP hosts to dotted form (filter-bypass aware)."""
    h = host.strip("[]")
    for parse in (lambda x: str(ipaddress.IPv4Address(int(x, 16))) if x.lower().startswith("0x") else None,
                  lambda x: str(ipaddress.IPv4Address(int(x))) if x.isdigit() else None):
        try:
            r = parse(h)
            if r:
                return r
        except Exception:
            pass
    return h


def _server_fetch(url: str):
    """The SSRF sink. Returns (status, body). Mocks metadata/internal services."""
    p = urlparse(url if "://" in url else "http://" + url)
    host = _norm_host(p.hostname or "")
    port = p.port or (443 if p.scheme == "https" else 80)
    path = p.path or "/"

    # --- mock cloud metadata ---
    if host == "169.254.169.254":
        if path.rstrip("/").endswith("security-credentials"):
            return 200, _FAKE_AWS_ROLE
        if _FAKE_AWS_ROLE in path:
            return 200, json.dumps(_FAKE_CREDS)
        if "user-data" in path:
            return 200, "#!/bin/bash\nexport DB_PASS=fake-init-secret\n"
        if "metadata/identity/oauth2/token" in path:  # azure
            return 200, json.dumps({"access_token": "FAKE.AZURE.TOKEN", "token_type": "Bearer"})
        return 200, json.dumps({"meta": "ami-id\niam/\nuser-data\nhostname"})
    if host == "169.254.170.2":  # ECS
        return 200, json.dumps({**_FAKE_CREDS, "RoleArn": "arn:aws:iam::111:role/ecs"})
    if host in ("metadata.google.internal", "169.254.169.254") and "computeMetadata" in path:
        return 200, json.dumps({"access_token": "FAKE.GCP.TOKEN"})

    # --- mock internal services ---
    if host in ("127.0.0.1", "localhost") and port == 9099:
        if "heapdump" in path:
            return 200, _FAKE_HEAPDUMP
        if "/actuator/env" in path:
            return 200, json.dumps({"propertySources": [{"name": "systemEnvironment"}]})
        if "/actuator" in path:
            return 200, json.dumps({"_links": {"heapdump": {}, "env": {}, "gateway": {}}})
        return 200, "internal-service"
    if host in ("127.0.0.1", "localhost") and port == 6379:  # redis via dict/gopher
        return 200, "redis_version:7.0.0\r\nrole:master\r\nconnected_clients:1"

    # --- everything else: a REAL fetch (so OOB collaborators get hit) ---
    try:
        r = requests.get(url, timeout=4, allow_redirects=True)
        return r.status_code, r.text[:2000]
    except Exception as exc:
        return 0, f"fetch error: {exc}"


_BLOCKED = ("127.0.0.1", "localhost", "0.0.0.0", "169.254.", "10.", "192.168.", "172.16.")


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj, ctype="application/json"):
        body = obj if isinstance(obj, str) else json.dumps(obj)
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        q = parse_qs(parsed.query)
        if parsed.path == "/":
            return self._send(200,
                "<html><body><a href='/fetch?url=http://example.com'>fetch</a> "
                "<a href='/fetch-safe?url=http://example.com'>safe</a>"
                "<script>fetch('/webhook',{method:'POST'})</script></body></html>",
                ctype="text/html")
        if parsed.path == "/fetch":
            url = q.get("url", [""])[0]
            if not url:
                return self._send(400, {"error": "url required"})
            status, body = _server_fetch(url)
            return self._send(200, {"fetched": url, "status": status, "body": body[:1500]})
        if parsed.path == "/fetch-safe":
            url = q.get("url", [""])[0]
            host = (urlparse(url).hostname or "").lower()
            if any(b in url.lower() or host.startswith(b) for b in _BLOCKED):
                return self._send(403, {"error": "blocked: internal address"})
            status, body = _server_fetch(url)
            return self._send(200, {"fetched": url, "status": status, "body": body[:1500]})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except Exception:
            body = {}
        if parsed.path == "/webhook":
            url = body.get("url", "")
            if url:
                _server_fetch(url)  # BLIND: fired server-side, response not returned
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8300
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Vulnerable SSRF app on http://127.0.0.1:{port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
