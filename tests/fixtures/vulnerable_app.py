"""
vulnerable_app.py — a TINY, intentionally-vulnerable web app for LOCAL testing.

This exists ONLY so we can validate the platform end-to-end against a target we
own, on localhost, without touching anyone else. It is the spiritual cousin of
OWASP Juice Shop, just small enough to ship in the repo.

Endpoints:
  /                  links page (so the crawler has something to find) + a DOM-XSS sink
  /search?q=         reflects q into the HTML body, UNESCAPED  -> reflected XSS
  /greet?name=       reflects name into an attribute, UNESCAPED -> reflected XSS (attr)
  /comment?text=     reflects text into the body, UNESCAPED     -> reflected XSS
  /safe?q=           reflects q but HTML-ESCAPED                 -> NOT vulnerable (control)
  /dom               JS reads location.hash and writes innerHTML -> DOM XSS

Run:  python tests/fixtures/vulnerable_app.py 8000
"""

from __future__ import annotations

import html
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

INDEX = """<!doctype html>
<html><head><title>Vulnerable Test App</title></head><body>
<h1>Vulnerable Test App</h1>
<ul>
  <li><a href="/search?q=hello">search</a></li>
  <li><a href="/greet?name=world">greet</a></li>
  <li><a href="/comment?text=hi">comment</a></li>
  <li><a href="/safe?q=hello">safe (escaped)</a></li>
  <li><a href="/dom">dom</a></li>
</ul>
</body></html>"""

DOM_PAGE = """<!doctype html>
<html><head><title>DOM sink</title></head><body>
<div id="out">no hash yet</div>
<script>
  // INTENTIONAL DOM XSS: location.hash flows straight into innerHTML.
  var data = decodeURIComponent(location.hash.slice(1));
  document.getElementById('out').innerHTML = data;
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # keep the test output quiet
        pass

    def _send(self, body: str, ctype: str = "text/html; charset=utf-8", headers=None):
        data = body.encode("utf-8", "replace")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        q = parse_qs(parsed.query, keep_blank_values=True)

        def first(name: str) -> str:
            return q.get(name, [""])[0]

        if path == "/":
            # Add a deliberately weak CSP so the CSP analyzer has something to flag.
            self._send(INDEX, headers={"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"})
        elif path == "/search":
            # UNESCAPED reflection in HTML body.
            self._send(f"<html><body><h1>Results for {first('q')}</h1></body></html>")
        elif path == "/greet":
            # UNESCAPED reflection inside an attribute value.
            self._send(f'<html><body><input type="text" value="{first("name")}"></body></html>')
        elif path == "/comment":
            self._send(f"<html><body><p>Comment: {first('text')}</p></body></html>")
        elif path == "/safe":
            # Properly escaped — must NOT be flagged as vulnerable.
            self._send(f"<html><body><h1>Results for {html.escape(first('q'))}</h1></body></html>")
        elif path == "/dom":
            self._send(DOM_PAGE)
        else:
            self._send("<html><body>not found</body></html>")


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Vulnerable test app on http://127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
