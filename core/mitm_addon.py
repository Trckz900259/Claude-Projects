"""
mitm_addon.py — the mitmproxy addon that captures YOUR authenticated browsing.

mitmproxy loads this file as an addon. While it runs, point your browser (or app)
at the proxy and browse the target AS each of your test accounts. Every in-scope
request/response pair is written to the datastore's captured_traffic table, which
becomes the raw material for the replay+compare engine.

Crucially, capture is ALSO scope-filtered: even your own browsing is only stored
if the host is on the program's allow-list, so nothing out-of-scope is recorded.

It reads three things from the environment (set by `bbp capture`):
  BBP_CONFIG       path to the program profile (for scope + program identity)
  BBP_DB           datastore path
  BBP_CAPTURE_AS   (optional) the identity name you're browsing as right now
"""

from __future__ import annotations

import os

from core.config import load_program_config
from core.datastore import Datastore
from core.scope import host_of


class BBPCapture:
    def __init__(self) -> None:
        cfg_path = os.environ.get("BBP_CONFIG", "")
        db_path = os.environ.get("BBP_DB", "data/findings.db")
        self.capture_as = os.environ.get("BBP_CAPTURE_AS", "")
        self.config = load_program_config(cfg_path)
        self.ds = Datastore(db_path)
        self.pid = self.ds.upsert_program(
            self.config.name, self.config.platform, self.config.handle, cfg_path
        )
        self.count = 0
        print(f"[bbp] capturing IN-SCOPE traffic for program '{self.config.name}' "
              f"(identity: {self.capture_as or 'unspecified'})")

    def response(self, flow) -> None:  # mitmproxy calls this on each response
        url = flow.request.pretty_url
        # Only store traffic that is on the program's allow-list.
        if not self.config.scope.check(url).allowed:
            return
        req = flow.request
        resp = flow.response
        try:
            req_body = req.get_text(strict=False) or ""
        except Exception:
            req_body = ""
        try:
            resp_body = resp.get_text(strict=False) or ""
        except Exception:
            resp_body = ""

        self.ds.add_captured(
            self.pid, method=req.method, url=url, host=host_of(url),
            req_headers=dict(req.headers), req_body=req_body[:200000],
            status_code=resp.status_code, resp_headers=dict(resp.headers),
            resp_body=resp_body[:200000], captured_as=self.capture_as, source="mitmproxy",
        )
        self.count += 1
        if self.count % 10 == 0:
            print(f"[bbp] captured {self.count} in-scope request(s)")


addons = [BBPCapture()]
