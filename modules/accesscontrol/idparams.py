"""
idparams.py — find object-reference parameters and classify how to handle each.

Two jobs:

  1. IDENTIFY likely object-reference params (id, userId, orderId, uuid, ...)
     wherever they appear — path, query, JSON/form body, headers, cookies — and
     catalogue EVERY location.

  2. CLASSIFY each id to pick a SAFE enumeration strategy:
       sequential  -> controlled, rate-limited, READ-ONLY sweep bracketed around
                      your own account ids (never blind enumeration of strangers).
       encoded     -> decode first (base64 / predictable hash), then test the
                      underlying reference.
       uuidv1      -> time-based: 'sandwich' approach (predict values between two
                      of your own observations); we flag it and point at the tool.
       uuidv4      -> random: DO NOT brute force. Source valid foreign ids from
                      leak sources and from your own second account.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import uuid
from urllib.parse import parse_qsl, urlparse

from core.context import PlatformContext

log = logging.getLogger("ac.idparams")

_NUM = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX_HASH = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
_B64ISH = re.compile(r"^[A-Za-z0-9+/=_-]{8,}$")


def is_id_name(name: str) -> bool:
    n = (name or "").lower()
    if n in {"id", "uid", "uuid", "guid", "ref", "key", "user", "account", "token"}:
        return True
    return bool(re.search(r"(^|[_\-.])(id|uid|uuid|guid|ref|key)$", n)) or n.endswith("id")


def _try_b64(v: str):
    try:
        dec = base64.b64decode(v + "=" * (-len(v) % 4), validate=False)
        s = dec.decode("utf-8")
        if s.isprintable() and len(s) >= 1:
            return s
    except Exception:
        pass
    return None


def classify_id(value: str) -> tuple[str, str]:
    """Return (id_class, safe-strategy text) for a reference value."""
    v = str(value)
    if _NUM.match(v):
        return "sequential", (
            "Controlled, rate-limited, READ-ONLY sweep bracketed around your own "
            "account ids — never blind enumeration of strangers' data.")
    if _UUID.match(v):
        try:
            ver = uuid.UUID(v).version
        except ValueError:
            ver = None
        if ver == 1:
            return "uuidv1", (
                "Time-based UUIDv1: 'sandwich' approach — capture values just "
                "before/after your own action and predict the in-between value "
                "(classic on password-reset links). Use a UUIDv1 sandwich tool.")
        if ver == 4:
            return "uuidv4", (
                "Random UUIDv4: DO NOT brute force. Source valid foreign ids only "
                "from leak sources (Wayback/URLScan/OTX/CORS/verbose errors/OAuth "
                "org ids) and from your own second account.")
        return f"uuidv{ver}", "UUID: assess predictability of this version's fields."
    if _HEX_HASH.match(v):
        return "encoded", (
            "Hash-like id: if derived from a predictable input (email, sequential "
            "id), precompute candidate hashes and test those.")
    if _B64ISH.match(v):
        dec = _try_b64(v)
        if dec is not None:
            inner_class, _ = classify_id(dec) if dec != v else ("unknown", "")
            return "encoded", (
                f"Base64-encoded reference (decodes to {dec!r}). Decode first, then "
                f"treat the underlying value as '{inner_class}'.")
    return "unknown", "Unclassified reference — inspect manually before testing."


def _walk_json(obj, prefix=""):
    """Yield (dotted_key, value) for scalar leaves in a JSON object/array."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_json(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _walk_json(v, f"{prefix}[{i}]")
    else:
        yield prefix, obj


def _value_is_idlike(v) -> bool:
    s = str(v)
    return bool(_NUM.match(s) or _UUID.match(s) or _HEX_HASH.match(s))


class IdParamIdentifier:
    def __init__(self, ctx: PlatformContext) -> None:
        self.ctx = ctx
        self.ds = ctx.datastore
        self.pid = ctx.program_id
        self._seen: set[tuple] = set()

    def _record(self, name, location, endpoint, value):
        key = (name, location, endpoint)
        if key in self._seen:
            return
        self._seen.add(key)
        id_class, strategy = classify_id(value) if value else ("unknown", "")
        self.ds.add_id_param(self.pid, name=name, location=location, endpoint=endpoint,
                             example_value=str(value)[:120], id_class=id_class, strategy=strategy)

    def run(self) -> int:
        before = len(self._seen)
        self._from_endpoints()
        self._from_traffic()
        self._from_recon_params()
        n = len(self._seen) - before
        log.info("identified %d id-parameter location(s)", n)
        return n

    def _from_endpoints(self):
        for row in self.ds.get_endpoints(self.pid):
            tmpl = row["path_template"]
            parts = tmpl.split("/")
            for i, seg in enumerate(parts):
                if seg in ("{id}", "{uuid}", "{token}"):
                    prev = parts[i - 1] if i > 0 else "id"
                    # example value: an int for {id}, a uuid-shape note otherwise
                    example = "1" if seg == "{id}" else (
                        "00000000-0000-4000-8000-000000000000" if seg == "{uuid}" else "")
                    self._record(name=f"{prev}.{seg.strip('{}')}", location="path",
                                 endpoint=f"{row['method']} {tmpl}", value=example)

    def _from_traffic(self):
        for row in self.ds.get_captured(self.pid):
            url = row["url"]
            endpoint = f"{row['method']} {urlparse(url).path}"
            # query
            for name, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
                if is_id_name(name) or _value_is_idlike(value):
                    self._record(name, "query", endpoint, value)
            # body (JSON)
            body = row["req_body"] or ""
            if body.strip().startswith("{") or body.strip().startswith("["):
                try:
                    for key, value in _walk_json(json.loads(body)):
                        leaf = key.split(".")[-1].split("[")[0]
                        if is_id_name(leaf) or _value_is_idlike(value):
                            self._record(key, "body", endpoint, value)
                except Exception:
                    pass
            # headers + cookies
            try:
                req_headers = json.loads(row["req_headers"] or "{}")
            except Exception:
                req_headers = {}
            for hname, hval in req_headers.items():
                if hname.lower() == "cookie":
                    for part in str(hval).split(";"):
                        if "=" in part:
                            cn, cv = part.strip().split("=", 1)
                            if is_id_name(cn) or _value_is_idlike(cv):
                                self._record(cn, "cookie", endpoint, cv)
                elif is_id_name(hname):
                    self._record(hname, "header", endpoint, hval)

    def _from_recon_params(self):
        for row in self.ds.get_parameters(self.pid):
            name, value = row["name"], row["example_value"]
            if is_id_name(name) or _value_is_idlike(value or ""):
                self._record(name, "query", endpoint=row["url"], value=value or "")
