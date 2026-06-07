"""
explain.py — ONE explanation engine, TWO audiences.

The same finding is explained for:

  * "learner"  — plain English, written for you. What kind of bug this is, how
                 the platform discovered it, how it was proven, and why it
                 matters. Teaching tone.
  * "client"   — the professional, technical root-cause narrative that goes into
                 the report for the program.

Keeping both in one place means they never drift apart.
"""

from __future__ import annotations

import json
from typing import Any

# Plain-English definitions used in learner explanations.
_TYPE_PLAIN = {
    "reflected": (
        "Reflected XSS means the website takes something from your request (here, "
        "a URL parameter) and echoes it straight back into the page WITHOUT making "
        "it safe first. If the echoed text contains HTML/JavaScript, the browser "
        "runs it. It's 'reflected' because the malicious input bounces straight "
        "back in the immediate response."
    ),
    "stored": (
        "Stored XSS means the malicious input is SAVED by the application (e.g. in "
        "a comment or profile) and then shown to other users later. It's more "
        "dangerous than reflected because victims don't need to click a crafted "
        "link — they just view the page."
    ),
    "dom": (
        "DOM-based XSS happens entirely in the browser: client-side JavaScript "
        "takes attacker-controllable data (a 'source', e.g. the part of the URL "
        "after #) and feeds it into a dangerous 'sink' (e.g. innerHTML) that turns "
        "text into live HTML. The server never even sees the payload."
    ),
    "blind": (
        "Blind XSS is stored XSS that fires somewhere you can't see — like an admin "
        "dashboard. You can't observe it directly, so you inject a payload that "
        "'phones home' to a server you control; when it eventually runs, you get a "
        "callback proving it executed."
    ),
    "csp": (
        "A Content-Security-Policy (CSP) is a browser security feature that limits "
        "what scripts a page may run. A weak or missing CSP doesn't create XSS by "
        "itself, but it removes a safety net that would otherwise blunt an attack."
    ),
    # --- access control ---
    "horizontal": (
        "Horizontal access control (IDOR/BOLA) means one user can read or change "
        "ANOTHER user's data just by changing an id in the request — the server "
        "forgot to check that you actually own that object."
    ),
    "graphql": (
        "GraphQL BOLA is IDOR through a GraphQL resolver: you ask for another "
        "user's object by id and the resolver hands it over without checking you're "
        "allowed."
    ),
    "vertical": (
        "Vertical access control (BFLA) means a low-privilege user can reach an "
        "admin-only function because the server never checks your role."
    ),
    "unauthenticated": (
        "Unauthenticated access means a protected resource is reachable with no "
        "login at all."
    ),
    "object_property": (
        "BOPLA / mass assignment means you can set fields you shouldn't (like "
        "role=admin) because the server blindly applies whatever fields you send."
    ),
    "jwt": (
        "A JWT is a signed login token. These weaknesses let you FORGE one — e.g. "
        "strip the signature (alg:none) or guess a weak signing secret — and become "
        "any user, including an admin."
    ),
    "race": (
        "A race condition (limit-overrun) means firing many requests at the exact "
        "same moment slips them all past a one-time check before it updates — e.g. "
        "redeeming a single-use coupon many times."
    ),
    "403bypass": (
        "A 403 bypass means an endpoint says 'forbidden', but a small trick (a "
        "spoofed header or a path tweak) gets you in anyway — the block was only "
        "skin-deep, enforced at the proxy/path layer instead of the app."
    ),
    # --- SSRF ---
    "ssrf": (
        "SSRF (Server-Side Request Forgery) means you can make the SERVER fetch a "
        "URL of your choosing. The server is usually trusted inside the network, so "
        "you can reach things you normally can't — internal services, or the cloud "
        "metadata endpoint that holds the machine's credentials."
    ),
    "blind-ssrf": (
        "Blind SSRF is SSRF where you DON'T see the fetched response. You prove it "
        "by making the server call a listener you control and watching the callback "
        "arrive — even if the response never comes back to you."
    ),
    "cloud-metadata": (
        "Cloud-metadata SSRF reaches the special internal address (169.254.169.254) "
        "that hands out the machine's cloud credentials. Reading it can mean full "
        "cloud-account compromise — so we only PROVE we can read it (possession "
        "proof) and never use the credentials."
    ),
    "internal-service": (
        "This SSRF reaches an INTERNAL service (e.g. a Spring Boot Actuator, Redis, "
        "or Docker API) that isn't meant to be exposed. We read a harmless marker to "
        "prove reachability; a heapdump can leak passwords and keys."
    ),
}

_AC_SUBTYPES = {"horizontal", "graphql", "vertical", "unauthenticated",
                "object_property", "jwt", "race", "403bypass"}
_SSRF_SUBTYPES = {"ssrf", "blind-ssrf", "cloud-metadata", "internal-service"}

_SSRF_HOW_FOUND = (
    "The platform injected a URL pointing at a collaborator server it controls "
    "(with a unique token) into the input, and the server fetched it — the callback "
    "(source-discriminated to rule out link scanners) confirms SSRF. For cloud/"
    "internal reach, it then asked the server to fetch the metadata/internal URL and "
    "captured the READ-ONLY response as proof."
)

_HOW_FOUND = {
    "reflected": (
        "1) Recon harvested this URL and its parameter into the inventory. "
        "2) The XSS module injected a unique harmless marker into the parameter and "
        "saw it come back in the response. 3) It analysed exactly WHERE the marker "
        "landed to pick a matching payload. 4) It loaded a benign alert() payload in "
        "a real headless browser and watched the alert actually fire — that's the proof."
    ),
    "dom": (
        "1) The module fetched the page's JavaScript. 2) It spotted attacker-"
        "controllable data flowing into a dangerous sink. 3) It loaded the page in a "
        "headless browser with a benign payload in the URL fragment and confirmed the "
        "alert fired."
    ),
    "blind": (
        "The module injected a payload containing a unique address on our out-of-band "
        "(interactsh) server. If/when it executes in some hidden view, our listener "
        "records the callback — even hours later."
    ),
    "csp": (
        "While analysing the page the module parsed the Content-Security-Policy "
        "header and checked it against the well-known weaknesses."
    ),
}


def _evidence(finding: Any) -> dict:
    raw = finding["evidence"] if "evidence" in finding.keys() else finding.get("evidence")  # type: ignore
    if isinstance(raw, dict):
        return raw
    try:
        return json.loads(raw) if raw else {}
    except Exception:
        return {}


def _get(finding: Any, key: str, default: str = "") -> str:
    try:
        val = finding[key]
    except Exception:
        val = finding.get(key, default) if hasattr(finding, "get") else default
    return val if val is not None else default


def explain_finding(finding: Any, audience: str = "client") -> str:
    """Return a Markdown explanation of a finding for the given audience."""
    subtype = _get(finding, "subtype") or "reflected"
    context = _get(finding, "context")
    param = _get(finding, "parameter")
    url = _get(finding, "url")

    if audience == "learner":
        return _learner(subtype, context, param, url)
    return _client(subtype, context, param, url, _evidence(finding))


_AC_HOW_FOUND = (
    "Using two accounts I CONTROL, the platform had my high-priv account read its "
    "own object (the baseline), then had my second account (or anonymous) request "
    "the SAME object. The decision engine compared the responses after normalising "
    "noise — if the attacker identity saw the owner's private data, it's flagged "
    "with a confidence score. No stranger's data is ever touched."
)


def _learner(subtype: str, context: str, param: str, url: str) -> str:
    parts = []
    parts.append(f"**What this is (in plain English):** {_TYPE_PLAIN.get(subtype, _TYPE_PLAIN['reflected'])}")
    is_ac = subtype in _AC_SUBTYPES
    is_ssrf = subtype in _SSRF_SUBTYPES
    if subtype in ("reflected", "stored") and context:
        parts.append(
            f"\n**Where it landed:** your input ended up in the *{context}* part of the "
            f"page. That matters because the fix (and the exploit) is different for each "
            f"place — text in the page body, inside an attribute, inside a script, etc."
        )
    how = (_SSRF_HOW_FOUND if is_ssrf else
           _AC_HOW_FOUND if is_ac else _HOW_FOUND.get(subtype, _HOW_FOUND["reflected"]))
    parts.append(f"\n**How the platform found it:** {how}")
    if is_ssrf:
        parts.append(
            "\n**Why it matters:** SSRF's impact ceiling is full cloud-account "
            "compromise (stealing the machine's credentials from the metadata service) "
            "or reaching internal systems for remote code execution. Even a blind "
            "callback proves the server can be steered to attacker-chosen destinations."
        )
    elif is_ac:
        parts.append(
            "\n**Why it matters:** broken access control lets one user reach another "
            "user's data or admin-only actions. It's the #1 web/API risk because the "
            "data is real and the blast radius scales with how many records are reachable."
        )
    else:
        parts.append(
            "\n**Why it matters:** if an attacker can run JavaScript in another user's "
            "session, they can do things AS that user — steal session cookies, perform "
            "actions on their behalf, capture what they type, or pivot deeper. That's why "
            "even a 'just an alert box' proof is taken seriously: the alert proves arbitrary "
            "code ran."
        )
    if param:
        parts.append(f"\n**The exact spot:** `{param}` on `{url}`.")
    return "\n".join(parts)


_AC_ROOT_CAUSE = {
    "horizontal": "The server does not perform an object-level ownership check, so an "
        "authenticated user can retrieve another user's object by supplying its id (IDOR/BOLA).",
    "graphql": "A GraphQL resolver returns another user's object by id with no per-resolver "
        "object-level authorization (BOLA).",
    "vertical": "A privileged function lacks a server-side role/permission check, so a "
        "lower-privilege account can invoke it (BFLA).",
    "unauthenticated": "A protected resource is served without requiring authentication.",
    "object_property": "The endpoint binds request fields directly onto the object, so "
        "unexpected privileged fields (e.g. role) are accepted (BOPLA / mass assignment).",
    "jwt": "The JWT implementation fails to verify tokens correctly (e.g. accepts alg:none "
        "or a weak/guessable secret), allowing forged tokens for arbitrary identities.",
    "race": "A check-then-act on a limited/single-use action is not atomic, so concurrent "
        "requests all pass the check before state updates (TOCTOU).",
    "403bypass": "Authorization is enforced at the proxy/path layer rather than the "
        "application, so path/header tricks reach the protected resource.",
}


_SSRF_ROOT_CAUSE = {
    "ssrf": "The application fetches a user-supplied URL server-side without an "
        "allow-list, so an attacker steers the server's outbound request to internal "
        "or attacker-chosen destinations (SSRF).",
    "blind-ssrf": "A user-supplied URL is fetched server-side (no response returned), "
        "confirmed by a target-originated out-of-band callback.",
    "cloud-metadata": "SSRF reaches the cloud instance-metadata endpoint, exposing the "
        "instance's IAM credentials. (Captured read-only as possession proof; the "
        "credentials were NOT used or exfiltrated-and-used.)",
    "internal-service": "SSRF reaches an internal, unauthenticated service "
        "(e.g. Spring Actuator/Redis/Docker) that should not be reachable from the "
        "application's request path.",
}


def _client(subtype: str, context: str, param: str, url: str, evidence: dict) -> str:
    if subtype in _SSRF_ROOT_CAUSE:
        parts = [f"**Root cause:** {_SSRF_ROOT_CAUSE[subtype]}"]
        if evidence.get("bypass"):
            parts.append(f"\nA filter was bypassed using: {evidence['bypass']}.")
        if evidence.get("secrets_seen"):
            parts.append(f"\nThe reachable response leaked: {', '.join(evidence['secrets_seen'])}.")
        if evidence.get("scanner_excluded"):
            parts.append(f"\n{evidence['scanner_excluded']} third-party link-scanner "
                         f"callback(s) were excluded as false positives (source discrimination).")
        parts.append(
            "\n**Attack scenario:** An attacker uses the server as a proxy into the "
            "internal network and cloud control plane.")
        parts.append(
            "\n**Business impact:** Ranges from internal reconnaissance to full cloud-"
            "account compromise (metadata credentials) and internal RCE.")
        return "\n".join(parts)

    if subtype in _AC_ROOT_CAUSE:
        conf = evidence.get("confidence")
        parts = [f"**Root cause:** {_AC_ROOT_CAUSE[subtype]}"]
        if conf is not None:
            parts.append(f"\nDecision-engine confidence: {conf} (tier: {evidence.get('tier','?')}; "
                         f"content similarity {evidence.get('similarity','?')}). This is surfaced for "
                         f"human review + side-by-side verification, not auto-confirmed.")
        parts.append(
            "\n**Attack scenario:** An attacker authenticated as a normal (or no) account "
            "accesses data or functions belonging to other users / higher privilege levels.")
        parts.append(
            "\n**Business impact:** Scales with data sensitivity and the number of records "
            "reachable — from per-user data exposure to full account takeover and admin "
            "compromise. (This finding used only my own test accounts.)")
        return "\n".join(parts)

    parts = []
    if subtype == "dom":
        src = evidence.get("source", "a client-side source")
        sink = evidence.get("sink", "a dangerous sink")
        parts.append(
            f"**Root cause:** Client-side JavaScript routes attacker-controllable data "
            f"from `{src}` into the `{sink}` sink without sanitisation, allowing arbitrary "
            f"markup/script execution in the page's origin (DOM-based XSS)."
        )
    elif subtype == "csp":
        parts.append(
            "**Root cause:** The page's Content-Security-Policy does not adequately "
            "constrain script execution, weakening defence-in-depth against XSS."
        )
    else:
        parts.append(
            f"**Root cause:** The application reflects the `{param}` parameter into the "
            f"response in the *{context or 'HTML'}* context without applying correct, "
            f"context-aware output encoding, so injected markup is parsed and executed by "
            f"the browser ({subtype} Cross-Site Scripting)."
        )
    parts.append(
        "\n**Attack scenario:** An attacker crafts a request (or stored payload) that "
        "executes JavaScript in a victim's authenticated session. This enables session/"
        "credential theft, unauthorized actions performed as the victim, UI redressing, "
        "and phishing from a trusted origin."
    )
    parts.append(
        "\n**Business impact:** Account takeover and data exposure for affected users, "
        "reputational harm, and — where administrative users are targeted — a foothold "
        "for broader compromise."
    )
    return "\n".join(parts)
