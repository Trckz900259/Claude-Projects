# Bug Bounty Platform

A modular Python framework for **authorized** security testing on bug-bounty
programs (e.g. HackerOne). It runs reconnaissance once, feeds a shared
inventory into pluggable vulnerability modules, verifies findings with a real
headless browser, and produces consultancy-grade reports — all behind a strict,
**enforced-in-code** safety model.

> ⚠️ **Use only on targets you are explicitly authorized to test.** Every target
> must be in the published scope of a program that has invited testing. This
> tool refuses out-of-scope requests by design, but *you* are responsible for
> pointing it only at programs you are permitted to test.

This repository currently contains **Stage 1 (the shared foundation)** plus the
scaffolding for the XSS module and later stages. See the
[build status](#build-status) below.

---

## Why this design is safe

These five controls are **enforced as code**, not just documented:

| # | Control | Where it lives | What it does |
|---|---------|----------------|--------------|
| 1 | **Scope allow-list** | `core/scope.py`, `core/http_engine.py` | A target is touched *only* if it matches an explicit in-scope entry. Out-of-scope = hard refusal at the HTTP layer. Default-deny; deny-list always wins. |
| 2 | **Rate limiting** | `core/ratelimit.py` | Conservative, configurable global + per-host + concurrency limits on every request. |
| 3 | **Identifiable User-Agent** | `core/http_engine.py`, `core/config.py` | A researcher User-Agent (required in config) is stamped on every request. |
| 4 | **Program rules** | `core/config.py`, modules | If `automated_scanning_allowed: false`, modules refuse to run automated scans. |
| 5 | **Minimal-impact proof** | `verify/`, `modules/xss` | Verification uses the least intrusive proof possible (a benign `alert`/marker), never destructive actions. |

The HTTP engine is the **only** sanctioned way to make a request, and the scope
check is the very first thing it does — so the allow-list cannot be bypassed by
any module. There is a unit test that proves an out-of-scope request raises
`OutOfScopeError` *before any network call is attempted*.

---

## Architecture

```
        ┌─────────────┐
        │   /config   │  per-program YAML profile (scope, rules, rate limits, UA)
        └──────┬──────┘
               │ load + validate
        ┌──────▼──────────────────────────────────────────────┐
        │                       /core                          │
        │  config · scope · ratelimit · http_engine · datastore │
        │           logging · tooling · exceptions             │
        └──────┬───────────────────────────────────┬──────────┘
               │ shared HTTP engine                 │ shared SQLite datastore
        ┌──────▼──────┐                      ┌──────▼──────┐
        │   /recon    │ ──writes inventory──▶│   (SQLite)  │
        │ subfinder…  │                      │  one store  │
        └─────────────┘                      └──────┬──────┘
                                                    │ reads inventory / writes findings
        ┌───────────────────────────────────────────▼───────────┐
        │                       /modules                          │
        │   base Module interface  →  /modules/xss (first module) │
        └──────┬─────────────────────────────────────────────────┘
               │ candidates
        ┌──────▼──────┐   ┌──────────┐   ┌─────────────┐
        │  /verify    │   │ /report  │   │ /dashboard  │
        │ Playwright  │   │ md + pdf │   │  Streamlit  │
        └─────────────┘   └──────────┘   └─────────────┘
```

* **Recon runs once** and populates a single shared inventory.
* **Every module** consumes that inventory and writes into one shared datastore.
* **HTTP, scope, rate limiting, datastore, verification, reporting, dashboard**
  are all shared services. Adding a vuln class = adding a module that
  implements the common interface.

Directory layout:

```
core/         http engine, scope+rules enforcement, rate limiter, datastore, config, logging
recon/        subdomain enum, live-host detection, URL harvesting, parameter discovery
modules/      pluggable vuln modules (base interface + /modules/xss)
verify/       Playwright verification + screenshot/video capture
report/       report generator (Markdown + PDF) and the "explain" engine
dashboard/    Streamlit app
orchestrator/ fault-tolerant, queue-based, resumable run engine
config/       per-program profiles
data/         SQLite db, captured PoCs, logs   (git-ignored)
tests/        core tests (scope enforcement especially)
```

---

## Setup

Requires **Python 3.11+**. (Recon/XSS tools also need **Go 1.21+**; verification
needs a browser via Playwright. Those are installed in later stages.)

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install Python dependencies + the `bbp` CLI
pip install -r requirements.txt
pip install -e .

# 3. (later stages) Install the external CLI tools and the browser
bash scripts/install_tools.sh
python -m playwright install chromium

# 4. Check what's installed
bbp doctor
```

---

## Usage (Stage 1 — foundation)

```bash
# Validate a program profile and see a summary of its scope & rules
bbp validate-config config/juice-shop.yml

# Ask whether a target is in scope — WITHOUT making any network request.
# (Great for understanding exactly what is and isn't allowed.)
bbp scope-check config/juice-shop.yml "http://localhost:3000/rest/products?q=1"
bbp scope-check config/juice-shop.yml "https://example.com/"   # -> refused

# See which external tools are installed
bbp doctor
```

## Usage (full pipeline)

```bash
bbp recon   config/myprogram.yml                 # discover surface -> inventory
bbp scan    config/myprogram.yml --module xss    # hunt XSS (verified in a browser)
bbp callbacks config/myprogram.yml               # (optional) listen for blind hits
bbp report  config/myprogram.yml --only-verified # consultancy-grade MD + PDF
bbp dashboard                                    # explore everything visually
```

See **USER_MANUAL.md** for a plain-English walkthrough of every stage, a
glossary, how to read the dashboard, how to reproduce a finding by hand, and
troubleshooting.

### Writing a program profile

Copy `config/example-program.yml` and edit it. The key section is `scope`:

```yaml
scope:
  in_scope:
    - { type: domain,   value: "example.com" }        # apex + all subdomains
    - { type: wildcard, value: "*.api.example.com" }  # subdomains only
    - { type: url,      value: "https://app.example.com/" }  # URL prefix
    - { type: cidr,     value: "192.0.2.0/24" }       # IP-literal hosts
  out_of_scope:
    - { type: domain, value: "blog.example.com" }     # deny-list always wins
```

`http.user_agent` is **required** and `rules.automated_scanning_allowed`
defaults to **false** (safe) — set it `true` only when the program permits
automation.

---

## Safe practice target

Before pointing this at any real program, validate the whole pipeline against a
**local, intentionally-vulnerable** app you own — OWASP Juice Shop:

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
# then it's reachable at http://localhost:3000
```

The included `config/juice-shop.yml` is already scoped to `localhost` only.

---

## Running the tests

```bash
pip install pytest
python -m pytest tests/ -v
```

The most important tests (`tests/test_scope.py`, `tests/test_http_engine.py`)
prove the scope allow-list refuses out-of-scope targets and that no network call
is made for them.

---

## Build status

- [x] **Stage 1 — Foundation:** config/rules engine, scope enforcement, rate
      limiter, HTTP engine, SQLite datastore, logging, CLI, tests. ✅
- [x] **Stage 2 — Recon:** subfinder → httpx → gau + katana → arjun → inventory. ✅
- [x] **Stage 3 — XSS module + verification** (reflected, attribute, DOM, CSP,
      blind/OOB scaffolding; Playwright proof + screenshots). ✅
- [x] **Stage 4 — Reporting + explain engine + USER_MANUAL.md** (Markdown + PDF,
      CVSS v3.1, context-specific remediation, two-audience explanations). ✅
- [x] **Stage 5 — Dashboard** (Streamlit: overview, filterable findings with
      drill-in, recon/coverage, live blind-callback panel, charts). ✅

**Prompt 1 (foundation + XSS module) is complete.** Future prompts add more
modules (SQLi, SSRF, …) by implementing the same `Module` interface in `/modules`.

### Prompt 2 — Broken Access Control / IDOR module ✅

A multi-engine module for the #1 OWASP API risk, on a shared multi-identity
foundation. **Safety: own-accounts-only** (requires ≥2 of *your* accounts; the
"victim" object is always one of yours), **read-only proof** (cross-identity
replay is GET-only; the only writes target your own object), and **fresh/own
state for races** — on top of the inherited scope/rate-limit/UA/rules gates.

- **Foundation:** multi-identity session manager (`core/identity.py`, isolated
  per-request auth + re-login), cookie-stateless HTTP engine, mitmproxy/HAR
  capture (`core/capture.py`), race engine with HTTP/2 single-packet + HTTP/1
  last-byte (`core/race.py`), token harvesting (`core/tokens.py`).
- **Engines** (`modules/accesscontrol/`): stateful replay + a content-aware
  **decision engine** with confidence scoring (IDOR/BOLA, BFLA, unauth, BOPLA),
  a **GraphQL** authz tester, a **JWT** forgery tester, a **race** engine, and a
  **403-bypass** sub-module.

```bash
# 1. Define ≥2 of your own test accounts in a gitignored identities file
#    (config/<prog>.identities.local.yml), then:
bbp identities      config/myprogram.yml          # check the accounts load
bbp capture         config/myprogram.yml --as userA   # browse as each (mitmproxy)
#    or:  bbp import-traffic config/myprogram.yml --har session.har --as userA
bbp harvest-tokens  config/myprogram.yml          # pull auth tokens from traffic
bbp discover        config/myprogram.yml [--openapi spec.yml] [--postman c.json]
bbp scan            config/myprogram.yml --module accesscontrol
bbp report          config/myprogram.yml
```

Validated end-to-end against a bundled local vulnerable API
(`tests/fixtures/vulnerable_api.py`): finds horizontal IDOR (with confidence
scoring + side-by-side PoC), vertical BFLA, BOPLA, JWT forgery (alg:none + weak
secret → admin), a race win, 403 bypasses, and GraphQL BOLA. Validate against
self-hosted OWASP Juice Shop before any real program.

### Prompt 3 — Server-Side Request Forgery (SSRF) module ✅

SSRF's impact ceiling is cloud-account compromise and internal RCE, so the
safety rules are enforced in code: **possession-proof only** (cloud metadata is
read READ-ONLY; credentials are never used/exfiltrated-and-used/pivoted),
**minimal-impact** internal proofs with **auto-cleanup**, **DNS rebinding only
toward authorized targets**, scope on every outbound + callback, and a
per-program `ssrf_testing_allowed` rule the module respects.

- **Shared infra:** `core/oob.py` (multi-protocol OOB engine with unique tokens +
  **source discrimination** — only target-originated callbacks count, link
  scanners are flagged), `core/rebind.py` (DNS rebinding with a scope gate),
  `verify/browser_fetch.py` (custom method/header fetch for IMDSv2-style targets).
- **Engines** (`modules/ssrf/`): URL-input discovery (HUNT params + headers),
  OOB confirmation (full/blind), a filter **bypass generator** (IP encodings,
  parser confusion, allowlist evasion), the full **cloud-metadata matrix**
  (AWS/Azure/GCP/OCI/…), an **internal-service catalog** (Spring Actuator heapdump
  → secret scan, Redis, Docker…), and protocol/file-format payload generators.

```bash
bbp scan config/myprogram.yml --module ssrf            # local collaborator (labs)
bbp scan config/myprogram.yml --module ssrf --interactsh   # real targets (OOB)
```

Validated against a bundled SSRF lab (`tests/fixtures/vulnerable_ssrf.py`): full
SSRF (OOB callback), blind SSRF, cloud-metadata exposure (direct **and** via a
decimal-IP filter bypass, possession-proof only), and internal Spring Actuator
with heapdump secrets scanned. CWE-918. **103 tests pass.**

See `USER_MANUAL.md` (added in Stage 4) for a plain-English walkthrough of every
pipeline stage, a glossary, and troubleshooting.

---

## License

MIT. For authorized security research and education only.
