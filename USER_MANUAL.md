# User Manual — Bug Bounty Platform

This manual explains, in plain language, what the platform does, how to drive it,
how to read its output, and how to reproduce a finding by hand. It's written for
someone fairly new to Python, the command line, and web security.

> **Golden rule:** only ever point this at a program you are *explicitly
> authorized* to test, within its *published scope*. The platform enforces scope
> in code, but choosing which program to test is on you.

---

## 1. The big picture

The platform works like an assembly line. Each stage hands its results to the
next through one shared database:

```
config  →  recon  →  inventory  →  XSS module  →  verification  →  reports  →  dashboard
(who/    (find the   (what we    (probe for     (prove it's    (write it   (look at
 scope)   surface)    found)      bugs)          real)          up)         it)
```

You run the stages with one command, `bbp`, and a per-program config file.

### The typical workflow

```bash
# 0. (once) set up — see README "Setup"
source .venv/bin/activate

# 1. Sanity-check your program profile and its scope
bbp validate-config config/myprogram.yml
bbp scope-check config/myprogram.yml "https://app.example.com/x?id=1"

# 2. Recon — discover the testable surface and fill the inventory
bbp recon config/myprogram.yml

# 3. Scan for XSS — exhaustively, fault-tolerantly
bbp scan config/myprogram.yml --module xss

# 4. (optional, separate terminal) keep listening for blind callbacks
bbp callbacks config/myprogram.yml

# 5. Generate consultancy-grade reports (Markdown + PDF)
bbp report config/myprogram.yml --only-verified

# 6. Explore everything visually
bbp dashboard
```

---

## 2. What each pipeline stage does (and why)

### Config / rules (`/config`, `core/config.py`)
A single YAML file per program defines the **scope allow-list**, **rate limits**,
your **User-Agent**, whether **automated scanning** is allowed, and your
**interactsh** callback server. Nothing is hardcoded — the platform only knows
about what's in this file. *Why:* one obvious, auditable place that controls
exactly what may be touched and how politely.

### Recon (`/recon`)
Discovers the attack surface and writes it into the inventory:
- **subfinder** — finds subdomains (passive; queries public data, not the target).
- **httpx** — checks which hosts are actually alive over HTTP/S (active).
- **gau** — pulls known URLs from public archives like the Wayback Machine (passive).
- **katana** — crawls live sites to discover URLs and forms (active).
- **arjun** — guesses hidden parameters an endpoint secretly accepts (active).

Everything is **scope-filtered** coming in and going out, stamped with your
User-Agent, and rate-limited. *Why split passive/active?* Passive tools never
send traffic to the target, so they always run; active tools do, so they only run
when the program allows automated scanning.

### Inventory (the shared SQLite database, `data/findings.db`)
One database holds assets/hosts, URLs, parameters, findings, blind callbacks, and
the resumable work queue. Every stage reads and writes here. *Why:* a single
source of truth that the scanner, reporter, and dashboard all share.

### XSS module (`/modules/xss`)
For every parameter and page in the inventory it:
1. **Probes reflection** — injects a unique harmless marker and sees if it comes back.
2. **Analyses context** — works out *where* the marker landed (page body, an
   attribute, inside a script, a URL, or CSS), because the right payload depends on it.
3. **Fires benign payloads** — chosen for that context.
4. **Verifies** — loads the payload in a real headless browser and watches a benign
   `alert()` actually fire. Only then is it "verified".
5. **Analyses DOM XSS** — reads the page's JavaScript for dangerous
   *source → sink* flows (e.g. `location.hash` → `innerHTML`) and confirms them.
6. **Checks CSP** — parses the Content-Security-Policy and flags weaknesses.
7. **Injects blind payloads** — that call back to your interactsh server if they
   fire later somewhere you can't see.

The run is **fault-tolerant** (one failure or one hit never stops it),
**concurrent** (bounded by your rate limit), and **resumable** (`--resume`).

### Verification (`/verify`)
The shared "is it real?" service. It uses Playwright (headless Chromium) and a
**benign proof** — only ever a harmless `alert()` — never anything destructive.
On success it saves a **screenshot** (and optional video). Anything it can't
confirm is kept **separate and marked UNVERIFIED** so you never submit a guess.

### Reporting (`/report`)
For each finding it writes a full report (Markdown + PDF) with: HTTP
request/response, numbered repro steps, the exact payload and context, the visual
PoC, root-cause, **CVSS v3.1** score + business impact, **context-specific
remediation**, and **CWE-79 / OWASP** references. It also writes ONE consolidated
report. Each report includes a **"Learning notes"** box written for you — delete
it before submitting.

### Dashboard (`/dashboard`)
A local web app to browse programs, runs, findings (filter/drill-in), recon
coverage, charts, and a live blind-callback panel.

---

## 3. Glossary

**Scope / allow-list** — the explicit list of things you're allowed to test.
Anything not on it is refused.

**In-scope rule types** — `domain` (a host and all its subdomains), `wildcard`
(`*.x.com`, subdomains only), `url` (a specific URL prefix), `cidr` (an IP range),
`regex` (advanced host match).

**Reflected XSS** — your input is echoed straight back in the *immediate*
response and runs. Needs the victim to open a crafted link.

**Stored XSS** — your input is *saved* and shown to other users later. Worse: the
victim just has to view the page.

**DOM XSS** — happens entirely in the browser: client-side JS takes attacker data
(a *source*) into a dangerous *sink* that turns text into live HTML/JS. The server
never sees the payload.

**Blind XSS** — stored XSS that fires somewhere you can't see (e.g. an admin
panel). You prove it with an *out-of-band callback* to a server you control.

**Source → Sink** — a *source* is attacker-controllable input (e.g.
`location.hash`); a *sink* is a dangerous API that executes/renders it (e.g.
`innerHTML`, `eval`).

**Context** — *where* your input lands in the response (HTML body, attribute, JS
string, URL, CSS). It dictates which payload can break out and run.

**Marker** — a unique harmless token we inject to find and locate a reflection.

**interactsh / OOB** — an out-of-band server that records DNS/HTTP callbacks, used
to catch blind/stored XSS that fires later.

**CVSS v3.1** — a standard 0–10 severity score. Reflected XSS is typically 6.1
(Medium).

**CWE-79** — the formal identifier for "Cross-site Scripting".

**Verified vs unverified** — *verified* = the platform watched the payload execute
in a browser. *Unverified* = it looked promising but execution wasn't confirmed —
reproduce by hand before reporting.

---

## 4. How to read the dashboard

Run `bbp dashboard` (it opens in your browser). Panels:

- **Overview** — your programs, recent runs, and live progress (pending vs done).
- **Findings** — a table you can filter by **severity**, **type**, and **status**.
  Click a finding to see its URL, parameter, payload, context, full HTTP
  request/response, and the PoC screenshot.
- **Recon / coverage** — how many URLs and parameters were discovered, and how
  much of the surface has been tested.
- **Blind callbacks** — a live panel that lists out-of-band hits as they arrive.
- **Charts** — severity distribution and a timeline of findings.

Tip: start by filtering **status = verified** to see what's submission-ready.

---

## 5. How to manually reproduce a finding

Reproducing by hand is essential before you submit — it confirms the report and
helps you write it confidently.

**Reflected / DOM XSS:**
1. Open the report (e.g. `data/reports/finding-6-reflected.md`).
2. Copy the **Full request URL** from the "Reproduction steps".
3. Paste it into a browser. You should see the benign `alert()` pop, matching the
   PoC screenshot. (For DOM XSS the payload is after the `#` in the URL.)
4. View source / DevTools to see exactly where your input landed (this matches the
   "Injection context").

**Stored / blind XSS:**
1. Submit the payload into the named input.
2. Visit the page that displays it (for blind, wait — it may be an admin view).
3. For blind, watch `bbp callbacks` (or the dashboard panel) for the callback with
   the report's correlation id.

**CSP weakness:**
1. `curl -I <url>` (or DevTools → Network → Headers) and read the
   `Content-Security-Policy` header.
2. Compare it to the weaknesses listed in the report.

---

## 6. Practising safely first

Before any real program, validate the whole pipeline on a target you own:

```bash
# OWASP Juice Shop (needs Docker)
docker run --rm -p 3000:3000 bkimminich/juice-shop
# then use config/juice-shop.yml (already scoped to localhost)

# Or the tiny bundled test app (no Docker needed)
python tests/fixtures/vulnerable_app.py 8000
bbp recon config/juice-shop.yml --seed-url http://127.0.0.1:8000/ --no-subfinder --no-gau
bbp scan  config/juice-shop.yml --module xss --no-blind
bbp report config/juice-shop.yml
```

---

## 7. Troubleshooting

**`bbp: command not found`** — activate the venv: `source .venv/bin/activate`
(and you ran `pip install -e .`).

**`bbp doctor` shows tools missing** — install them: `bash scripts/install_tools.sh`,
and make sure your Go bin dir is on `PATH`. arjun is a pip package; the Go tools
install to `$(go env GOPATH)/bin`.

**Config error about `user_agent`** — `http.user_agent` is required. Put a real,
identifiable researcher UA with contact info.

**"Automated scanning is DISABLED"** — the XSS module refuses to run because
`rules.automated_scanning_allowed` is `false`. Set it `true` *only* if the program
permits automation.

**Everything is "out of scope"** — check your `scope.in_scope` rules with
`bbp scope-check`. Remember: `domain` covers subdomains, `wildcard` does not cover
the apex, and `url` needs a full URL to match.

**No findings after a scan** — did recon populate the inventory? Check with the
dashboard or re-run `bbp recon`. For local apps on odd ports, use `--seed-url`.

**Findings are UNVERIFIED** — Playwright/Chromium may be missing. Install with
`pip install playwright && playwright install chromium`. Unverified findings are
real candidates — just reproduce them by hand before submitting.

**PDF reports didn't generate** — PDF rendering uses headless Chromium; if it's
unavailable the Markdown reports are still written. Re-run with the browser
installed, or use the `.md` files.

**A scan was interrupted** — re-run the same command with `--resume`; completed
candidates are skipped.

**Blind callbacks never arrive** — confirm `interactsh-client` is installed and
your `callback.interactsh_server` is reachable, and keep `bbp callbacks` running
(callbacks can take hours).

**It's going too fast / too slow** — tune `rate_limit` in the config
(`requests_per_second`, `per_host_rps`, `max_concurrency`).

---

## 8. Access Control / IDOR module (Prompt 2)

This module finds **broken access control** — the #1 OWASP API risk — using
**two or more accounts you control**. It never touches a real third party's data.

### Safety model (enforced in code)
- **Own-accounts-only:** it refuses to run without ≥2 of *your* authenticated
  accounts; the "victim" object in every test is always one of *your* accounts.
- **Read-only proof:** cross-identity replay is GET-only; the only writes target
  your own object (to test mass assignment). It won't modify others' data.
- **Fresh/own state for races:** race tests use your own single-use codes.
- Plus the inherited scope allow-list, rate limiting, User-Agent, and the
  `automated_scanning_allowed` gate.

### Workflow
1. Create a **gitignored identities file** (`config/<prog>.identities.local.yml`)
   with ≥2 of your own accounts. Each has `auth` (cookies/headers) or a `relogin`
   flow, and `owned_ids` (the object ids that account owns). Reference it from the
   program profile via `identities_file:`.
2. `bbp identities <config>` — confirm the accounts load (and ≥2 authenticated).
3. **Capture** your authenticated browsing: `bbp capture <config> --as userA`
   (mitmproxy) or `bbp import-traffic <config> --har file.har --as userA`.
4. `bbp harvest-tokens <config>` — optionally pull tokens to fill profiles.
5. `bbp discover <config>` — catalogue endpoints (recon + spec + traffic) and
   classify id parameters.
6. `bbp scan <config> --module accesscontrol` — run all the engines.
7. `bbp report <config>` and `bbp dashboard` — review the side-by-side PoCs.

### Glossary (access control)
- **IDOR / BOLA** (horizontal) — reading/altering *another user's* object by
  changing an id (broken **object**-level authorization).
- **BFLA** (vertical) — a low-privilege user reaching an **admin function**
  (broken **function**-level authorization).
- **BOPLA / mass assignment** — setting fields you shouldn't (e.g. `role=admin`)
  because the server binds your whole request body onto the object.
- **Confidence score / tier** — the decision engine compares response *content*
  across identities (not just status codes) and scores how likely a violation is
  (`high-confidence` / `needs-review`). Nothing is auto-confirmed — you verify the
  side-by-side PoC.
- **Side-by-side PoC** — the same object retrieved as its owner, then as the
  attacker identity, returning the same private data.
- **JWT forgery** — making a valid-looking token the server wrongly accepts
  (e.g. `alg:none`, or a guessed weak secret) to become another user.
- **Race condition / limit-overrun** — firing many requests at once to slip past
  a one-time check (e.g. redeem a single-use coupon many times).
- **403 bypass** — a "forbidden" endpoint reached anyway via a header or path
  trick because authorization was only enforced at the proxy/path layer.

### Access-control troubleshooting
- *"requires at least 2 of YOUR OWN accounts"* — add a second authenticated
  identity to your identities file.
- *No findings* — did you capture/import traffic and run `bbp discover` first?
  The engines need captured requests + a discovered endpoint catalogue.
- *Race never wins* — race tests run sequentially in a quiet phase; if the action
  truly serialises server-side, that's a *good* result (no finding).
- *mitmproxy capture shows nothing* — install mitmproxy's CA cert in your browser
  (visit `http://mitm.it` while the proxy is set), and confirm the host is in
  scope (capture is scope-filtered too).

---

## 9. SSRF module (Prompt 3)

This module finds **Server-Side Request Forgery** — getting the *server* to make
requests for you. Its impact ceiling is cloud-account compromise and internal
RCE, so the proofs are deliberately minimal.

### Safety model (enforced in code)
- **Possession-proof only:** cloud-metadata credentials are read READ-ONLY to
  show exposure — never used, exfiltrated-and-used, or pivoted with.
- **Minimal-impact internal proofs:** read a benign marker (Actuator `_links`,
  Redis `INFO`); any created state (e.g. a gateway route) is auto-cleaned.
- **Source discrimination:** only **target-originated** callbacks count; Slack/
  Outlook/etc. link-scanner unfurls are flagged as false positives.
- **DNS rebinding only toward authorized targets**, scope on every outbound +
  callback, and a per-program `ssrf_testing_allowed` rule (set it `false` to
  forbid SSRF/metadata testing — the module refuses).

### How OOB confirmation works
The platform injects a URL pointing at a **collaborator** it controls (with a
unique token) into each input. If the server fetches it, the callback confirms
SSRF — even when you can't see the response (*blind* SSRF). Two backends: a
**local collaborator** (for localhost labs, default) and **interactsh**
(`--interactsh`, for real targets — public DNS/HTTP/TCP).

### Workflow
```bash
# discover inputs first (recon/capture), review, then test:
bbp discover config/myprogram.yml
bbp scan     config/myprogram.yml --module ssrf --interactsh
bbp report   config/myprogram.yml ; bbp dashboard   # OOB panel shows callbacks
```

### Glossary (SSRF)
- **SSRF** — making the server fetch an attacker-chosen URL.
- **Full vs blind** — *full* reflects the fetched response back to you; *blind* is
  confirmed only by the out-of-band callback.
- **Cloud metadata** — the internal `169.254.169.254` endpoint holding the
  machine's cloud credentials; reading it can mean full account compromise.
- **Filter bypass** — encoding the internal IP (decimal/hex/octal/IPv6) or
  confusing the URL parser so a blocklist doesn't recognise it.
- **DNS rebinding** — flip a hostname's IP between a safe one (for the filter's
  check) and the internal target (for the fetch) — a TOCTOU.
- **Source discrimination** — distinguishing a callback from the *target* (real
  SSRF) vs a third-party link scanner (false positive).

### SSRF troubleshooting
- *No callbacks on a real target* — use `--interactsh` (a localhost collaborator
  can't be reached by a remote target), and check the program allows SSRF testing.
- *"forbidden by program rules"* — `rules.ssrf_testing_allowed: false` is set.
- *DNS-only callback, no HTTP* — server-side resolution is confirmed but an egress
  filter likely blocks outbound HTTP (still a finding, lower confidence).
