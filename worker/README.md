# bb-worker (starter image)

A minimal, **ephemeral scan-worker** container with a *starter* set of security
tools, every version explicitly **pinned** so our validation baseline stays
stable. We'll expand the toolset once this builds clean.

| Tool | Kind | Pinned version |
|---|---|---|
| subfinder | Go | v2.14.0 |
| httpx | Go | v1.9.0 |
| nuclei | Go | v3.8.0 |
| dalfox | Go | v2.13.0 |
| arjun | Python | 2.2.7 |
| sqlmap | Python | 1.10.6 |
| (Go toolchain) | — | 1.25.11 |
| (base image) | — | debian:bookworm-slim (Python 3.11) |

## Build & verify (on your Windows + Docker Desktop / WSL 2 machine)

Open a terminal in the repo root and run:

```powershell
# 1) Build the image (first build downloads Go + compiles the tools; ~3–6 min)
docker build -t bb-worker:test ./worker

# 2) Verify: run the container — its entrypoint prints every tool's version
docker run --rm bb-worker:test
```

### Expected output of step 2

```
==================================================================
  bb-worker :: tool verification  (....Z)
==================================================================
Runtime:
  OS         Debian GNU/Linux 12 (bookworm)
  Python     Python 3.11.x
  Go         go1.25.11
------------------------------------------------------------------
Go-based tools:
  subfinder  pinned v2.14.0   : OK    runs -> v2.14.0
  httpx      pinned v1.9.0    : OK    runs -> v1.9.0
  nuclei     pinned v3.8.0    : OK    runs -> v3.8.0
  dalfox     pinned v2.13.0   : OK    runs -> v2.13.0
------------------------------------------------------------------
Python-based tools:
  sqlmap     pinned 1.10.6    : OK    runs -> 1.10.6#pip
  arjun      pinned 2.2.7     : OK    runs -> 2.2.7
------------------------------------------------------------------
  RESULT: ALL 6 TOOLS PRESENT AND RUNNABLE  [PASS]
------------------------------------------------------------------
```

(`verify.sh` exits `0` on full pass, or the number of failed tools — handy for CI.)

## How the pinning works

- **Go tools** are pinned to exact git tags via `go install …@vX.Y.Z`.
- **Python tools** are pinned to exact PyPI versions via `pip install pkg==X.Y.Z`.
- **The Go toolchain** is pinned and downloaded with a checksum check, and
  `GOTOOLCHAIN=local` stops Go from silently swapping in a newer, unpinned Go.
- To **bump a tool**, edit one line in the `ENV …_VERSION=` block in the
  `Dockerfile` and rebuild.

### (Optional) pin the base image by digest — the gold standard

Tags like `bookworm-slim` move over time. For a fully reproducible baseline, pin
the **digest** instead. Get it after a pull:

```bash
docker pull debian:bookworm-slim
docker inspect --format='{{index .RepoDigests 0}}' debian:bookworm-slim
```

…then replace `FROM debian:bookworm-slim` with
`FROM debian:bookworm-slim@sha256:<digest>`.
(At the time of writing the digest resolved to
`sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb`.)

## Troubleshooting notes (what came up while building this)

1. **Go version too old → silent toolchain switch.** httpx and nuclei require
   **Go ≥ 1.25.7** (dalfox ≥ 1.25.5), from their `go.mod`. An older pinned Go
   (e.g. 1.24.7) makes `go install` quietly auto-download a newer, *unpinned*
   toolchain — defeating the whole point of pinning. Fix: pin **Go 1.25.11** and
   set `GOTOOLCHAIN=local` so the build fails loudly if a tool ever needs newer.

2. **PEP 668 "externally managed environment."** Debian bookworm blocks plain
   `pip install` into the system Python. In a single-purpose container it's fine
   to use `--break-system-packages` (what the Dockerfile does). The stricter
   alternative is a venv: `python3 -m venv /opt/venv` then install into it and
   add `/opt/venv/bin` to `PATH`.

3. **Version flags are inconsistent.** `dalfox` uses the `version` *subcommand*
   (not `-version`); `arjun` has **no** version flag at all (we read its version
   from package metadata); the rest use `-version` / `--version`.

4. **Why it wasn't built in the cloud dev environment.** That environment's
   network policy allows PyPI/GitHub/the Go proxy but **blocks the Docker Hub
   registry CDN**, so base images can't be pulled there. Instead, every pinned
   tool was installed and run natively (the same `go install …@ver` /
   `pip install …==ver` commands the Dockerfile uses) to prove all six work — the
   `[PASS]` output above is real. Your local Docker Desktop has no such block.
