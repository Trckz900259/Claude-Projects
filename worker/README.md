# bb-worker

The **ephemeral scan-worker** container: a disposable image with the full set of
security tools the platform's modules wrap, **every version explicitly pinned**
(and the base image pinned by digest) so our validation baseline is reproducible.

**Not in this image** (these are persistent **control-plane** services, run
separately): the interactsh callback **server**, and the DNS-rebinding service
(Singularity / rbndr). The interactsh **client** *is* included.

## Pinned toolset

| Category | Tool | Pin | Install |
|---|---|---|---|
| Recon | subfinder | v2.14.0 | go |
| Recon | httpx | v1.9.0 | go |
| Recon | katana | v1.6.1 | go |
| Recon | gau | v2.2.4 | go |
| Recon | waybackurls | v0.1.0 | go |
| Recon | gf (+ Gf-Patterns) | `dcd4c361` / patterns `f686f06a` | go / git |
| Recon | kxss | `acb2dc76` | go |
| Recon | ffuf | v2.1.0 | go |
| Recon | nuclei | v3.8.0 | go |
| XSS | dalfox | v2.13.0 | go |
| Access control | jwt_tool | v2.3.0 | git (venv) |
| Access control | nomore403 | v1.4.0 | go |
| GraphQL | clairvoyance | 2.5.5 | pip |
| GraphQL | graphql-cop | 1.16 | git (venv) |
| SSRF | SSRFmap | `69103b27` | git (venv) |
| SSRF | Gopherus | `90a2fd57` | git — **Python 2 only** (see notes) |
| SSRF | ipfuscator | `6d24eb03` | git (venv) |
| SSRF/OOB | interactsh-client | v1.3.1 | go |
| Python lib | fuzz-lightyear | 0.0.11 | pip |
| Python | arjun | 2.2.7 | pip |
| Python | sqlmap | 1.10.6 | pip |
| Toolchain | Go | **1.25.11** | tarball + checksum |
| Base image | debian:bookworm-slim | `@sha256:0104b334…` (multi-arch index) | — |

## Build & verify (Windows + Docker Desktop / WSL 2)

```powershell
docker build -t bb-worker:test ./worker      # first build ~5–10 min (compiles Go tools)
docker run --rm bb-worker:test               # entrypoint prints EVERY tool's version
```

`verify.sh` checks each tool the right way — `-version` / `--version` / a
`version` subcommand / presence-only for stdin tools (gf, kxss, waybackurls) /
package metadata (arjun, fuzz-lightyear) — and exits `0` on full pass. The tail
of a good run looks like:

```
  RESULT: ALL TOOLS PRESENT AND RUNNABLE  [PASS]
```

## How the pinning works

- **Go tools** → `go install …@<exact tag/commit>`. `GOTOOLCHAIN=local` forces
  the build to use exactly **Go 1.25.11** and FAIL LOUDLY if a tool ever needs
  newer (so we bump the Go pin on purpose, never silently).
- **PyPI tools** → `pip install pkg==<version>` (into system Python; Debian's
  PEP-668 lock is handled with `--break-system-packages`).
- **Git tools** (jwt_tool, SSRFmap, graphql-cop, ipfuscator) → cloned at an exact
  tag/commit, each in its **own venv** with a tiny PATH wrapper, because they ship
  as scripts with *conflicting* dependency pins and would otherwise clobber each
  other.
- **Base image** → pinned by **multi-arch manifest digest** (not the moving
  `bookworm-slim` tag).

## Re-pinning the base image (do this DELIBERATELY, on a cadence)

The base is currently frozen to:

```
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb
# Go toolchain pinned: 1.25.11
```

A pinned digest is great for reproducibility — but it also **freezes the base
image's security updates**. Debian re-publishes `bookworm-slim` with patched
packages regularly; our pin keeps using the old layers until we move it. So
re-pinning to a fresh, patched digest is a **deliberate maintenance step**, not
something to silently automate. Do it on a **cadence (e.g. monthly)**, and
**whenever you bump tool versions**, so the security baseline and the tool
baseline move together and intentionally.

To re-pin, resolve the **current multi-arch index digest** and replace the `FROM`:

```bash
docker buildx imagetools inspect debian:bookworm-slim --format '{{.Manifest.Digest}}'
# -> sha256:<new digest>   (verify MediaType is .index.v1+json = multi-arch)
```

Then rebuild and run `verify.sh` again to confirm every tool still passes before
adopting the new baseline.

## Troubleshooting notes (things that came up building this)

1. **Go version (the big one).** httpx, nuclei, and **katana** need **Go ≥
   1.25.7** (from their `go.mod`). We pinned **Go 1.25.11** and set
   `GOTOOLCHAIN=local`; with an older Go, `go install` would *silently
   auto-download* a newer, unpinned toolchain — defeating the pinning. None of
   the added tools require newer than 1.25.11, so the Go pin held.
2. **`nomore403` reports `dev`.** Installed via `go install`, its version isn't
   stamped in (that happens via release-time ldflags), so `nomore403 --version`
   prints `dev`. The *source pin* is still `v1.4.0` — it just doesn't self-report.
3. **Gopherus is Python 2 only (EOL).** We clone it pinned for reference but do
   **not** add a Python 2 runtime (keeps the worker lean), and the platform's
   SSRF module generates gopher payloads natively anyway. Its wrapper prints a
   clear message; if you truly need the standalone tool, install `python2`.
4. **PEP-668 / conflicting deps.** System Python uses `--break-system-packages`;
   the git tools each get an isolated venv so their conflicting requirement pins
   (e.g. different `requests` versions) don't fight.
5. **Why it wasn't fully built in the cloud dev env.** That sandbox blocks the
   Docker Hub registry CDN, so base-image *layers* can't be pulled there (the
   `FROM` digest still *resolves*). Every pinned tool was instead installed and
   run natively with the exact `go install …@ver` / `pip install …==ver` / git
   clone commands the Dockerfile uses — the `[PASS]` is real. Your local Docker
   Desktop has no such block and builds the whole image.
