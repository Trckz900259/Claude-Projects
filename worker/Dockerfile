# ============================================================================
#  bb-worker — minimal scan-worker image (STARTER toolset)
# ----------------------------------------------------------------------------
#  Every version is explicitly PINNED so our future validation baseline stays
#  stable. To bump a tool, change ONE value in the "pinned versions" block below.
#
#  Build:   docker build -t bb-worker:test ./worker
#  Verify:  docker run --rm bb-worker:test
# ============================================================================

# --- Base image -------------------------------------------------------------
# Debian 12 "bookworm", slim. Bookworm ships Python 3.11, which is exactly what
# we want. For a FULLY reproducible baseline you can pin by digest instead of the
# moving tag (see worker/README.md): debian:bookworm-slim@sha256:<digest>
FROM debian:bookworm-slim

# --- Pinned versions (the single place to bump) -----------------------------
# Go-based tools are pinned to exact git tags; Python tools to exact PyPI
# versions; the Go toolchain itself is pinned too.
# NOTE: Go is pinned to 1.25.11 because httpx/nuclei need Go >= 1.25.7 and
# dalfox needs >= 1.25.5 (from their go.mod). Pinning Go too low makes the build
# silently auto-download an UNPINNED newer toolchain — see GOTOOLCHAIN=local below.
ENV GO_VERSION=1.25.11 \
    SUBFINDER_VERSION=v2.14.0 \
    HTTPX_VERSION=v1.9.0 \
    NUCLEI_VERSION=v3.8.0 \
    DALFOX_VERSION=v2.13.0 \
    ARJUN_VERSION=2.2.7 \
    SQLMAP_VERSION=1.10.6

# Make apt non-interactive, and put Go + Go-installed binaries on PATH.
# GOBIN=/usr/local/bin means `go install` drops each tool straight onto PATH.
ENV DEBIAN_FRONTEND=noninteractive \
    GOPATH=/root/go \
    GOBIN=/usr/local/bin \
    PATH=/usr/local/go/bin:/usr/local/bin:/root/go/bin:$PATH \
    GOTOOLCHAIN=local
# GOTOOLCHAIN=local forces `go install` to use ONLY the Go we pinned above. If a
# tool ever needs a newer Go than we pinned, the build FAILS LOUDLY (instead of
# quietly downloading an unpinned toolchain) — telling us to bump GO_VERSION.

# --- 1) OS packages: Python 3.11 (+pip), git, curl, CA certs ---------------
# `--no-install-recommends` + cleaning the apt lists keeps the image small.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        git \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- 2) Go toolchain (download the OFFICIAL tarball + verify its checksum) ---
# We pin the Go VERSION and verify the download against Google's published
# SHA-256 (fetched next to the tarball). For strict supply-chain pinning you can
# hardcode the hash here instead of fetching it.
RUN curl -fsSL -o /tmp/go.tgz   "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    && curl -fsSL -o /tmp/go.sha "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz.sha256" \
    && echo "$(cat /tmp/go.sha)  /tmp/go.tgz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tgz \
    && rm -f /tmp/go.tgz /tmp/go.sha \
    && go version

# --- 3) Go-based security tools, version-pinned -----------------------------
# Each `@vX.Y.Z` pins the exact tag. GOBIN puts the binary on PATH.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} \
    && go install github.com/hahwul/dalfox/v2@${DALFOX_VERSION} \
    && rm -rf /root/go/pkg /root/.cache/go-build   # drop the Go build cache to slim the image

# --- 4) Python-based security tools, version-pinned -------------------------
# Debian "bookworm" marks the system Python as "externally managed" (PEP 668),
# so plain `pip install` is blocked. In a single-purpose container it's safe to
# install straight into it with --break-system-packages. (Alternative: a venv;
# see worker/README.md.)
RUN pip3 install --no-cache-dir --break-system-packages \
        arjun==${ARJUN_VERSION} \
        sqlmap==${SQLMAP_VERSION}

# --- 5) Verification entrypoint ---------------------------------------------
# `docker run --rm bb-worker:test` runs this and prints every tool's version.
COPY verify.sh /usr/local/bin/verify.sh
RUN chmod +x /usr/local/bin/verify.sh

ENTRYPOINT ["/usr/local/bin/verify.sh"]
