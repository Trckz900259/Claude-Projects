# ============================================================================
#  bb-worker — scan-worker image (FULL toolset)
# ----------------------------------------------------------------------------
#  Every version is explicitly PINNED so our validation baseline stays stable.
#  To bump a tool, change ONE value in the "pinned versions" block below.
#
#  Build:   docker build -t bb-worker:test ./worker
#  Verify:  docker run --rm bb-worker:test
#
#  NOT in this image (they are persistent CONTROL-PLANE services, not part of the
#  disposable worker): the interactsh callback SERVER, and the DNS-rebinding
#  service (Singularity / rbndr). The interactsh CLIENT *is* included.
# ============================================================================

# --- Base image: PINNED BY MULTI-ARCH MANIFEST DIGEST -----------------------
# debian:bookworm-slim, frozen to an exact index digest for a reproducible
# baseline (Debian 12 -> Python 3.11). Re-pinning to a fresher patched digest is
# a DELIBERATE step on a cadence — see worker/README.md ("Re-pinning the base").
FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb

# --- Pinned versions (the single place to bump) -----------------------------
# Go is pinned to 1.25.11 because the newest tools (httpx, nuclei, katana) need
# Go >= 1.25.7. GOTOOLCHAIN=local (below) stops Go from silently using a newer,
# unpinned toolchain — so if a future tool needs newer, the build FAILS LOUDLY.
ENV GO_VERSION=1.25.11 \
    \
    SUBFINDER_VERSION=v2.14.0 \
    HTTPX_VERSION=v1.9.0 \
    NUCLEI_VERSION=v3.8.0 \
    DALFOX_VERSION=v2.13.0 \
    KATANA_VERSION=v1.6.1 \
    GAU_VERSION=v2.2.4 \
    WAYBACKURLS_VERSION=v0.1.0 \
    GF_VERSION=v0.0.0-20200618134122-dcd4c361f9f5 \
    KXSS_VERSION=acb2dc76e84077d2e529f6c488269c32c5e2b07a \
    FFUF_VERSION=v2.1.0 \
    NOMORE403_VERSION=v1.4.0 \
    INTERACTSH_VERSION=v1.3.1 \
    \
    ARJUN_VERSION=2.2.7 \
    SQLMAP_VERSION=1.10.6 \
    CLAIRVOYANCE_VERSION=2.5.5 \
    FUZZ_LIGHTYEAR_VERSION=0.0.11 \
    \
    JWT_TOOL_VERSION=v2.3.0 \
    GRAPHQL_COP_VERSION=1.16 \
    SSRFMAP_COMMIT=69103b27f5898d9707630dc572798df63727b90f \
    GOPHERUS_COMMIT=90a2fd5799342bbd493966ed95ed2489068ea568 \
    IPFUSCATOR_COMMIT=6d24eb03e63d0ba687c3978d607aa57c42824008 \
    GF_PATTERNS_COMMIT=f686f06ae647726578920084c894100d702496cc

ENV DEBIAN_FRONTEND=noninteractive \
    GOPATH=/root/go \
    GOBIN=/usr/local/bin \
    PATH=/usr/local/go/bin:/usr/local/bin:/root/go/bin:$PATH \
    GOTOOLCHAIN=local

# --- 1) OS packages: Python 3.11 (+pip/venv), git, curl, CA certs -----------
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv \
        git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# --- 2) Go toolchain (download official tarball + verify checksum) ----------
RUN curl -fsSL -o /tmp/go.tgz   "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
    && curl -fsSL -o /tmp/go.sha "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz.sha256" \
    && echo "$(cat /tmp/go.sha)  /tmp/go.tgz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tgz && rm -f /tmp/go.tgz /tmp/go.sha \
    && go version

# --- 3) Go-based tools, version-pinned (GOBIN puts them on PATH) -------------
# Recon/discovery + XSS + access-control + SSRF helpers + the interactsh CLIENT.
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION} \
    && go install github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION} \
    && go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION} \
    && go install github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION} \
    && go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@${INTERACTSH_VERSION} \
    && go install github.com/hahwul/dalfox/v2@${DALFOX_VERSION} \
    && go install github.com/lc/gau/v2/cmd/gau@${GAU_VERSION} \
    && go install github.com/tomnomnom/waybackurls@${WAYBACKURLS_VERSION} \
    && go install github.com/tomnomnom/gf@${GF_VERSION} \
    && go install github.com/Emoe/kxss@${KXSS_VERSION} \
    && go install github.com/ffuf/ffuf/v2@${FFUF_VERSION} \
    && go install github.com/devploit/nomore403@${NOMORE403_VERSION} \
    && rm -rf /root/go/pkg /root/.cache/go-build

# --- 3b) gf patterns (the rules `gf` greps with) ----------------------------
RUN git clone https://github.com/1ndianl33t/Gf-Patterns /root/.gf \
    && git -C /root/.gf checkout -q ${GF_PATTERNS_COMMIT}

# --- 4) Python tools from PyPI (system Python; PEP-668 -> break-system) ------
RUN pip3 install --no-cache-dir --break-system-packages \
        arjun==${ARJUN_VERSION} \
        sqlmap==${SQLMAP_VERSION} \
        clairvoyance==${CLAIRVOYANCE_VERSION} \
        fuzz-lightyear==${FUZZ_LIGHTYEAR_VERSION}

# --- 5) Python tools from git (each ISOLATED in its own venv + a wrapper) ----
# These ship as scripts (not PyPI packages) and have CONFLICTING dependency
# pins, so we give each its own venv to keep them from clobbering each other.
# A tiny wrapper on PATH runs each with its own interpreter.
RUN set -eux; \
    install_git_tool() { \
      name="$1"; repo="$2"; ref="$3"; script="$4"; \
      git clone -q "https://github.com/${repo}" "/opt/${name}"; \
      git -C "/opt/${name}" checkout -q "${ref}"; \
      python3 -m venv "/opt/${name}/venv"; \
      if [ -f "/opt/${name}/requirements.txt" ]; then \
        "/opt/${name}/venv/bin/pip" install --no-cache-dir -r "/opt/${name}/requirements.txt"; \
      fi; \
      printf '#!/bin/sh\nexec /opt/%s/venv/bin/python /opt/%s/%s "$@"\n' "${name}" "${name}" "${script}" \
        > "/usr/local/bin/${name}"; \
      chmod +x "/usr/local/bin/${name}"; \
    }; \
    install_git_tool jwt_tool    ticarpi/jwt_tool   "${JWT_TOOL_VERSION}"    jwt_tool.py; \
    install_git_tool ssrfmap     swisskyrepo/SSRFmap "${SSRFMAP_COMMIT}"     ssrfmap.py; \
    install_git_tool graphql-cop dolevf/graphql-cop  "${GRAPHQL_COP_VERSION}" graphql-cop.py; \
    install_git_tool ipfuscator  vysecurity/IPFuscator "${IPFUSCATOR_COMMIT}" ipfuscator.py

# --- 5b) Gopherus: cloned (pinned) but Python 2 ONLY (EOL) ------------------
# We do NOT add a Python 2 runtime (keeps the worker lean). The platform's SSRF
# module GENERATES gopher payloads natively, so this is reference/manual-use only.
# The wrapper runs it if you add python2 yourself, else prints a clear message.
RUN git clone -q https://github.com/tarunkant/Gopherus /opt/gopherus \
    && git -C /opt/gopherus checkout -q ${GOPHERUS_COMMIT} \
    && printf '#!/bin/sh\nif command -v python2 >/dev/null 2>&1; then exec python2 /opt/gopherus/gopherus.py "$@"; else echo "gopherus is Python 2 only; install python2 to use it (the platform generates gopher payloads natively)"; exit 0; fi\n' \
        > /usr/local/bin/gopherus \
    && chmod +x /usr/local/bin/gopherus

# --- 6) Verification entrypoint ---------------------------------------------
COPY verify.sh /usr/local/bin/verify.sh
RUN chmod +x /usr/local/bin/verify.sh
ENTRYPOINT ["/usr/local/bin/verify.sh"]
