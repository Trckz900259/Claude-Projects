#!/usr/bin/env bash
# ============================================================================
#  install_tools.sh — install the external CLI tools the platform wraps.
# ----------------------------------------------------------------------------
#  Safe to run more than once. It skips anything already installed. Requires Go
#  (for the Go tools) and pip (for arjun). Go tool binaries land in
#  $(go env GOPATH)/bin — make sure that's on your PATH.
# ============================================================================
set -u

GOBIN_DIR="$(go env GOPATH 2>/dev/null)/bin"
echo "Go tools will install to: ${GOBIN_DIR}"
echo "Make sure this is on your PATH (add to ~/.bashrc):"
echo "    export PATH=\"\$PATH:${GOBIN_DIR}\""
echo

have() { command -v "$1" >/dev/null 2>&1; }

go_install() {
  local bin="$1" pkg="$2"
  if have "$bin"; then
    echo "  ✓ $bin already installed"
  else
    echo "  → installing $bin ..."
    GO111MODULE=on go install "$pkg" && echo "    done." || echo "    FAILED: $bin"
  fi
}

echo "== Recon tools =="
go_install subfinder "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
go_install httpx     "github.com/projectdiscovery/httpx/cmd/httpx@latest"
go_install gau       "github.com/lc/gau/v2/cmd/gau@latest"
go_install katana    "github.com/projectdiscovery/katana/cmd/katana@latest"

echo "== XSS tools =="
go_install gf        "github.com/tomnomnom/gf@latest"
go_install kxss      "github.com/Emoe/kxss@latest"
go_install dalfox    "github.com/hahwul/dalfox/v2@latest"

echo "== Out-of-band callback tool =="
go_install interactsh-client "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest"

echo "== gf XSS patterns =="
if [ -d "$HOME/.gf" ]; then
  echo "  ✓ ~/.gf already exists"
else
  echo "  → cloning gf-patterns to ~/.gf ..."
  git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns "$HOME/.gf" \
    && echo "    done." || echo "    FAILED to clone gf-patterns"
fi

echo "== Python: arjun (parameter discovery) =="
if have arjun; then echo "  ✓ arjun already installed"; else pip install --quiet arjun && echo "  ✓ arjun installed"; fi

echo "== Playwright browser (Chromium) =="
python -m playwright install chromium 2>/dev/null && echo "  ✓ chromium ready" || \
  echo "  (run 'python -m playwright install chromium' after 'pip install playwright')"

echo
echo "Done. Verify with:  bbp doctor"
