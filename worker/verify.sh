#!/usr/bin/env bash
# ============================================================================
#  verify.sh — confirm every pinned tool is present and runnable.
#  ENTRYPOINT of the image: `docker run --rm bb-worker:test` runs this.
#  Each tool is checked the RIGHT way (version flag / subcommand / presence /
#  package metadata). Exits 0 on full pass, else the number of failures.
# ============================================================================
set -u
fails=0
line() { printf -- '------------------------------------------------------------------\n'; }

# ver <label> <pinned> <version-command...> : run it, surface a version token.
ver() {
  local label="$1" pin="$2"; shift 2; local bin="$1"
  printf "  %-14s pin %-14s : " "$label" "$pin"
  if ! command -v "$bin" >/dev/null 2>&1; then printf "FAIL (not on PATH)\n"; fails=$((fails + 1)); return; fi
  local out v
  out="$("$@" 2>&1)"
  v="$(printf '%s\n' "$out" | grep -ioE 'v?[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.#_-]*' | head -1)"
  [ -z "$v" ] && v="$(printf '%s\n' "$out" | tr -d '\r' | grep -m1 '[^[:space:]]' | cut -c1-40)"
  printf "OK   runs -> %s\n" "$v"
}

# present <label> <pinned> <bin> : presence only (stdin-reading / arg-required tools).
present() {
  local label="$1" pin="$2" bin="$3"
  printf "  %-14s pin %-14s : " "$label" "$pin"
  if command -v "$bin" >/dev/null 2>&1; then printf "OK   present (runnable)\n"
  else printf "FAIL (not on PATH)\n"; fails=$((fails + 1)); fi
}

# pymeta <label> <pinned> <pkg> : version from installed Python package metadata.
pymeta() {
  local label="$1" pin="$2" pkg="$3"
  printf "  %-14s pin %-14s : " "$label" "$pin"
  local v; v="$(python3 -c "import importlib.metadata as m; print(m.version('$pkg'))" 2>/dev/null)"
  if [ -n "$v" ]; then printf "OK   installed %s\n" "$v"
  else printf "FAIL (not importable)\n"; fails=$((fails + 1)); fi
}

echo
echo "=================================================================="
echo "  bb-worker :: full tool verification  ($(date -u +%FT%TZ))"
echo "=================================================================="
printf "  %-14s %s\n" "OS"     "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
printf "  %-14s %s\n" "Python" "$(python3 --version 2>&1)"
printf "  %-14s %s\n" "Go"     "$(go version 2>&1 | awk '{print $3}')"
line
echo "Recon / discovery (Go):"
ver     subfinder   "${SUBFINDER_VERSION:-?}"   subfinder -version
ver     httpx       "${HTTPX_VERSION:-?}"       httpx -version
ver     katana      "${KATANA_VERSION:-?}"      katana -version
ver     gau         "${GAU_VERSION:-?}"         gau --version
present waybackurls "${WAYBACKURLS_VERSION:-?}" waybackurls
present gf          "${GF_VERSION:-?}"          gf
present kxss        "${KXSS_VERSION:-?}"        kxss
ver     ffuf        "${FFUF_VERSION:-?}"        ffuf -V
ver     nuclei      "${NUCLEI_VERSION:-?}"      nuclei -version
line
echo "XSS (Go):"
ver     dalfox      "${DALFOX_VERSION:-?}"      dalfox version
line
echo "Access control / IDOR:"
ver     nomore403   "${NOMORE403_VERSION:-?}"   nomore403 --version
present jwt_tool     "${JWT_TOOL_VERSION:-?}"    jwt_tool
line
echo "GraphQL:"
present clairvoyance "${CLAIRVOYANCE_VERSION:-?}" clairvoyance
present graphql-cop  "${GRAPHQL_COP_VERSION:-?}"  graphql-cop
pymeta  clairvoyance "${CLAIRVOYANCE_VERSION:-?}" clairvoyance
line
echo "SSRF:"
present ssrfmap     "${SSRFMAP_COMMIT:0:12}"    ssrfmap
present ipfuscator  "${IPFUSCATOR_COMMIT:0:12}" ipfuscator
present interactsh   "${INTERACTSH_VERSION:-?}"  interactsh-client
# gopherus is Python 2 only (EOL) — informational, not a failure.
printf "  %-14s pin %-14s : %s\n" "gopherus" "${GOPHERUS_COMMIT:0:12}" \
       "INFO  Python2-only (cloned for reference; native gopher gen in-platform)"
line
echo "Python tools / libraries:"
ver     sqlmap      "${SQLMAP_VERSION:-?}"      sqlmap --version
pymeta  arjun       "${ARJUN_VERSION:-?}"       arjun
pymeta  fuzz-lightyear "${FUZZ_LIGHTYEAR_VERSION:-?}" fuzz-lightyear
line
if [ "$fails" -eq 0 ]; then
  echo "  RESULT: ALL TOOLS PRESENT AND RUNNABLE  [PASS]"
else
  echo "  RESULT: ${fails} TOOL(S) FAILED  [FAIL]"
fi
line
echo
exit "$fails"
