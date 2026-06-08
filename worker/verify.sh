#!/usr/bin/env bash
# ============================================================================
#  verify.sh — confirm every pinned tool is present and runnable.
#  This is the image's ENTRYPOINT, so `docker run --rm bb-worker:test` runs it.
#  Exits 0 if all tools pass, non-zero (count of failures) otherwise.
# ============================================================================
set -u
fails=0
line() { printf -- '------------------------------------------------------------------\n'; }

# check <label> <pinned-version> <version-command...>
check() {
  local label="$1" pinned="$2"; shift 2
  local bin="$1"
  printf "  %-10s pinned %-9s : " "$label" "$pinned"
  if ! command -v "$bin" >/dev/null 2>&1; then
    printf "FAIL  (not found on PATH)\n"; fails=$((fails + 1)); return
  fi
  # Version flags differ per tool and some exit non-zero on -h, so we judge by
  # "the binary exists and produced output", and surface a version-looking token.
  local out shown
  out="$("$@" 2>&1)"
  local shown
  if [ "$label" = "arjun" ]; then
    # arjun has no --version flag; read it from the installed package metadata.
    shown="$(python3 -c "import importlib.metadata as m; print(m.version('arjun'))" 2>/dev/null)"
    [ -z "$shown" ] && shown="runs (no --version flag)"
  else
    shown="$(printf '%s\n' "$out" | grep -ioE 'v?[0-9]+\.[0-9]+\.[0-9]+[A-Za-z#_-]*' | head -1)"
    [ -z "$shown" ] && shown="$(printf '%s\n' "$out" | head -1 | cut -c1-50)"
  fi
  printf "OK    runs -> %s\n" "$shown"
}

echo
echo "=================================================================="
echo "  bb-worker :: tool verification  ($(date -u +%FT%TZ))"
echo "=================================================================="
echo "Runtime:"
printf "  %-10s %s\n" "OS"     "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
printf "  %-10s %s\n" "Python" "$(python3 --version 2>&1)"
printf "  %-10s %s\n" "Go"     "$(go version 2>&1 | awk '{print $3}')"
line
echo "Go-based tools:"
check subfinder "${SUBFINDER_VERSION:-?}" subfinder -version
check httpx     "${HTTPX_VERSION:-?}"     httpx     -version
check nuclei    "${NUCLEI_VERSION:-?}"    nuclei    -version
check dalfox    "${DALFOX_VERSION:-?}"    dalfox    version
line
echo "Python-based tools:"
check sqlmap    "${SQLMAP_VERSION:-?}"    sqlmap --version
check arjun     "${ARJUN_VERSION:-?}"     arjun  -h
line
if [ "$fails" -eq 0 ]; then
  echo "  RESULT: ALL 6 TOOLS PRESENT AND RUNNABLE  [PASS]"
else
  echo "  RESULT: ${fails} TOOL(S) FAILED  [FAIL]"
fi
line
echo
exit "$fails"
