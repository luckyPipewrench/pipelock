#!/usr/bin/env bash
set -euo pipefail

# Tripwire: forbid the two flaky-test root causes (fixed wall-clock sleeps and
# fixed local ports) from re-entering the test suite. Runs in CI and via
# `make lint`, so it must FAIL CLOSED: a runner that cannot actually scan has
# to error loudly, never report "clean" by scanning nothing.

# Fail closed if ripgrep is missing. The scans below would otherwise behave as
# "no match" when `rg` is absent (exit 127 swallowed) and silently pass,
# defeating the entire point of the gate. Mirrors scripts/release-audit.sh.
if ! command -v rg >/dev/null 2>&1; then
  echo "check-test-stability: ripgrep (rg) is required and is not on PATH." >&2
  echo "Install ripgrep (e.g., apt-get install -y ripgrep) before running this check." >&2
  exit 127
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Roots scanned for *_test.go. Repo-wide so the no-sleep / no-fixed-port rule
# is not silently scoped to a subtree: enterprise/ is the highest-concurrency
# code in the tree and must be covered.
roots=(internal cmd enterprise sdk bench)

allowlist="scripts/test-stability-allowlist.txt"
status=0

filter_allowlist() {
  if [[ -f "$allowlist" ]]; then
    grep -F -x -v -f <(grep -vE '^[[:space:]]*(#|$)' "$allowlist") || true
  else
    cat
  fi
}

# scan runs ripgrep and leaves the allowlist-filtered matches in scan_result.
# It distinguishes "no matches" (rg exit 1, clean) from a real search error
# (exit >=2) and exits the whole script on the latter — `|| true` alone would
# mask exit 2 as clean, the fail-open trap this gate exists to prevent. Called
# as a statement (not in a $() subshell) so `exit` terminates the script.
scan_result=""
scan() {
  local out rc
  set +e
  out="$(rg -n "$@" "${roots[@]}" --glob '*_test.go')"
  rc=$?
  set -e
  if [[ "$rc" -gt 1 ]]; then
    echo "check-test-stability: ripgrep exited with $rc while running: rg $* ${roots[*]}" >&2
    echo "The stability gate must fail closed on scan errors, not pass with zero scans." >&2
    exit "$rc"
  fi
  scan_result="$(printf '%s' "$out" | filter_allowlist)"
}

scan 'time\.Sleep\('
if [[ -n "$scan_result" ]]; then
  echo "check-test-stability: time.Sleep is forbidden in tests; use testwait, channels, or a fake clock." >&2
  echo "$scan_result" >&2
  status=1
fi

scan 'Listen(Context)?\([^)]*"(tcp|tcp4|tcp6)"[^)]*"(127\.0\.0\.1|0\.0\.0\.0|localhost|\[::1\]|:)[^"]*:[1-9][0-9]*"'
if [[ -n "$scan_result" ]]; then
  echo "check-test-stability: fixed local ports in test Listen calls are forbidden; bind :0 and read back the assigned address." >&2
  echo "$scan_result" >&2
  status=1
fi

exit "$status"
