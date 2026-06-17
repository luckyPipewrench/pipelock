#!/usr/bin/env bash
set -euo pipefail

# Tripwire: forbid the two flaky-test root causes (fixed wall-clock sleeps and
# fixed local ports) from re-entering the test suite. Runs in CI and via
# `make lint`, so it must FAIL CLOSED: a runner that cannot actually scan has
# to error loudly, never report "clean" by scanning nothing.

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

# scan runs a real recursive search and leaves the allowlist-filtered matches in
# scan_result. It distinguishes "no matches" (exit 1, clean) from a real search
# error and exits the whole script on the latter — `|| true` alone would mask
# errors as clean, the fail-open trap this gate exists to prevent.
scan_result=""
scan() {
  local pattern out rc
  pattern="$1"
  set +e
  if command -v rg >/dev/null 2>&1; then
    out="$(rg -n "$pattern" "${roots[@]}" --glob '*_test.go')"
  elif command -v grep >/dev/null 2>&1; then
    out="$(grep -RInE --include='*_test.go' "$pattern" "${roots[@]}")"
  else
    echo "check-test-stability: neither ripgrep (rg) nor grep is on PATH." >&2
    echo "The stability gate must fail closed when it cannot scan." >&2
    exit 127
  fi
  rc=$?
  set -e
  if [[ "$rc" -gt 1 ]]; then
    echo "check-test-stability: search exited with $rc while scanning for: $pattern" >&2
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
