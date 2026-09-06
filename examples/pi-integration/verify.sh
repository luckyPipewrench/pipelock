#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Pi integration verification for examples/pi-integration/
#
# Uses a temp PI_CODING_AGENT_DIR, runs pipelock pi install/remove, and
# asserts settings.json. Exit 0 = all pass. Fully offline.
#
# Usage:
#   ./verify.sh
#   PIPELOCK_BIN=/path/to/pipelock ./verify.sh
set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
PIPELOCK="${PIPELOCK_BIN:-$REPO_ROOT/pipelock}"
SOURCE_CONFIG="$EXAMPLE_DIR/pipelock.yaml"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
. "$REPO_ROOT/scripts/e2e/hermetic-env.sh"
pipelock_hermetic_env "$WORK/hermetic"

YAML="$WORK/pipelock.yaml"
AGENT_DIR="$WORK/pi-agent"
PROXY="http://127.0.0.1:18991"
SETTINGS="$AGENT_DIR/settings.json"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '\033[32m  [PASS]\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '\033[31m  [FAIL]\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m--- %s ---\033[0m\n' "$1"; }

install -m 600 "$SOURCE_CONFIG" "$YAML"
mkdir -p "$AGENT_DIR"

run_pi() {
  PI_CODING_AGENT_DIR="$AGENT_DIR" PIPELOCK_CONFIG="" \
    "$PIPELOCK" pi "$@"
}

# -- Test 0 -------------------------------------------------------------------
step "Test 0: pipelock pi is available"
if [ ! -x "$PIPELOCK" ] && ! command -v "$PIPELOCK" >/dev/null 2>&1; then
  fail "pipelock not found at $PIPELOCK (run 'make build' or set PIPELOCK_BIN)"
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi
if ! "$PIPELOCK" pi --help >/dev/null 2>&1; then
  fail "pipelock pi subcommand unavailable"
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi
pass "pipelock pi available ($PIPELOCK)"

# -- Test 1 -------------------------------------------------------------------
step "Test 1: install --dry-run does not write"
DRY_OUT="$(run_pi install --config "$YAML" --profile pi --proxy "$PROXY" --dry-run 2>&1)"
if printf '%s' "$DRY_OUT" | grep -q 'httpProxy' && printf '%s' "$DRY_OUT" | grep -q 'Would set'; then
  pass "dry-run mentions httpProxy"
else
  fail "dry-run missing expected output"
  printf '%s\n' "$DRY_OUT" >&2
fi
if [ ! -e "$SETTINGS" ]; then
  pass "dry-run left settings absent"
else
  fail "dry-run created settings.json"
fi

# -- Test 2 -------------------------------------------------------------------
step "Test 2: install writes only httpProxy"
printf '%s\n' '{"theme":"keep-me"}' >"$SETTINGS"
chmod 600 "$SETTINGS"
INSTALL_OUT="$(run_pi install --config "$YAML" --profile pi --proxy "$PROXY" 2>&1)"
if printf '%s' "$INSTALL_OUT" | grep -q 'Configured Pi'; then
  pass "install reported configuration"
else
  fail "install did not report configuration"
  printf '%s\n' "$INSTALL_OUT" >&2
fi
python3 - <<'PY' "$SETTINGS" "$PROXY"
import json, sys
from pathlib import Path
path, proxy = sys.argv[1], sys.argv[2]
data = json.loads(Path(path).read_text())
if data.get("httpProxy") != proxy:
    raise SystemExit(f"unexpected settings: {data!r}")
if data.get("theme") != "keep-me":
    raise SystemExit(f"unexpected settings: {data!r}")
PY
pass "settings kept theme and set httpProxy"

# -- Test 3 -------------------------------------------------------------------
step "Test 3: second install is idempotent"
AGAIN_OUT="$(run_pi install --config "$YAML" --profile pi --proxy "$PROXY" 2>&1)"
if printf '%s' "$AGAIN_OUT" | grep -q 'already routes'; then
  pass "second install reported already configured"
else
  fail "second install was not idempotent"
  printf '%s\n' "$AGAIN_OUT" >&2
fi

# -- Test 4 -------------------------------------------------------------------
step "Test 4: remove --dry-run does not restore yet"
REMOVE_DRY="$(run_pi remove --dry-run 2>&1)"
if printf '%s' "$REMOVE_DRY" | grep -q 'Would restore'; then
  pass "remove dry-run mentions restore"
else
  fail "remove dry-run missing expected output"
  printf '%s\n' "$REMOVE_DRY" >&2
fi
python3 - <<'PY' "$SETTINGS" "$PROXY"
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text())
if data.get("httpProxy") != sys.argv[2]:
    raise SystemExit(f"unexpected settings: {data!r}")
PY
pass "remove dry-run left httpProxy in place"

# -- Test 5 -------------------------------------------------------------------
step "Test 5: remove restores other settings"
REMOVE_OUT="$(run_pi remove 2>&1)"
if printf '%s' "$REMOVE_OUT" | grep -q 'Restored Pi'; then
  pass "remove reported restore"
else
  fail "remove did not report restore"
  printf '%s\n' "$REMOVE_OUT" >&2
fi
python3 - <<'PY' "$SETTINGS"
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text())
if "httpProxy" in data:
    raise SystemExit(f"unexpected settings: {data!r}")
if data.get("theme") != "keep-me":
    raise SystemExit(f"unexpected settings: {data!r}")
PY
pass "remove dropped httpProxy and kept theme"

# -- Test 6 -------------------------------------------------------------------
step "Test 6: remove restores a prior httpProxy"
PRIOR_PROXY="http://127.0.0.1:19999"
printf '%s\n' "{\"theme\":\"keep-me\",\"httpProxy\":\"$PRIOR_PROXY\"}" >"$SETTINGS"
chmod 600 "$SETTINGS"
run_pi install --config "$YAML" --profile pi --proxy "$PROXY" >/dev/null
REMOVE_PRIOR="$(run_pi remove 2>&1)"
if printf '%s' "$REMOVE_PRIOR" | grep -q 'Restored Pi'; then
  pass "remove reported restore of prior proxy"
else
  fail "remove did not report restore of prior proxy"
  printf '%s\n' "$REMOVE_PRIOR" >&2
fi
python3 - <<'PY' "$SETTINGS" "$PRIOR_PROXY"
import json, sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text())
if data.get("httpProxy") != sys.argv[2]:
    raise SystemExit(f"unexpected settings: {data!r}")
if data.get("theme") != "keep-me":
    raise SystemExit(f"unexpected settings: {data!r}")
PY
pass "remove restored prior httpProxy and kept theme"

# -- Test 7 -------------------------------------------------------------------
step "Test 7: remove deletes a newly created settings file"
rm -f "$SETTINGS" "$SETTINGS.pipelock-pi-state.json"
run_pi install --config "$YAML" --profile pi --proxy "$PROXY" >/dev/null
REMOVE_NEW="$(run_pi remove 2>&1)"
if printf '%s' "$REMOVE_NEW" | grep -q 'Restored Pi'; then
  pass "remove reported restore of new settings"
else
  fail "remove did not report restore of new settings"
  printf '%s\n' "$REMOVE_NEW" >&2
fi
if [ ! -e "$SETTINGS" ]; then
  pass "remove deleted newly created settings.json"
else
  fail "remove left newly created settings.json"
fi

printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
