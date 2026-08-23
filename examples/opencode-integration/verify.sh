#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# OpenCode integration verification for examples/opencode-integration/
#
# Seeds a temp opencode.json, wraps/unwraps MCP servers via
# `pipelock opencode install|remove --path`, and asserts structure.
# Exit 0 = all pass. Fully offline.
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

CONFIG="$WORK/opencode.json"
SEED="$WORK/opencode.seed.json"
YAML="$WORK/pipelock.yaml"
E2E_HOME="$WORK/empty-home"
E2E_XDG="$WORK/empty-xdg"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '\033[32m  [PASS]\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '\033[31m  [FAIL]\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m--- %s ---\033[0m\n' "$1"; }

install -m 600 "$SOURCE_CONFIG" "$YAML"
mkdir -p "$E2E_HOME" "$E2E_XDG"

# Seed: local + remote MCP (neutral domains). Keep a sibling unwrapped entry.
python3 - <<'PY' >"$SEED"
import json
print(json.dumps({
    "$schema": "https://opencode.ai/config.json",
    "theme": "demo-theme",
    "mcp": {
        "fixture-local": {
            "type": "local",
            "command": ["cat"],
            "environment": {"FIXTURE_VAR": "value"},
        },
        "fixture-remote": {
            "type": "remote",
            "url": "https://mcp.vendor.example/mcp",
            "headers": {"Authorization": "Bearer fixture-token"},
        },
        # OAuth remotes are left unchanged by install (skipped).
        "leave-alone": {
            "type": "remote",
            "url": "https://oauth.vendor.example/mcp",
            "oauth": {"clientId": "demo"},
        },
    },
}, indent=2))
PY
cp "$SEED" "$CONFIG"
chmod 600 "$CONFIG"

run_install() {
  HOME="$E2E_HOME" XDG_CONFIG_HOME="$E2E_XDG" PIPELOCK_CONFIG="" \
    "$PIPELOCK" opencode install --path "$CONFIG" --config "$YAML" "$@"
}

run_remove() {
  HOME="$E2E_HOME" XDG_CONFIG_HOME="$E2E_XDG" PIPELOCK_CONFIG="" \
    "$PIPELOCK" opencode remove --path "$CONFIG" "$@"
}

# -- Test 0 -------------------------------------------------------------------
step "Test 0: pipelock binary is available"
if [ ! -x "$PIPELOCK" ] && ! command -v "$PIPELOCK" >/dev/null 2>&1; then
  fail "pipelock not found at $PIPELOCK (run 'make build' or set PIPELOCK_BIN)"
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi
if ! "$PIPELOCK" opencode --help >/dev/null 2>&1; then
  fail "pipelock opencode subcommand unavailable"
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi
pass "pipelock opencode available ($PIPELOCK)"

# -- Test 1 -------------------------------------------------------------------
step "Test 1: install --dry-run does not write"
DRY_OUT="$(run_install --dry-run 2>&1)"
if printf '%s' "$DRY_OUT" | grep -q 'Would write' \
  && printf '%s' "$DRY_OUT" | grep -q 'mcp' \
  && printf '%s' "$DRY_OUT" | grep -q 'proxy'; then
  pass "dry-run mentions wrap plan"
else
  fail "dry-run missing expected output"
  printf '%s\n' "$DRY_OUT" >&2
fi
if cmp -s "$SEED" "$CONFIG"; then
  pass "dry-run left opencode.json unchanged"
else
  fail "dry-run mutated opencode.json"
fi

# -- Test 2 -------------------------------------------------------------------
step "Test 2: install wraps local and remote MCP servers"
INSTALL_OUT="$(run_install 2>&1)"
if printf '%s' "$INSTALL_OUT" | grep -qE 'Wrapped [0-9]+ server'; then
  pass "install reported wrapped servers"
else
  fail "install did not report wraps"
  printf '%s\n' "$INSTALL_OUT" >&2
fi
if [ -f "${CONFIG}.bak" ]; then
  pass "backup .bak created"
else
  fail "missing ${CONFIG}.bak"
fi

python3 - <<'PY' "$CONFIG" "$YAML" "$PIPELOCK"
import json, sys
from pathlib import Path

cfg_path, yaml_path, pipelock = sys.argv[1], sys.argv[2], sys.argv[3]
data = json.loads(Path(cfg_path).read_text())
mcp = data["mcp"]

local = mcp["fixture-local"]
assert local["type"] == "local", local
cmd = local["command"]
assert cmd[0] == pipelock or Path(cmd[0]).name == "pipelock", cmd
assert "mcp" in cmd and "proxy" in cmd, cmd
assert "--config" in cmd, cmd
assert yaml_path in cmd, cmd
assert "--" in cmd and cmd[cmd.index("--") + 1] == "cat", cmd
assert local.get("environment", {}).get("FIXTURE_VAR") == "value", local
assert "_pipelock" in local, local

remote = mcp["fixture-remote"]
assert remote["type"] == "local", remote
rcmd = remote["command"]
assert "--upstream" in rcmd, rcmd
assert "https://mcp.vendor.example/mcp" in rcmd, rcmd
assert "--header-file" in rcmd, rcmd
hf = rcmd[rcmd.index("--header-file") + 1]
assert Path(hf).is_file(), hf
assert Path(hf).stat().st_mode & 0o777 == 0o600, oct(Path(hf).stat().st_mode)
body = Path(hf).read_text()
assert "Authorization:" in body and "fixture-token" in body, body
assert "fixture-token" not in " ".join(rcmd), rcmd
meta = remote["_pipelock"]
assert meta.get("original_type") == "remote", meta
assert meta.get("original_url") == "https://mcp.vendor.example/mcp", meta

alone = mcp["leave-alone"]
assert alone["type"] == "remote", alone
assert alone["url"] == "https://oauth.vendor.example/mcp", alone
assert "oauth" in alone, alone
assert "_pipelock" not in alone, alone
assert data.get("theme") == "demo-theme", data
print("ok")
PY
pass "wrapped structure + sidecar + preserved oauth sibling"

# -- Test 3 -------------------------------------------------------------------
step "Test 3: install is idempotent"
BEFORE="$(python3 -c 'import json; print(json.dumps(json.load(open("'"$CONFIG"'")), sort_keys=True))')"
IDEM_OUT="$(run_install 2>&1)"
AFTER="$(python3 -c 'import json; print(json.dumps(json.load(open("'"$CONFIG"'")), sort_keys=True))')"
if [ "$BEFORE" = "$AFTER" ] && printf '%s' "$IDEM_OUT" | grep -qiE 'already wrapped|Wrapped 0'; then
  pass "second install left config unchanged"
else
  fail "install not idempotent"
  printf '%s\n' "$IDEM_OUT" >&2
fi

# -- Test 4 -------------------------------------------------------------------
step "Test 4: remove restores seed and deletes sidecar"
HF_BEFORE="$(python3 -c 'import json; c=json.load(open("'"$CONFIG"'")); print(c["mcp"]["fixture-remote"]["command"][c["mcp"]["fixture-remote"]["command"].index("--header-file")+1])')"
REMOVE_OUT="$(run_remove 2>&1)"
if printf '%s' "$REMOVE_OUT" | grep -qiE 'Unwrapped [12]'; then
  pass "remove reported unwrap"
else
  fail "remove missing unwrap message"
  printf '%s\n' "$REMOVE_OUT" >&2
fi
python3 - <<'PY' "$CONFIG" "$SEED" "$HF_BEFORE"
import json, sys
from pathlib import Path

cfg, seed, hf = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3])
got = json.loads(cfg.read_text())
want = json.loads(seed.read_text())
# Canonical compare of mcp entries we care about
for name in ("fixture-local", "fixture-remote", "leave-alone"):
    assert name in got["mcp"], name
    assert "_pipelock" not in got["mcp"][name], got["mcp"][name]
assert got["mcp"]["fixture-local"]["command"] == ["cat"], got
assert got["mcp"]["fixture-remote"]["type"] == "remote", got
assert got["mcp"]["fixture-remote"]["url"] == "https://mcp.vendor.example/mcp", got
assert got.get("theme") == "demo-theme", got
assert not hf.exists(), f"sidecar still present: {hf}"
print("ok")
PY
pass "config restored; header sidecar removed"

# -- Summary ------------------------------------------------------------------
printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
