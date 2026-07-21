#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Learn-and-lock (behavioral baseline) verification for examples/learn-and-lock/
#
# Stdio MCP decoy: learn echo samples → auto_ratify lock → echo still allowed →
# novel run_shell denied by baseline (not mcp_tool_policy).
#
# Usage:
#   ./verify.sh
#   PIPELOCK_BIN=/path/to/pipelock ./verify.sh
set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
PIPELOCK="${PIPELOCK_BIN:-$REPO_ROOT/pipelock}"
SOURCE_CONFIG="$EXAMPLE_DIR/pipelock.yaml"
SERVER="$EXAMPLE_DIR/baseline_decoy_server.py"
WORK="$(mktemp -d)"
CONFIG="$WORK/pipelock.yaml"
PROFILE_DIR="$WORK/profiles"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '\033[32m  [PASS]\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '\033[31m  [FAIL]\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m--- %s ---\033[0m\n' "$1"; }

RESP_FILE=""
PROXY_PID=""
PROXY_PIPE=""
PROXY_ERR=""
PROXY_TMPDIR=""

cleanup_proxy() {
  if [ -n "${PROXY_PID:-}" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
    if [ -n "${PROXY_PIPE:-}" ] && [ -e "$PROXY_PIPE" ]; then
      exec 3>&- 2>/dev/null || true
    fi
    kill -9 "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  PROXY_PID=""
}

cleanup() {
  cleanup_proxy
  rm -f "${RESP_FILE:-}" "${PROXY_ERR:-}" 2>/dev/null || true
  rm -rf "${PROXY_TMPDIR:-}" "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

write_config() {
  mkdir -p "$PROFILE_DIR"
  chmod 750 "$PROFILE_DIR"
  python3 - <<'PY' "$SOURCE_CONFIG" "$CONFIG" "$PROFILE_DIR"
import sys
from pathlib import Path

src, dst, profile_dir = sys.argv[1:4]
out = []
replaced = False
for line in Path(src).read_text().splitlines():
    if line.strip().startswith("profile_dir:"):
        out.append(f'  profile_dir: "{profile_dir}"')
        replaced = True
    else:
        out.append(line)
if not replaced:
    sys.exit("write_config: failed to locate profile_dir: in pipelock.yaml")
Path(dst).write_text("\n".join(out) + "\n")
PY
  chmod 600 "$CONFIG"
}

start_proxy() {
  cleanup_proxy
  RESP_FILE="$(mktemp)"
  : >"$RESP_FILE"
  PROXY_ERR="$(mktemp)"
  PROXY_TMPDIR="$(mktemp -d)"
  PROXY_PIPE="$PROXY_TMPDIR/pipe"
  mkfifo "$PROXY_PIPE"
  "$PIPELOCK" mcp proxy --config "$CONFIG" -- python3 "$SERVER" \
    >>"$RESP_FILE" 2>"$PROXY_ERR" <"$PROXY_PIPE" &
  PROXY_PID=$!
  exec 3<>"$PROXY_PIPE"
}

send_json() { printf '%s\n' "$1" >&3; }

read_response() {
  local want="$1"
  local deadline=$(( $(date +%s) + 12 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    local line
    line="$(grep -m1 "\"id\": *$want\\b" "$RESP_FILE" 2>/dev/null || true)"
    if [ -n "$line" ]; then
      echo "$line"
      return 0
    fi
    if ! kill -0 "$PROXY_PID" 2>/dev/null; then
      sleep 0.2
      line="$(grep -m1 "\"id\": *$want\\b" "$RESP_FILE" 2>/dev/null || true)"
      if [ -n "$line" ]; then echo "$line"; return 0; fi
      return 1
    fi
    sleep 0.1
  done
  return 1
}

initialize_mcp() {
  local id="$1"
  send_json "{\"jsonrpc\":\"2.0\",\"id\":${id},\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2024-11-05\",\"capabilities\":{},\"clientInfo\":{\"name\":\"learn-lock-verify\",\"version\":\"0.0.1\"}}}"
  read_response "$id"
}

call_tool() {
  local id="$1"
  local name="$2"
  local args_json="$3"
  send_json "{\"jsonrpc\":\"2.0\",\"id\":${id},\"method\":\"tools/call\",\"params\":{\"name\":\"${name}\",\"arguments\":${args_json}}}"
  read_response "$id"
}

# One short-lived proxy session: initialize + one tools/call, then exit so
# stdio records a discrete baseline sample on process exit.
learn_sample() {
  local id="$1"
  local label="$2"
  start_proxy
  if ! initialize_mcp "$id" >/dev/null; then
    fail "$label: initialize failed"
    if [ -f "$PROXY_ERR" ]; then tail -20 "$PROXY_ERR" >&2 || true; fi
    return 1
  fi
  local resp
  resp="$(call_tool $((id + 1)) echo '{"text":"learn"}' || true)"
  if printf '%s' "$resp" | grep -q 'baseline-decoy ok: echo' \
    && ! printf '%s' "$resp" | grep -qE '"code": *(-32001|-32002)'; then
    pass "$label"
  else
    fail "$label"
    printf '%s\n' "$resp" >&2
    if [ -f "$PROXY_ERR" ]; then tail -20 "$PROXY_ERR" >&2 || true; fi
  fi
  # Close client stdin so RunProxy exits cleanly and defer recordMCPBaselineSample runs.
  # kill -9 would skip the sample flush.
  exec 3>&- 2>/dev/null || true
  wait "$PROXY_PID" 2>/dev/null || true
  PROXY_PID=""
  sleep 0.2
}

expect_allow() {
  local label="$1"
  local resp="$2"
  if printf '%s' "$resp" | grep -q 'baseline-decoy ok' \
    && ! printf '%s' "$resp" | grep -qE '"code": *(-32001|-32002)'; then
    pass "$label"
  else
    fail "$label"
    printf '%s\n' "$resp" >&2
    if [ -f "$PROXY_ERR" ]; then tail -20 "$PROXY_ERR" >&2 || true; fi
  fi
}

expect_baseline_deny() {
  local label="$1"
  local resp="$2"
  if printf '%s' "$resp" | grep -qE '"code": *-32001|baseline deviation|behavioral baseline' \
    && ! printf '%s' "$resp" | grep -qE '"code": *-32002|tool call policy'; then
    pass "$label"
  else
    fail "$label"
    printf '%s\n' "$resp" >&2
    if [ -f "$PROXY_ERR" ]; then tail -40 "$PROXY_ERR" >&2 || true; fi
  fi
}

profile_locked() {
  python3 - <<'PY' "$PROFILE_DIR"
import json, sys
from pathlib import Path
d = Path(sys.argv[1])
cands = list(d.glob("*.json"))
if not cands:
    raise SystemExit("no profile json")
# Prefer _default.json when present.
path = d / "_default.json"
if not path.is_file():
    path = cands[0]
prof = json.loads(path.read_text())
state = str(prof.get("state", "")).lower()
if state != "locked" and not prof.get("ratified"):
    raise SystemExit(f"profile not locked: state={state!r} path={path}")
print(path.name)
PY
}

# -- Test 0 -------------------------------------------------------------------
step "Test 0: pipelock binary is available"
if [ ! -x "$PIPELOCK" ] && ! command -v "$PIPELOCK" >/dev/null 2>&1; then
  fail "pipelock not found at $PIPELOCK (run 'make build' or set PIPELOCK_BIN)"
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi
pass "pipelock available ($PIPELOCK)"

# -- Test 1 -------------------------------------------------------------------
step "Test 1: learn-and-lock config validates"
write_config
if "$PIPELOCK" check --config "$CONFIG" >/dev/null 2>&1; then
  pass "pipelock.yaml validates (temp profile_dir)"
else
  fail "pipelock.yaml failed validation"
  "$PIPELOCK" check --config "$CONFIG" >&2 || true
fi

# Also validate the committed template (placeholder profile_dir).
if "$PIPELOCK" check --config "$SOURCE_CONFIG" >/dev/null 2>&1; then
  pass "committed pipelock.yaml validates"
else
  fail "committed pipelock.yaml failed validation"
fi

# -- Test 2 -------------------------------------------------------------------
step "Test 2: learn phase — one echo sample (learning_window: 1)"
# Stdio records a baseline sample on proxy exit; Observe samples are not
# flushed mid-window, so window=1 is required for multi-process offline CI.
learn_sample 1 "learn sample (echo)"

# -- Test 3 -------------------------------------------------------------------
step "Test 3: profile auto-ratified to locked"
if PROFILE_NAME="$(profile_locked)"; then
  pass "locked profile on disk ($PROFILE_NAME)"
else
  fail "profile not locked after learning_window"
  ls -la "$PROFILE_DIR" >&2 || true
  for f in "$PROFILE_DIR"/*.json; do
    [ -f "$f" ] && { echo "--- $f ---"; cat "$f"; } >&2
  done
fi

# -- Test 4 -------------------------------------------------------------------
step "Test 4: post-lock — learned echo allowed, novel run_shell denied"
start_proxy
if ! initialize_mcp 10 >/dev/null; then
  fail "post-lock initialize failed"
  if [ -f "$PROXY_ERR" ]; then tail -20 "$PROXY_ERR" >&2 || true; fi
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

ECHO_RESP="$(call_tool 11 echo '{"text":"still-ok"}' || true)"
expect_allow "learned echo still allowed after lock" "$ECHO_RESP"

SHELL_RESP="$(call_tool 12 run_shell '{"command":"id"}' || true)"
expect_baseline_deny "novel run_shell denied by baseline" "$SHELL_RESP"

# Distinction: must not look like static tool policy.
if printf '%s' "$SHELL_RESP" | grep -qE '"code": *-32002|tool call policy'; then
  fail "deny looked like mcp_tool_policy (-32002) instead of baseline"
else
  pass "deny is baseline (not mcp_tool_policy)"
fi

# -- Summary ------------------------------------------------------------------
printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
