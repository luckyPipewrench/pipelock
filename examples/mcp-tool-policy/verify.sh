#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# MCP tool-policy verification for examples/mcp-tool-policy/
#
# Drives pipelock mcp proxy against a benign stdio decoy and proves allow vs
# deny for name and argument rules. Exit 0 = all pass.
#
# Usage:
#   ./verify.sh
#   PIPELOCK_BIN=/path/to/pipelock ./verify.sh
set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
PIPELOCK="${PIPELOCK_BIN:-$REPO_ROOT/pipelock}"
CONFIG="$EXAMPLE_DIR/pipelock.yaml"
SERVER="$EXAMPLE_DIR/policy_decoy_server.py"

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

trap 'cleanup_proxy; rm -f "${RESP_FILE:-}" "${PROXY_ERR:-}" 2>/dev/null || true; rm -rf "${PROXY_TMPDIR:-}" 2>/dev/null || true' EXIT

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

call_tool() {
  local id="$1"
  local name="$2"
  local args_json="$3"
  send_json "{\"jsonrpc\":\"2.0\",\"id\":${id},\"method\":\"tools/call\",\"params\":{\"name\":\"${name}\",\"arguments\":${args_json}}}"
  read_response "$id"
}

expect_allow() {
  local label="$1"
  local resp="$2"
  if printf '%s' "$resp" | grep -q 'policy-decoy ok' \
    && ! printf '%s' "$resp" | grep -q '"code": *-32002'; then
    pass "$label"
  else
    fail "$label"
    printf '%s\n' "$resp" >&2
    if [ -f "$PROXY_ERR" ]; then tail -20 "$PROXY_ERR" >&2 || true; fi
  fi
}

expect_deny() {
  local label="$1"
  local resp="$2"
  if printf '%s' "$resp" | grep -qE '"code": *-32002|tool call policy'; then
    pass "$label"
  else
    fail "$label"
    printf '%s\n' "$resp" >&2
    if [ -f "$PROXY_ERR" ]; then tail -20 "$PROXY_ERR" >&2 || true; fi
  fi
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
step "Test 1: mcp-tool-policy config validates"
if "$PIPELOCK" check --config "$CONFIG" >/dev/null 2>&1; then
  pass "pipelock.yaml validates"
else
  fail "pipelock.yaml failed validation"
  "$PIPELOCK" check --config "$CONFIG" >&2 || true
fi

# -- Start proxy once for policy round-trips ----------------------------------
step "Test 2: initialize MCP proxy + decoy"
start_proxy
send_json '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mcp-tool-policy-verify","version":"0"}}}'
INIT_RESP="$(read_response 1 || true)"
if printf '%s' "$INIT_RESP" | grep -q 'policy-decoy-demo\|protocolVersion\|"result"'; then
  pass "initialize succeeded"
else
  fail "initialize failed"
  printf '%s\n' "$INIT_RESP" >&2
  cat "$PROXY_ERR" >&2 || true
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

# -- Allow / deny cases -------------------------------------------------------
step "Test 3: allow unmatched echo"
expect_allow "echo allowed" "$(call_tool 2 echo '{"text":"hello"}' || true)"

step "Test 4: deny run_shell by tool name"
expect_deny "run_shell blocked" "$(call_tool 3 run_shell '{"command":"ls"}' || true)"

step "Test 5: allow safe read_file path"
expect_allow "safe read_file allowed" "$(call_tool 4 read_file '{"path":"/tmp/notes.txt"}' || true)"

step "Test 6: deny secret-path read_file"
expect_deny "ssh path read_file blocked" "$(call_tool 5 read_file '{"path":"/home/agent/.ssh/id_rsa"}' || true)"

step "Test 7: allow small transfer"
expect_allow "transfer amount=50 allowed" "$(call_tool 6 transfer '{"amount":50}' || true)"

step "Test 8: deny large transfer"
expect_deny "transfer amount=1001 blocked" "$(call_tool 7 transfer '{"amount":1001}' || true)"

step "Test 9: allow reader role"
expect_allow "set_role reader allowed" "$(call_tool 8 set_role '{"role":"reader"}' || true)"

step "Test 10: deny admin role"
expect_deny "set_role admin blocked" "$(call_tool 9 set_role '{"role":"admin"}' || true)"

step "Test 11: allow short note"
expect_allow "short write_note allowed" "$(call_tool 10 write_note '{"text":"short"}' || true)"

LONG_TEXT="$(printf 'x%.0s' {1..65})"
step "Test 12: deny oversized note"
expect_deny "long write_note blocked" "$(call_tool 11 write_note "{\"text\":\"${LONG_TEXT}\"}" || true)"

cleanup_proxy

# -- Summary ------------------------------------------------------------------
printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
