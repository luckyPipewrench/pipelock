#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Verification for examples/tool-poisoning-honeypot/
#
# Runs the real `pipelock mcp proxy` round-trip against the decoy server and
# proves two layers block the attack before the agent can act:
#   1. mcp_tool_scanning blocks the poisoned tools/list manifest.
#   2. mcp_tool_policy blocks a dangerous tool/call even if it slips through.
#
# Exit 0 = all checks passed. Runs fully offline (loopback only).
set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
PIPELOCK="${PIPELOCK_BIN:-$REPO_ROOT/pipelock}"
CONFIG="$EXAMPLE_DIR/pipelock.yaml"
SERVER="$EXAMPLE_DIR/decoy_mcp_server.py"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '\033[32m  [PASS]\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '\033[31m  [FAIL]\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m--- %s ---\033[0m\n' "$1"; }

# -- Test 0: binary available ------------------------------------------------
step "Test 0: pipelock binary is available"
if [ ! -x "$PIPELOCK" ] && ! command -v "$PIPELOCK" >/dev/null 2>&1; then
  fail "pipelock not found at $PIPELOCK (run 'make build' or set PIPELOCK_BIN)"
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi
pass "pipelock available ($PIPELOCK)"

# -- Helpers: drive the stdio MCP proxy -------------------------------------
# All responses are appended to RESP_FILE; we wait for a line tagged with the
# requested JSON-RPC id, which is robust against ordering and partial writes.
RESP_FILE=""
PROXY_PID=""
PROXY_PIPE=""
PROXY_ERR=""

# Best-effort cleanup of proxy + its python child, plus temp files. Used both
# between round-trips and on script exit.
cleanup_proxy() {
  if [ -n "${PROXY_PID:-}" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
    # Close the fifo writer end first so the decoy python server gets EOF on
    # stdin and exits; then SIGKILL the proxy. SIGTERM is avoided because the
    # proxy can outlive it and leave wait() blocked. SIGKILL + closed fd makes
    # wait() return immediately.
    if [ -n "${PROXY_PIPE:-}" ] && [ -e "$PROXY_PIPE" ]; then
      exec 3>&- 2>/dev/null || true
    fi
    kill -9 "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  PROXY_PID=""
}

# Remove temp artifacts on any exit path. RESP_FILE/PROXY_ERR/PROXY_PIPE are
# reassigned per round-trip, so read them at exit time.
trap 'cleanup_proxy; rm -f "${RESP_FILE:-}" "${PROXY_ERR:-}" "${PROXY_PIPE:-}" 2>/dev/null || true' EXIT

start_proxy() {
  # Tear down any prior proxy first so a leaked process never blocks the
  # next round-trip (each proxy owns its own fifo on fd 3).
  cleanup_proxy
  RESP_FILE="$(mktemp)"
  : >"$RESP_FILE"
  PROXY_ERR="$(mktemp)"
  PROXY_PIPE="$(mktemp -u)"
  mkfifo "$PROXY_PIPE"
  # Launch directly. setsid is absent on macOS and unnecessary: pkill -P in
  # cleanup_proxy reaps the child python server. The fifo is opened read-write
  # (fd 3) so the open never blocks waiting for the proxy's reader end.
  "$PIPELOCK" mcp proxy --config "$CONFIG" -- python3 "$SERVER" \
    >>"$RESP_FILE" 2>"$PROXY_ERR" <"$PROXY_PIPE" &
  PROXY_PID=$!
  exec 3<>"$PROXY_PIPE"
}

send_json() { printf '%s\n' "$1" >&3; }

# Wait up to 12s for a JSON object line whose "id" equals $1. Prints it.
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

# -- Test 1: poisoned tools/list blocked before the agent sees it ----------
step "Test 1: poisoned tools/list blocked by mcp_tool_scanning"
start_proxy
send_json '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"tool-poisoning-honeypot-verify","version":"0"}}}'
_="$(read_response 1 || true)"
send_json '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
LIST_RESP="$(read_response 2 || true)"
cleanup_proxy

if printf '%s' "$LIST_RESP" | grep -q 'tool poisoning detected in tools/list'; then
  pass "tools/list with poisoned descriptions was blocked"
elif printf '%s' "$LIST_RESP" | grep -q '"tools"'; then
  fail "tools/list leaked poisoned tool descriptions to the agent"
  printf '%s\n' "$LIST_RESP" >&2
else
  fail "unexpected tools/list response (not blocked, not a tool list)"
  printf '%s\n' "$LIST_RESP" >&2
  printf 'stderr:\n%s\n' "$(cat "${PROXY_ERR:-/dev/null}")" >&2
fi

# -- Test 2: a dangerous tool/call blocked by mcp_tool_policy -----------
step "Test 2: dangerous tool/call blocked by mcp_tool_policy"
start_proxy
send_json '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"tool-poisoning-honeypot-verify","version":"0"}}}'
_="$(read_response 1 || true)"
send_json '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"summarize_notes","arguments":{"text":"hi"}}}'
CALL_RESP="$(read_response 3 || true)"
cleanup_proxy

if printf '%s' "$CALL_RESP" | grep -qi 'block\|policy'; then
  pass "dangerous tool/call was blocked by policy"
elif printf '%s' "$CALL_RESP" | grep -q 'decoy tool'; then
  fail "dangerous tool/call reached the decoy server (policy did not block)"
  printf '%s\n' "$CALL_RESP" >&2
else
  fail "unexpected tool/call response"
  printf '%s\n' "$CALL_RESP" >&2
  printf 'stderr:\n%s\n' "$(cat "${PROXY_ERR:-/dev/null}")" >&2
fi

# -- Summary ----------------------------------------------------------------
printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
