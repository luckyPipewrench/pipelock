#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
#
# MCP 2026-07-28 conformance rig for Pipelock.
#
# Drives the OFFICIAL MCP Python SDK (mcp==2.0.0) client against the OFFICIAL
# SDK server with Pipelock's MCP reverse proxy in the middle, and asserts on the
# SERVER-SIDE request trace. Server-side is the only place a protocol downgrade
# is visible: a fallback-capable client reports success either way.
#
# Usage:
#   ./verify.sh                     # all cases
#   PIPELOCK_BIN=/path ./verify.sh  # against a specific binary
#
# Exit 0 = all cases pass.
set -uo pipefail

RIG_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$RIG_DIR/../.." && pwd)"
PIPELOCK="${PIPELOCK_BIN:-$REPO_ROOT/pipelock}"
PY="$RIG_DIR/.venv/bin/python"

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf '\033[32m  [PASS]\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '\033[31m  [FAIL]\033[0m %s\n' "$1"; }

[ -x "$PIPELOCK" ] || { echo "no pipelock binary at $PIPELOCK (build it first)"; exit 2; }
[ -x "$PY" ] || { echo "no venv at $PY (python3 -m venv .venv && .venv/bin/pip install mcp==2.0.0)"; exit 2; }

free_port() { "$PY" -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()"; }
wait_port() {
  for _ in $(seq 1 60); do ss -ltn 2>/dev/null | grep -q ":$1 " && return 0; sleep 0.25; done
  return 1
}

SRV_PID=""; PLK_PID=""
cleanup() {
  # Kill by PID only. Never pkill -f pipelock: it would reap the shared proxy.
  [ -n "$PLK_PID" ] && kill "$PLK_PID" 2>/dev/null
  [ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

# start_stack <config> -> sets SPORT/PPORT/TRACE, starts server + pipelock
start_stack() {
  local config="$1"
  SPORT="$(free_port)"; PPORT="$(free_port)"
  TRACE="$(mktemp -t mcp-rig-trace.XXXXXX)"
  MCP_RIG_TRACE="$TRACE" "$PY" "$RIG_DIR/server_2026.py" "$SPORT" >"$RIG_DIR/.server.log" 2>&1 &
  SRV_PID=$!
  wait_port "$SPORT" || { echo "server failed to bind"; return 1; }
  "$PIPELOCK" mcp proxy --config "$config" \
    --listen "127.0.0.1:$PPORT" --upstream "http://127.0.0.1:$SPORT/mcp" \
    >"$RIG_DIR/.pipelock.log" 2>&1 &
  PLK_PID=$!
  wait_port "$PPORT" || { echo "pipelock failed to bind"; return 1; }
}

trace_q() { "$PY" "$RIG_DIR/trace_check.py" "$1" "$2"; }

echo "MCP 2026-07-28 conformance rig"
echo "  pipelock: $PIPELOCK"
echo

# ---------------------------------------------------------------------------
# Case 1: a compliant 2026-07-28 client can call a tool through Pipelock.
# ---------------------------------------------------------------------------
echo "Case 1: tool call transits Pipelock"
start_stack "$RIG_DIR/pipelock-baseline.yaml" || exit 2
if "$PY" "$RIG_DIR/client_2026.py" "http://127.0.0.1:$PPORT/mcp" >/dev/null 2>&1; then
  pass "client completed a tool call through Pipelock"
else
  fail "client could not complete a tool call through Pipelock"
fi

# ---------------------------------------------------------------------------
# Case 2: Pipelock must not be a protocol-downgrade vector.
#
# Both parties support 2026-07-28. If Pipelock's presence causes a fallback to
# the deprecated session-based transport, the security control has weakened the
# protocol it is protecting. Visible only in the server-side trace.
# ---------------------------------------------------------------------------
echo "Case 2: no protocol downgrade"
downgraded="$(trace_q "$TRACE" used_legacy_handshake)"
sessioned="$(trace_q "$TRACE" used_session_transport)"
mismatch="$(trace_q "$TRACE" count_400)"

if [ "$downgraded" = "False" ]; then
  pass "no legacy initialize handshake"
else
  fail "DOWNGRADE: client fell back to the legacy initialize handshake"
fi
if [ "$sessioned" = "False" ]; then
  pass "no session-era GET/DELETE requests"
else
  fail "DOWNGRADE: session-era GET/DELETE requests present"
fi
if [ "$mismatch" = "0" ]; then
  pass "no upstream 400s"
else
  fail "upstream rejected $mismatch request(s) with 400"
fi

# ---------------------------------------------------------------------------
# Case 3: required 2026-07-28 request headers reach the upstream.
#
# Minor-4 makes Mcp-Method and Mcp-Name REQUIRED on Streamable HTTP POST. An
# upstream that enforces them answers a stripped request with HeaderMismatch
# (-32020).
# ---------------------------------------------------------------------------
echo "Case 3: required headers forwarded"
hdr_method="$(trace_q "$TRACE" all_posts_have_mcp_method)"
hdr_name="$(trace_q "$TRACE" tools_call_has_mcp_name)"
if [ "$hdr_method" = "True" ]; then
  pass "Mcp-Method forwarded on every POST"
else
  fail "Mcp-Method missing on at least one POST (upstream sees a header mismatch)"
fi
if [ "$hdr_name" = "True" ]; then
  pass "Mcp-Name forwarded on tools/call"
else
  fail "Mcp-Name not forwarded on tools/call"
fi

# ---------------------------------------------------------------------------
# Case 4: a routing header that disagrees with the body is refused locally.
#
# Mcp-Method and Mcp-Name route the request at the upstream while Pipelock
# scans the body. Forwarding a disagreement lets the upstream act on a call no
# scanner in that request ever saw. Must fail closed BEFORE upstream, with
# HeaderMismatch (-32020).
# ---------------------------------------------------------------------------
echo "Case 4: routing header/body disagreement refused"
before_rows="$(wc -l < "$TRACE")"

mismatch_body='{"jsonrpc":"2.0","id":9,"method":"tools/list"}'
code="$(curl -s -o /tmp/mcp-rig-mismatch.json -w '%{http_code}' \
  -H 'Content-Type: application/json' -H 'Mcp-Method: tools/call' \
  -X POST --data "$mismatch_body" "http://127.0.0.1:$PPORT/mcp")"
if [ "$code" = "400" ]; then
  pass "method/body disagreement rejected with 400"
else
  fail "method/body disagreement got HTTP $code, want 400"
fi
if grep -q -- '-32020' /tmp/mcp-rig-mismatch.json 2>/dev/null; then
  pass "rejection carries HeaderMismatch (-32020)"
else
  fail "rejection did not carry -32020: $(head -c 200 /tmp/mcp-rig-mismatch.json 2>/dev/null)"
fi

name_body='{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}'
code="$(curl -s -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: read_note' \
  -X POST --data "$name_body" "http://127.0.0.1:$PPORT/mcp")"
if [ "$code" = "400" ]; then
  pass "tool-name/body disagreement rejected with 400"
else
  fail "tool-name/body disagreement got HTTP $code, want 400"
fi

for bad in 'tools/	list' 'oversized'; do
  case "$bad" in oversized) value="$(printf 'a%.0s' $(seq 1 9010))" ;; *) value="$bad" ;; esac
  code="$(curl -s -o /dev/null -w '%{http_code}' \
    -H 'Content-Type: application/json' -H "Mcp-Method: $value" \
    -X POST --data "$mismatch_body" "http://127.0.0.1:$PPORT/mcp")"
  if [ "$code" = "400" ]; then
    pass "malformed routing header rejected ($bad)"
  else
    fail "malformed routing header ($bad) got HTTP $code, want 400"
  fi
done

after_rows="$(wc -l < "$TRACE")"
if [ "$before_rows" = "$after_rows" ]; then
  pass "no rejected request reached the upstream"
else
  fail "$((after_rows - before_rows)) rejected request(s) reached the upstream"
fi

# ---------------------------------------------------------------------------
# Case 5: a budget bills a sessionless 2026-07-28 client instead of refusing it.
#
# Denial-of-wallet used to require a server-minted Mcp-Session-Id observed in an
# upstream response. Revision 2026-07-28 removes sessions, so that check could
# never be satisfied again and refused every tool call wherever a budget was
# configured. At the default minimum grade the call must go through.
# ---------------------------------------------------------------------------
echo "Case 5: budget bills a sessionless client (default minimum grade)"
cleanup
start_stack "$RIG_DIR/pipelock-dow-network.yaml" || exit 2
if "$PY" "$RIG_DIR/client_2026.py" "http://127.0.0.1:$PPORT/mcp" >/dev/null 2>&1; then
  pass "tool call allowed with a budget configured"
else
  fail "budget refused a compliant sessionless tool call"
fi
if [ "$(trace_q "$TRACE" used_legacy_handshake)" = "False" ]; then
  pass "still no downgrade with a budget configured"
else
  fail "DOWNGRADE reappeared once a budget was configured"
fi

# ---------------------------------------------------------------------------
# Case 6: raising the minimum grade refuses what it cannot identify.
#
# The listener has no authenticated principal, so a request can only reach
# network grade. An operator demanding principal grade must have the call
# refused rather than billed to a subject they declared insufficient.
# ---------------------------------------------------------------------------
echo "Case 6: minimum grade above what the request can prove is refused"
cleanup
start_stack "$RIG_DIR/pipelock-dow-principal.yaml" || exit 2
before_rows="$(wc -l < "$TRACE")"
if "$PY" "$RIG_DIR/client_2026.py" "http://127.0.0.1:$PPORT/mcp" >/dev/null 2>&1; then
  fail "tool call allowed despite being below the declared minimum grade"
else
  pass "tool call refused below the declared minimum grade"
fi
if grep -q 'minimum trust grade' "$RIG_DIR/.pipelock.log" 2>/dev/null; then
  pass "refusal names the subject-trust reason"
else
  fail "refusal did not name the subject-trust reason"
fi

cleanup
echo
printf 'passed: %d  failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
