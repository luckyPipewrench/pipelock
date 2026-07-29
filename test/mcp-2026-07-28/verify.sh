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
cache_hdr="$(curl -s -D - -o /dev/null -H 'Content-Type: application/json' -H 'Mcp-Method: tools/list' \
  -X POST --data '{"jsonrpc":"2.0","id":11,"method":"tools/list"}' "http://127.0.0.1:$PPORT/mcp" \
  | tr -d '\r' | grep -i '^cache-control:' | head -1)"
if printf '%s' "$cache_hdr" | grep -qi 'no-store'; then
  pass "responses carry Cache-Control: no-store"
else
  fail "response cache directive was '${cache_hdr:-<none>}', want no-store"
fi

before_rows="$(wc -l < "$TRACE")"

mismatch_body='{"jsonrpc":"2.0","id":9,"method":"tools/list"}'
mismatch_out="$(mktemp -t mcp-rig-mismatch.XXXXXX)"
code="$(curl -s -o "$mismatch_out" -w '%{http_code}' \
  -H 'Content-Type: application/json' -H 'Mcp-Method: tools/call' \
  -X POST --data "$mismatch_body" "http://127.0.0.1:$PPORT/mcp")"
if [ "$code" = "400" ]; then
  pass "method/body disagreement rejected with 400"
else
  fail "method/body disagreement got HTTP $code, want 400"
fi
if grep -q -- '-32020' "$mismatch_out" 2>/dev/null; then
  pass "rejection carries HeaderMismatch (-32020)"
else
  fail "rejection did not carry -32020: $(head -c 200 "$mismatch_out" 2>/dev/null)"
fi
rm -f "$mismatch_out"

name_body='{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"echo","arguments":{"text":"hi"}}}'
code="$(curl -s -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: read_note' \
  -X POST --data "$name_body" "http://127.0.0.1:$PPORT/mcp")"
if [ "$code" = "400" ]; then
  pass "tool-name/body disagreement rejected with 400"
else
  fail "tool-name/body disagreement got HTTP $code, want 400"
fi

# These agree with the body method, so a rejection can only come from the
# header's own shape validation, not from the disagreement check.
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
# The fixture caps the budget at ONE tool call. A single successful call would
# also pass if the sessionless request were never billed at all, so the proof is
# that the SECOND call is refused: that can only happen if the first was charged
# to a subject the second resolves to as well.
if "$PY" "$RIG_DIR/client_2026.py" "http://127.0.0.1:$PPORT/mcp" >/dev/null 2>&1; then
  pass "first tool call allowed with a budget configured"
else
  fail "budget refused a compliant sessionless tool call"
fi
if "$PY" "$RIG_DIR/client_2026.py" "http://127.0.0.1:$PPORT/mcp" >/dev/null 2>&1; then
  fail "second tool call allowed past a one-call budget: the request is not being billed"
else
  pass "second tool call refused, so the first was charged to a stable subject"
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

# ---------------------------------------------------------------------------
# Case 7: MRTR inputResponses are scanned like any other request content.
#
# Revision 2026-07-28 replaces server-initiated sampling and elicitation with
# Multi Round-Trip Requests: the server returns inputRequests, and the client
# answers with inputResponses on a retry of the original request. That answer is
# an outbound channel a malicious server can solicit secrets through, so it must
# be covered by the same DLP the tool arguments get.
#
# The tools/call argument case is the control: if it stops blocking, this case
# proves nothing about inputResponses.
# ---------------------------------------------------------------------------
echo "Case 7: MRTR inputResponses covered by request DLP"
cleanup
start_stack "$RIG_DIR/pipelock-scan.yaml" || exit 2
# Built at runtime so the fixture is not itself a committed credential shape.
secret="AKIA""IOSFODNN7EXAMPLE"

control="$(curl -s -H 'Content-Type: application/json' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: echo' \
  -X POST --data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{\"text\":\"$secret\"}}}" \
  "http://127.0.0.1:$PPORT/mcp")"
if printf '%s' "$control" | grep -q 'dlp_match'; then
  pass "control: secret in tool arguments is blocked"
else
  fail "control did not block, so the MRTR case below proves nothing: $control"
fi

mrtr="$(curl -s -H 'Content-Type: application/json' -H 'Mcp-Method: tools/call' -H 'Mcp-Name: echo' \
  -X POST --data "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"echo\",\"arguments\":{},\"inputResponses\":[{\"requestId\":\"r1\",\"content\":\"$secret\"}]}}" \
  "http://127.0.0.1:$PPORT/mcp")"
if printf '%s' "$mrtr" | grep -q 'dlp_match'; then
  pass "secret in MRTR inputResponses is blocked"
else
  fail "MRTR inputResponses exfiltrated a secret: $mrtr"
fi

# ---------------------------------------------------------------------------
# Case 8: a long-lived response body is not severed.
#
# Revision 2026-07-28 replaces the GET notification endpoint with
# subscriptions/listen: one long-lived POST response body. The upstream client
# therefore carries no TOTAL timeout, only a header timeout plus an idle budget.
# A total timeout would cut a healthy stream on a fixed schedule, and only an
# end-to-end stream that outlives such a bound can show the difference.
# ---------------------------------------------------------------------------
echo "Case 8: long-lived response body survives"
cleanup
start_stack "$RIG_DIR/pipelock-baseline.yaml" || exit 2

stream_out="$(mktemp -t mcp-rig-stream.XXXXXX)"
stream_hdr="$(mktemp -t mcp-rig-stream-hdr.XXXXXX)"
stream_start="$(date +%s)"
# THROUGH Pipelock ($PPORT), not the fixture directly: the point is that
# Pipelock's upstream reader does not sever a healthy long-lived body, which a
# direct call to the fixture cannot show.
curl -s --max-time 30 -D "$stream_hdr" -o "$stream_out" \
  -H 'Content-Type: application/json' -H 'Mcp-Method: subscriptions/listen' \
  -X POST --data '{"jsonrpc":"2.0","id":20,"method":"subscriptions/listen","params":{"types":["toolsListChanged"]}}' \
  "http://127.0.0.1:$PPORT/mcp" 2>/dev/null
stream_elapsed=$(( $(date +%s) - stream_start ))
events="$(grep -c 'notifications/message' "$stream_out" 2>/dev/null || echo 0)"

if [ "$events" -ge 6 ]; then
  pass "streamed $events events through Pipelock over ${stream_elapsed}s without being severed"
else
  fail "stream through Pipelock delivered $events events in ${stream_elapsed}s, want at least 6"
fi
if grep -qi 'cache-control:.*no-store' "$stream_hdr" 2>/dev/null; then
  pass "streamed response carries Cache-Control: no-store"
else
  fail "streamed response cache directive was '$(grep -i '^cache-control:' "$stream_hdr" 2>/dev/null || echo '<none>')', want no-store"
fi
rm -f "$stream_out" "$stream_hdr"

# ---------------------------------------------------------------------------
# Case 9: shape validation refuses a header the agreement check would accept.
#
# The malformed cases above also DISAGREE with the body, so their rejection is
# ambiguous: shape validation and the agreement check both produce a 400. A
# single malformed VALUE cannot separate them, because any value carrying an
# invalid byte necessarily differs from the clean method in the body, so the
# agreement check would reject it anyway.
#
# Duplication is the separable case. Both values are well formed AND agree with
# the body, so the agreement check has nothing to object to; only the singleton
# rule can reject it. The Go suite covers the malformed-value shapes directly.
# ---------------------------------------------------------------------------
echo "Case 9: shape validation rejects what agreement alone would accept"
agree_body='{"jsonrpc":"2.0","id":21,"method":"tools/list"}'

code="$(curl -s -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' -H 'Mcp-Method: tools/list' -H 'Mcp-Method: tools/list' \
  -X POST --data "$agree_body" "http://127.0.0.1:$PPORT/mcp")"
if [ "$code" = "400" ]; then
  pass "duplicate header rejected even when both values agree"
else
  fail "duplicate agreeing header got HTTP $code, want 400"
fi

cleanup
echo
printf 'passed: %d  failed: %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
