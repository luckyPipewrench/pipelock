#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Request-policy GraphQL verification for examples/request-policy-graphql/
#
# Local GraphQL stub + forward proxy prove allow query / deny mutation /
# alias block / parse fail-closed. Fully offline.
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
CONFIG="$WORK/pipelock.yaml"
API_LOG="$WORK/api.log"
PROXY_LOG="$WORK/pipelock.log"
API_PID=""
PROXY_PID=""

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '\033[32m  [PASS]\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '\033[31m  [FAIL]\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m--- %s ---\033[0m\n' "$1"; }

cleanup() {
  if [ -n "${PROXY_PID:-}" ]; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  if [ -n "${API_PID:-}" ]; then
    kill "$API_PID" 2>/dev/null || true
    wait "$API_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

pick_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

write_config() {
  local proxy_port="$1"
  python3 - <<'PY' "$SOURCE_CONFIG" "$CONFIG" "$proxy_port"
import sys
from pathlib import Path

src, dst, port = sys.argv[1:4]
out = []
listen_ok = False
for line in Path(src).read_text().splitlines():
    if line.startswith("  listen:"):
        out.append(f'  listen: "127.0.0.1:{port}"')
        listen_ok = True
    else:
        out.append(line)
if not listen_ok:
    sys.exit("write_config: failed to locate listen: line")
Path(dst).write_text("\n".join(out) + "\n")
PY
  chmod 600 "$CONFIG"
}

wait_for_health() {
  local port="$1"
  for _ in $(seq 1 80); do
    if curl -sf --max-time 1 "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

start_api() {
  local port="$1"
  python3 - <<PY >"$API_LOG" 2>&1 &
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int("$port")

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/graphql":
            self.send_error(404)
            return
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n)
        try:
            doc = json.loads(raw.decode("utf-8"))
        except Exception:
            self.send_error(400)
            return
        q = (doc.get("query") or "").lstrip()
        kind = "mutation" if q.startswith("mutation") else "query"
        body = json.dumps({"data": {"ok": True}, "extensions": {"kind": kind}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return

HTTPServer(("127.0.0.1", PORT), H).serve_forever()
PY
  API_PID=$!
  for _ in $(seq 1 50); do
    if curl -sf --max-time 1 -X POST "http://127.0.0.1:${port}/graphql" \
      -H 'Content-Type: application/json' \
      -d '{"query":"query { ping }"}' >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

proxy_post() {
  local proxy="$1"
  local api="$2"
  local body="$3"
  local hdr="$4"
  local out="$5"
  # --noproxy '' is required: many environments set no_proxy=127.0.0.1 and
  # would silently bypass pipelock, making request_policy look like a no-op.
  # Target hostname is the neutral placeholder; dns.host_overrides dials loopback.
  curl -sS --max-time 5 --noproxy '' -D "$hdr" -o "$out" -x "http://127.0.0.1:${proxy}" \
    -X POST "http://api.vendor.example:${api}/graphql" \
    -H 'Content-Type: application/json' \
    -d "$body" -w '%{http_code}'
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
step "Test 1: config validates"
if "$PIPELOCK" check --config "$SOURCE_CONFIG" >/dev/null 2>&1; then
  pass "pipelock.yaml validates"
else
  fail "pipelock.yaml failed validation"
  "$PIPELOCK" check --config "$SOURCE_CONFIG" >&2 || true
fi

# -- Test 2 -------------------------------------------------------------------
step "Test 2: start GraphQL stub and pipelock"
# Bind the API first, then pick the proxy port so the two pick_port calls
# cannot collide on the same free port.
API_PORT="$(pick_port)"

if start_api "$API_PORT"; then
  pass "GraphQL stub on 127.0.0.1:$API_PORT"
else
  fail "GraphQL stub did not start"
  cat "$API_LOG" >&2 || true
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

PROXY_PORT="$(pick_port)"
write_config "$PROXY_PORT"

"$PIPELOCK" run --config "$CONFIG" >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

if wait_for_health "$PROXY_PORT"; then
  pass "pipelock healthy on 127.0.0.1:$PROXY_PORT"
else
  fail "pipelock did not become healthy"
  tail -40 "$PROXY_LOG" >&2 || true
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

# -- Test 3 -------------------------------------------------------------------
step "Test 3: benign GraphQL query allowed"
HDR="$WORK/h-allow.txt"
BODY="$WORK/b-allow.json"
CODE="$(proxy_post "$PROXY_PORT" "$API_PORT" '{"query":"query { record { id } }"}' "$HDR" "$BODY")"
if [ "$CODE" = "200" ] && grep -q '"ok": true\|"ok":true' "$BODY" \
  && ! grep -qi 'X-Pipelock-Block-Reason' "$HDR"; then
  pass "query forwarded (HTTP 200)"
else
  fail "query not allowed (http=$CODE)"
  cat "$HDR" "$BODY" >&2 || true
fi

# -- Test 4 -------------------------------------------------------------------
step "Test 4: deleteRecord mutation blocked"
HDR="$WORK/h-deny.txt"
BODY="$WORK/b-deny.txt"
CODE="$(proxy_post "$PROXY_PORT" "$API_PORT" '{"query":"mutation { deleteRecord { id } }"}' "$HDR" "$BODY")"
if [ "$CODE" = "403" ] && grep -qiE 'X-Pipelock-Block-Reason:[[:space:]]*request_policy_deny' "$HDR" \
  && grep -qi 'request policy\|deleteRecord' "$BODY"; then
  pass "mutation blocked (403 request_policy_deny)"
else
  fail "mutation not blocked (http=$CODE)"
  cat "$HDR" "$BODY" >&2 || true
fi

# -- Test 5 -------------------------------------------------------------------
step "Test 5: aliased deleteRecord still blocked"
HDR="$WORK/h-alias.txt"
BODY="$WORK/b-alias.txt"
CODE="$(proxy_post "$PROXY_PORT" "$API_PORT" '{"query":"mutation { rm: deleteRecord { id } }"}' "$HDR" "$BODY")"
if [ "$CODE" = "403" ] && grep -qiE 'X-Pipelock-Block-Reason:[[:space:]]*request_policy_deny' "$HDR"; then
  pass "aliased mutation blocked"
else
  fail "aliased mutation not blocked (http=$CODE)"
  cat "$HDR" "$BODY" >&2 || true
fi

# -- Test 6 -------------------------------------------------------------------
step "Test 6: malformed GraphQL fails closed on matched route"
HDR="$WORK/h-bad.txt"
BODY="$WORK/b-bad.txt"
CODE="$(proxy_post "$PROXY_PORT" "$API_PORT" '{"query":"mutation { deleteRecord "}' "$HDR" "$BODY")"
if [ "$CODE" = "403" ] && grep -qiE 'X-Pipelock-Block-Reason:[[:space:]]*request_policy_deny' "$HDR"; then
  pass "parse error fail-closed (403)"
else
  fail "parse error not fail-closed (http=$CODE)"
  cat "$HDR" "$BODY" >&2 || true
fi

# -- Summary ------------------------------------------------------------------
printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
