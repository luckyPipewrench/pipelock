#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# SIEM event emission verification for examples/siem-events/
#
# Starts a local webhook collector + pipelock, proves a clean fetch emits no
# blocked event, then SSRF-blocks metadata IP and asserts the webhook payload.
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
ECHO_LOG="$WORK/echo.log"
PROXY_LOG="$WORK/pipelock.log"
WEBHOOK_LOG="$WORK/webhook.log"
ECHO_PID=""
PROXY_PID=""
WEBHOOK_PID=""

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '\033[32m  [PASS]\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '\033[31m  [FAIL]\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m--- %s ---\033[0m\n' "$1"; }

cleanup() {
  if [ -n "$PROXY_PID" ]; then
    kill "$PROXY_PID" 2>/dev/null || true
    wait "$PROXY_PID" 2>/dev/null || true
  fi
  if [ -n "$ECHO_PID" ]; then
    kill "$ECHO_PID" 2>/dev/null || true
    wait "$ECHO_PID" 2>/dev/null || true
  fi
  if [ -n "$WEBHOOK_PID" ]; then
    kill "$WEBHOOK_PID" 2>/dev/null || true
    wait "$WEBHOOK_PID" 2>/dev/null || true
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
  local webhook_port="$2"
  python3 - <<'PY' "$SOURCE_CONFIG" "$CONFIG" "$proxy_port" "$webhook_port"
import sys
from pathlib import Path

src, dst, proxy_port, webhook_port = sys.argv[1:5]
out = []
listen_replaced = False
url_replaced = False
for line in Path(src).read_text().splitlines():
    if line.startswith("  listen:"):
        out.append(f'  listen: "127.0.0.1:{proxy_port}"')
        listen_replaced = True
    elif line.strip().startswith("url:") and "events" in line:
        out.append(f'    url: "http://127.0.0.1:{webhook_port}/events"')
        url_replaced = True
    else:
        out.append(line)
if not (listen_replaced and url_replaced):
    sys.exit("write_config: failed to locate listen: and/or webhook url: lines in pipelock.yaml")
Path(dst).write_text("\n".join(out) + "\n")
PY
  chmod 600 "$CONFIG"
}

wait_for_health() {
  local port="$1"
  for _ in $(seq 1 80); do
    if curl -sf "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

start_webhook() {
  python3 - <<'PY' >"$WEBHOOK_LOG" 2>&1 &
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

EVENTS = []

class H(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/events":
            self.send_response(404)
            self.end_headers()
            return
        n = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(n)
        try:
            EVENTS.append(json.loads(body.decode("utf-8")))
        except Exception:
            EVENTS.append({"raw": body.decode("utf-8", "replace")})
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        if self.path == "/events":
            data = json.dumps(EVENTS).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path == "/events/count":
            data = str(len(EVENTS)).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, fmt, *args):
        return

httpd = HTTPServer(("127.0.0.1", 0), H)
host, port = httpd.server_address
print(f"127.0.0.1:{port}", flush=True)
httpd.serve_forever()
PY
  WEBHOOK_PID=$!
  WEBHOOK_ADDR=""
  for _ in $(seq 1 50); do
    WEBHOOK_ADDR="$(grep -Eo '127\.0\.0\.1:[0-9]+' "$WEBHOOK_LOG" | tail -1 || true)"
    if [ -n "$WEBHOOK_ADDR" ]; then
      break
    fi
    sleep 0.1
  done
  [ -n "$WEBHOOK_ADDR" ]
}

start_echo() {
  python3 - <<'PY' >"$ECHO_LOG" 2>&1 &
import http.server
import socketserver

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"hello-from-echo"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return

with socketserver.TCPServer(("127.0.0.1", 0), H) as httpd:
    host, port = httpd.server_address
    print(f"127.0.0.1:{port}", flush=True)
    httpd.serve_forever()
PY
  ECHO_PID=$!
  ECHO_ADDR=""
  for _ in $(seq 1 50); do
    ECHO_ADDR="$(grep -Eo '127\.0\.0\.1:[0-9]+' "$ECHO_LOG" | tail -1 || true)"
    if [ -n "$ECHO_ADDR" ]; then
      break
    fi
    sleep 0.1
  done
  [ -n "$ECHO_ADDR" ]
}

fetch_url() {
  local port="$1"
  local url="$2"
  local out_file="$3"
  curl -sS -o "$out_file" -w '%{http_code}' -G \
    --data-urlencode "url=${url}" \
    "http://127.0.0.1:${port}/fetch"
}

wait_for_blocked_event() {
  local deadline=$(( $(date +%s) + 8 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    events_json="$(curl -sf "http://${WEBHOOK_ADDR}/events" 2>/dev/null || true)"
    if [ -n "$events_json" ] && python3 -c '
import json,sys
events=json.load(sys.stdin)
for e in events:
    if e.get("type")=="blocked" and str(e.get("severity","")).lower()=="warn":
        fields=e.get("fields") or {}
        scanner=str(fields.get("scanner",""))
        if "ssrf" in scanner.lower() or "169.254" in str(fields.get("url","")) or "ssrf" in str(fields.get("reason","")).lower():
            print("ok")
            raise SystemExit(0)
raise SystemExit(1)
' <<<"$events_json" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 1
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
step "Test 1: siem-events config validates"
if "$PIPELOCK" check --config "$SOURCE_CONFIG" >/dev/null 2>&1; then
  pass "pipelock.yaml validates"
else
  fail "pipelock.yaml failed validation"
  "$PIPELOCK" check --config "$SOURCE_CONFIG" >&2 || true
fi

# -- Test 2 -------------------------------------------------------------------
step "Test 2: start webhook, echo, and pipelock"
if start_webhook; then
  WEBHOOK_PORT="${WEBHOOK_ADDR##*:}"
  pass "webhook collector on $WEBHOOK_ADDR"
else
  fail "webhook collector did not start"
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

if start_echo; then
  pass "echo server on $ECHO_ADDR"
else
  fail "echo server did not start"
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

PROXY_PORT="$(pick_port)"
write_config "$PROXY_PORT" "$WEBHOOK_PORT"

"$PIPELOCK" run --config "$CONFIG" >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

if wait_for_health "$PROXY_PORT"; then
  pass "pipelock healthy on 127.0.0.1:$PROXY_PORT"
else
  fail "pipelock did not become healthy"
  tail -30 "$PROXY_LOG" >&2 || true
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

# -- Test 3 -------------------------------------------------------------------
step "Test 3: clean fetch does not emit blocked event"
BODY="$WORK/clean.json"
CODE="$(fetch_url "$PROXY_PORT" "http://${ECHO_ADDR}/" "$BODY")"
if [ "$CODE" = "200" ] && grep -q 'hello-from-echo' "$BODY"; then
  pass "clean fetch allowed"
else
  fail "clean fetch failed (http=$CODE)"
  cat "$BODY" >&2 || true
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi
sleep 0.3
CLEAN_EVENTS_JSON="$(curl -sf "http://${WEBHOOK_ADDR}/events" 2>/dev/null || echo '[]')"
BLOCKED_AFTER_CLEAN="$(python3 -c 'import json,sys; print(sum(1 for e in json.load(sys.stdin) if e.get("type")=="blocked"))' <<<"${CLEAN_EVENTS_JSON:-[]}" 2>/dev/null || echo 0)"
if [ "$BLOCKED_AFTER_CLEAN" = "0" ]; then
  pass "no blocked webhook events after clean fetch"
else
  fail "unexpected blocked events after clean fetch (count=$BLOCKED_AFTER_CLEAN)"
  curl -sf "http://${WEBHOOK_ADDR}/events" >&2 || true
fi

# -- Test 4 -------------------------------------------------------------------
step "Test 4: SSRF block emits webhook event"
BODY="$WORK/ssrf.json"
CODE="$(fetch_url "$PROXY_PORT" "http://169.254.169.254/latest/meta-data/" "$BODY")"
if [ "$CODE" = "403" ] && grep -qiE 'blocked.: *true|"blocked":true' "$BODY"; then
  pass "metadata SSRF fetch blocked (HTTP 403)"
else
  fail "expected SSRF block (http=$CODE)"
  cat "$BODY" >&2 || true
fi

if wait_for_blocked_event; then
  pass "webhook received blocked/ssrf event"
else
  fail "webhook missing blocked/ssrf event"
  curl -sf "http://${WEBHOOK_ADDR}/events" >&2 || true
  tail -30 "$PROXY_LOG" >&2 || true
fi

# Assert instance id when present
if curl -sf "http://${WEBHOOK_ADDR}/events" | grep -q 'siem-events-example'; then
  pass "event includes instance_id siem-events-example"
else
  fail "event missing instance_id"
fi

# -- Summary ------------------------------------------------------------------
printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
