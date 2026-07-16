#!/usr/bin/env bash
# Kill switch verification for examples/kill-switch/
#
# Starts a local echo server + pipelock, proves fetch works, then activates a
# sentinel file and confirms HTTP 503 while /health stays healthy.
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
SENTINEL="$WORK/pipelock-kill"
ECHO_LOG="$WORK/echo.log"
PROXY_LOG="$WORK/pipelock.log"
ECHO_PID=""
PROXY_PID=""

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
  python3 - <<'PY' "$SOURCE_CONFIG" "$CONFIG" "$proxy_port" "$SENTINEL"
import sys
from pathlib import Path

src, dst, port, sentinel = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
out = []
for line in Path(src).read_text().splitlines():
    if line.startswith("  listen:"):
        out.append(f'  listen: "127.0.0.1:{port}"')
    elif line.startswith("  sentinel_file:"):
        out.append(f'  sentinel_file: "{sentinel}"')
    else:
        out.append(line)
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

health_field() {
  local port="$1"
  local field="$2"
  local health_json
  health_json="$(mktemp "$WORK/health.XXXXXX.json")"
  curl -sf -o "$health_json" "http://127.0.0.1:${port}/health"
  python3 -c \
    'import json,sys; print(json.load(open(sys.argv[2], encoding="utf-8")).get(sys.argv[1],""))' \
    "$field" "$health_json"
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
  if [ -z "$ECHO_ADDR" ]; then
    return 1
  fi
  return 0
}

fetch_url() {
  local port="$1"
  local url="$2"
  local out_file="$3"
  curl -sS -o "$out_file" -w '%{http_code}' -G \
    --data-urlencode "url=${url}" \
    "http://127.0.0.1:${port}/fetch"
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
step "Test 1: kill-switch example config validates"
if "$PIPELOCK" check --config "$SOURCE_CONFIG" >/dev/null 2>&1; then
  pass "pipelock.yaml validates"
else
  fail "pipelock.yaml failed validation"
fi

# -- Test 2 -------------------------------------------------------------------
step "Test 2: start echo server and pipelock"
PROXY_PORT="$(pick_port)"
write_config "$PROXY_PORT"

if start_echo; then
  pass "echo server listening on $ECHO_ADDR"
else
  fail "echo server did not start"
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

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

KS="$(health_field "$PROXY_PORT" kill_switch_active || true)"
if [ "$KS" = "False" ] || [ "$KS" = "false" ] || [ "$KS" = "" ]; then
  pass "kill_switch_active is false at start"
else
  fail "kill_switch_active unexpected at start (got $KS)"
fi

# -- Test 3 -------------------------------------------------------------------
step "Test 3: fetch works while kill switch is inactive"
FETCH_BODY="$WORK/fetch-ok.json"
CODE="$(fetch_url "$PROXY_PORT" "http://${ECHO_ADDR}/" "$FETCH_BODY")"
if [ "$CODE" = "200" ] && grep -q 'hello-from-echo' "$FETCH_BODY" \
  && grep -q '"blocked": *false' "$FETCH_BODY"; then
  pass "clean fetch returned echo content"
else
  fail "clean fetch failed (http=$CODE)"
  cat "$FETCH_BODY" >&2 || true
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

# -- Test 4 -------------------------------------------------------------------
step "Test 4: sentinel activates kill switch"
touch "$SENTINEL"
BLOCK_BODY="$WORK/fetch-blocked.json"
ACTIVATED=0
CODE=""
for _ in $(seq 1 20); do
  CODE="$(fetch_url "$PROXY_PORT" "http://${ECHO_ADDR}/" "$BLOCK_BODY")"
  if [ "$CODE" = "503" ] && grep -q 'kill_switch_active' "$BLOCK_BODY"; then
    ACTIVATED=1
    break
  fi
  sleep 0.1
done
if [ "$ACTIVATED" -eq 1 ]; then
  pass "fetch blocked with HTTP 503 kill_switch_active"
else
  fail "expected HTTP 503 kill_switch_active (http=$CODE)"
  cat "$BLOCK_BODY" >&2 || true
fi

KS="$(health_field "$PROXY_PORT" kill_switch_active || true)"
if [ "$KS" = "True" ] || [ "$KS" = "true" ]; then
  pass "health reports kill_switch_active=true"
else
  fail "health kill_switch_active not true (got $KS)"
fi

HEALTH_CODE="$(curl -sS -o "$WORK/health.json" -w '%{http_code}' \
  "http://127.0.0.1:${PROXY_PORT}/health")"
if [ "$HEALTH_CODE" = "200" ]; then
  pass "health endpoint still returns HTTP 200"
else
  fail "health endpoint expected 200 (got $HEALTH_CODE)"
fi

# -- Test 5 -------------------------------------------------------------------
step "Test 5: removing sentinel clears kill switch"
rm -f "$SENTINEL"
# Poll briefly until fetch works again (sentinel is checked on each request).
CLEARED=0
for _ in $(seq 1 20); do
  CODE="$(fetch_url "$PROXY_PORT" "http://${ECHO_ADDR}/" "$WORK/fetch-clear.json")"
  if [ "$CODE" = "200" ] && grep -q 'hello-from-echo' "$WORK/fetch-clear.json"; then
    CLEARED=1
    break
  fi
  sleep 0.1
done
if [ "$CLEARED" -eq 1 ]; then
  pass "fetch restored after sentinel removed"
else
  fail "fetch still blocked after sentinel removal"
  cat "$WORK/fetch-clear.json" >&2 || true
fi

KS="$(health_field "$PROXY_PORT" kill_switch_active || true)"
if [ "$KS" = "False" ] || [ "$KS" = "false" ] || [ "$KS" = "" ]; then
  pass "kill_switch_active cleared after sentinel removal"
else
  fail "kill_switch_active still set (got $KS)"
fi

# -- Summary ------------------------------------------------------------------
printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
