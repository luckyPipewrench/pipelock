#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Hot-reload verification for examples/hot-reload/
#
# Starts a local echo server + pipelock with a loopback SSRF allowlist, proves
# /fetch is allowed, atomically removes the allowlist (fsnotify + optional
# SIGHUP), then asserts the same URL is blocked without restart while /health
# stays up.
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
ECHO_PID=""
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
  if [ -n "${ECHO_PID:-}" ]; then
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
  python3 - <<'PY' "$SOURCE_CONFIG" "$CONFIG" "$proxy_port"
import sys
from pathlib import Path

src, dst, port = sys.argv[1], sys.argv[2], sys.argv[3]
out = []
listen_replaced = False
for line in Path(src).read_text().splitlines():
    if line.startswith("  listen:"):
        out.append(f'  listen: "127.0.0.1:{port}"')
        listen_replaced = True
    else:
        out.append(line)
if not listen_replaced:
    sys.exit("write_config: failed to locate listen: line in pipelock.yaml")
Path(dst).write_text("\n".join(out) + "\n")
PY
  chmod 600 "$CONFIG"
}

# Atomic rewrite: drop the ssrf block from the live temp config (keep listen port).
write_blocked_config() {
  python3 - <<'PY' "$CONFIG"
import os
import sys
from pathlib import Path

dst = sys.argv[1]
lines = Path(dst).read_text().splitlines()
out = []
in_ssrf = False
for line in lines:
    if line.startswith("ssrf:"):
        in_ssrf = True
        continue
    if in_ssrf:
        # Skip indented lines belonging to the ssrf block.
        if line.startswith(" ") or line.startswith("\t") or line.startswith("#"):
            continue
        if line == "":
            continue
        in_ssrf = False
    out.append(line)
tmp = dst + ".tmp"
Path(tmp).write_text("\n".join(out) + "\n")
os.replace(tmp, dst)
os.chmod(dst, 0o600)
PY
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

health_json() {
  local port="$1"
  local out_file="$2"
  curl -sS --max-time 2 -o "$out_file" -w '%{http_code}' "http://127.0.0.1:${port}/health"
}

uptime_seconds() {
  local health_file="$1"
  python3 - <<'PY' "$health_file"
import json, sys
print(json.load(open(sys.argv[1])).get("uptime_seconds", 0))
PY
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
  curl -sS --max-time 2 -o "$out_file" -w '%{http_code}' -G \
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
step "Test 1: hot-reload config validates"
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

# -- Test 3 -------------------------------------------------------------------
step "Test 3: baseline /fetch allowed + record health"
HEALTH_BEFORE="$WORK/health-before.json"
CODE="$(health_json "$PROXY_PORT" "$HEALTH_BEFORE")"
if [ "$CODE" = "200" ] && grep -qiE '"status"[[:space:]]*:[[:space:]]*"healthy"' "$HEALTH_BEFORE"; then
  pass "health healthy before reload"
else
  fail "health not healthy before reload (http=$CODE)"
  cat "$HEALTH_BEFORE" >&2 || true
fi
UPTIME_BEFORE="$(uptime_seconds "$HEALTH_BEFORE")"

BODY="$WORK/clean.json"
CODE="$(fetch_url "$PROXY_PORT" "http://${ECHO_ADDR}/" "$BODY")"
if [ "$CODE" = "200" ] && grep -q 'hello-from-echo' "$BODY" \
  && grep -qE '"blocked": *false|"blocked":false' "$BODY"; then
  pass "clean fetch allowed before reload"
else
  fail "clean fetch failed before reload (http=$CODE)"
  cat "$BODY" >&2 || true
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

# -- Test 4 -------------------------------------------------------------------
step "Test 4: rewrite config and trigger hot reload"
write_blocked_config
# SIGHUP is Unix-only; fsnotify already watches the directory. Harmless if unsupported.
kill -HUP "$PROXY_PID" 2>/dev/null || true
pass "wrote blocked-phase config (fsnotify + optional SIGHUP)"

BLOCKED=0
BODY="$WORK/post-reload.json"
for _ in $(seq 1 80); do
  CODE="$(fetch_url "$PROXY_PORT" "http://${ECHO_ADDR}/" "$BODY")"
  if [ "$CODE" = "403" ] && grep -qiE 'blocked.: *true|"blocked":true' "$BODY" \
    && grep -qiE 'ssrf|127\.0\.0\.1|private|internal' "$BODY"; then
    BLOCKED=1
    break
  fi
  sleep 0.1
done
if [ "$BLOCKED" = "1" ]; then
  pass "same echo URL blocked after reload (HTTP 403)"
else
  fail "echo URL still allowed after reload (last http=$CODE)"
  cat "$BODY" >&2 || true
  tail -40 "$PROXY_LOG" >&2 || true
fi

# -- Test 5 -------------------------------------------------------------------
step "Test 5: /health stays up; same process"
HEALTH_AFTER="$WORK/health-after.json"
CODE="$(health_json "$PROXY_PORT" "$HEALTH_AFTER")"
if [ "$CODE" = "200" ] && grep -qiE '"status"[[:space:]]*:[[:space:]]*"healthy"' "$HEALTH_AFTER"; then
  pass "health still healthy after reload"
else
  fail "health not healthy after reload (http=$CODE)"
  cat "$HEALTH_AFTER" >&2 || true
fi

if kill -0 "$PROXY_PID" 2>/dev/null; then
  pass "same pipelock PID still running ($PROXY_PID)"
else
  fail "pipelock process exited during reload"
fi

UPTIME_AFTER="$(uptime_seconds "$HEALTH_AFTER")"
if python3 - <<PY
import sys
sys.exit(0 if float("$UPTIME_AFTER") >= float("$UPTIME_BEFORE") else 1)
PY
then
  pass "uptime_seconds non-decreasing ($UPTIME_BEFORE → $UPTIME_AFTER)"
else
  fail "uptime decreased ($UPTIME_BEFORE → $UPTIME_AFTER) — process may have restarted"
fi

# -- Summary ------------------------------------------------------------------
printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
