#!/usr/bin/env bash
# WebSocket proxy verification for examples/websocket-proxy/
#
# Starts a local echo server and pipelock with websocket_proxy enabled, then
# exercises clean echo and DLP-blocked client frames. Exit 0 = all pass.
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
ECHO_LOG="$WORK/ws-echo.log"
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
  python3 - <<'PY' "$SOURCE_CONFIG" "$CONFIG" "$proxy_port"
import sys
from pathlib import Path

src, dst, port = sys.argv[1], sys.argv[2], sys.argv[3]
lines = Path(src).read_text().splitlines()
out = []
for line in lines:
    if line.startswith('  listen:'):
        out.append(f'  listen: "127.0.0.1:{port}"')
    else:
        out.append(line)
Path(dst).write_text("\n".join(out) + "\n")
PY
  chmod 600 "$CONFIG"
}

wait_for_health() {
  local port="$1"
  local i
  for i in $(seq 1 50); do
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
  curl -sf "http://127.0.0.1:${port}/health" | python3 -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1],""))' "$field"
}

# -- Test 0: Binary available -------------------------------------------------
step "Test 0: pipelock binary is available"
if [ ! -x "$PIPELOCK" ] && ! command -v "$PIPELOCK" >/dev/null 2>&1; then
  fail "pipelock not found at $PIPELOCK (run 'make build' or set PIPELOCK_BIN)"
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi
pass "pipelock available ($PIPELOCK)"

# -- Test 1: Config validates -------------------------------------------------
step "Test 1: websocket example config validates"
if "$PIPELOCK" check --config "$SOURCE_CONFIG" >/dev/null 2>&1; then
  pass "pipelock.yaml validates"
else
  fail "pipelock.yaml failed validation"
fi

# -- Test 2: Start echo server and proxy --------------------------------------
step "Test 2: start echo server and pipelock proxy"
PROXY_PORT="$(pick_port)"
write_config "$PROXY_PORT"

# Warm Go module cache so ws_echo startup prints only the listen address.
(
  cd "$REPO_ROOT"
  go build -o /dev/null "$EXAMPLE_DIR/ws_echo.go" "$EXAMPLE_DIR/ws_probe.go" >/dev/null 2>&1
) || true

(
  cd "$REPO_ROOT"
  go run "$EXAMPLE_DIR/ws_echo.go"
) >"$ECHO_LOG" 2>&1 &
ECHO_PID=$!

ECHO_ADDR=""
for _ in $(seq 1 100); do
  ECHO_ADDR="$(grep -Eo '127\.0\.0\.1:[0-9]+' "$ECHO_LOG" | tail -1 || true)"
  if [ -n "$ECHO_ADDR" ]; then
    break
  fi
  sleep 0.1
done
if [ -z "$ECHO_ADDR" ]; then
  fail "echo server did not print listen address"
  tail -20 "$ECHO_LOG" >&2 || true
else
  pass "echo server listening on $ECHO_ADDR"
fi

"$PIPELOCK" run --config "$CONFIG" >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!

if wait_for_health "$PROXY_PORT"; then
  pass "pipelock proxy healthy on 127.0.0.1:$PROXY_PORT"
else
  fail "pipelock proxy did not become healthy"
  tail -20 "$PROXY_LOG" >&2 || true
fi

WS_ENABLED="$(health_field "$PROXY_PORT" websocket_proxy_enabled || true)"
if [ "$WS_ENABLED" = "True" ] || [ "$WS_ENABLED" = "true" ]; then
  pass "health reports websocket_proxy_enabled=true"
else
  fail "websocket_proxy_enabled not true (got $WS_ENABLED)"
fi

# -- Test 3: Clean text frame echoes ------------------------------------------
step "Test 3: clean WebSocket text frame echoes through proxy"
if (
  cd "$REPO_ROOT"
  go run "$EXAMPLE_DIR/ws_probe.go" \
    -proxy "127.0.0.1:${PROXY_PORT}" \
    -backend "$ECHO_ADDR" \
    -message "hello-from-verify" \
    -expect echo
); then
  pass "clean message echoed"
else
  fail "clean message was not echoed"
fi

# -- Test 4: DLP blocks secret in client frame --------------------------------
step "Test 4: DLP blocks secret in outbound WebSocket frame"
SECRET_MSG="$(python3 - <<'PY'
import secrets
print("sk-ant-api03-" + secrets.token_hex(18))
PY
)"
if (
  cd "$REPO_ROOT"
  go run "$EXAMPLE_DIR/ws_probe.go" \
    -proxy "127.0.0.1:${PROXY_PORT}" \
    -backend "$ECHO_ADDR" \
    -message "$SECRET_MSG" \
    -expect close
); then
  pass "secret frame closed connection (blocked)"
else
  fail "secret frame was not blocked"
fi

# -- Test 5: Binary frames rejected -------------------------------------------
step "Test 5: binary WebSocket frames are rejected"
if (
  cd "$REPO_ROOT"
  go run "$EXAMPLE_DIR/ws_probe.go" \
    -proxy "127.0.0.1:${PROXY_PORT}" \
    -backend "$ECHO_ADDR" \
    -frame binary \
    -expect close
); then
  pass "binary frame rejected"
else
  fail "binary frame was not rejected"
fi

# -- Summary ------------------------------------------------------------------
printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
