#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# SSE streaming scan verification for examples/sse-streaming-scan/
#
# Starts a local SSE upstream + pipelock reverse_proxy. Asserts clean events
# pass and injection truncates the stream so "never reached" is absent.
#
# Usage:
#   ./verify.sh
#   PIPELOCK_BIN=/path/to/pipelock ./verify.sh
set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
PIPELOCK="${PIPELOCK_BIN:-$REPO_ROOT/pipelock}"
SOURCE_CONFIG="$EXAMPLE_DIR/pipelock.yaml"
UPSTREAM_PY="$EXAMPLE_DIR/sse_upstream.py"
WORK="$(mktemp -d)"
CONFIG="$WORK/pipelock.yaml"
PROXY_LOG="$WORK/pipelock.log"
UPSTREAM_LOG="$WORK/upstream.log"
PROXY_PID=""
UPSTREAM_PID=""

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
  if [ -n "${UPSTREAM_PID:-}" ]; then
    kill "$UPSTREAM_PID" 2>/dev/null || true
    wait "$UPSTREAM_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT

pick_ports() {
  local count="$1"
  python3 - <<PY
import socket
socks = []
ports = []
for _ in range($count):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    ports.append(str(s.getsockname()[1]))
    socks.append(s)
for s in socks:
    s.close()
print(" ".join(ports))
PY
}

write_config() {
  local fetch_port="$1"
  local reverse_port="$2"
  local upstream_port="$3"
  python3 - <<'PY' "$SOURCE_CONFIG" "$CONFIG" "$fetch_port" "$reverse_port" "$upstream_port"
import sys
from pathlib import Path

src, dst, fetch_port, reverse_port, upstream_port = sys.argv[1:6]
out = []
fetch_ok = reverse_ok = upstream_ok = False
in_fetch = in_reverse = False
for line in Path(src).read_text().splitlines():
    if line.startswith("fetch_proxy:"):
        in_fetch, in_reverse = True, False
        out.append(line)
        continue
    if line.startswith("reverse_proxy:"):
        in_fetch, in_reverse = False, True
        out.append(line)
        continue
    if line and not line.startswith(" ") and not line.startswith("#"):
        in_fetch = in_reverse = False
    if in_fetch and line.startswith("  listen:"):
        out.append(f'  listen: "127.0.0.1:{fetch_port}"')
        fetch_ok = True
    elif in_reverse and line.startswith("  listen:"):
        out.append(f'  listen: "127.0.0.1:{reverse_port}"')
        reverse_ok = True
    elif in_reverse and line.startswith("  upstream:"):
        out.append(f'  upstream: "http://127.0.0.1:{upstream_port}"')
        upstream_ok = True
    else:
        out.append(line)
if not (fetch_ok and reverse_ok and upstream_ok):
    sys.exit("write_config: failed to rewrite fetch/reverse listen + upstream")
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

wait_for_upstream() {
  local port="$1"
  for _ in $(seq 1 80); do
    if curl -sf --max-time 1 "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
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
step "Test 1: sse-streaming-scan config validates"
if "$PIPELOCK" check --config "$SOURCE_CONFIG" >/dev/null 2>&1; then
  pass "pipelock.yaml validates"
else
  fail "pipelock.yaml failed validation"
  "$PIPELOCK" check --config "$SOURCE_CONFIG" >&2 || true
fi

# -- Start upstream + proxy ---------------------------------------------------
# Bind upstream first; then reserve fetch+reverse ports together so they cannot
# collide with each other or with the upstream listener.
step "Test 2: start SSE upstream + reverse proxy"
read -r UPSTREAM_PORT < <(pick_ports 1)
python3 "$UPSTREAM_PY" "$UPSTREAM_PORT" >"$UPSTREAM_LOG" 2>&1 &
UPSTREAM_PID=$!
if ! wait_for_upstream "$UPSTREAM_PORT"; then
  fail "SSE upstream did not become ready"
  cat "$UPSTREAM_LOG" >&2 || true
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

read -r FETCH_PORT REVERSE_PORT < <(pick_ports 2)
write_config "$FETCH_PORT" "$REVERSE_PORT" "$UPSTREAM_PORT"

"$PIPELOCK" run --config "$CONFIG" >"$PROXY_LOG" 2>&1 &
PROXY_PID=$!
if ! wait_for_health "$FETCH_PORT"; then
  fail "pipelock did not become healthy"
  cat "$PROXY_LOG" >&2 || true
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi
pass "upstream + reverse proxy ready (reverse :${REVERSE_PORT})"

# -- Test 3: clean stream -----------------------------------------------------
step "Test 3: clean SSE events pass through"
CLEAN_BODY="$(curl -sS --max-time 10 "http://127.0.0.1:${REVERSE_PORT}/clean" 2>/dev/null || true)"
if printf '%s' "$CLEAN_BODY" | grep -q 'hello-token' \
  && printf '%s' "$CLEAN_BODY" | grep -q 'world-token'; then
  pass "clean stream delivered both events"
else
  fail "clean stream missing expected tokens"
  printf '%s\n' "$CLEAN_BODY" >&2
  tail -40 "$PROXY_LOG" >&2 || true
fi

# -- Test 4: injection truncates ----------------------------------------------
step "Test 4: injection event terminates stream"
# Truncation closes the connection mid-transfer; curl may exit 18 — body is what matters.
INJECT_BODY="$(curl -sS --max-time 10 "http://127.0.0.1:${REVERSE_PORT}/inject" 2>/dev/null || true)"
if printf '%s' "$INJECT_BODY" | grep -q 'clean-prefix' \
  && ! printf '%s' "$INJECT_BODY" | grep -q 'never reached'; then
  pass "stream truncated before post-detection event"
else
  fail "injection did not truncate stream as expected"
  printf '%s\n' "$INJECT_BODY" >&2
  tail -60 "$PROXY_LOG" >&2 || true
fi

# -- Summary ------------------------------------------------------------------
printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
