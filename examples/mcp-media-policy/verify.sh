#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# MCP media-policy verification for examples/mcp-media-policy/
#
# Stdio decoy returns text / JPEG+EXIF / audio / video. Asserts strip vs block.
#
# Usage:
#   ./verify.sh
#   PIPELOCK_BIN=/path/to/pipelock ./verify.sh
set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$EXAMPLE_DIR/../.." && pwd)"
PIPELOCK="${PIPELOCK_BIN:-$REPO_ROOT/pipelock}"
CONFIG="$EXAMPLE_DIR/pipelock.yaml"
SERVER="$EXAMPLE_DIR/media_decoy_server.py"

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
  send_json "{\"jsonrpc\":\"2.0\",\"id\":${id},\"method\":\"tools/call\",\"params\":{\"name\":\"${name}\",\"arguments\":{}}}"
  read_response "$id"
}

expect_text_ok() {
  local label="$1"
  local resp="$2"
  if printf '%s' "$resp" | grep -q 'media-decoy ok' \
    && ! printf '%s' "$resp" | grep -qE '"code"[[:space:]]*:[[:space:]]*-32002'; then
    pass "$label"
  else
    fail "$label"
    printf '%s\n' "$resp" >&2
    if [ -f "$PROXY_ERR" ]; then tail -20 "$PROXY_ERR" >&2 || true; fi
  fi
}

expect_media_block() {
  local label="$1"
  local resp="$2"
  local needle="$3"
  if printf '%s' "$resp" | grep -qE '"code"[[:space:]]*:[[:space:]]*-32002' \
    && printf '%s' "$resp" | grep -qiE "media policy|${needle}"; then
    pass "$label"
  else
    fail "$label"
    printf '%s\n' "$resp" >&2
    if [ -f "$PROXY_ERR" ]; then tail -40 "$PROXY_ERR" >&2 || true; fi
  fi
}

expect_jpeg_stripped() {
  local label="$1"
  local resp="$2"
  if printf '%s' "$resp" | grep -q 'media-decoy ok: get_jpeg_exif' \
    && ! printf '%s' "$resp" | grep -qE '"code"[[:space:]]*:[[:space:]]*-32002' \
    && printf '%s' "$resp" | python3 -c '
import base64, json, sys
r = json.load(sys.stdin)
content = (r.get("result") or {}).get("content") or []
img = next((c for c in content if c.get("type") == "image"), None)
if img is None:
    raise SystemExit("no image content")
raw = base64.b64decode(img["data"])
if b"mcp-secret-metadata" in raw:
    raise SystemExit("EXIF marker still present")
if raw[:2] != b"\xff\xd8":
    raise SystemExit("not a JPEG")
' 2>/dev/null; then
    pass "$label"
  else
    fail "$label"
    printf '%s\n' "$resp" >&2
    if [ -f "$PROXY_ERR" ]; then tail -40 "$PROXY_ERR" >&2 || true; fi
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
step "Test 1: media-policy config validates"
if "$PIPELOCK" check --config "$CONFIG" >/dev/null 2>&1; then
  pass "pipelock.yaml validates"
else
  fail "pipelock.yaml failed validation"
  "$PIPELOCK" check --config "$CONFIG" >&2 || true
fi

# -- Test 2 -------------------------------------------------------------------
step "Test 2: initialize MCP proxy + decoy"
start_proxy
send_json '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mcp-media-policy-verify","version":"0"}}}'
INIT_RESP="$(read_response 1 || true)"
if printf '%s' "$INIT_RESP" | grep -q 'media-decoy-demo\|protocolVersion\|"result"'; then
  pass "initialize succeeded"
else
  fail "initialize failed"
  printf '%s\n' "$INIT_RESP" >&2
  cat "$PROXY_ERR" >&2 || true
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi
send_json '{"jsonrpc":"2.0","method":"notifications/initialized"}'

# -- Tests 3–6 ----------------------------------------------------------------
step "Test 3: text tool result allowed"
expect_text_ok "get_text allowed" "$(call_tool 2 get_text || true)"

step "Test 4: JPEG EXIF metadata stripped"
expect_jpeg_stripped "get_jpeg_exif stripped (not blocked)" "$(call_tool 3 get_jpeg_exif || true)"

step "Test 5: audio blocked by media_policy"
expect_media_block "get_audio blocked" "$(call_tool 4 get_audio || true)" "audio"

step "Test 6: video blocked by media_policy"
expect_media_block "get_video blocked" "$(call_tool 5 get_video || true)" "video"

cleanup_proxy

# -- Summary ------------------------------------------------------------------
printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
