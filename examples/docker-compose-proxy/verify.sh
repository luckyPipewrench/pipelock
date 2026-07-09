#!/usr/bin/env bash
# Docker Compose proxy verification for examples/docker-compose-proxy/
#
# Starts docker-compose (local upstream + pipelock) and verifies:
# - proxy is healthy on 127.0.0.1:${PIPELOCK_PROXY_PORT:-18088}
# - curl routes traffic through pipelock to the upstream service
# - DLP blocks a runtime-generated secret-shaped string
#
# Usage:
#   ./verify.sh
set -euo pipefail

EXAMPLE_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="$EXAMPLE_DIR/work"
PIPELOCK_PROXY_HOST="127.0.0.1"
PIPELOCK_PROXY_PORT="${PIPELOCK_PROXY_PORT:-18088}"
PIPELOCK_PROXY_URL="http://${PIPELOCK_PROXY_HOST}:${PIPELOCK_PROXY_PORT}"
export PIPELOCK_PROXY_PORT

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); printf '\033[32m  [PASS]\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '\033[31m  [FAIL]\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m--- %s ---\033[0m\n' "$1"; }

cleanup() {
  (cd "$EXAMPLE_DIR" && docker compose down -v >/dev/null 2>&1) || true
}
trap cleanup EXIT

mkdir -p "$WORK"

wait_for_health() {
  for _ in $(seq 1 80); do
    if curl -sf "${PIPELOCK_PROXY_URL}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

# -- Test 0: docker compose is available ---------------------------------------
step "Test 0: docker compose is available"
if docker compose version >/dev/null 2>&1; then
  pass "docker compose available"
else
  fail "docker compose not available"
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

step "Test 0b: Docker daemon is running"
if docker info >/dev/null 2>&1; then
  pass "docker daemon available"
else
  fail "docker daemon not running (start Docker Desktop / Engine)"
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

# -- Test 1: build and start ---------------------------------------------------
step "Test 1: build and start docker compose"
if (
  cd "$EXAMPLE_DIR"
  docker compose build >/dev/null
  docker compose up -d >/dev/null
) >/dev/null 2>&1; then
  pass "compose started"
else
  fail "compose failed to start"
  (cd "$EXAMPLE_DIR" && docker compose logs --no-color) >&2 || true
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

if wait_for_health; then
  pass "pipelock healthy on ${PIPELOCK_PROXY_HOST}:${PIPELOCK_PROXY_PORT}"
else
  fail "pipelock did not become healthy"
  (cd "$EXAMPLE_DIR" && docker compose logs --no-color pipelock) >&2 || true
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

# -- Test 2: curl proxy flag routes to upstream --------------------------------
step "Test 2: curl proxy flag routes request through pipelock"
OUT="$(
  curl -x "$PIPELOCK_PROXY_URL" --noproxy "" -fsS --max-time 10 "http://upstream:8080/" 2>&1
)" && true
if [ "$OUT" = "hello-from-upstream" ]; then
  pass "upstream response reached via proxy"
else
  fail "unexpected upstream response via proxy"
  printf '%s\n' "$OUT" >&2
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

# -- Test 3: DLP blocks secret-shaped value ------------------------------------
step "Test 3: DLP blocks secret-shaped value"
SECRET="$(python3 - <<'PY'
import secrets
print("sk-ant-api03-" + secrets.token_hex(18))
PY
)"
BLOCK_BODY="$WORK/blocked-body.txt"
HTTP_CODE="$(
  curl -x "$PIPELOCK_PROXY_URL" --noproxy "" -sS --max-time 10 \
    -H "Authorization: Bearer ${SECRET}" \
    -o "$BLOCK_BODY" \
    -w '%{http_code}' \
    "http://upstream:8080/"
)"

if [ "$HTTP_CODE" != "200" ] && grep -qiE 'blocked|policy|forbidden|denied' "$BLOCK_BODY"; then
  pass "secret request blocked by proxy"
else
  fail "secret request was not blocked (http_code=$HTTP_CODE)"
  printf 'body:\n' >&2
  cat "$BLOCK_BODY" >&2 || true
fi

# -- Summary -------------------------------------------------------------------
printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
