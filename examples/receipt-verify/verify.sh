#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Receipt emit + verify harness for examples/receipt-verify/
#
# Generates a runtime signing key, starts pipelock with flight recorder,
# triggers a metadata SSRF block, verifies the receipt, then tampers the
# signature and asserts verification fails.
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
KEY="$WORK/keys/signing.key"
PUB="$WORK/keys/signing.key.pub"
RECORDER_DIR="$WORK/recorder"
PROXY_LOG="$WORK/pipelock.log"
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
  python3 - <<'PY' "$SOURCE_CONFIG" "$CONFIG" "$proxy_port" "$RECORDER_DIR" "$KEY"
import sys
from pathlib import Path

src, dst, port, recorder_dir, key_path = sys.argv[1:6]
out = []
listen_ok = dir_ok = key_ok = False
for line in Path(src).read_text().splitlines():
    if line.startswith("  listen:"):
        out.append(f'  listen: "127.0.0.1:{port}"')
        listen_ok = True
    elif line.strip().startswith("dir:"):
        out.append(f'  dir: "{recorder_dir}"')
        dir_ok = True
    elif line.strip().startswith("signing_key_path:"):
        out.append(f'  signing_key_path: "{key_path}"')
        key_ok = True
    else:
        out.append(line)
if not (listen_ok and dir_ok and key_ok):
    sys.exit("write_config: failed to rewrite listen:/dir:/signing_key_path:")
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

fetch_url() {
  local port="$1"
  local url="$2"
  local out_file="$3"
  curl -sS --max-time 10 -o "$out_file" -w '%{http_code}' -G \
    --data-urlencode "url=${url}" \
    "http://127.0.0.1:${port}/fetch"
}

extract_block_receipt() {
  local evidence="$1"
  local out_receipt="$2"
  python3 - <<'PY' "$evidence" "$out_receipt"
import json, sys
from pathlib import Path

evidence, out_path = sys.argv[1:3]
blocks = []
for line in Path(evidence).read_text().splitlines():
    if not line.strip():
        continue
    entry = json.loads(line)
    if entry.get("type") != "action_receipt":
        continue
    detail = entry.get("detail")
    if isinstance(detail, str):
        detail = json.loads(detail)
    ar = detail.get("action_record") or {}
    if ar.get("verdict") == "block" and str(ar.get("transport", "")).lower() == "fetch":
        blocks.append(detail)
if not blocks:
    raise SystemExit("no fetch block receipt found in evidence JSONL")
Path(out_path).write_text(json.dumps(blocks[-1], indent=2) + "\n")
print(len(blocks))
PY
}

tamper_receipt() {
  local src="$1"
  local dst="$2"
  python3 - <<'PY' "$src" "$dst"
import copy, json, sys
from pathlib import Path

src, dst = sys.argv[1:3]
receipt = json.loads(Path(src).read_text())
tampered = copy.deepcopy(receipt)
prefix, value = tampered["signature"].split(":", 1)
first = value[:2]
flipped = "00" if first.lower() != "00" else "ff"
tampered["signature"] = f"{prefix}:{flipped}{value[2:]}"
Path(dst).write_text(json.dumps(tampered, indent=2) + "\n")
PY
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
step "Test 1: generate signing key + write config"
mkdir -p "$WORK/keys" "$RECORDER_DIR"
chmod 750 "$WORK/keys" "$RECORDER_DIR"

if "$PIPELOCK" signing key generate --purpose receipt-signing --out "$KEY" >/dev/null \
  && "$PIPELOCK" signing pubkey --key-file "$KEY" --out "$PUB" >/dev/null \
  && [ -s "$KEY" ] && [ -s "$PUB" ]; then
  pass "runtime receipt-signing key + pubkey"
else
  fail "signing key generate / pubkey failed"
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

PROXY_PORT="$(pick_port)"
write_config "$PROXY_PORT"

if "$PIPELOCK" check --config "$CONFIG" >/dev/null 2>&1; then
  pass "temp config validates"
else
  fail "temp config failed validation"
  "$PIPELOCK" check --config "$CONFIG" >&2 || true
fi

# -- Test 2 -------------------------------------------------------------------
step "Test 2: start pipelock and block metadata SSRF"
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

BODY="$WORK/meta.json"
CODE="$(fetch_url "$PROXY_PORT" "http://169.254.169.254/latest/meta-data/" "$BODY")"
if [ "$CODE" = "403" ] && grep -qiE 'blocked.: *true|"blocked":true' "$BODY"; then
  pass "metadata SSRF fetch blocked (HTTP 403)"
else
  fail "expected SSRF block (http=$CODE)"
  cat "$BODY" >&2 || true
  tail -40 "$PROXY_LOG" >&2 || true
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

# Stop proxy so flight recorder flushes session_close cleanly.
kill "$PROXY_PID" 2>/dev/null || true
wait "$PROXY_PID" 2>/dev/null || true
PROXY_PID=""
sleep 0.3

# -- Test 3 -------------------------------------------------------------------
step "Test 3: receipt artifact written"
EVIDENCE="$RECORDER_DIR/evidence-proxy-0.jsonl"
BLOCK_RECEIPT="$WORK/block-receipt.json"
if [ -s "$EVIDENCE" ]; then
  pass "evidence JSONL exists ($EVIDENCE)"
else
  fail "missing evidence JSONL at $EVIDENCE"
  ls -la "$RECORDER_DIR" >&2 || true
  tail -40 "$PROXY_LOG" >&2 || true
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

if COUNT="$(extract_block_receipt "$EVIDENCE" "$BLOCK_RECEIPT")"; then
  pass "extracted fetch block receipt (count=$COUNT)"
else
  fail "no fetch block receipt in JSONL"
  cat "$EVIDENCE" >&2 || true
  printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
  exit 1
fi

# -- Test 4 -------------------------------------------------------------------
step "Test 4: verify-receipt passes on good receipt"
if "$PIPELOCK" verify-receipt "$BLOCK_RECEIPT" --key "$PUB" >/dev/null 2>"$WORK/verify-good.err"; then
  pass "verify-receipt accepts signed block receipt"
else
  fail "verify-receipt rejected valid receipt"
  cat "$WORK/verify-good.err" >&2 || true
fi

if "$PIPELOCK" verify-receipt "$EVIDENCE" --key "$PUB" >/dev/null 2>"$WORK/verify-chain.err"; then
  pass "verify-receipt accepts evidence JSONL chain"
else
  fail "verify-receipt rejected evidence JSONL"
  cat "$WORK/verify-chain.err" >&2 || true
fi

# -- Test 5 -------------------------------------------------------------------
step "Test 5: tampered receipt fails verification (required)"
TAMPERED="$WORK/block-receipt.tampered.json"
tamper_receipt "$BLOCK_RECEIPT" "$TAMPERED"
if "$PIPELOCK" verify-receipt "$TAMPERED" --key "$PUB" >/dev/null 2>"$WORK/verify-tampered.err"; then
  fail "tampered receipt unexpectedly verified"
else
  pass "tampered receipt rejected by verify-receipt"
fi

# -- Summary ------------------------------------------------------------------
printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
