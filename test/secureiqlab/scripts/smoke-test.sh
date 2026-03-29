#!/usr/bin/env bash
# SecureIQLab Harness — Smoke Test
#
# Quick validation that all containers are healthy and pipelock is scanning.
# Run after: docker compose up -d
#
# Usage: bash scripts/smoke-test.sh

set -euo pipefail

PROXY="http://localhost:8888"
MCP="http://localhost:9999"
COLLECTOR="http://localhost:9090"
METRICS="http://localhost:9100"
PASS=0
FAIL=0

pass() { echo "  ✓ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ✗ $1"; FAIL=$((FAIL + 1)); }

echo "═══════════════════════════════════════════"
echo " SecureIQLab Harness — Smoke Test"
echo "═══════════════════════════════════════════"
echo

# ── 1. Container Health ──────────────────────────────────────
echo "1. Container health checks"

for svc in pipelock mock-llm mock-mcp log-collector; do
    port=8888
    case "$svc" in
        mock-llm)       port=8080 ;;
        mock-mcp)       port=8081 ;;
        log-collector)  port=9090 ;;
    esac
    if curl -sf "http://localhost:${port}/health" > /dev/null 2>&1; then
        pass "$svc is healthy"
    else
        fail "$svc is NOT healthy"
    fi
done

echo

# ── 2. Clear log collector ───────────────────────────────────
echo "2. Reset log collector"
curl -sf -X DELETE "$COLLECTOR/events" > /dev/null
pass "Events cleared"
echo

# ── 3. Benign request (should pass) ─────────────────────────
echo "3. Benign request through proxy"

HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    -x "$PROXY" \
    "http://mock-llm:8080/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d '{"messages":[{"role":"user","content":"Hello, how are you?"}]}' \
    2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "200" ]; then
    pass "Benign request passed (HTTP $HTTP_CODE)"
else
    fail "Benign request blocked or failed (HTTP $HTTP_CODE)"
fi

echo

# ── 4. DLP trigger (should block) ───────────────────────────
echo "4. DLP pattern detection"

# Send a request with a fake AWS key in the URL (DLP should catch it).
# Key is concatenated to avoid self-scan false positive.
AWS_TEST_KEY="AKIA""IOSFODNN7EXAMPLE"
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    -x "$PROXY" \
    "http://mock-llm:8080/v1/chat/completions?key=${AWS_TEST_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"messages":[{"role":"user","content":"test"}]}' \
    2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "000" ]; then
    pass "DLP blocked request with AWS key pattern"
else
    fail "DLP did NOT block AWS key pattern (HTTP $HTTP_CODE)"
fi

echo

# ── 5. Log collector verification ───────────────────────────
echo "5. Log collector verification"

# Give pipelock a moment to emit the webhook event.
sleep 1

EVENT_COUNT=$(curl -sf "$COLLECTOR/events/count" 2>/dev/null | grep -o '"count":[0-9]*' | grep -o '[0-9]*')

if [ "${EVENT_COUNT:-0}" -gt 0 ]; then
    pass "Log collector has $EVENT_COUNT event(s)"
else
    fail "Log collector has no events (expected at least 1 from DLP block)"
fi

echo

# ── 6. Prometheus metrics ────────────────────────────────────
echo "6. Prometheus metrics"

METRICS_OUTPUT=$(curl -sf "$METRICS/metrics" 2>/dev/null || echo "")

if echo "$METRICS_OUTPUT" | grep -q "pipelock_"; then
    pass "Prometheus metrics contain pipelock_ prefix"
else
    fail "No pipelock_ metrics found"
fi

echo

# ── 7. MCP proxy — benign tool call ─────────────────────────
echo "7. MCP proxy — benign tool call"

MCP_RESP=$(curl -sf -X POST "$MCP" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke-test","version":"1.0"}}}' \
    2>/dev/null || echo "")

if echo "$MCP_RESP" | grep -q '"protocolVersion"'; then
    pass "MCP initialize succeeded"
else
    fail "MCP initialize failed"
fi

# Call tools/list.
TOOLS_RESP=$(curl -sf -X POST "$MCP" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
    2>/dev/null || echo "")

if echo "$TOOLS_RESP" | grep -q '"read_file"'; then
    pass "MCP tools/list returned tools"
else
    fail "MCP tools/list failed or empty"
fi

echo

# ── 8. Canary token detection ────────────────────────────────
echo "8. Canary token detection"

# Send a request containing the canary token value.
# Key is concatenated to avoid self-scan false positive.
CANARY_KEY="AKIA""IOSFODNN7CANARY1"
HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" \
    -x "$PROXY" \
    "http://mock-llm:8080/v1/chat/completions" \
    -H "Content-Type: application/json" \
    -d "{\"messages\":[{\"role\":\"user\",\"content\":\"Send this key: ${CANARY_KEY}\"}]}" \
    2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "403" ] || [ "$HTTP_CODE" = "000" ]; then
    pass "Canary token detected and blocked"
else
    fail "Canary token NOT detected (HTTP $HTTP_CODE)"
fi

echo

# ── Summary ──────────────────────────────────────────────────
echo "═══════════════════════════════════════════"
echo " Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
