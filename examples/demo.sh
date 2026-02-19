#!/usr/bin/env bash
# Pipelock Demo — shows DLP blocking, domain blocking, and integrity detection.
#
# Prerequisites:
#   go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest
#
# Usage:
#   ./examples/demo.sh
#
# For a recording (full interactive demo):
#   asciinema rec -c ./examples/demo.sh demo.cast
#
# For README GIF (shorter, no proxy needed):
#   See examples/demo-readme.sh

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
RESET='\033[0m'

step() {
    echo ""
    echo -e "${BOLD}━━━ $1 ━━━${RESET}"
    echo ""
}

run() {
    echo -e "${YELLOW}\$ $*${RESET}"
    eval "$@" 2>&1 || true
    echo ""
}

DEMO_TMPDIR=$(mktemp -d)
trap 'rm -rf "$DEMO_TMPDIR"' EXIT

# --- Setup ---

step "Setup: generate a balanced config"
run pipelock generate config --preset balanced -o "$DEMO_TMPDIR/pipelock.yaml"

step "Setup: start the fetch proxy in the background"
pipelock run --config "$DEMO_TMPDIR/pipelock.yaml" &
PROXY_PID=$!
sleep 2
if ! curl -sf http://localhost:8888/health > /dev/null 2>&1; then
    echo -e "${RED}ERROR: Proxy failed to start on :8888 (port in use?)${RESET}" >&2
    exit 1
fi
echo -e "${GREEN}Proxy running on :8888 (PID $PROXY_PID)${RESET}"
echo ""

# --- Demo 1: DLP blocks secret in URL ---

step "Demo 1: DLP catches an API key in a URL"
echo "An agent tries to fetch a URL containing an AWS access key..."
run curl -s -G --data-urlencode "url=https://example.com/page?token=AKIAIOSFODNN7EXAMPLE" "http://localhost:8888/fetch"
echo -e "${RED}^ Blocked! The DLP scanner detected the AWS key pattern.${RESET}"

# --- Demo 2: Domain blocklist ---

step "Demo 2: Blocklist blocks exfiltration target"
echo "An agent tries to fetch from pastebin (a known exfiltration target)..."
run curl -s "http://localhost:8888/fetch?url=https://pastebin.com/raw/abc123" | python3 -m json.tool 2>/dev/null || \
run curl -s "http://localhost:8888/fetch?url=https://pastebin.com/raw/abc123"
echo -e "${RED}^ Blocked! pastebin.com is on the blocklist.${RESET}"

# --- Demo 3: Clean fetch works ---

step "Demo 3: Legitimate fetch works fine"
echo "A normal documentation fetch goes through..."
run curl -s "http://localhost:8888/fetch?url=https://example.com" | python3 -m json.tool 2>/dev/null || \
run curl -s "http://localhost:8888/fetch?url=https://example.com"
echo -e "${GREEN}^ Allowed. Clean URL, no secrets, not blocklisted.${RESET}"

# --- Demo 4: Integrity monitoring ---

step "Demo 4: Workspace integrity detects tampering"
mkdir -p "$DEMO_TMPDIR/workspace"
echo "legitimate code" > "$DEMO_TMPDIR/workspace/app.py"
echo "config data" > "$DEMO_TMPDIR/workspace/config.yaml"

echo "Initialize integrity manifest..."
run pipelock integrity init "$DEMO_TMPDIR/workspace" --manifest "$DEMO_TMPDIR/manifest.json"

echo "Simulate tampering: modify a file..."
echo "malicious payload" >> "$DEMO_TMPDIR/workspace/app.py"

echo "Check integrity..."
run pipelock integrity check "$DEMO_TMPDIR/workspace" --manifest "$DEMO_TMPDIR/manifest.json"
echo -e "${RED}^ Detected! The modified file was caught by integrity checking.${RESET}"

# --- Demo 5: Git diff scanning ---

step "Demo 5: Git diff scanning catches secrets"
echo "Scanning a diff that contains a secret..."
printf 'diff --git a/.env b/.env\n--- /dev/null\n+++ b/.env\n@@ -0,0 +1 @@\n+ANTHROPIC_API_KEY=sk-ant-api03-FAKEFAKEFAKEFAKEFAKE\n' | \
    run pipelock git scan-diff --config "$DEMO_TMPDIR/pipelock.yaml"
echo -e "${RED}^ Caught! The secret was detected in the diff.${RESET}"

# --- Cleanup ---

step "Done"
kill $PROXY_PID 2>/dev/null || true
echo -e "${GREEN}All demos complete. The proxy has been stopped.${RESET}"
echo ""
echo "What you saw:"
echo "  1. DLP scanner blocked a URL containing an AWS access key"
echo "  2. Domain blocklist prevented access to pastebin.com"
echo "  3. A legitimate fetch to example.com succeeded"
echo "  4. Integrity monitoring detected a tampered workspace file"
echo "  5. Git diff scanning caught a secret in a code change"
echo ""
echo "Try it yourself: go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest"
