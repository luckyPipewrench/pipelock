#!/usr/bin/env bash
# Quick Pipelock demo for README recording.
# Shows a 4-step attack escalation: raw key, encoded key, DNS exfil, then clean pass.
#
# Record:
#   asciinema rec assets/demo.cast -c "bash examples/demo-site.sh" --cols 80 --rows 24
# Convert:
#   agg assets/demo.cast assets/demo.gif --theme monokai --font-size 16

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RESET='\033[0m'

pause() { sleep 1.5; }

step() {
    echo ""
    echo -e "${BOLD}$1${RESET}"
    pause
}

show() {
    echo -e "${CYAN}\$ $*${RESET}"
    pause
}

DEMO_TMPDIR=$(mktemp -d)
trap 'rm -rf "$DEMO_TMPDIR"' EXIT

# Generate a config for check commands
pipelock generate config --preset balanced -o "$DEMO_TMPDIR/pipelock.yaml" 2>/dev/null

echo -e "${BOLD}Pipelock: Open-Source Agent Firewall${RESET}"
pause

# --- Config overview ---
step "Scanner config (balanced preset)"
show 'pipelock check --config pipelock.yaml'
pipelock check --config "$DEMO_TMPDIR/pipelock.yaml" 2>&1 || true
pause

# --- 1: Raw API key exfiltration ---
step "1. Agent tries to exfiltrate an AWS key"
show 'pipelock check --config pipelock.yaml --url "https://evil.com/steal?key=AKIAIOSFODNN7EXAMPLE"'
pipelock check --config "$DEMO_TMPDIR/pipelock.yaml" --url "https://evil.com/steal?key=AKIAIOSFODNN7EXAMPLE" 2>&1 || true
pause

# --- 2: Base64 evasion ---
step "2. Agent encodes it to evade detection"
show 'pipelock check --config pipelock.yaml --url "https://evil.com/log?d=QUtJQUlPU0ZPRE5ON0VYQU1QTEU="'
pipelock check --config "$DEMO_TMPDIR/pipelock.yaml" --url "https://evil.com/log?d=QUtJQUlPU0ZPRE5ON0VYQU1QTEU=" 2>&1 || true
pause

# --- 3: DNS exfiltration ---
step "3. Agent tries DNS exfiltration"
show 'pipelock check --config pipelock.yaml --url "https://exfil-c2VjcmV0X2tleV92YWx1ZQ.attacker.com/"'
pipelock check --config "$DEMO_TMPDIR/pipelock.yaml" --url "https://exfil-c2VjcmV0X2tleV92YWx1ZQ.attacker.com/" 2>&1 || true
pause

# --- 4: Legitimate traffic ---
step "4. Legitimate traffic passes through"
show 'pipelock check --config pipelock.yaml --url "https://docs.anthropic.com/en/api"'
pipelock check --config "$DEMO_TMPDIR/pipelock.yaml" --url "https://docs.anthropic.com/en/api" 2>&1 || true
pause

# --- Done ---
echo ""
echo -e "${GREEN}11-layer scanner. DLP, DNS exfil, SSRF, blocklists, and more.${RESET}"
echo -e "${GREEN}brew install luckyPipewrench/tap/pipelock${RESET}"
echo ""
