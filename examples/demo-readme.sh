#!/usr/bin/env bash
# Quick Pipelock demo for README recording.
# Uses 'pipelock check' (no proxy needed) + integrity commands.
#
# Record:
#   asciinema rec assets/demo.cast -c "bash examples/demo-readme.sh"
# Convert:
#   agg assets/demo.cast assets/demo.gif --theme monokai

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
RESET='\033[0m'

pause() { sleep 1.2; }

step() {
    echo ""
    echo -e "${BOLD}━━━ $1 ━━━${RESET}"
    pause
}

show() {
    echo -e "${CYAN}\$ $*${RESET}"
    pause
}

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Generate a config for check commands
pipelock generate config --preset balanced -o "$TMPDIR/pipelock.yaml" 2>/dev/null

echo -e "${BOLD}Pipelock — AI Agent Security Harness${RESET}"
pause

# --- 1: DLP catches API key ---
step "DLP: Block secret exfiltration"
show 'pipelock check --url "https://evil.com/steal?key=AKIAIOSFODNN7EXAMPLE"'
pipelock check --config "$TMPDIR/pipelock.yaml" --url "https://evil.com/steal?key=AKIAIOSFODNN7EXAMPLE" 2>&1 || true
pause

# --- 2: Domain blocklist ---
step "Blocklist: Block known exfil targets"
show 'pipelock check --url "https://pastebin.com/raw/data"'
pipelock check --config "$TMPDIR/pipelock.yaml" --url "https://pastebin.com/raw/data" 2>&1 || true
pause

# --- 3: Clean URL passes ---
step "Clean URL passes through"
show 'pipelock check --url "https://docs.anthropic.com/en/api"'
pipelock check --config "$TMPDIR/pipelock.yaml" --url "https://docs.anthropic.com/en/api" 2>&1 || true
pause

# --- 4: Integrity monitoring ---
step "Integrity: Detect workspace tampering"
mkdir -p "$TMPDIR/workspace"
echo "legitimate code" > "$TMPDIR/workspace/main.py"
echo "config" > "$TMPDIR/workspace/settings.yaml"

show 'pipelock integrity init ./workspace'
pipelock integrity init "$TMPDIR/workspace" --manifest "$TMPDIR/manifest.json" 2>&1

echo ""
echo -e "${RED}# Attacker modifies a file...${RESET}"
echo "injected payload" >> "$TMPDIR/workspace/main.py"
pause

show 'pipelock integrity check ./workspace'
pipelock integrity check "$TMPDIR/workspace" --manifest "$TMPDIR/manifest.json" 2>&1 || true
pause

# --- Done ---
echo ""
echo -e "${GREEN}Single binary. Zero deps. 9-layer scanner pipeline.${RESET}"
echo -e "${GREEN}go install github.com/luckyPipewrench/pipelock/cmd/pipelock@latest${RESET}"
echo ""
