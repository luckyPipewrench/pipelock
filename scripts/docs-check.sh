#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

scope=(README.md CLAUDE.md docs)

check_no_match() {
	local pattern="$1"
	local label="$2"

	if rg -n --color=never "$pattern" "${scope[@]}"; then
		echo
		echo "docs-check: failed: found stale ${label}"
		exit 1
	fi
}

echo "docs-check: checking for stale public doc claims"

check_no_match '143 attack cases' 'gauntlet corpus count'
check_no_match '16 categories' 'gauntlet category count'
check_no_match '7,500\+ tests' 'old test count'
check_no_match '10,800\+' 'old test count'
check_no_match '47 DLP patterns' 'old DLP pattern count'
check_no_match '47 regex patterns' 'old DLP regex count'
check_no_match '47 DLP-pattern' 'old DLP pattern count'

echo "docs-check: printing canonical local stats"
make stats

echo "docs-check: ok"
