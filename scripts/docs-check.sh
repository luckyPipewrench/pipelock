#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0


set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

scope=(README.md CLAUDE.md CONTRIBUTING.md GOVERNANCE.md SECURITY.md docs examples)

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
check_no_match '\b11-layer\b|\b11 layers\b' 'fixed scanner-layer count'
check_no_match '\b(all|All) 4 sources\b|\bfour independent (activation )?sources\b|\b4 independent sources\b' 'four-source kill-switch count'
check_no_match 'verifiable trail of all agent network activity' 'unprovable audit-completeness claim'
check_no_match 'inspects all cross-boundary traffic' 'unscoped transport-inspection claim'
check_no_match 'every proxy decision produces a signed (action )?receipt' 'unprovable receipt-completeness claim'
check_no_match 'all five reference verifiers|five independent verifier implementations' 'wasm-as-independent-verifier claim'
check_no_match 'timeline (lists|of) every mediated decision' 'unprovable evidence-timeline completeness claim'
check_no_match 'stale_policy\.(grace_multiplier|after_grace).*\| Reserved' 'stale-policy-as-reserved claim'
check_no_match 'Every signed bundle hash is written to an append-only transparency log' 'unshipped universal transparency-log claim'
check_no_match 'No implementation should start until these are accepted' 'obsolete Conductor pre-implementation gate'

echo "docs-check: printing canonical local stats"
make stats

echo "docs-check: validating current claims and local Markdown links"
go test -count=1 -run 'TestDocs(DeclareLiveStatsAndDefaults|LocalLinksResolve)$' ./internal/config/

echo "docs-check: ok"
