#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0


set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

scope=(README.md CLAUDE.md CONTRIBUTING.md GOVERNANCE.md SECURITY.md docs examples)

if ! command -v rg >/dev/null 2>&1; then
	echo "docs-check: failed: rg is required" >&2
	exit 1
fi

check_no_match() {
	local pattern="$1"
	local label="$2"

	if rg -n --color=never "$pattern" "${scope[@]}"; then
		echo
		echo "docs-check: failed: found stale ${label}"
		exit 1
	else
		local status=$?
		if ((status != 1)); then
			echo "docs-check: failed: rg could not check ${label} (exit ${status})" >&2
			exit "$status"
		fi
	fi
}

check_conductor_serve_scope() {
	local file="$1"
	if ! awk -v file="$file" '
		function is_serve_command(line, fields, count, i) {
			gsub(/^[[:space:]]+/, "", line)
			count = split(line, fields, /[[:space:]]+/)
			i = 1
			while (i <= count && fields[i] ~ /^[A-Za-z_][A-Za-z0-9_]*=/) {
				i++
			}
			return i + 2 <= count && (fields[i] == "pipelock" || fields[i] == "/tmp/pipelock-ent") && fields[i + 1] == "conductor" && fields[i + 2] == "serve"
		}
		function scope_error(prefix) {
			printf "docs-check: failed: %sconductor serve example in %s lacks required publisher, auditor, or admin organization scope\n", prefix, file > "/dev/stderr"
			failed = 1
			exit 1
		}
		function chaining_error() {
			printf "docs-check: failed: conductor serve example in %s uses same-line command chaining\n", file > "/dev/stderr"
			failed = 1
			exit 1
		}
		function reset_serve() {
			serve = 0
			publisher_scope = 0
			auditor_scope = 0
			admin_scope = 0
		}
		function finish_serve(prefix) {
			if (serve && (!publisher_scope || !auditor_scope || !admin_scope)) {
				scope_error(prefix)
			}
			reset_serve()
		}
		/^```/ {
			if (in_fence && shell_fence) {
				finish_serve("")
			}
			if (in_fence) {
				in_fence = 0
				shell_fence = 0
			} else {
				in_fence = 1
				shell_fence = ($0 ~ /^```(bash|sh|shell|console)[[:space:]]*$/)
			}
			reset_serve()
			next
		}
		shell_fence && /conductor[[:space:]]+serve/ && /[;&|]/ {
			chaining_error()
		}
		shell_fence && $0 !~ /--help/ && is_serve_command($0) {
			finish_serve("")
			serve = 1
		}
		serve && /--publisher-org([[:space:]\\]|$)/ { publisher_scope = 1 }
		serve && /--auditor-org([[:space:]\\]|$)/ { auditor_scope = 1 }
		serve && /--admin-org([[:space:]\\]|$)/ { admin_scope = 1 }
		serve && $0 !~ /\\[[:space:]]*$/ { finish_serve("") }
		END {
			if (!failed && in_fence && shell_fence) {
				finish_serve("unterminated ")
			}
		}
	' "$file"; then
		return 1
	fi
}

if check_conductor_serve_scope <(
	printf '%s\n' \
		'```bash' \
		'pipelock conductor serve \' \
		'  --publisher-org org-a \' \
		'  --auditor-org org-a' \
		'pipelock conductor serve \' \
		'  --admin-org org-b' \
		'```'
) 2>/dev/null; then
	echo "docs-check: failed: cross-command scopes satisfied separate conductor serve examples" >&2
	exit 1
fi

for chained_example in \
	'pipelock conductor serve --help --publisher-org org-a --auditor-org org-a --admin-org org-a; pipelock conductor serve' \
	'pipelock conductor serve --publisher-org org-a --auditor-org org-a --admin-org org-a && pipelock conductor serve' \
	'pipelock conductor serve --publisher-org org-a --auditor-org org-a --admin-org org-a || pipelock conductor serve' \
	'pipelock conductor serve --publisher-org org-a --auditor-org org-a --admin-org org-a | pipelock conductor serve' \
	'pipelock conductor serve --publisher-org org-a --auditor-org org-a --admin-org org-a & pipelock conductor serve'; do
	if check_conductor_serve_scope <(
		printf '%s\n' \
			'```bash' \
			"$chained_example" \
			'```'
	) 2>/dev/null; then
		echo "docs-check: failed: same-line conductor serve chaining bypassed scope validation" >&2
		exit 1
	fi
done

echo "docs-check: checking for stale public doc claims"

python3 scripts/render_brand.py --check

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
check_no_match 'releases/latest/download/pipelock_(linux|darwin|windows)' 'unversioned release archive URL'
check_no_match 'go install github\.com/luckyPipewrench/pipelock/cmd/pipelock@' 'Go install command that cannot address the v3 module line'
check_no_match 'ghcr\.io/luckypipewrench/pipelock(-init)?:latest' 'moving Pipelock image tag in an operator example'
if rg -n --color=never 'image:[[:space:]]+ghcr\.io/luckypipewrench/pipelock:[^[:space:]]+' docs/guides/deployment-recipes.md; then
	echo
	echo 'docs-check: failed: deployment recipe uses a mutable Pipelock image tag'
	exit 1
fi
check_no_match 'release_tag=.*releases/latest' 'moving latest-release archive install command'
check_no_match 'pipelock_3\.4\.0_linux_amd64\.tar\.gz|pipelock:3\.4\.0' 'stale v3.4 release verification command'
check_no_match 'app\.kubernetes\.io/name=pipelock --timeout=5m' 'hard-coded Kubernetes pod selector'
check_no_match '4c748ab986d611138ce202ab800b16eca6fb589f' 'v3.4 GitHub Action pin'
check_no_match '"version": "v3\.1\.0"' 'v3.1 health-response example'

for workflow in examples/ci-workflow.yaml examples/ci-workflow-advanced.yaml; do
	if ! rg -q --fixed-strings "version: '3.5.0'" "$workflow"; then
		echo "docs-check: failed: $workflow does not pin the downloaded Pipelock version" >&2
		exit 1
	fi
done

for conductor_doc in \
	docs/guides/conductor.md \
	docs/guides/conductor-operator-runbook.md \
	docs/guides/conductor-production-runbook.md \
	docs/guides/enterprise-license-issuance-runbook.md \
	docs/specs/pipelock-conductor-audit-sink.md; do
	check_conductor_serve_scope "$conductor_doc"
done

echo "docs-check: printing canonical local stats"
make stats

echo "docs-check: validating current claims and local Markdown links"
go test -count=1 -run 'TestDocs(DeclareLiveStatsAndDefaults|LocalLinksResolve)$' ./internal/config/

echo "docs-check: ok"
