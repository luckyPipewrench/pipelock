#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Fail closed if ripgrep is missing. Several of the checks below use
# `rg -q ... || true`, which would otherwise silently pass (exit 127
# gets swallowed and the branch behaves as if "no match"). Runners
# without ripgrep must fail loudly, not scan nothing and report OK.
if ! command -v rg >/dev/null 2>&1; then
	printf '%s\n' "ERROR: ripgrep (rg) is required for the release audit and is not on PATH." >&2
	printf '%s\n' "Install ripgrep (e.g., apt-get install -y ripgrep) before running this script." >&2
	exit 127
fi

errors=0

note() {
	printf '%s\n' "$*" >&2
}

fail() {
	note "ERROR: $*"
	errors=1
}

# rg_search runs ripgrep and distinguishes "no matches" (exit 1, clean)
# from a search error (exit >=2, which `|| true` would otherwise mask
# and let the audit pass with zero scans — exactly what happened on
# runners that lack ripgrep before this fix).
rg_search() {
	local status
	set +e
	rg_output="$(rg "$@")"
	status=$?
	set -e
	if [[ "$status" -gt 1 ]]; then
		note "ERROR: ripgrep exited with $status while running: rg $*"
		note "The release audit is a release-blocking tripwire and must fail closed on scan errors."
		errors=1
		return 2
	fi
	return 0
}

check_no_matches() {
	local pattern="$1"
	local message="$2"

	if ! rg_search -n "$pattern" .github/workflows; then
		return
	fi
	if [[ -n "$rg_output" ]]; then
		fail "$message"
		note "$rg_output"
	fi
}

note "release audit: checking workflow trigger and token hygiene"

check_no_matches '^[[:space:]]*pull_request_target:' "pull_request_target is banned for this repo; use pull_request plus read-only permissions"
check_no_matches 'permissions:[[:space:]]*write-all' "write-all workflow permissions are banned"
check_no_matches 'persist-credentials:[[:space:]]*true' "persist-credentials: true is banned; PR and CI jobs must not retain checkout credentials"

note "release audit: checking action pinning"

while IFS= read -r match; do
	file="${match%%:*}"
	rest="${match#*:}"
	line="${rest%%:*}"
	uses="${rest#*:}"
	# Strip either step-level (leading dash) or job-level (no dash)
	# `uses:` prefix so reusable-workflow calls are audited too.
	ref="$(printf '%s\n' "$uses" | sed -E 's/^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*//; s/[[:space:]]+#.*$//')"

	case "$ref" in
		./*|docker://*)
			continue
			;;
	esac

	if [[ "$ref" != *@* ]]; then
		fail "${file}:${line} uses an unpinned action (${ref}); pin every external action to a full commit SHA"
		continue
	fi

	version="${ref##*@}"
	if [[ ! "$version" =~ ^[0-9a-f]{40}$ ]]; then
		fail "${file}:${line} action is not pinned to a full commit SHA (${ref})"
	fi
done < <(rg -n '^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*[^[:space:]]+' .github/workflows/*.y*ml || true)

note "release audit: checking pull_request workflows stay secret-light"

while IFS= read -r workflow; do
	if ! rg -q '^[[:space:]]*pull_request:' "$workflow"; then
		continue
	fi

	# Per-step validation: every actions/checkout invocation must have
	# persist-credentials: false within its own step block. Checking the
	# workflow as a whole (the previous behavior) lets a second
	# actions/checkout without the flag piggy-back on the first step's
	# setting and evade the audit.
	#
	# Step boundaries in GitHub Actions workflows are `-` list items
	# under `steps:` whose first key is `uses:`, `name:`, `run:`, `id:`,
	# `if:`, `with:`, `env:`, `continue-on-error:`, or `timeout-minutes:`.
	# We walk each file, track whether the current step is a checkout,
	# and emit the checkout line number when its step ends without
	# persist-credentials: false.
	missing_checkouts="$(awk '
		function flush() {
			if (in_checkout && !found_persist) {
				printf "%s:%d\n", FILENAME, checkout_line
			}
			in_checkout = 0
			found_persist = 0
		}
		/^[[:space:]]*-[[:space:]]+(uses|name|run|id|if|env|with|continue-on-error|timeout-minutes):/ {
			flush()
			if ($0 ~ /uses:[[:space:]]*actions\/checkout(@|[[:space:]]|$)/) {
				in_checkout = 1
				checkout_line = NR
			}
			next
		}
		in_checkout && /persist-credentials:[[:space:]]*false/ { found_persist = 1 }
		END { flush() }
	' "$workflow")"
	if [[ -n "$missing_checkouts" ]]; then
		fail "${workflow} has actions/checkout step(s) without persist-credentials: false:"
		note "$missing_checkouts"
	fi

	secrets_matches="$(rg -n 'secrets\.[A-Za-z0-9_]+' "$workflow" || true)"
	if [[ -n "$secrets_matches" ]]; then
		custom_secret_matches="$(printf '%s\n' "$secrets_matches" | rg -v 'secrets\.GITHUB_TOKEN\b' || true)"
		if [[ -n "$custom_secret_matches" ]]; then
			fail "${workflow} is pull_request-triggered and references custom secrets; keep PR workflows secretless"
			note "$custom_secret_matches"
		fi
	fi
done < <(find .github/workflows -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) | sort)

note "release audit: checking secret-bearing comment workflows"

while IFS= read -r workflow; do
	if ! rg -q '^[[:space:]]*issue_comment:' "$workflow"; then
		continue
	fi
	if ! rg -q 'secrets\.' "$workflow"; then
		continue
	fi
	if ! rg -q 'author_association' "$workflow"; then
		fail "${workflow} uses secrets on issue_comment without an author_association gate"
	fi
	if rg -q 'refs/pull/\$\{\{[[:space:]]*github\.event\.issue\.number[[:space:]]*\}\}/head' "$workflow"; then
		fail "${workflow} checks out the PR head ref in a secret-bearing comment workflow; use the merge ref instead"
	fi
done < <(find .github/workflows -maxdepth 1 -type f \( -name '*.yml' -o -name '*.yaml' \) | sort)

if [[ "$errors" -ne 0 ]]; then
	exit 1
fi

note "release audit: OK"
