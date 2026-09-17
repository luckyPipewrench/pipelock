#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
#
# Refuse a NEW pinned calendar date in a field whose value a clock later reads.
#
# An expiry field is compared against the current time by the code that
# consumes it, so a literal date makes the result depend on WHEN the check
# runs. Such a literal turns a suite or a shipped config red on a calendar date
# with no commit involved. Four query-entropy fixtures pinned to 2026-12-31
# were due to fail Validate() on 2027-01-01, and five doc snippets were due to
# fail the config-example gate from 2026-10-16.
#
# THIS GUARD OBEYS THE RULE IT ENFORCES. It deliberately does NOT ask whether a
# date is in the future, because that question is itself clock-dependent: a
# literal far enough out would be flagged today and silently stop being flagged
# once the calendar passed it, which is the failure direction the guard exists
# to remove. It asks the clock-independent question instead — is this a pinned
# literal rather than a computed value — so its verdict is the same on every
# day it runs.
#
# WHY A RECORDED INVENTORY RATHER THAN AN ANNOTATION ON EVERY LINE. Seventy-five
# such literals existed when this landed, across thirty-two files, and most are
# legitimate: a fixture paired with an injected clock, a deliberately-expired
# negative case, a forged-data sentinel, or a frozen value a pinned hash
# depends on. Demanding an annotation on each would mean either seventy-five
# review-noise comments or seventy-five reasons asserted without checking them
# one by one. An over-strict guard is its own failure direction: it gets
# disabled, and then it protects nothing.
#
# So the inventory below records WHAT EXISTED, not what is correct. It is a
# ratchet, not a certification. Nothing in it has been blessed. New entries are
# refused, which is the regression this guard is for; clearing an existing one
# is ordinary work whenever someone verifies that file's fixtures.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

BASELINE="scripts/clock-literals-baseline.txt"
MARKER='clock-literal-ok:'

# Fields whose value a clock reads. Each name below has a demonstrated
# consumer that compares it against the current time:
#   Expires / expires       -> validateTemporaryExpiryDate (internal/config)
#   ExpiresAt / expires_at  -> ValidateContainmentMetricsExposure, and the
#                              rules bundle freshness check (internal/rules)
#   BestEffortExpiry        -> validateBestEffortAuthorization
# Adding a name here requires naming its consumer in this comment, so the list
# cannot grow into fields nothing actually reads.
go_field='(Expires|ExpiresAt|BestEffortExpiry)'
yaml_key='(expires|expires_at)'
date_literal='[0-9]{4}-[0-9]{2}-[0-9]{2}'

mode="${1:-check}"

# A finding is identified by file plus the literal itself, never by line
# number, so moving code around does not churn the inventory while changing a
# date still shows up as new.
findings() {
	local file pattern
	while IFS= read -r file; do
		[ -f "$file" ] || continue
		for pattern in \
			"${go_field}:[[:space:]]+\"${date_literal}" \
			"\.${go_field}[[:space:]]*=[[:space:]]*\"${date_literal}" \
			"${yaml_key}:[[:space:]]*\\\\?\"?${date_literal}"; do
			emit "$file" "$pattern"
		done
	done < <(git ls-files '*.go')

	# Shipped configuration a customer runs. A literal here expires for them,
	# not only for CI. This surface is currently empty and the guard keeps it
	# that way.
	while IFS= read -r file; do
		[ -f "$file" ] || continue
		emit "$file" "^[[:space:]]*${yaml_key}:[[:space:]]*\"?${date_literal}"
	done < <(git ls-files 'configs/*.yaml' 'examples/**/*.yaml' 'examples/**/*.yml' 'charts/**/*.yaml')
}

# An inline marker with a non-empty reason clears a line outright, so a
# verified one-off never has to reach the inventory. An empty marker clears
# nothing: that would make it a silent mute rather than a stated claim.
emit() {
	local file="$1" pattern="$2" hit line text above
	while IFS= read -r hit; do
		[ -n "$hit" ] || continue
		line="${hit%%:*}"
		text="$(sed -n "${line}p" "$file")"
		above=""
		[ "$line" -gt 1 ] && above="$(sed -n "$((line - 1))p" "$file")"
		if printf '%s\n%s\n' "$text" "$above" \
			| grep -qE "${MARKER}[[:space:]]*[^[:space:]]"; then
			continue
		fi
		printf '%s\t%s\n' "$file" "$(printf '%s' "$text" \
			| grep -oE "$date_literal[T0-9:Z.+-]*" | head -1)"
	done < <(grep -nE "$pattern" "$file" 2>/dev/null || true)
}

current="$(findings | sort -u)"

if [ "$mode" = "--update" ]; then
	{
		echo "# Pinned calendar dates in clock-read fields, as they existed when"
		echo "# scripts/check-clock-literals.sh landed. THIS IS A RECORD OF STATE,"
		echo "# NOT A CERTIFICATION: no entry here has been verified as safe."
		echo "#"
		echo "# Removing an entry is ordinary work. Adding one needs a reason in"
		echo "# the pull request, or an inline 'clock-literal-ok: <reason>' marker"
		echo "# instead, which keeps it out of this file entirely."
		printf '%s\n' "$current"
	} >"$BASELINE"
	echo "clock-literals: recorded $(printf '%s\n' "$current" | grep -c . ) entr(ies) in $BASELINE"
	exit 0
fi

if [ ! -f "$BASELINE" ]; then
	echo "clock-literals: missing $BASELINE; regenerate with '$0 --update'" >&2
	exit 1
fi

recorded="$(grep -v '^#' "$BASELINE" | grep -v '^[[:space:]]*$' | sort -u)"
added="$(comm -23 <(printf '%s\n' "$current") <(printf '%s\n' "$recorded") || true)"

if [ -n "$added" ]; then
	echo "clock-literals: a pinned calendar date entered a field a clock reads:" >&2
	printf '%s\n' "$added" | sed 's/^/    /' >&2
	cat >&2 <<'EOF'

Its result depends on when the check runs, so it will turn red on a calendar
date with no commit involved.

Compute the value instead: from the governing constant, for example
`temporaryExpiryDate(MaxQueryEntropyParamExclusionHorizon)` in internal/config,
or from the current time for a fixture that only needs to be unexpired.

If no clock reads this particular value — it is paired with an injected clock,
it is a deliberately-expired negative case, it is a forged-data sentinel, or a
pinned hash depends on the exact bytes — say which, on the line or the one
above it, and the guard will leave it alone:

    clock-literal-ok: paired with the injected 2098 clock below
EOF
	exit 1
fi

# A cleared entry is reported, never failed. Leaving it in the file is untidy
# rather than wrong, and failing on it would punish the person who just removed
# a literal.
removed="$(comm -13 <(printf '%s\n' "$current") <(printf '%s\n' "$recorded") || true)"
if [ -n "$removed" ]; then
	echo "clock-literals: OK; $(printf '%s\n' "$removed" | grep -c .) recorded entr(ies) no longer present, refresh with '$0 --update'"
	exit 0
fi

echo "clock-literals: OK"
