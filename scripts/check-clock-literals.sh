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
# THE COMPLETE SET OF DELIMITERS A DATE VALUE CAN CARRY. Enumerated here in one
# place because this guard has now been defeated twice by a form nobody listed:
# first `expires_at: '2028-01-01'` in YAML, then Expires: `2030-01-01` as a Go
# raw string. Both were the same mistake, fixing the instance in front of me
# instead of asking what the full set was. It is:
#
#   Go interpreted string   Expires: "2030-01-01"
#   Go raw string           Expires: `2030-01-01`
#   YAML bare               expires: 2030-01-01
#   YAML single-quoted      expires: '2030-01-01'
#   YAML double-quoted      expires: "2030-01-01"
#
# A Go value always carries one of its two delimiters; a YAML value may carry
# none. Adding a language here means extending this list, not adding a pattern
# beside it.
go_quote='["`]'
quote='["'"'"']?'

mode="${1:-check}"

# A finding is identified by file, the clock-read FIELD, and the literal itself,
# never by line number, so moving code around does not churn the inventory while
# changing a date, or moving one between fields, still shows up as new.
#
# Multiplicity is part of the identity. Collapsing with `sort -u` made a new
# pinned literal invisible whenever it duplicated a date already recorded for
# that file, which defeats the whole point of the ratchet: reproduced 2026-09-17
# by adding a second `2030-01-01T00:05:00Z` to a file that already had one and
# watching the guard report OK. Every occurrence is emitted, and the comparison
# is a multiset difference, so the second one is new.
findings() {
	local file pattern
	# Piped rather than a process substitution: findings runs inside a command
	# substitution that is itself a pipeline, and in that nesting a /dev/fd
	# pathname can be opened after its descriptor is gone. A pipe has no such
	# dependency. The loop body sets nothing the caller needs, so running it in
	# a subshell costs nothing.
	#
	# NUL-delimited, because git ls-files QUOTES a path containing a newline
	# ("weird\nname.go") and the quoted form fails [ -f ], so the file is
	# silently skipped and a literal inside it evades the gate. Verified by
	# reproduction rather than assumed.
	git ls-files -z '*.go' | while IFS= read -r -d '' file; do
		[ -f "$file" ] || continue
		for pattern in \
			"${go_field}:[[:space:]]+${go_quote}${date_literal}" \
			"\.${go_field}[[:space:]]*=[[:space:]]*${go_quote}${date_literal}" \
			"${yaml_key}:[[:space:]]*\\\\?${quote}${date_literal}"; do
			emit "$file" "$pattern"
		done
	done

	# Shipped configuration a customer runs. A literal here expires for them,
	# not only for CI. This surface is currently empty and the guard keeps it
	# that way.
	git ls-files -z 'configs/*.yaml' 'examples/**/*.yaml' 'examples/**/*.yml' 'charts/**/*.yaml' |
		while IFS= read -r -d '' file; do
		[ -f "$file" ] || continue
		emit "$file" "^[[:space:]]*${yaml_key}:[[:space:]]*${quote}${date_literal}"
	done
}

# Every file argument is terminated with --. A tracked path may begin with a
# hyphen, and `grep -nE "$pattern" "-clock.go"` parses it as options: grep then
# prints NOTHING and exits 0, so a literal in that file is invisible and the
# guard reports clean. sed fails outright on the same input. Verified by
# reproduction, and it is the same question as the NUL-delimited read above --
# what forms can a path take -- answered one form at a time.
#
# An inline marker with a non-empty reason clears a line outright, so a
# verified one-off never has to reach the inventory. An empty marker clears
# nothing: that would make it a silent mute rather than a stated claim.
emit() {
	local file="$1" pattern="$2" hit line text above
	while IFS= read -r hit; do
		[ -n "$hit" ] || continue
		line="${hit%%:*}"
		text="$(sed -n "${line}p" -- "$file")"
		above=""
		[ "$line" -gt 1 ] && above="$(sed -n "$((line - 1))p" -- "$file")"
		if printf '%s\n%s\n' "$text" "$above" \
			| grep -qE "${MARKER}[[:space:]]*[^[:space:]]"; then
			continue
		fi
		# One record per MATCHING FIELD on the line, not per date on the
		# line: a fixture can carry a clock-read `Expires` beside a
		# `Created` that nothing reads, and only the former is a finding.
		# Each grep here can legitimately match nothing, and under
		# `set -e` with `pipefail` that aborted the pipeline and DROPPED
		# records instead of reporting them: seven entries vanished from a
		# freshly regenerated inventory, which the check then reported as
		# "no longer present". A guard that loses findings quietly is worse
		# than one that never ran, so every stage tolerates a non-match.
		printf '%s' "$text" \
			| { grep -oE "${pattern}[T0-9:Z.+-]*" || true; } \
			| while IFS= read -r match; do
				[ -n "$match" ] || continue
				# The FIELD belongs in the identity. With only file and
				# date, deleting a recorded Expires and adding the same
				# date to ExpiresAt in that file leaves the multiset
				# identical, so the new occurrence is invisible. The
				# field name is the first run of letters in the match;
				# the date follows it.
				field="$(printf '%s' "$match" | { grep -oE '[A-Za-z_]+' || true; } | head -1)"
				found="$(printf '%s' "$match" | { grep -oE "${date_literal}[T0-9:Z.+-]*" || true; } | head -1)"
				[ -n "$field" ] && [ -n "$found" ] || continue
				printf '%s\t%s\t%s\n' "$file" "$field" "$found"
			done
	done < <(grep -nE "$pattern" -- "$file" 2>/dev/null || true)
}

# comm compares byte-wise in the C collation, so both sides must be sorted that
# way or it silently mispairs lines and reports phantom differences: observed
# immediately after a regeneration, where seven entries just written to the file
# came back as "no longer present".
current="$(findings | LC_ALL=C sort)"

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

# awk exits 0 whether or not it matched, so a fully cleared inventory reports
# clean instead of aborting. `sort` without -u keeps multiplicity on this side
# too, so the comparison below is a real multiset difference.
recorded="$(awk '!/^#/ && NF' "$BASELINE" | LC_ALL=C sort)"
added="$(LC_ALL=C comm -23 <(printf '%s\n' "$current") <(printf '%s\n' "$recorded") || true)"

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

# BASELINE GROWTH IS REPORTED, LOUDLY, AND NEVER BLOCKS.
#
# The inventory is a tracked file, so anyone can make a red check green by
# adding the new literal to it. That is not hypothetical: this guard's own
# author ran --update twice on the day it landed, once legitimately, because
# merging main brought in fourteen literals from another pull request. Refusing
# additions outright would have blocked that correct work, so the guard does not
# refuse them.
#
# What it does instead is make growth impossible to miss. Every addition already
# appears in the diff; this prints the count so a reviewer reads it as a claim
# needing justification rather than as noise at the bottom of a file. The trust
# boundary is review, and this states that plainly instead of implying the check
# enforces something it does not.
main_baseline="$(git show "origin/main:$BASELINE" 2>/dev/null || true)"
if [ -n "$main_baseline" ]; then
	main_count="$(printf '%s\n' "$main_baseline" | awk '!/^#/ && NF' | wc -l | tr -d ' ')"
	here_count="$(printf '%s\n' "$recorded" | awk 'NF' | wc -l | tr -d ' ')"
	if [ "$here_count" -gt "$main_count" ]; then
		printf 'clock-literals: NOTE this branch ADDS %d baseline entr(ies) (%d -> %d).\n' \
			"$((here_count - main_count))" "$main_count" "$here_count"
		printf '  Each one records a pinned date this branch is accepting rather than fixing.\n'
		printf '  Justify them in the pull request, or compute the value instead.\n'
		LC_ALL=C comm -13 \
			<(printf '%s\n' "$main_baseline" | awk '!/^#/ && NF' | LC_ALL=C sort) \
			<(printf '%s\n' "$recorded") 2>/dev/null | sed 's/^/    + /' || true
	fi
fi

# A cleared entry is reported, never failed. Leaving it in the file is untidy
# rather than wrong, and failing on it would punish the person who just removed
# a literal.
removed="$(LC_ALL=C comm -13 <(printf '%s\n' "$current") <(printf '%s\n' "$recorded") || true)"
if [ -n "$removed" ]; then
	echo "clock-literals: OK; $(printf '%s\n' "$removed" | grep -c .) recorded entr(ies) no longer present, refresh with '$0 --update'"
	exit 0
fi

echo "clock-literals: OK"
