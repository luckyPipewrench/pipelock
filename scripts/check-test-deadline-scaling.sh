#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
#
# Refuse a NEW unscaled deadline in a test that waits on a subprocess.
#
# internal/testwait.Deadline multiplies a wait by four when CI is set, because
# a shared runner under load is slower than a developer laptop by roughly that
# much. A test that waits on a subprocess with a raw duration therefore runs at
# 1x on the machine that needs the headroom most. When that clock expires first
# it kills exec.CommandContext, the child dies, and the failure surfaces as an
# assertion rather than as the timeout it actually is: the MCP sandbox environ
# proof reported "exit status 10", which is ExitSubprocess, and read as a
# broken security property rather than a starved runner.
#
# This class was already fixed once, on 2026-09-06, in three teardown waits.
# Nothing stopped it regrowing, and by 2026-09-22 the repository held 439 raw
# time.After waits and 184 raw context.WithTimeout calls against 17 uses of the
# helper, with main red from one of them. A mechanism that is adopted and then
# forgotten needs a guard or it decays back.
#
# SCOPE IS DELIBERATELY NARROW. It covers only test files that start a
# subprocess, because those are the waits whose failure mode is a killed child
# and a misleading assertion. A sub-second wait is exempt everywhere: in this
# codebase those are poll ticks inside a loop, and scaling a tick slows the
# loop without making anything more reliable. Widening this to every wait in
# every test would flag hundreds of legitimate lines, and an over-strict guard
# gets deleted rather than obeyed.
#
# The forms below are the ones that appear in this tree. Extend the list rather
# than adding a second pattern beside it.
#   context.WithTimeout(parent, 30*time.Second)
#   context.WithTimeout(parent, time.Minute)
#   <-time.After(5 * time.Second)
#   <-time.After(time.Second)

set -euo pipefail

cd "$(dirname "$0")/.."

violations=0
scanned=0
file_list=$(mktemp)
trap 'rm -f "$file_list"' EXIT

# git ls-files quotes a path containing a newline, so a file could otherwise be
# skipped in silence. -z keeps the names intact.
if ! git ls-files -z 'internal/**/*_test.go' >"$file_list"; then
	echo "check-test-deadline-scaling: could not enumerate tracked test files" >&2
	exit 1
fi

if [ ! -s "$file_list" ]; then
	echo "check-test-deadline-scaling: no tracked internal test files found; refusing to pass" >&2
	exit 1
fi

while IFS= read -r -d '' file; do
	if [ ! -f "$file" ] || [ ! -r "$file" ]; then
		printf 'check-test-deadline-scaling: cannot read tracked test file: %s\n' "$file" >&2
		exit 1
	fi
	grep -q 'exec\.CommandContext' "$file" || continue
	scanned=$((scanned + 1))

	# A deadline of a second or more, not already wrapped in the helper.
	matches=$(grep -nE '(<-time\.After\(|context\.WithTimeout\([^,]+,)[[:space:]]*\(?([0-9]+[[:space:]]*\*[[:space:]]*)?time\.(Second|Minute)' "$file" |
		grep -v 'testwait\.Deadline' || true)

	if [ -n "$matches" ]; then
		while IFS= read -r line; do
			printf '%s:%s\n' "$file" "$line"
			violations=$((violations + 1))
	done <<<"$matches"
	fi
done <"$file_list"

if [ "$scanned" -eq 0 ]; then
	echo "check-test-deadline-scaling: no subprocess test files found; refusing to pass" >&2
	exit 1
fi

if [ "$violations" -gt 0 ]; then
	cat >&2 <<'MSG'

Unscaled deadline in a test that starts a subprocess.

Wrap the duration in the helper so a loaded CI runner gets four times the
budget, which is the difference between a real failure and a starved one:

    context.WithTimeout(ctx, testwait.Deadline(30*time.Second))
    case <-time.After(testwait.Deadline(5 * time.Second)):

    import "github.com/luckyPipewrench/pipelock/internal/testwait"

A wait under one second is a poll tick and is not flagged. If this fires on a
wait that must stay unscaled, say why in a comment on the line and widen the
grep here rather than removing the check.
MSG
	exit 1
fi

printf 'check-test-deadline-scaling: %d subprocess test file(s) scanned, no unscaled deadlines\n' "$scanned"
