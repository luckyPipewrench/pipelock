#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
#
# Pull-request CI runs only the Go floor version (see ci.yaml's
# test-oss-go126/test-enterprise-go126/test-replay-go126 jobs, which are
# skipped with `if: github.event_name != 'pull_request'`). Pushes to main and
# the release workflow are the only two places every supported Go minor is
# still exercised together, and AGENTS.md promises "CI tests Go 1.25 and
# 1.26". This asserts release.yaml's test matrix is a superset of the Go
# minors ci.yaml runs on a push to main, so trimming a version from one
# workflow without the other fails here instead of silently narrowing the
# pre-tag guarantee.
#
# This checks MINOR versions only (1.25, 1.26), not exact patches: the
# release matrix intentionally pins an exact patch (see its own comment on
# why) and that patch drifts independently of this guard.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CI_WORKFLOW="$ROOT/.github/workflows/ci.yaml"
RELEASE_WORKFLOW="$ROOT/.github/workflows/release.yaml"

for f in "$CI_WORKFLOW" "$RELEASE_WORKFLOW"; do
	if [[ ! -f "$f" ]]; then
		printf 'check-go-matrix: cannot read %s\n' "$f" >&2
		exit 2
	fi
done

# ci.yaml's Go-minor test lanes are named test-<suite>-go<major><minor-no-dot>,
# e.g. test-oss-go125, test-enterprise-go126, test-replay-go126. Every one of
# these runs on push to main (the pull_request skip only ever excludes the
# go126 lanes, never the go125 ones), so the set of distinct job-name suffixes
# is exactly the set of Go minors ci.yaml proves on main.
mapfile -t ci_minors < <(
	grep -oE '^  test-(oss|enterprise|replay)-go[0-9]+:' "$CI_WORKFLOW" \
		| grep -oE 'go[0-9]+' \
		| sed -E 's/^go([0-9])([0-9]+)$/\1.\2/' \
		| sort -u
)

if [[ "${#ci_minors[@]}" -eq 0 ]]; then
	printf 'check-go-matrix: found no test-*-go<NN> jobs in %s; parse broke\n' "$CI_WORKFLOW" >&2
	exit 2
fi

# release.yaml's release-tests matrix pins exact patches as
# `version: 'X.Y.Z'`. Reduce to major.minor for the superset comparison.
mapfile -t release_minors < <(
	awk '/^  release-tests:/{in_block=1} in_block && /^  [a-zA-Z_-]+:$/ && !/^  release-tests:$/{in_block=0} in_block' "$RELEASE_WORKFLOW" \
		| grep -oE "version: '[0-9]+\.[0-9]+\.[0-9]+'" \
		| grep -oE "[0-9]+\.[0-9]+\.[0-9]+" \
		| sed -E 's/^([0-9]+\.[0-9]+)\.[0-9]+$/\1/' \
		| sort -u
)

if [[ "${#release_minors[@]}" -eq 0 ]]; then
	printf 'check-go-matrix: found no release-tests go matrix versions in %s; parse broke\n' "$RELEASE_WORKFLOW" >&2
	exit 2
fi

printf 'ci.yaml push-event Go minors: %s\n' "${ci_minors[*]}"
printf 'release.yaml release-tests Go minors: %s\n' "${release_minors[*]}"

missing=()
for minor in "${ci_minors[@]}"; do
	found=0
	for r in "${release_minors[@]}"; do
		if [[ "$r" == "$minor" ]]; then
			found=1
			break
		fi
	done
	if [[ "$found" -eq 0 ]]; then
		missing+=("$minor")
	fi
done

if [[ "${#missing[@]}" -gt 0 ]]; then
	printf 'check-go-matrix: release.yaml is missing Go minor(s) that ci.yaml proves on push to main: %s\n' "${missing[*]}" >&2
	printf 'check-go-matrix: a tag would ship having been proven on fewer Go versions than main is.\n' >&2
	exit 1
fi

printf 'check-go-matrix: release.yaml covers every Go minor ci.yaml runs on push to main.\n'
