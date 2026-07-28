#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
# Codecov posts its verdict once after_n_builds uploads have arrived and does
# not wait for the rest. If that number is lower than the number of coverage
# uploads CI actually produces, the status is computed on partial data: the
# lines covered only by the missing shards count as missed, patch coverage
# reads low, and the check fails before flipping to pass minutes later when the
# remaining uploads land. That is indistinguishable from a real coverage
# regression while you are looking at it.
#
# This drifted once already. The enterprise shard list grew from four to six
# and after_n_builds stayed at five, so every PR started failing coverage
# spuriously. Assert the two agree so the next shard change fails here, loudly,
# instead of silently poisoning every PR's coverage status.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW="$ROOT/.github/workflows/ci.yaml"
CODECOV="$ROOT/codecov.yml"

for f in "$WORKFLOW" "$CODECOV"; do
	if [[ ! -f "$f" ]]; then
		printf 'codecov-upload-count: cannot read %s\n' "$f" >&2
		exit 2
	fi
done

# Shards on the enterprise matrix. The upload step is gated to a single Go
# version, so this is one upload per shard, not per shard per version.
shard_line="$(grep -m1 "^ *shard: \[" "$WORKFLOW" || true)"
if [[ -z "$shard_line" ]]; then
	printf 'codecov-upload-count: no shard matrix found in %s\n' "$WORKFLOW" >&2
	exit 2
fi
shard_count="$(grep -o "'" <<<"$shard_line" | wc -l)"
shard_count=$((shard_count / 2))

# Plus the separate merged sandbox subprocess profile.
subprocess_uploads="$(grep -c 'name: Upload subprocess coverage' "$WORKFLOW" || true)"
expected=$((shard_count + subprocess_uploads))

actual="$(grep -oP '^\s*after_n_builds:\s*\K[0-9]+' "$CODECOV" || true)"
if [[ -z "$actual" ]]; then
	printf 'codecov-upload-count: after_n_builds not found in %s\n' "$CODECOV" >&2
	exit 2
fi

if [[ "$actual" != "$expected" ]]; then
	printf 'codecov-upload-count: MISMATCH\n' >&2
	printf '  codecov.yml after_n_builds = %s\n' "$actual" >&2
	printf '  CI actually uploads        = %s (%s enterprise shards + %s subprocess)\n' \
		"$expected" "$shard_count" "$subprocess_uploads" >&2
	printf '  A lower value makes Codecov judge partial data and fail spuriously.\n' >&2
	printf '  A higher value makes it never post at all.\n' >&2
	exit 1
fi

printf 'codecov-upload-count: OK (after_n_builds=%s matches %s shards + %s subprocess)\n' \
	"$actual" "$shard_count" "$subprocess_uploads"
