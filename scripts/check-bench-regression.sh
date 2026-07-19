#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BENCH_BASELINE="${BENCH_BASELINE:-bench/scanner-baseline.txt}"
BENCH_REGRESSION_THRESHOLD_PCT="${BENCH_REGRESSION_THRESHOLD_PCT:-50}"
BENCH_COUNT="${BENCH_COUNT:-6}"
BENCH_TIME="${BENCH_TIME:-100ms}"
BENCH_PATTERN="${BENCH_PATTERN:-.}"
BENCH_PACKAGES="${BENCH_PACKAGES:-./internal/scanner/ ./internal/mcp/}"
BENCHSTAT_ALPHA="${BENCHSTAT_ALPHA:-1.0}"

export TMPDIR="${TMPDIR:-$HOME/.cache/pipelock-tmp}"
export GOTMPDIR="${GOTMPDIR:-$HOME/.cache/pipelock-tmp}"
export GOCACHE="${GOCACHE:-$HOME/.cache/go-build}"
mkdir -p "$TMPDIR" "$GOTMPDIR" "$GOCACHE"

read -r -a packages <<<"$BENCH_PACKAGES"

bench_cmd=(
	go test
	-bench="$BENCH_PATTERN"
	-benchmem
	-count="$BENCH_COUNT"
	-benchtime="$BENCH_TIME"
	-run='^$'
	"${packages[@]}"
)

benchstat_path() {
	if command -v benchstat >/dev/null 2>&1; then
		command -v benchstat
		return 0
	fi

	local gopath
	gopath="$(go env GOPATH 2>/dev/null || true)"
	if [[ -n "$gopath" && -x "$gopath/bin/benchstat" ]]; then
		printf '%s\n' "$gopath/bin/benchstat"
		return 0
	fi

	return 1
}

write_baseline() {
	local baseline_tmp
	baseline_tmp="$(mktemp "$TMPDIR/pipelock-bench-baseline.XXXXXX")"
	mkdir -p "$(dirname "$BENCH_BASELINE")"
	{
		printf '# Pipelock scanner/MCP benchmark baseline\n'
		printf '# Moving reference for scripts/check-bench-regression.sh; regenerate with `make bench-baseline`.\n'
		printf '# Generated: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		printf '# Machine: %s\n' "$(uname -srmo)"
		if [[ -r /proc/cpuinfo ]]; then
			awk -F': ' '/^model name[[:space:]]*:/ { print "# CPU: " $2; exit }' /proc/cpuinfo
		fi
		printf '# Go: %s\n' "$(go version)"
		printf '# Command:'
		printf ' %q' "${bench_cmd[@]}"
		printf '\n'
		"${bench_cmd[@]}"
	} >"$baseline_tmp"
	mv "$baseline_tmp" "$BENCH_BASELINE"
	printf 'bench-baseline: wrote %s\n' "$BENCH_BASELINE"
}

if [[ "${1:-}" == "--update-baseline" || "${BENCH_UPDATE_BASELINE:-0}" == "1" ]]; then
	write_baseline
	exit 0
fi

if [[ ! "$BENCH_REGRESSION_THRESHOLD_PCT" =~ ^[0-9]+([.][0-9]+)?%?$ ]]; then
	echo "bench-regression: BENCH_REGRESSION_THRESHOLD_PCT must be a non-negative percentage, got: $BENCH_REGRESSION_THRESHOLD_PCT" >&2
	exit 2
fi
threshold="${BENCH_REGRESSION_THRESHOLD_PCT%\%}"

if [[ ! -f "$BENCH_BASELINE" ]]; then
	echo "bench-regression: baseline not found: $BENCH_BASELINE" >&2
	echo "bench-regression: regenerate it with: make bench-baseline" >&2
	exit 1
fi

# benchstat is optional and used only for a human-readable summary. The pass/fail
# decision below is computed directly from the raw `go test -bench` output so the
# guard does not depend on benchstat's version-specific CSV column layout (older
# benchstat emits no "vs base" column, which silently defeated CSV parsing).
benchstat_bin="$(benchstat_path || true)"
if [[ -z "$benchstat_bin" ]]; then
	echo "bench-regression: benchstat not found; summary display disabled (decision still enforced)." >&2
	echo "bench-regression: for the readable summary, install: go install golang.org/x/perf/cmd/benchstat@latest" >&2
fi

current="$(mktemp "$TMPDIR/pipelock-bench-current.XXXXXX")"
summary="$(mktemp "$TMPDIR/pipelock-benchstat.XXXXXX")"
failures="$(mktemp "$TMPDIR/pipelock-bench-failures.XXXXXX")"
benchstat_warnings="$(mktemp "$TMPDIR/pipelock-benchstat-warnings.XXXXXX")"
trap 'rm -f "$current" "$summary" "$failures" "$benchstat_warnings"' EXIT

printf 'bench-regression: baseline=%s threshold=+%s%% count=%s benchtime=%s\n' "$BENCH_BASELINE" "$threshold" "$BENCH_COUNT" "$BENCH_TIME"
printf 'bench-regression: running:'
printf ' %q' "${bench_cmd[@]}"
printf '\n'

"${bench_cmd[@]}" >"$current"

# Optional human-readable summary; display-only, never gates the result.
if [[ -n "$benchstat_bin" ]]; then
	if "$benchstat_bin" -alpha "$BENCHSTAT_ALPHA" "$BENCH_BASELINE" "$current" >"$summary" 2>"$benchstat_warnings"; then
		cat "$summary"
	else
		echo "bench-regression: benchstat summary unavailable (continuing with raw comparison):" >&2
		cat "$benchstat_warnings" >&2
	fi
fi

# Decision: compare the fastest (min) ns/op per benchmark between baseline and
# current, straight from the raw `go test -bench` output. Min-of-N is the most
# noise-resistant single statistic (the least-contended run) and needs no
# benchstat. A benchmark must appear in BOTH files to be compared.
#
# awk exit contract (distinct sentinels so an awk fatal error is never mistaken
# for a valid outcome): 0 = comparison done (regressions, if any, are in
# "$failures"); 3 = no overlapping benchmarks to compare. awk fatally exits 2 on
# its own errors, so 2 must NOT be a business sentinel — any exit other than 0/3
# is treated as a hard failure, never as a clean run. `|| awk_status=$?` captures
# the code without disabling errexit globally.
awk_status=0
awk -v threshold="$threshold" '
	function nsop(   i, v) {
		for (i = 1; i <= NF; i++) {
			if ($i == "ns/op") {
				return $(i - 1) + 0
			}
		}
		return -1
	}
	FNR == NR {
		if ($1 ~ /^Benchmark/) {
			v = nsop()
			if (v >= 0 && (!($1 in base) || v < base[$1])) base[$1] = v
		}
		next
	}
	$1 ~ /^Benchmark/ {
		v = nsop()
		if (v >= 0 && (!($1 in cur) || v < cur[$1])) cur[$1] = v
	}
	END {
		for (name in cur) {
			if (name in base && base[name] > 0) {
				seen = 1
				pct = (cur[name] / base[name] - 1) * 100
				if (pct > threshold + 0) printf "%s +%.2f%%\n", name, pct
			}
		}
		if (!seen) exit 3
	}
' "$BENCH_BASELINE" "$current" >"$failures" || awk_status=$?

case "$awk_status" in
	0) ;;
	3)
		echo "bench-regression: no benchmark names overlap between baseline and current run; cannot compare" >&2
		echo "bench-regression: ensure BENCH_PATTERN/BENCH_PACKAGES match the baseline, or regenerate with: make bench-baseline" >&2
		exit 2
		;;
	*)
		echo "bench-regression: benchmark comparison failed unexpectedly (awk exit $awk_status)" >&2
		exit 2
		;;
esac

if [[ -s "$failures" ]]; then
	echo "bench-regression: detected ns/op regressions above +${threshold}%:" >&2
	sort "$failures" >&2
	exit 1
fi

echo "bench-regression: OK, no ns/op regression above +${threshold}%."
