# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
#
# Benchmark comparator for scripts/check-bench-regression.sh.
# Usage: awk -v threshold=PCT -v missing=FILE -f bench-compare.awk BASELINE CURRENT
#
# Prints "<name> +<pct>%" for each benchmark whose fastest ns/op regressed by more
# than threshold percent, and writes each baseline benchmark name absent from
# CURRENT to the file named by missing. Exit 0 = comparison done; 3 = no
# benchmark names overlap. awk exits 2 on its own fatal errors, so 2 is never a
# business sentinel.
function benchmark_name(raw) {
	# Go appends the effective GOMAXPROCS (for example -4 or -16) to
	# benchmark names. It is run metadata, not benchmark identity.
	sub(/-[0-9]+$/, "", raw)
	return raw
}
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
		name = benchmark_name($1)
		v = nsop()
		if (v >= 0 && (!(name in base) || v < base[name])) base[name] = v
	}
	next
}
$1 ~ /^Benchmark/ {
	name = benchmark_name($1)
	v = nsop()
	if (v >= 0 && (!(name in cur) || v < cur[name])) cur[name] = v
}
END {
	# A baseline benchmark absent from the current run is lost coverage, not a
	# pass: without this, deleting or renaming a benchmark hides it.
	for (name in base) {
		if (!(name in cur)) print name > missing
	}
	for (name in cur) {
		if (name in base && base[name] > 0) {
			seen = 1
			pct = (cur[name] / base[name] - 1) * 100
			if (pct > threshold + 0) printf "%s +%.2f%%\n", name, pct
		}
	}
	if (!seen) exit 3
}
