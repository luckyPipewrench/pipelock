#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
export LC_ALL=C

usage() {
	printf 'usage: %s BASE HEAD OUTPUT [MAX_BYTES]\n' "${0##*/}" >&2
	exit 2
}

fail() {
	printf 'ERROR: %s\n' "$*" >&2
	exit 1
}

[[ $# -ge 3 && $# -le 4 ]] || usage

base=$1
head=$2
output=$3
max_bytes=${4:-52428800}

[[ "$max_bytes" =~ ^[1-9][0-9]*$ ]] || fail "MAX_BYTES must be a positive integer"
[[ "$max_bytes" -lt 9223372036854775807 ]] || fail "MAX_BYTES is too large"

git rev-parse --verify --quiet "${base}^{commit}" >/dev/null || fail "base is not a commit: ${base}"
git rev-parse --verify --quiet "${head}^{commit}" >/dev/null || fail "head is not a commit: ${head}"
merge_base=$(git merge-base "$base" "$head") || fail "could not find a merge base"

tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/pipelock-trusted-diff.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT
path_file="$tmp_dir/paths"
draft="$tmp_dir/diff"
blob_file="$tmp_dir/blob"
header_file="$tmp_dir/header"

# Bound the path inventory while preserving git's exit status. A repository
# can classify content as binary through .gitattributes, but name-only output
# still enumerates the changed object. Disabling rename detection makes every
# new-side rename/copy destination appear independently.
set +e
git -c diff.external= -c core.attributesFile=/dev/null \
	diff --no-textconv --no-ext-diff --no-renames \
	--diff-filter=ACMRTUX --name-only -z "$merge_base" "$head" |
	head -c "$((max_bytes + 1))" > "$path_file"
statuses=("${PIPESTATUS[@]}")
set -e

path_bytes=$(wc -c < "$path_file")
if [[ "${statuses[1]}" -ne 0 ]]; then
	fail "could not bound changed-path inventory"
fi
if [[ "${statuses[0]}" -ne 0 ]]; then
	if [[ "${statuses[0]}" -ne 141 || "$path_bytes" -le "$max_bytes" ]]; then
		fail "git diff failed while enumerating changed paths (exit ${statuses[0]})"
	fi
fi
if [[ "$path_bytes" -gt "$max_bytes" ]]; then
	fail "changed-path inventory exceeds the ${max_bytes}-byte scan limit"
fi

: > "$draft"

while IFS= read -r -d '' path; do
	if [[ "$path" =~ [[:cntrl:]] ]]; then
		fail "changed path contains a control character and cannot be represented safely"
	fi

	object="${head}:${path}"
	object_type=$(git cat-file -t "$object") || fail "cannot read changed object: ${path}"
	[[ "$object_type" == "blob" ]] || fail "changed path is not a scannable blob: ${path} (${object_type})"

	blob_size=$(git cat-file -s "$object") || fail "cannot size changed blob: ${path}"
	[[ "$blob_size" =~ ^[0-9]+$ ]] || fail "invalid blob size for changed path: ${path}"
	[[ "$blob_size" -le "$max_bytes" ]] || fail "changed blob exceeds the ${max_bytes}-byte scan limit: ${path}"
	git cat-file blob "$object" > "$blob_file" || fail "cannot materialize changed blob: ${path}"
	actual_blob_size=$(wc -c < "$blob_file")
	[[ "$actual_blob_size" -eq "$blob_size" ]] || fail "short read while materializing changed blob: ${path}"

	line_count=$(wc -l < "$blob_file")
	missing_newline=0
	if [[ "$blob_size" -gt 0 ]]; then
		last_byte=$(od -An -tu1 -j "$((blob_size - 1))" -N 1 "$blob_file" | tr -d '[:space:]')
		if [[ "$last_byte" != "10" ]]; then
			line_count=$((line_count + 1))
			missing_newline=1
		fi
	fi

	{
		printf 'diff --git a/%s b/%s\n' "$path" "$path"
		printf '%s\n' '--- /dev/null'
		printf '+++ b/%s\n' "$path"
		printf '@@ -0,0 +1,%s @@\n' "$line_count"
	} > "$header_file"

	current_bytes=$(wc -c < "$draft")
	header_bytes=$(wc -c < "$header_file")
	# Every source line receives a two-byte "+ " prefix. A final newline is
	# inserted only when the blob did not have one, keeping subsequent diff
	# headers structurally separate without dropping any source byte.
	encoded_bytes=$((header_bytes + blob_size + (2 * line_count) + missing_newline))
	if [[ "$current_bytes" -gt "$((max_bytes - encoded_bytes))" ]]; then
		fail "raw changed blobs exceed the ${max_bytes}-byte scan limit"
	fi

	cat "$header_file" >> "$draft"
	if [[ "$blob_size" -gt 0 ]]; then
		sed 's/^/+ /' "$blob_file" >> "$draft"
		if [[ "$missing_newline" -eq 1 ]]; then
			printf '\n' >> "$draft"
		fi
	fi

	actual_bytes=$(wc -c < "$draft")
	[[ "$actual_bytes" -le "$max_bytes" ]] || fail "generated scan input exceeded its byte limit"
done < "$path_file"

mv -- "$draft" "$output"
printf 'raw changed-blob diff bytes: %s\n' "$(wc -c < "$output")"
