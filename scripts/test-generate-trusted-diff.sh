#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

[[ $# -eq 1 ]] || {
	printf 'usage: %s PIPELOCK_BIN\n' "${0##*/}" >&2
	exit 2
}

pipelock_bin=$1
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
generator="$script_dir/generate-trusted-diff.sh"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/pipelock-trusted-diff-test.XXXXXX")
trap 'rm -rf -- "$tmp_dir"' EXIT

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

init_repo() {
	local repo=$1
	mkdir -p "$repo"
	git -C "$repo" init -q
	git -C "$repo" config user.name test
	git -C "$repo" config user.email test@example.com
	printf 'baseline\n' > "$repo/README.md"
	git -C "$repo" add README.md
	git -C "$repo" commit -qm base
}

commit_all() {
	local repo=$1
	git -C "$repo" add -A
	git -C "$repo" commit -qm change
}

assert_scan_blocks() {
	local repo=$1
	local label=$2
	local base head diff_file scan_output status
	base=$(git -C "$repo" rev-parse HEAD^)
	head=$(git -C "$repo" rev-parse HEAD)
	diff_file="$tmp_dir/${label}.diff"
	scan_output="$tmp_dir/${label}.scan"
	(
		cd "$repo"
		bash "$generator" "$base" "$head" "$diff_file"
	)
	set +e
	"$pipelock_bin" git scan-diff < "$diff_file" > "$scan_output" 2>&1
	status=$?
	set -e
	[[ "$status" -eq 1 ]] || fail "$label: expected secret scan exit 1, got $status: $(< "$scan_output")"
	grep -q 'AWS Access ID' "$scan_output" || fail "$label: scanner did not report the synthetic credential"
}

token="AKIA$(printf 'A%.0s' {1..16})"

existing_repo="$tmp_dir/existing-credential"
init_repo "$existing_repo"
printf 'docs example\n%s\n' "$token" > "$existing_repo/doc.md"
commit_all "$existing_repo"
printf 'one more line\n' >> "$existing_repo/doc.md"
commit_all "$existing_repo"
existing_base=$(git -C "$existing_repo" rev-parse HEAD^)
existing_head=$(git -C "$existing_repo" rev-parse HEAD)
(
	cd "$existing_repo"
	bash "$generator" "$existing_base" "$existing_head" "$tmp_dir/existing.diff"
)
"$pipelock_bin" git scan-diff < "$tmp_dir/existing.diff" > "$tmp_dir/existing.scan" 2>&1 ||
	fail "untouched credential blocked an unrelated edit: $(< "$tmp_dir/existing.scan")"
grep -q '^+ one more line$' "$tmp_dir/existing.diff" || fail "ordinary text diff omitted the added line"
if grep -q "^+ .*${token}" "$tmp_dir/existing.diff"; then
	fail "ordinary text diff included an untouched credential"
fi

text_repo="$tmp_dir/new-text-credential"
init_repo "$text_repo"
printf 'ordinary content\n' > "$text_repo/notes.txt"
commit_all "$text_repo"
printf 'credential=%s\n' "$token" >> "$text_repo/notes.txt"
commit_all "$text_repo"
assert_scan_blocks "$text_repo" new_text_credential

attr_repo="$tmp_dir/attributes"
init_repo "$attr_repo"
printf 'secret.txt -diff\n' > "$attr_repo/.gitattributes"
printf 'credential=%s\n' "$token" > "$attr_repo/secret.txt"
commit_all "$attr_repo"
assert_scan_blocks "$attr_repo" attributes_binary_override

nul_repo="$tmp_dir/nul"
init_repo "$nul_repo"
printf 'prefix\0credential=%s\nsuffix\n' "$token" > "$nul_repo/payload.bin"
commit_all "$nul_repo"
assert_scan_blocks "$nul_repo" nul_blob

header_repo="$tmp_dir/header-shaped-content"
init_repo "$header_repo"
printf '++ b/credential=%s\n' "$token" > "$header_repo/header-shaped.txt"
commit_all "$header_repo"
assert_scan_blocks "$header_repo" header_shaped_content

clean_repo="$tmp_dir/clean"
init_repo "$clean_repo"
printf 'ordinary content\n' > "$clean_repo/clean.txt"
commit_all "$clean_repo"
clean_base=$(git -C "$clean_repo" rev-parse HEAD^)
clean_head=$(git -C "$clean_repo" rev-parse HEAD)
(
	cd "$clean_repo"
	bash "$generator" "$clean_base" "$clean_head" "$tmp_dir/clean.diff"
)
"$pipelock_bin" git scan-diff < "$tmp_dir/clean.diff" > "$tmp_dir/clean.scan" 2>&1 ||
	fail "clean blob did not scan cleanly: $(< "$tmp_dir/clean.scan")"
clean_hash=$(sha256sum "$tmp_dir/clean.diff" | cut -d ' ' -f 1)
(
	cd "$clean_repo"
	bash "$generator" "$clean_base" "$clean_head" "$tmp_dir/clean.diff"
)
rerun_hash=$(sha256sum "$tmp_dir/clean.diff" | cut -d ' ' -f 1)
[[ "$rerun_hash" == "$clean_hash" ]] || fail "rerun did not replace output deterministically"

delete_repo="$tmp_dir/delete-only"
init_repo "$delete_repo"
git -C "$delete_repo" rm -q README.md
git -C "$delete_repo" commit -qm delete
delete_base=$(git -C "$delete_repo" rev-parse HEAD^)
delete_head=$(git -C "$delete_repo" rev-parse HEAD)
(
	cd "$delete_repo"
	bash "$generator" "$delete_base" "$delete_head" "$tmp_dir/delete.diff"
)
"$pipelock_bin" git scan-diff < "$tmp_dir/delete.diff" > "$tmp_dir/delete.scan" 2>&1 ||
	fail "deletion-only change did not scan cleanly: $(< "$tmp_dir/delete.scan")"
[[ ! -s "$tmp_dir/delete.diff" ]] || fail "deletion-only change emitted new-side content"

set +e
(
	cd "$clean_repo"
	bash "$generator" "$clean_base" "$clean_head" "$tmp_dir/oversized.diff" 64
) > "$tmp_dir/oversized.out" 2>&1
oversized_status=$?
set -e
[[ "$oversized_status" -ne 0 ]] || fail "oversized blob was not rejected"
grep -q 'scan limit' "$tmp_dir/oversized.out" || fail "oversized rejection did not explain the scan limit"

gitlink_repo="$tmp_dir/gitlink"
init_repo "$gitlink_repo"
gitlink_target=$(git -C "$gitlink_repo" rev-parse HEAD)
git -C "$gitlink_repo" update-index --add --cacheinfo "160000,$gitlink_target,vendor/submodule"
git -C "$gitlink_repo" commit -qm gitlink
gitlink_base=$(git -C "$gitlink_repo" rev-parse HEAD^)
gitlink_head=$(git -C "$gitlink_repo" rev-parse HEAD)
set +e
(
	cd "$gitlink_repo"
	bash "$generator" "$gitlink_base" "$gitlink_head" "$tmp_dir/gitlink.diff"
) > "$tmp_dir/gitlink.out" 2>&1
gitlink_status=$?
set -e
[[ "$gitlink_status" -ne 0 ]] || fail "unscannable gitlink was not rejected"
grep -q 'not a scannable blob' "$tmp_dir/gitlink.out" || fail "gitlink rejection did not identify the unscannable object"

control_repo="$tmp_dir/control-path"
init_repo "$control_repo"
control_path=$'unsafe\nname.txt'
printf 'ordinary content\n' > "$control_repo/$control_path"
commit_all "$control_repo"
control_base=$(git -C "$control_repo" rev-parse HEAD^)
control_head=$(git -C "$control_repo" rev-parse HEAD)
set +e
(
	cd "$control_repo"
	bash "$generator" "$control_base" "$control_head" "$tmp_dir/control.diff"
) > "$tmp_dir/control.out" 2>&1
control_status=$?
set -e
[[ "$control_status" -ne 0 ]] || fail "unrepresentable control-character path was not rejected"
grep -q 'control character' "$tmp_dir/control.out" || fail "control-character rejection was not explicit"

# A mode-only change reports as changed while the content is byte-identical.
# It must scan nothing: there is no new content, and falling through to the
# full-blob path would block the author on a pre-existing finding they never
# touched. Pinned because that is exactly the availability regression this
# generator was narrowed to avoid.
mode_repo="$tmp_dir/mode-only"
init_repo "$mode_repo"
# Assemble the specimen at runtime so this test file does not itself carry a
# scannable credential literal, matching the repository convention for fake
# credentials in tests.
mode_specimen="AKIA""IOSFODNN7EXAMPLE"
printf '#!/bin/sh\n%s\n' "$mode_specimen" > "$mode_repo/script.sh"
commit_all "$mode_repo"
chmod +x "$mode_repo/script.sh"
commit_all "$mode_repo"
mode_base=$(git -C "$mode_repo" rev-parse HEAD^)
mode_head=$(git -C "$mode_repo" rev-parse HEAD)
(
	cd "$mode_repo"
	bash "$generator" "$mode_base" "$mode_head" "$tmp_dir/mode.diff"
) > /dev/null 2>&1 || fail "mode-only change was rejected"
if [[ -s "$tmp_dir/mode.diff" ]]; then
	fail "mode-only change produced scan input; a pre-existing finding would block it"
fi

printf 'trusted diff generator tests: PASS\n'
