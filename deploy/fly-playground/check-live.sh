#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
#
# Check that a served playground viewer matches its baked build record.
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
	echo "usage: $0 <public-origin> [site-viewer-dir|-] [expected-pipelock-version]" >&2
	exit 2
fi
origin="${1%/}"
site_dir="${2:-}"
# A trailing slash makes every local path fail to strip back to the manifest key.
while [ -n "${site_dir}" ] && [ "${site_dir}" != "-" ] && [ "${site_dir}" != "${site_dir%/}" ]; do
	site_dir="${site_dir%/}"
done
expected_version="${3:-}"
if [[ ! "${origin}" =~ ^https?://[^/@?#]+$ ]]; then
	echo "[check-live] ERROR: origin must be an HTTP(S) origin without a path or credentials" >&2
	exit 2
fi
if [ -n "${site_dir}" ] && [ "${site_dir}" != - ] && [ ! -d "${site_dir}" ]; then
	echo "[check-live] ERROR: site viewer directory does not exist: ${site_dir}" >&2
	exit 2
fi
for tool in curl jq; do
	if ! command -v "${tool}" >/dev/null 2>&1; then
		echo "[check-live] ERROR: ${tool} is required" >&2
		exit 2
	fi
done

hash_stream() {
	local digest
	if command -v sha256sum >/dev/null 2>&1; then
		digest="$(sha256sum)"
	else
		digest="$(shasum -a 256)"
	fi
	printf '%s' "${digest:0:64}"
}

fetch() {
	curl --fail --silent --show-error --max-time 20 --proto '=http,https' "${origin}/$1"
}

if ! info="$(fetch build-info.json)"; then
	echo "[check-live] ERROR: could not fetch build-info.json" >&2
	exit 1
fi
if ! jq -e '
	type == "object" and .schema_version == 1 and
	(.pipelock_version | type == "string") and
	(.pipelock_commit | type == "string" and test("^[0-9a-f]{40}([0-9a-f]{24})?$")) and
	(.site_commit | type == "string" and test("^[0-9a-f]{40}([0-9a-f]{24})?$")) and
	(.viewer_path | type == "string" and length > 0) and
	(.dirty | type == "boolean") and
	(.pipelock_dirty | type == "boolean") and
	(.site_dirty | type == "boolean") and
	(.built_at | type == "string" and test("Z$")) and
	(.files | type == "object" and length > 0 and has("index.html") and (has("build-info.json") | not)) and
	(.files | to_entries | all(.[];
		(.key | type == "string" and length > 0 and
			(startswith("/") or contains("\\") or test("[[:cntrl:]]") or
			(split("/") | any(. == "" or . == "." or . == ".."))) | not) and
		(.value | type == "string" and test("^[0-9a-f]{64}$"))))
' >/dev/null <<< "${info}"; then
	echo "[check-live] ERROR: invalid build-info.json" >&2
	exit 1
fi
# dirty is the bypass mark. Component flags catch a record that names a commit
# while admitting the tree did not match it. PASS must not mean "diagnostic".
if jq -e '(.dirty == true) or (.pipelock_dirty == true) or (.site_dirty == true)' >/dev/null <<< "${info}"; then
	echo "[check-live] ERROR: build record is marked dirty; refusing a diagnostic image" >&2
	exit 1
fi
if ! health="$(fetch api/live/health)"; then
	echo "[check-live] ERROR: could not fetch health" >&2
	exit 1
fi
if ! jq -e '.ok == true' >/dev/null <<< "${health}"; then
	echo "[check-live] ERROR: health is not ok" >&2
	exit 1
fi

version="$(jq -r '.pipelock_version' <<< "${info}")"
failures=0
checked=0
if [ -n "${expected_version}" ] && [ "${version}" != "${expected_version}" ]; then
	echo "[check-live] version mismatch: served=${version} expected=${expected_version}" >&2
	failures=$((failures + 1))
fi
if [ -n "${site_dir}" ] && [ "${site_dir}" != - ]; then
	if ! local_site_commit="$(git -C "${site_dir}" rev-parse --verify HEAD 2>/dev/null)"; then
		echo "[check-live] ERROR: local viewer must be inside a git work tree" >&2
		exit 1
	fi
	# Site commits that leave the viewer alone are not drift; the per-file
	# comparison below is what fails the check.
	if [ "${local_site_commit}" != "$(jq -r '.site_commit' <<< "${info}")" ]; then
		echo "[check-live] note: local site has moved past the built commit; comparing viewer files"
	fi
fi
while IFS= read -r path; do
	expected_hash="$(jq -r --arg path "${path}" '.files[$path]' <<< "${info}")"
	encoded_path="$(jq -nr --arg path "${path}" '$path | split("/") | map(@uri) | join("/")')"
	# Go's http.FileServer redirects an index.html path to its directory URL.
	case "${encoded_path}" in
	index.html|*/index.html) encoded_path="${encoded_path%index.html}" ;;
	esac
	if ! served_hash="$(fetch "${encoded_path}" | hash_stream)"; then
		echo "[check-live] fetch failed: ${path}" >&2
		failures=$((failures + 1))
	elif [ "${served_hash}" != "${expected_hash}" ]; then
		echo "[check-live] served hash mismatch: ${path}" >&2
		failures=$((failures + 1))
	fi
	checked=$((checked + 1))
	if [ -n "${site_dir}" ] && [ "${site_dir}" != - ]; then
		case "${path}" in
		pipelock-verifier.wasm|wasm_exec.js) continue ;;
		esac
		if [ ! -f "${site_dir}/${path}" ]; then
			echo "[check-live] local file missing: ${path}" >&2
			failures=$((failures + 1))
		elif [ "$(hash_stream < "${site_dir}/${path}")" != "${expected_hash}" ]; then
			echo "[check-live] local hash mismatch: ${path}" >&2
			failures=$((failures + 1))
		fi
	fi
done < <(jq -r '.files | keys[]' <<< "${info}")
if [ -n "${site_dir}" ] && [ "${site_dir}" != - ]; then
	if ! find "${site_dir}" -type f -print0 > /dev/null; then
		echo "[check-live] ERROR: cannot inspect local viewer directory" >&2
		exit 1
	fi
	while IFS= read -r -d '' local_file; do
		local_path="${local_file#"${site_dir}"/}"
		case "${local_path}" in
		build-info.json|pipelock-verifier.wasm|wasm_exec.js) continue ;;
		esac
		if ! jq -e --arg path "${local_path}" '.files | has($path)' >/dev/null <<< "${info}"; then
			echo "[check-live] local file absent from build: ${local_path}" >&2
			failures=$((failures + 1))
		fi
	done < <(find "${site_dir}" -type f -print0)
fi

if [ "${failures}" -ne 0 ]; then
	echo "[check-live] FAIL: ${checked} served files checked, ${failures} mismatch(es)" >&2
	exit 1
fi
echo "[check-live] PASS: health ok, version ${version}, ${checked} served files match build info"
echo "[check-live] sources: pipelock $(jq -r '.pipelock_commit[:12]' <<< "${info}"), site $(jq -r '.site_commit[:12]' <<< "${info}")"
if [ -n "${site_dir}" ] && [ "${site_dir}" != - ]; then
	echo "[check-live] local viewer matches recorded source files"
fi
