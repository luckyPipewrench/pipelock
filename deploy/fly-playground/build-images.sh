#!/usr/bin/env bash
# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0
#
# Build (and optionally push) the playground VM and broker images.
#
# The broker bundles the static playground viewer at /srv/ui via a BuildKit
# named build context, so the viewer lives in the site repo (not vendored here)
# while the build stays reproducible. This script is the single source of the
# image build recipe — keep deploys going through it rather than ad-hoc
# `docker build` invocations whose flags then drift out of version control.
#
# Required env:
#   PLAYGROUND_REGISTRY  registry/app prefix, e.g. registry.fly.io/<fly-app>
#   PLAYGROUND_UI_DIR    site static/playground/demo directory (broker builds)
# Optional env:
#   PLAYGROUND_PUSH=1    also push each selected image after building
#   PLAYGROUND_ALLOW_DIRTY=1  allow source changes and mark the build dirty
#   VERSION              version embedded in the binaries (default: scripts/git-version.sh, as make build)
#
# Example:
#   PLAYGROUND_REGISTRY=registry.fly.io/<app> \
#   PLAYGROUND_UI_DIR=/path/to/site/static/playground/demo \
#   PLAYGROUND_PUSH=1 deploy/fly-playground/build-images.sh
#
# Build one image:
#   deploy/fly-playground/build-images.sh --only broker
set -euo pipefail

source "$(dirname "$0")/viewer-generated.sh"

# git status hides skip-worktree and assume-unchanged edits, and the image
# still copies or compiles those bytes. Return 0 when every committed blob
# under prefix matches the work tree, 1 when it does not, and 2 when the
# comparison itself cannot be made. An empty prefix covers the whole tree.
# exclude_generated skips the three viewer outputs staging replaces.
worktree_matches_head() {
	local root="$1" prefix="$2" exclude_generated="$3"
	local list entry mode oid path rel work differs=0 i j hashes
	local -a works=() oids=() modes=() batch=() batch_index=() hashed=() results=()
	list="$(mktemp)"
	if [ -n "${prefix}" ]; then
		if ! git -C "${root}" ls-tree -r -z HEAD -- ":(literal)${prefix}" > "${list}"; then
			rm -f -- "${list}"
			return 2
		fi
	elif ! git -C "${root}" ls-tree -r -z HEAD > "${list}"; then
		rm -f -- "${list}"
		return 2
	fi
	while IFS= read -r -d '' entry || [ -n "${entry}" ]; do
		[ -n "${entry}" ] || continue
		mode="${entry%% *}"
		oid="${entry#* }"
		oid="${oid#* }"
		oid="${oid%%$'\t'*}"
		path="${entry#*$'\t'}"
		rel="${path}"
		if [ -n "${prefix}" ]; then
			rel="${path#"${prefix}/"}"
		fi
		if [ "${exclude_generated}" = 1 ]; then
			if viewer_file_is_generated "${rel}"; then continue; fi
		fi
		# A gitlink or symlink is not the blob this record would be claiming.
		if [ "${mode}" = 120000 ] || [ "${mode}" = 160000 ]; then
			differs=1
			break
		fi
		work="${root}/${path}"
		if [ ! -f "${work}" ] || [ -L "${work}" ]; then
			differs=1
			break
		fi
		works+=("${work}")
		oids+=("${oid}")
		modes+=("${mode}")
	done < "${list}"
	rm -f -- "${list}"
	if [ "${differs}" -ne 0 ] || [ "${#works[@]}" -eq 0 ]; then
		return "${differs}"
	fi
	# One hash-object process for the whole tree. It reads one path per line,
	# so a path containing a newline is hashed on its own.
	for i in "${!works[@]}"; do
		if [[ "${works[$i]}" == *$'\n'* ]]; then
			if ! hashed[i]="$(git -C "${root}" hash-object --no-filters -- "${works[$i]}")"; then
				return 2
			fi
		else
			batch+=("${works[$i]}")
			batch_index+=("${i}")
		fi
	done
	if [ "${#batch[@]}" -gt 0 ]; then
		if ! hashes="$(printf '%s\n' "${batch[@]}" | git -C "${root}" hash-object --no-filters --stdin-paths)"; then
			return 2
		fi
		mapfile -t results <<< "${hashes}"
		if [ "${#results[@]}" -ne "${#batch[@]}" ]; then
			return 2
		fi
		for j in "${!batch_index[@]}"; do
			hashed[batch_index[j]]="${results[$j]}"
		done
	fi
	for i in "${!works[@]}"; do
		if [ "${hashed[$i]}" != "${oids[$i]}" ] ||
			{ [ "${modes[$i]}" = 100755 ] && [ ! -x "${works[$i]}" ]; } ||
			{ [ "${modes[$i]}" = 100644 ] && [ -x "${works[$i]}" ]; }; then
			return 1
		fi
	done
	return 0
}

# Files cp will copy that HEAD does not contain. The three staging outputs are
# replaced and are not source. Return 1 when such a file exists, 2 on error.
viewer_has_unrecorded_file() {
	local list extra rel
	local -A recorded=()
	list="$(mktemp)"
	if ! git -C "${SITE_ROOT}" ls-tree -r -z --name-only HEAD -- ":(literal)${VIEWER_PATH}" > "${list}"; then
		rm -f -- "${list}"
		return 2
	fi
	while IFS= read -r -d '' extra || [ -n "${extra}" ]; do
		[ -n "${extra}" ] || continue
		recorded["${extra}"]=1
	done < "${list}"
	if ! find "${PLAYGROUND_UI_DIR}" \( -type f -o -type l \) -print0 > "${list}"; then
		rm -f -- "${list}"
		return 2
	fi
	while IFS= read -r -d '' extra || [ -n "${extra}" ]; do
		[ -n "${extra}" ] || continue
		rel="${extra#"${PLAYGROUND_UI_DIR}/"}"
		if viewer_file_is_generated "${rel}"; then continue; fi
		if [ -z "${recorded["${VIEWER_PATH}/${rel}"]+x}" ]; then
			rm -f -- "${list}"
			return 1
		fi
	done < "${list}"
	rm -f -- "${list}"
	return 0
}

# Docker applies its own ignore grammar, including per-Dockerfile overrides.
# A scratch export has no RUN or external image and exposes exactly what COPY
# consumes. Ignored Git files excluded by Docker are not unrecorded inputs.
pipelock_has_unrecorded_context_file() {
	local ignored snapshot recipe context file
	ignored="$(mktemp)"
	if ! git ls-files --others --ignored --exclude-standard -z > "${ignored}"; then
		rm -f -- "${ignored}"
		return 2
	fi
	# The browser verifier is compiled on the host, outside Docker's context.
	# Go publishes the actual selected sources and embed inputs via go list.
	if [ "${build_broker}" -eq 1 ]; then
		local flags goroot modcache source_root sources input canonical
		local -A recorded_paths=()
		if ! flags="$(GOWORK=off go env GOFLAGS)"; then rm -f -- "${ignored}"; return 2; fi
		# Any GOFLAGS value can change what the host compiles (-toolexec,
		# -overlay, -modfile, -ldflags), so a clean record requires none.
		if [ -n "${flags}" ]; then
			echo "[build-images] note: GOFLAGS is set; unset GOFLAGS and run 'go env -u GOFLAGS' for a clean build record" >&2
			rm -f -- "${ignored}"
			return 1
		fi
		# Ignore workspaces for inspection and compilation: they can select a
		# cached module version that this commit does not require. GOPATH mode
		# and directory replaces can still select source outside the record.
		# Only this tree, the toolchain and the module cache count.
		if ! goroot="$(GOWORK=off go env GOROOT)" || ! modcache="$(GOWORK=off go env GOMODCACHE)" ||
			[ -z "${goroot}" ] || [ -z "${modcache}" ]; then
			rm -f -- "${ignored}"
			return 2
		fi
		# Compare physical paths: Go can retain a directory-replace symlink in
		# .Dir, while normalizing trailing slashes and dot components elsewhere.
		# The module cache need not exist yet when no dependency uses it.
		if ! source_root="$(realpath -e -- "${REPO_ROOT}")" ||
			! goroot="$(realpath -e -- "${goroot}")" ||
			! modcache="$(realpath -m -- "${modcache}")"; then
			echo "[build-images] cannot resolve the source tree, GOROOT or module cache; GNU realpath is required" >&2
			rm -f -- "${ignored}"
			return 2
		fi
		# A compiled file in this tree must be a HEAD path, whose bytes the
		# tracked-tree comparison has checked. Git lists an ignored nested clone
		# as one directory, so an ignored-file list cannot name its sources.
		sources="$(mktemp)"
		if ! git ls-tree -r -z --name-only HEAD > "${sources}"; then
			rm -f -- "${sources}" "${ignored}"
			return 2
		fi
		while IFS= read -r -d '' file; do recorded_paths["${file}"]=1; done < "${sources}"
		if ! GOWORK=off GOOS=js GOARCH=wasm go list -deps -f '{{ $dir := .Dir }}{{range .GoFiles}}{{printf "%s/%s\x00" $dir .}}{{end}}{{range .SFiles}}{{printf "%s/%s\x00" $dir .}}{{end}}{{range .HFiles}}{{printf "%s/%s\x00" $dir .}}{{end}}{{range .SysoFiles}}{{printf "%s/%s\x00" $dir .}}{{end}}{{range .EmbedFiles}}{{printf "%s/%s\x00" $dir .}}{{end}}' ./cmd/pipelock-verifier-wasm > "${sources}"; then
			rm -f -- "${sources}" "${ignored}"
			return 2
		fi
		# go list adds a newline between packages; filenames are NUL-delimited.
		while IFS= read -r -d '' input; do
			while [[ "${input}" == $'\n'* ]]; do input="${input#$'\n'}"; done
			if ! canonical="$(realpath -e -- "${input}")"; then
				echo "[build-images] cannot resolve browser verifier input ${input}" >&2
				rm -f -- "${sources}" "${ignored}"
				return 2
			fi
			case "${canonical}" in
			"${source_root}"/*)
				if [ -z "${recorded_paths["${canonical#"${source_root}/"}"]+x}" ]; then
					echo "[build-images] browser verifier compiles ${input}, which the recorded commit does not contain" >&2
					rm -f -- "${sources}" "${ignored}"
					return 1
				fi
				;;
			"${goroot}"/* | "${modcache}"/*) ;;
			*)
				echo "[build-images] browser verifier compiles ${input}, outside the recorded tree and module cache" >&2
				rm -f -- "${sources}" "${ignored}"
				return 1
				;;
			esac
		done < "${sources}"
		rm -f -- "${sources}"
	fi
	if [ ! -s "${ignored}" ]; then rm -f -- "${ignored}"; return 0; fi
	snapshot="$(mktemp -d)"
	printf 'FROM scratch\nCOPY . /\n' > "${snapshot}/Dockerfile"
	for recipe in "${CONTEXT_RECIPES[@]}"; do
		context="${snapshot}/context"
		if [ -f "${recipe}.dockerignore" ]; then
			cp "${recipe}.dockerignore" "${snapshot}/Dockerfile.dockerignore"
		else
			rm -f -- "${snapshot}/Dockerfile.dockerignore"
		fi
		if ! docker build --network none --output "type=local,dest=${context}" -f "${snapshot}/Dockerfile" . >&2; then
			rm -rf -- "${snapshot}"
			rm -f -- "${ignored}"
			return 2
		fi
		while IFS= read -r -d '' file; do
			if [ -e "${context}/${file}" ] || [ -L "${context}/${file}" ]; then
				rm -rf -- "${snapshot}"
				rm -f -- "${ignored}"
				return 1
			fi
		done < "${ignored}"
		rm -rf -- "${context}"
	done
	rm -rf -- "${snapshot}"
	rm -f -- "${ignored}"
	return 0
}

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
: "${PLAYGROUND_REGISTRY:?set PLAYGROUND_REGISTRY, e.g. registry.fly.io/<fly-app>}"

build_vm=1
build_broker=1
if [ "$#" -gt 0 ]; then
	if [ "$#" -ne 2 ] || [ "$1" != "--only" ]; then
		echo "usage: $0 [--only vm|broker]" >&2
		exit 2
	fi
	case "$2" in
	vm) build_broker=0 ;;
	broker) build_vm=0 ;;
	*)
		echo "usage: $0 [--only vm|broker]" >&2
		exit 2
		;;
	esac
fi

if [ "${build_broker}" -eq 1 ]; then
	: "${PLAYGROUND_UI_DIR:?set PLAYGROUND_UI_DIR to the site static/playground/demo dir}"
	PLAYGROUND_UI_DIR="$(cd "${PLAYGROUND_UI_DIR}" && pwd -P)"
	if [ ! -f "${PLAYGROUND_UI_DIR}/index.html" ]; then
		echo "PLAYGROUND_UI_DIR=${PLAYGROUND_UI_DIR} has no index.html; refusing to build a broker with an empty viewer" >&2
		exit 1
	fi
fi

cd "${REPO_ROOT}"
PIPELOCK_COMMIT="$(git rev-parse --verify HEAD)"
PIPELOCK_DIRTY=false
if ! pipelock_status="$(git status --porcelain --untracked-files=all)"; then
	echo "[build-images] ERROR: cannot inspect Pipelock work tree" >&2
	exit 1
fi
if [ -n "${pipelock_status}" ]; then
	PIPELOCK_DIRTY=true
fi
pipelock_match=0
worktree_matches_head "${REPO_ROOT}" "" 0 || pipelock_match=$?
if [ "${pipelock_match}" -eq 2 ]; then
	echo "[build-images] ERROR: cannot compare Pipelock tree to HEAD" >&2
	exit 1
fi
if [ "${pipelock_match}" -ne 0 ]; then
	PIPELOCK_DIRTY=true
fi
CONTEXT_RECIPES=()
if [ "${build_vm}" -eq 1 ]; then CONTEXT_RECIPES+=(deploy/fly-playground/Dockerfile); fi
if [ "${build_broker}" -eq 1 ]; then CONTEXT_RECIPES+=(deploy/fly-playground/Dockerfile.broker); fi
context_match=0
pipelock_has_unrecorded_context_file || context_match=$?
if [ "${context_match}" -eq 2 ]; then
	echo "[build-images] ERROR: cannot inspect Docker build context" >&2
	exit 1
fi
if [ "${context_match}" -ne 0 ]; then PIPELOCK_DIRTY=true; fi
SITE_DIRTY=false
if [ "${build_broker}" -eq 1 ]; then
	if ! SITE_ROOT="$(git -C "${PLAYGROUND_UI_DIR}" rev-parse --show-toplevel 2>/dev/null)"; then
		echo "[build-images] ERROR: PLAYGROUND_UI_DIR must be inside a git work tree" >&2
		exit 1
	fi
	SITE_ROOT="$(cd "${SITE_ROOT}" && pwd -P)"
	SITE_COMMIT="$(git -C "${SITE_ROOT}" rev-parse --verify HEAD)"
	VIEWER_PATH="${PLAYGROUND_UI_DIR#"${SITE_ROOT}"/}"
	if [ "${VIEWER_PATH}" = "${PLAYGROUND_UI_DIR}" ]; then
		echo "[build-images] ERROR: PLAYGROUND_UI_DIR must be inside its git work tree" >&2
		exit 1
	fi
	if ! site_status="$(git -C "${SITE_ROOT}" status --porcelain --untracked-files=all -- ":(literal)${VIEWER_PATH}")"; then
		echo "[build-images] ERROR: cannot inspect site viewer work tree" >&2
		exit 1
	fi
	if [ -n "${site_status}" ]; then SITE_DIRTY=true; fi
	site_match=0
	worktree_matches_head "${SITE_ROOT}" "${VIEWER_PATH}" 1 || site_match=$?
	if [ "${site_match}" -eq 2 ]; then
		echo "[build-images] ERROR: cannot compare site viewer tree to HEAD" >&2
		exit 1
	fi
	unrecorded=0
	viewer_has_unrecorded_file || unrecorded=$?
	if [ "${unrecorded}" -eq 2 ]; then
		echo "[build-images] ERROR: cannot list site viewer files" >&2
		exit 1
	fi
	if [ "${site_match}" -ne 0 ] || [ "${unrecorded}" -ne 0 ]; then
		SITE_DIRTY=true
	fi
fi
if [ "${PIPELOCK_DIRTY}" = true ] || [ "${SITE_DIRTY}" = true ]; then
	if [ "${PLAYGROUND_ALLOW_DIRTY:-}" != 1 ]; then
		echo "[build-images] ERROR: unrecorded build inputs found; restore clean sources and Go settings or set PLAYGROUND_ALLOW_DIRTY=1" >&2
		exit 1
	fi
fi

TAG_SUFFIX=""
if [ "${PLAYGROUND_ALLOW_DIRTY:-}" = 1 ]; then
	TAG_SUFFIX="-dirty"
fi
VM_TAG="${PLAYGROUND_REGISTRY}:vm-${PIPELOCK_COMMIT:0:12}${TAG_SUFFIX}"
if [ "${build_broker}" -eq 1 ]; then
	BROKER_TAG="${PLAYGROUND_REGISTRY}:broker-${PIPELOCK_COMMIT:0:12}-${SITE_COMMIT:0:12}${TAG_SUFFIX}"
fi

# Same version source as `make build`, so a running image names the commit it came from.
VERSION="${VERSION:-$(./scripts/git-version.sh 2>/dev/null || echo 0.0.0-dev.unknown)}"
IMAGE_LABELS=(
	--label "org.opencontainers.image.revision=${PIPELOCK_COMMIT}"
	--label "org.opencontainers.image.version=${VERSION}"
	--label "org.opencontainers.image.source=https://github.com/pipelab-org/pipelock"
)

# Honor the host HTTP proxy for `go mod download` inside the build. On this
# workstation the proxy is loopback-only, so the build also uses host
# networking; both are skipped when no proxy is set.
DOCKER_BUILD_FLAGS=()
if [ -n "${HTTP_PROXY:-${http_proxy:-${HTTPS_PROXY:-${https_proxy:-}}}}" ]; then
	proxy="${HTTP_PROXY:-${http_proxy:-${HTTPS_PROXY:-${https_proxy:-}}}}"
	https_proxy_val="${HTTPS_PROXY:-${https_proxy:-$proxy}}"
	DOCKER_BUILD_FLAGS+=(
		--network "${DOCKER_BUILD_NETWORK:-host}"
		--build-arg "HTTP_PROXY=${proxy}"
		--build-arg "HTTPS_PROXY=${https_proxy_val}"
		--build-arg "http_proxy=${proxy}"
		--build-arg "https_proxy=${https_proxy_val}"
		--build-arg "NO_PROXY=${NO_PROXY:-${no_proxy:-}}"
		--build-arg "no_proxy=${NO_PROXY:-${no_proxy:-}}"
	)
fi

if [ "${build_vm}" -eq 1 ]; then
	echo "[build-images] building VM image ${VM_TAG}"
	docker build "${DOCKER_BUILD_FLAGS[@]}" "${IMAGE_LABELS[@]}" --build-arg "VERSION=${VERSION}" -f deploy/fly-playground/Dockerfile -t "${VM_TAG}" .
fi

# The viewer's inline "Verify in your browser" button loads a WASM build of the
# shipped verifier from the served dir. Build it into a private staging copy so
# the operator's site checkout stays untouched. Requires deploy/wasm-verify/build.sh
# + cmd/pipelock-verifier-wasm (the WASM-verifier change). Fail closed if that
# build path is absent or produces no .wasm, so the image cannot silently ship a
# viewer whose inline-verify button points at missing browser-verifier assets.
# go (with the js/wasm target) and GNU realpath must be on PATH.
if [ "${build_broker}" -eq 1 ] && [ ! -x deploy/wasm-verify/build.sh ]; then
	echo "[build-images] ERROR: deploy/wasm-verify/build.sh absent; refusing to build a broker with potentially stale inline browser-verify UI" >&2
	exit 1
fi

BROKER_PREFLIGHT_ARGS=(
	serve
	--check-config
	--fly-app preflight
	--fly-token-env PREFLIGHT_FLY_TOKEN
	--image registry.example/playground@sha256:0000000000000000000000000000000000000000000000000000000000000000
	--vm-image-digest sha256:0000000000000000000000000000000000000000000000000000000000000000
	--global-daily-budget 1
	--vm-daily-turn-budget 1
	--turnstile-secret-env PREFLIGHT_TURNSTILE_SECRET
	--turnstile-sitekey 1x00000000000000000000AA
	--turnstile-expected-hostname preflight.invalid
	--turnstile-action preflight-session
	--static-dir /srv/ui
)

if [ "${build_broker}" -eq 1 ]; then
	stage="$(mktemp -d)"
	trap 'rm -rf -- "${stage}"' EXIT
	mkdir "${stage}/ui"
	cp -a "${PLAYGROUND_UI_DIR}/." "${stage}/ui/"
	if [ -n "$(find "${stage}/ui" -type l -print -quit)" ]; then
		echo "[build-images] ERROR: viewer contains symlinks; refusing incomplete provenance" >&2
		exit 1
	fi
	echo "[build-images] building browser-verifier WASM into private staging copy"
	wasm_stamp="${stage}/wasm-stamp"
	: > "${wasm_stamp}"
	GOWORK=off deploy/wasm-verify/build.sh "${stage}/ui"
	if [ -z "$(find "${stage}/ui" -type f -name '*.wasm' -newer "${wasm_stamp}" -print -quit)" ]; then
		echo "[build-images] ERROR: browser-verifier build produced no .wasm in staging; refusing to ship unwired inline verify UI" >&2
		exit 1
	fi

	# Quote JSON without a runtime parser dependency. Paths are sorted bytewise.
	json_quote() {
		local value="$1" char replacement i
		value="${value//\\/\\\\}"
		value="${value//\"/\\\"}"
		for ((i = 1; i < 32; i++)); do
			printf -v char '%b' "$(printf '\\%03o' "${i}")"
			printf -v replacement '\\u%04x' "${i}"
			value="${value//"${char}"/"${replacement}"}"
		done
		printf '"%s"' "${value}"
	}
	file_hash() {
		local digest
		if command -v sha256sum >/dev/null 2>&1; then
			if ! digest="$(sha256sum < "$1")"; then return 1; fi
		else
			if ! digest="$(shasum -a 256 < "$1")"; then return 1; fi
		fi
		printf '%s' "${digest:0:64}"
	}
	find "${stage}/ui" -type f -print0 > "${stage}/files"
	LC_ALL=C sort -z "${stage}/files" > "${stage}/sorted-files"
	{
		printf '{\n  "schema_version": 1,\n  "pipelock_version": %s,\n' "$(json_quote "${VERSION}")"
		printf '  "pipelock_commit": "%s",\n  "site_commit": "%s",\n' "${PIPELOCK_COMMIT}" "${SITE_COMMIT}"
		printf '  "viewer_path": %s,\n' "$(json_quote "${VIEWER_PATH}")"
		printf '  "dirty": %s,\n  "pipelock_dirty": %s,\n  "site_dirty": %s,\n' "$([ "${PLAYGROUND_ALLOW_DIRTY:-}" = 1 ] && echo true || echo false)" "${PIPELOCK_DIRTY}" "${SITE_DIRTY}"
		printf '  "built_at": "%s",\n  "files": {\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
		first=true
		while IFS= read -r -d '' path; do
			relative="${path#"${stage}/ui/"}"
			if [ "${relative}" = build-info.json ]; then continue; fi
			if [[ "${relative}" == *\\* || "${relative}" =~ [[:cntrl:]] ]]; then
				echo "[build-images] ERROR: viewer filename cannot be checked live" >&2
				exit 1
			fi
			if ! digest="$(file_hash "${path}")"; then
				echo "[build-images] ERROR: cannot hash staged viewer file ${relative}" >&2
				exit 1
			fi
			if [ "${first}" = false ]; then printf ',\n'; fi
			first=false
			printf '    %s: "%s"' "$(json_quote "${relative}")" "${digest}"
		done < "${stage}/sorted-files"
		printf '\n  }\n}\n'
	} > "${stage}/ui/build-info.json"

	echo "[build-images] building broker image ${BROKER_TAG} (viewer from ${PLAYGROUND_UI_DIR})"
	docker build "${DOCKER_BUILD_FLAGS[@]}" "${IMAGE_LABELS[@]}" --label "org.pipelab.playground.site-revision=${SITE_COMMIT}" --build-arg "VERSION=${VERSION}" -f deploy/fly-playground/Dockerfile.broker \
		--build-context "ui=${stage}/ui" \
		-t "${BROKER_TAG}" .

	echo "[build-images] validating broker/viewer image contract"
	docker run --rm "${BROKER_TAG}" "${BROKER_PREFLIGHT_ARGS[@]}"
fi

# The record describes the inputs checked before the build. Check them again
# before pushing, so an edit made while the images built cannot ship under a
# clean record. A check that cannot run counts as a change.
if [ "${PIPELOCK_DIRTY}" = false ] && [ "${SITE_DIRTY}" = false ]; then
	changed=0
	if ! after_commit="$(git rev-parse --verify HEAD)" || [ "${after_commit}" != "${PIPELOCK_COMMIT}" ]; then changed=1; fi
	pipelock_has_unrecorded_context_file || changed=1
	if ! after_status="$(git status --porcelain --untracked-files=all)" || [ -n "${after_status}" ]; then changed=1; fi
	worktree_matches_head "${REPO_ROOT}" "" 0 || changed=1
	if [ "${build_broker}" -eq 1 ]; then
		if ! after_commit="$(git -C "${SITE_ROOT}" rev-parse --verify HEAD)" || [ "${after_commit}" != "${SITE_COMMIT}" ]; then changed=1; fi
		if ! after_status="$(git -C "${SITE_ROOT}" status --porcelain --untracked-files=all -- ":(literal)${VIEWER_PATH}")" || [ -n "${after_status}" ]; then changed=1; fi
		worktree_matches_head "${SITE_ROOT}" "${VIEWER_PATH}" 1 || changed=1
		viewer_has_unrecorded_file || changed=1
	fi
	if [ "${changed}" -ne 0 ]; then
		echo "[build-images] ERROR: source changed during the build; nothing was pushed. Rebuild from unchanged checkouts" >&2
		exit 1
	fi
fi

if [ "${PLAYGROUND_PUSH:-}" = "1" ]; then
	if [ "${build_vm}" -eq 1 ]; then
		echo "[build-images] pushing ${VM_TAG}"
		docker push "${VM_TAG}"
	fi
	if [ "${build_broker}" -eq 1 ]; then
		echo "[build-images] pushing ${BROKER_TAG}"
		docker push "${BROKER_TAG}"
	fi
fi

echo "[build-images] done"
echo "IMAGE_REFS vm=$([ "${build_vm}" -eq 1 ] && echo "${VM_TAG}" || echo -) broker=$([ "${build_broker}" -eq 1 ] && echo "${BROKER_TAG}" || echo -)"
