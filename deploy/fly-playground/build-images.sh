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
	# The image copies ignored files too. Only these three generated outputs are
	# replaced in staging; other ignored inputs are not described by SITE_COMMIT.
	if ! ignored_site_files="$(git -C "${SITE_ROOT}" ls-files --others --ignored --exclude-standard -- \
		":(literal)${VIEWER_PATH}" \
		":(exclude,literal)${VIEWER_PATH}/pipelock-verifier.wasm" \
		":(exclude,literal)${VIEWER_PATH}/wasm_exec.js" \
		":(exclude,literal)${VIEWER_PATH}/build-info.json")"; then
		echo "[build-images] ERROR: cannot inspect ignored site viewer files" >&2
		exit 1
	fi
	if [ -n "${site_status}" ] || [ -n "${ignored_site_files}" ]; then
		SITE_DIRTY=true
	fi
fi
if [ "${PIPELOCK_DIRTY}" = true ] || [ "${SITE_DIRTY}" = true ]; then
	if [ "${PLAYGROUND_ALLOW_DIRTY:-}" != 1 ]; then
		echo "[build-images] ERROR: source changes found; commit them or set PLAYGROUND_ALLOW_DIRTY=1" >&2
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
# go (with the js/wasm target) must be on PATH.
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
	deploy/wasm-verify/build.sh "${stage}/ui"
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
