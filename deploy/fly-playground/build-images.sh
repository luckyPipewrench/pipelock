#!/usr/bin/env bash
# Copyright 2026 Josh Waldrep
# SPDX-License-Identifier: Apache-2.0
#
# Build (and optionally push) the playground VM + broker images.
#
# The broker bundles the static playground viewer at /srv/ui via a BuildKit
# named build context, so the viewer lives in the site repo (not vendored here)
# while the build stays reproducible. This script is the single source of the
# image build recipe — keep deploys going through it rather than ad-hoc
# `docker build` invocations whose flags then drift out of version control.
#
# Required env:
#   PLAYGROUND_REGISTRY  registry/app prefix, e.g. registry.fly.io/<fly-app>
#   PLAYGROUND_UI_DIR    path to the site's static/playground/demo directory
# Optional env:
#   PLAYGROUND_PUSH=1    also `docker push` both images after building
#
# Example:
#   PLAYGROUND_REGISTRY=registry.fly.io/<app> \
#   PLAYGROUND_UI_DIR=/path/to/site/static/playground/demo \
#   PLAYGROUND_PUSH=1 deploy/fly-playground/build-images.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
: "${PLAYGROUND_REGISTRY:?set PLAYGROUND_REGISTRY, e.g. registry.fly.io/<fly-app>}"
: "${PLAYGROUND_UI_DIR:?set PLAYGROUND_UI_DIR to the site static/playground/demo dir}"

if [ ! -f "${PLAYGROUND_UI_DIR}/index.html" ]; then
	echo "PLAYGROUND_UI_DIR=${PLAYGROUND_UI_DIR} has no index.html; refusing to build a broker with an empty viewer" >&2
	exit 1
fi

VM_TAG="${PLAYGROUND_REGISTRY}:vm"
BROKER_TAG="${PLAYGROUND_REGISTRY}:broker"

cd "${REPO_ROOT}"

echo "[build-images] building VM image ${VM_TAG}"
docker build -f deploy/fly-playground/Dockerfile -t "${VM_TAG}" .

# The viewer's inline "Verify in your browser" button loads a WASM build of the
# shipped verifier from the served dir. Build it straight into PLAYGROUND_UI_DIR
# so the broker bundles it into /srv/ui. The .wasm is gitignored in the site repo
# (built here at image time, never committed). Requires deploy/wasm-verify/build.sh
# + cmd/pipelock-verifier-wasm (the WASM-verifier change). Fail closed if that
# build path is absent or produces no .wasm, so the image cannot silently ship a
# viewer whose inline-verify button points at missing browser-verifier assets.
# go (with the js/wasm target) must be on PATH.
if [ ! -x deploy/wasm-verify/build.sh ]; then
	echo "[build-images] ERROR: deploy/wasm-verify/build.sh absent; refusing to build a broker with potentially stale inline browser-verify UI" >&2
	exit 1
fi
echo "[build-images] building browser-verifier WASM into ${PLAYGROUND_UI_DIR}"
wasm_stamp="$(mktemp)"
trap 'rm -f "${wasm_stamp}"' EXIT
deploy/wasm-verify/build.sh "${PLAYGROUND_UI_DIR}"
if ! find "${PLAYGROUND_UI_DIR}" -type f -name '*.wasm' -newer "${wasm_stamp}" -print -quit | grep -q .; then
	echo "[build-images] ERROR: browser-verifier build produced no .wasm under PLAYGROUND_UI_DIR=${PLAYGROUND_UI_DIR}; refusing to ship unwired inline verify UI" >&2
	exit 1
fi

echo "[build-images] building broker image ${BROKER_TAG} (viewer from ${PLAYGROUND_UI_DIR})"
docker build -f deploy/fly-playground/Dockerfile.broker \
	--build-context "ui=${PLAYGROUND_UI_DIR}" \
	-t "${BROKER_TAG}" .

if [ "${PLAYGROUND_PUSH:-}" = "1" ]; then
	echo "[build-images] pushing ${VM_TAG}"
	docker push "${VM_TAG}"
	echo "[build-images] pushing ${BROKER_TAG}"
	docker push "${BROKER_TAG}"
fi

echo "[build-images] done"
