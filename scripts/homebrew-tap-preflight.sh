#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Read the Homebrew formula through the tap credential the release job uses.
# A local GitHub login is a different identity and does not prove that
# credential can see the tap. Missing credentials and any status other than
# 200 fail closed. The token is never printed.

set -euo pipefail

token="${HOMEBREW_TAP_TOKEN:-${GH_TOKEN:-}}"
if [[ -z "$token" ]]; then
	printf 'homebrew tap preflight: HOMEBREW_TAP_TOKEN is required\n' >&2
	exit 2
fi

if ! command -v gh >/dev/null 2>&1; then
	printf 'homebrew tap preflight: gh is required\n' >&2
	exit 127
fi

export GH_TOKEN="$token"
unset HOMEBREW_TAP_TOKEN || true

body="$(mktemp)"
err="$(mktemp)"
cleanup() {
	rm -f "$body" "$err"
}
trap cleanup EXIT

set +e
gh api --include "repos/luckyPipewrench/homebrew-tap/contents/Formula/pipelock.rb?ref=main" >"$body" 2>"$err"
gh_status=$?
set -e

status_line="$(awk 'NR == 1 { print; exit }' "$body")"
case "$status_line" in
	HTTP/*\ 200|HTTP/*\ 200\ *) ;;
	*)
		printf 'homebrew tap preflight: tap contents status is not 200: %s\n' "${status_line:-no status line}" >&2
		exit 1
		;;
esac
if ((gh_status != 0)); then
	printf 'homebrew tap preflight: tap contents request failed after HTTP 200\n' >&2
	exit 1
fi
