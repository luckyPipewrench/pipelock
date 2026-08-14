#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

verify_accepts_and_rejects() {
	local label="$1"
	local receipt="$2"
	local tampered="$3"
	local public_key="$4"
	shift 4
	if ! "$@" "$receipt" --key "$public_key" >/dev/null; then
		printf 'release verifier install gate: %s rejected the candidate receipt\n' "$label" >&2
		return 1
	fi
	if "$@" "$tampered" --key "$public_key" >/dev/null 2>&1; then
		printf 'release verifier install gate: %s ACCEPTED the tampered candidate receipt\n' "$label" >&2
		return 1
	fi
	printf '  [ok] %s accepts candidate receipt and rejects tampered copy\n' "$label"
}
