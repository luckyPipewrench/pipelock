#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

verify_accepts_and_rejects() {
	local label="$1"
	local receipt="$2"
	local payload_tampered="$3"
	local signature_tampered="$4"
	local public_key="$5"
	shift 5
	if ! "$@" "$receipt" --key "$public_key" >/dev/null; then
		printf 'release verifier install gate: %s rejected the candidate receipt\n' "$label" >&2
		return 1
	fi
	if "$@" "$payload_tampered" --key "$public_key" >/dev/null 2>&1; then
		printf 'release verifier install gate: %s ACCEPTED the payload-tampered candidate receipt\n' "$label" >&2
		return 1
	fi
	if "$@" "$signature_tampered" --key "$public_key" >/dev/null 2>&1; then
		printf 'release verifier install gate: %s ACCEPTED the signature-tampered candidate receipt\n' "$label" >&2
		return 1
	fi
	printf '  [ok] %s accepts candidate receipt and rejects payload/signature tampering\n' "$label"
}
