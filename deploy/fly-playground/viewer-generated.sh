#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Staging replaces only these top-level viewer paths. Build provenance and live
# source comparison share this predicate so a new generated name cannot drift.
viewer_file_is_generated() {
	case "$1" in
	pipelock-verifier.wasm|wasm_exec.js|build-info.json) return 0 ;;
	*) return 1 ;;
	esac
}
