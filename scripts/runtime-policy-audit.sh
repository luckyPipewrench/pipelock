#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Scan with ripgrep when it is available and fall back to grep, matching what
# scripts/check-test-stability.sh already does. Requiring ripgrep made a
# release-blocking gate depend on installing a package: a stalled distribution
# mirror failed this job on main on 2026-08-18, and the same audit runs in
# release.yaml, so a bad mirror day would have blocked a release.
#
# Fail closed only where it belongs. Neither tool present is still fatal,
# because a tripwire that cannot scan must not report clean.
# Decide the search tool by CAPABILITY, not by name. grep implementations
# differ in ways that would make this audit quietly useless rather than loudly
# broken: BusyBox grep rejects --exclude, and a grep without POSIX character
# classes would match nothing and report clean. Probe both behaviours against a
# known string and refuse a grep that fails, so the audit can never run on a
# tool that would miss what it is looking for.
grep_is_usable() {
	command -v grep >/dev/null 2>&1 || return 1
	# POSIX character classes. A grep without them matches nothing in the audit
	# pattern below, which would report clean rather than fail.
	printf 'Probe.Field \t= x\n' | grep -qE 'Probe\.Field[[:space:]]*=' || return 1
	# --exclude actually takes effect. Two distinct failures matter here and they
	# need different evidence, so the first command's status is captured rather
	# than piped: piping it into a second grep masked a rejection, because the
	# rejection prints nothing and the second grep then reports no-match.
	#
	#   status 2+                    the option was rejected outright (BusyBox)
	#   status 0 with this file      the option was accepted and ignored
	#   anything else                the exclusion took effect
	#
	# Excluding this script from a listing of its own small directory proves it
	# without a temporary directory or a large scan.
	exclude_out="$(grep -Rl --exclude='runtime-policy-audit.sh' 'grep_is_usable' scripts 2>/dev/null)"
	exclude_status=$?
	[ "$exclude_status" -le 1 ] || return 1
	case "$exclude_out" in
	*runtime-policy-audit.sh*) return 1 ;;
	esac
	return 0
}

if ! command -v rg >/dev/null 2>&1 && ! grep_is_usable; then
	printf '%s\n' "ERROR: no usable search tool. ripgrep (rg) is absent and grep either is missing," >&2
	printf '%s\n' "does not support POSIX character classes, or ignores --exclude." >&2
	printf '%s\n' "The runtime policy audit is release-blocking and must fail closed when it cannot scan." >&2
	exit 127
fi

# [[:space:]] rather than \s: \s is a GNU extension, not POSIX ERE, so a grep
# without it would match nothing and the audit would report clean. ripgrep
# accepts the POSIX class as well, so both tools read the same pattern.
pattern='MCPInputScanning\.(Enabled|Action)[[:space:]]*=|MCPToolScanning\.(Enabled|Action|DetectDrift)[[:space:]]*=|MCPToolPolicy\.(Enabled|Action|Rules)[[:space:]]*=|ResponseScanning[[:space:]]*=|ResponseScanning\.(Enabled|Patterns)[[:space:]]*=|DLP\.Patterns[[:space:]]*=|Internal[[:space:]]*='

# Capture rg's exit code explicitly. ripgrep returns:
#   0 — match(es) found (policy mutation detected — fail release)
#   1 — no matches (clean — pass)
#   2 or higher — search error (unreadable paths, invalid regex, etc.)
#
# The previous `|| true` swallowed exit 2, letting a misconfigured repo
# (missing directory, permission denied) silently pass the audit. A
# release-blocking tripwire must fail closed on scan failures.
set +e
if command -v rg >/dev/null 2>&1; then
	matches="$(rg -n "$pattern" internal/cli/runtime internal/mcp internal/proxy --glob '!**/*_test.go')"
else
	matches="$(grep -RInE --exclude='*_test.go' "$pattern" internal/cli/runtime internal/mcp internal/proxy)"
fi
status=$?
set -e

if [[ "$status" -gt 1 ]]; then
	printf '%s\n' "ERROR: runtime policy audit could not complete (search exit $status)." >&2
	printf '%s\n' "The audit is a release-blocking tripwire; a scan failure must not pass silently." >&2
	printf '%s\n' "$matches" >&2
	exit "$status"
fi

if [[ "$status" -eq 0 ]]; then
	printf '%s\n' "ERROR: runtime packages still mutate policy-relevant config directly." >&2
	printf '%s\n' "Move runtime defaults and bundle-driven policy changes into config-level clone-and-resolve logic before release." >&2
	printf '%s\n' "$matches" >&2
	exit 1
fi

printf '%s\n' "runtime policy audit: OK"
