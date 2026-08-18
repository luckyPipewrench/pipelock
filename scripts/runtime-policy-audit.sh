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
if ! command -v rg >/dev/null 2>&1 && ! command -v grep >/dev/null 2>&1; then
	printf '%s\n' "ERROR: neither ripgrep (rg) nor grep is on PATH." >&2
	printf '%s\n' "The runtime policy audit is release-blocking and must fail closed when it cannot scan." >&2
	exit 127
fi

pattern='MCPInputScanning\.(Enabled|Action)\s*=|MCPToolScanning\.(Enabled|Action|DetectDrift)\s*=|MCPToolPolicy\.(Enabled|Action|Rules)\s*=|ResponseScanning\s*=|ResponseScanning\.(Enabled|Patterns)\s*=|DLP\.Patterns\s*=|Internal\s*='

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
