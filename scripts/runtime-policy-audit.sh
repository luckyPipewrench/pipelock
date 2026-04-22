#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# Fail closed if ripgrep is missing. The release-blocking tripwire must
# not silently pass when its only scan tool is unavailable.
if ! command -v rg >/dev/null 2>&1; then
	printf '%s\n' "ERROR: ripgrep (rg) is required for the runtime policy audit and is not on PATH." >&2
	printf '%s\n' "Install ripgrep (e.g., apt-get install -y ripgrep) before running this script." >&2
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
matches="$(rg -n "$pattern" internal/cli/runtime internal/mcp internal/proxy --glob '!**/*_test.go')"
status=$?
set -e

if [[ "$status" -gt 1 ]]; then
	printf '%s\n' "ERROR: runtime policy audit could not complete (ripgrep exit $status)." >&2
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
