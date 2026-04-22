#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

pattern='MCPInputScanning\.(Enabled|Action)\s*=|MCPToolScanning\.(Enabled|Action|DetectDrift)\s*=|MCPToolPolicy\.(Enabled|Action|Rules)\s*=|ResponseScanning\s*=|ResponseScanning\.(Enabled|Patterns)\s*=|DLP\.Patterns\s*=|Internal\s*='

matches="$(rg -n "$pattern" internal/cli/runtime internal/mcp internal/proxy --glob '!**/*_test.go' || true)"

if [[ -n "$matches" ]]; then
	printf '%s\n' "ERROR: runtime packages still mutate policy-relevant config directly." >&2
	printf '%s\n' "Move runtime defaults and bundle-driven policy changes into config-level clone-and-resolve logic before release." >&2
	printf '%s\n' "$matches" >&2
	exit 1
fi

printf '%s\n' "runtime policy audit: OK"
