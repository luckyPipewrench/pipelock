#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

# check-cloudflare-ranges.sh — manual operator tool (NOT wired into required CI).
#
# Fetches the current Cloudflare proxy IP ranges and diffs them against the
# hardcoded prefixes in internal/playground/livechat/client_ip.go. Exits
# non-zero when the lists diverge.
#
# Usage:
#   bash scripts/check-cloudflare-ranges.sh

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SOURCE_FILE="$REPO_ROOT/internal/playground/livechat/client_ip.go"

if [[ ! -f "$SOURCE_FILE" ]]; then
  echo "ERROR: source file not found: $SOURCE_FILE" >&2
  exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# Fetch the current published ranges.
curl -sfL "https://www.cloudflare.com/ips-v4" -o "$tmpdir/ips-v4.txt"
curl -sfL "https://www.cloudflare.com/ips-v6" -o "$tmpdir/ips-v6.txt"

# Combine and sort.
{ cat "$tmpdir/ips-v4.txt"; echo; cat "$tmpdir/ips-v6.txt"; } \
  | tr -d '\r' | sed '/^$/d' | sort > "$tmpdir/published.txt"

# Extract the hardcoded prefixes from the Go source.
grep -oP 'mustParsePrefix\("\K[^"]+' "$SOURCE_FILE" | sort > "$tmpdir/hardcoded.txt"

if diff -u "$tmpdir/hardcoded.txt" "$tmpdir/published.txt" > "$tmpdir/diff.txt"; then
  echo "OK: hardcoded Cloudflare prefixes match the published lists."
  exit 0
fi

echo "DRIFT DETECTED: hardcoded Cloudflare prefixes are out of date." >&2
cat "$tmpdir/diff.txt" >&2
echo "" >&2
echo "Update internal/playground/livechat/client_ip.go and refresh the" >&2
echo "'Last refreshed' comment." >&2
exit 1
