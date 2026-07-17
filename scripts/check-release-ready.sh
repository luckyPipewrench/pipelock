#!/usr/bin/env bash
# Release-readiness gate. Hard-fails a release whose metadata does not match the
# tag, BEFORE anything is built. Catches the recurring release mistakes that no
# human checklist reliably caught:
#   - CHANGELOG version section missing, or dated UNRELEASED / a placeholder
#     (shipped wrong on v3.0.0 and v3.1.0).
#   - Chart appVersion not bumped to the release version (values.yaml defaults
#     image.tag to appVersion, so a stale one deploys the previous image).
#
# Usage:
#   scripts/check-release-ready.sh v3.2.0     # explicit tag
#   scripts/check-release-ready.sh            # reads $GITHUB_REF_NAME (CI tag push)
#
# Exit 0 = ready. Exit 1 = a blocking problem (printed). Run it locally before
# tagging; release CI runs it as the first gate every other release job needs.
set -euo pipefail

VERSION="${1:-${GITHUB_REF_NAME:-}}"
if [ -z "$VERSION" ]; then
  echo "check-release-ready: no version given and GITHUB_REF_NAME unset" >&2
  exit 2
fi
VER="${VERSION#v}" # strip leading v -> bare semver used in CHANGELOG/Chart

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHANGELOG="$REPO_ROOT/CHANGELOG.md"
CHART="$REPO_ROOT/charts/pipelock/Chart.yaml"

fail=0
note() { printf '  [FAIL] %s\n' "$1" >&2; fail=1; }

echo "release-ready gate: version=$VER"

# 1. CHANGELOG: a "## [<ver>] - <YYYY-MM-DD>" heading must exist with a real date.
line="$(grep -E "^## \[${VER//./\\.}\]" "$CHANGELOG" | head -n 1 || true)"
if [ -z "$line" ]; then
  note "CHANGELOG.md has no '## [$VER]' section. The version heading never landed on this ref."
elif ! printf '%s\n' "$line" | grep -qE "^## \[${VER//./\\.}\] - [0-9]{4}-[0-9]{2}-[0-9]{2}( .*)?$"; then
  note "CHANGELOG.md '$VER' section is not dated YYYY-MM-DD (found: '${line}'). Stamp the real release date; 'UNRELEASED' and blanks are the recurring bug."
else
  echo "  [ok]   CHANGELOG: ${line}"
fi

# 2. Chart appVersion must equal the release version.
app="$(grep -E '^appVersion:' "$CHART" | head -n 1 | sed -E 's/^appVersion:[[:space:]]*"?([^"[:space:]]+)"?.*/\1/' || true)"
if [ "$app" != "$VER" ]; then
  note "charts/pipelock/Chart.yaml appVersion is '$app', expected '$VER'. values.yaml defaults image.tag to appVersion, so a mismatch deploys the wrong image."
else
  echo "  [ok]   Chart appVersion: $app"
fi

if [ "$fail" -ne 0 ]; then
  echo "release-ready gate: FAILED — fix the above before tagging $VERSION." >&2
  exit 1
fi
echo "release-ready gate: OK"
