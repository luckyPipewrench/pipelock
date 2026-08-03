#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

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
# 0. Release tag format. The version is used verbatim as an OCI/Docker image tag
# and as attestation subject names, so it must be v-prefixed SemVer with an
# OPTIONAL prerelease and NO build metadata: '+' is invalid in an OCI/Docker tag
# (tagChars is [A-Za-z0-9_.-]), so a '+build' version would pass an abstract-SemVer
# check yet break the container publish or mismatch the provenance subject. This
# gate is the real guard (the 'v[0-9]*.[0-9]*.[0-9]*' release trigger is only a
# coarse prefilter: it rejects non-product prefixes like verifier-v0.2.0 and bare
# floating pointers like v2, but still admits v1.2.3.4 and v3.2.0+build.1), so a
# malformed tag fails closed BEFORE anything is built or pushed.
release_tag_re='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-((0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*))?$'
max_product_release_version_length=128
if ! printf '%s\n' "$VERSION" | grep -qE "$release_tag_re"; then
  echo "check-release-ready: tag '$VERSION' must be vMAJOR.MINOR.PATCH[-prerelease] with no build metadata" >&2
  exit 2
fi

VER="${VERSION#v}" # strip leading v -> bare semver used in CHANGELOG/Chart and as the OCI image tag

# The v-stripped version is used verbatim as an OCI/Docker image tag, which is
# capped at 128 characters; a longer tag passes the format check above yet fails
# only once container publishing begins.
if [ "${#VER}" -gt "$max_product_release_version_length" ]; then
  echo "check-release-ready: tag '$VERSION' exceeds the 128-character OCI image-tag limit" >&2
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHANGELOG="$REPO_ROOT/CHANGELOG.md"
CHART="$REPO_ROOT/charts/pipelock/Chart.yaml"

fail=0
note() { printf '  [FAIL] %s\n' "$1" >&2; fail=1; }

echo "release-ready gate: version=$VER"

# 0a. The release workflow's test matrix and its coverage loop must consume
# exactly the shards accepted by ci_test_packages.py. Ordinary CI and release CI
# are separate workflow surfaces; keeping this assertion in the preflight stops
# a stale release-only shard name before the tag workflow fans out.
(cd "$REPO_ROOT" && python3 -m unittest scripts.test_ci_test_packages)

# 1. CHANGELOG: a "## [<ver>] - <YYYY-MM-DD>" heading must exist with a real date.
# Match the version LITERALLY (grep -F) so metacharacters in a version string
# (e.g. the '+' in '3.2.0+build.1') are never interpreted as regex; validate the
# date part on its own, where no version text is interpolated.
heading="$(grep -F "## [$VER] - " "$CHANGELOG" | head -n 1 || true)"
if [ -n "$heading" ]; then
  date_part="${heading#"## [$VER] - "}"
  if printf '%s\n' "$date_part" | grep -qE '^[0-9]{4}-[0-9]{2}-[0-9]{2}( .*)?$'; then
    echo "  [ok]   CHANGELOG: ${heading}"
  else
    note "CHANGELOG.md '$VER' date is '${date_part}', not YYYY-MM-DD. Stamp the real release date; 'UNRELEASED' and blanks are the recurring bug."
  fi
elif grep -Fq "## [$VER]" "$CHANGELOG"; then
  note "CHANGELOG.md '$VER' section exists but has no '## [$VER] - <date>' heading. Stamp the real release date; 'UNRELEASED' and blanks are the recurring bug."
else
  note "CHANGELOG.md has no '## [$VER]' section. The version heading never landed on this ref."
fi

# 2. Chart appVersion must equal the release version.
app="$(grep -E '^appVersion:' "$CHART" | head -n 1 | sed -E 's/^appVersion:[[:space:]]*"?([^"[:space:]]+)"?.*/\1/' || true)"
if [ "$app" != "$VER" ]; then
  note "charts/pipelock/Chart.yaml appVersion is '$app', expected '$VER'. values.yaml defaults image.tag to appVersion, so a mismatch deploys the wrong image."
else
  echo "  [ok]   Chart appVersion: $app"
fi

# 3. The release keyring must be present BEFORE anything is built.
#
# GoReleaser embeds the public release keyring via
# -X ...release.PublicKeyringHex={{.Env.RELEASE_KEYRING_HEX}}. A binary built
# with that env var unset carries an EMPTY keyring, so it cannot verify any
# signed update. It then fails closed at exactly the moment someone is using it
# to prove that self-update works, which is far too late and has already cost a
# post-tag discovery once.
#
# Presence is checked here because this gate runs before the build. The
# authoritative parse of the keyring's CONTENTS lives in Go
# (release.CheckKeyringPreflight), which inspects a built binary; this check
# deliberately does not re-implement that parsing, so the two cannot drift.
#
# Set PIPELOCK_ALLOW_EMPTY_KEYRING=1 ONLY for a deliberately unofficial build
# that will be verified out of band. It is not a convenience switch: an official
# release with an empty keyring is a release nobody can safely update from.
# Trim before testing presence. The Go side trims before deciding a keyring is
# empty, so a whitespace-only value must read as empty here too; otherwise this
# gate passes a keyring the build then embeds as nothing, which is precisely the
# drift the split between these two checks was meant to avoid.
keyring_trimmed="$(printf '%s' "${RELEASE_KEYRING_HEX:-}" | tr -d '[:space:]')"
if [ -n "$keyring_trimmed" ]; then
  echo "  [ok]   release keyring: present"
elif [ "${PIPELOCK_ALLOW_EMPTY_KEYRING:-}" = "1" ]; then
  echo "  [warn] release keyring: EMPTY, explicitly allowed for an unofficial build." >&2
  echo "         This binary cannot verify a signed update. Verify it out of band." >&2
else
  note "RELEASE_KEYRING_HEX is unset or whitespace-only, so the built binary would embed an empty release keyring and could never verify a signed update. Set it, or set PIPELOCK_ALLOW_EMPTY_KEYRING=1 for a deliberately unofficial build."
fi

if [ "$fail" -ne 0 ]; then
  echo "release-ready gate: FAILED — fix the above before tagging $VERSION." >&2
  exit 1
fi
echo "release-ready gate: OK"
