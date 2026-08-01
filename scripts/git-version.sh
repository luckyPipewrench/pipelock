#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
#
# Resolve the product version from git tags. Single source of truth for every
# local and CI build that stamps a version into the binary.
#
# Only product release tags are considered. The repository also carries
# independently-versioned tags for the published verifiers (for example
# `verifier-v0.2.0`), and an unfiltered `git describe --tags` selects whichever
# tag is nearest in history regardless of series. Because callers then strip one
# leading "v", a nearby verifier tag produced malformed versions such as
# `erifier-v0.2.0-1-gabc1234`. Matching dotted product tags excludes both
# non-product tag prefixes and floating action pointer tags such as `v1`/`v2`.
#
# When no product tag is reachable this prints the abbreviated commit rather
# than guessing a version number: an honest commit id is preferable to a version
# borrowed from an unrelated release series.

set -euo pipefail

if version="$(git describe --tags --always --dirty --match 'v[0-9]*.[0-9]*.[0-9]*' 2>/dev/null)" &&
	[ -n "$version" ]; then
	# Strip at most one leading "v" so `v3.3.0` reports as `3.3.0`. Abbreviated
	# commit ids are hexadecimal and therefore never start with "v".
	printf '%s\n' "${version#v}"
else
	printf '%s\n' "0.0.0-dev.unknown"
fi
