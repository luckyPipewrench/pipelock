#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

missing=0
while IFS= read -r -d '' path; do
	case "$path" in
		testdata/* | */testdata/*)
			continue
			;;
	esac

	if ! grep -q 'Copyright' "$path"; then
		echo "$path: missing copyright statement" >&2
		missing=1
	fi

	# Enterprise-tagged sources carry the repository's ELv2 notice instead of
	# the Apache SPDX identifier used by the open-source core.
	if grep -q 'Licensed under the Elastic License 2.0' "$path"; then
		continue
	fi
	if ! grep -q 'SPDX-License-Identifier: Apache-2.0' "$path"; then
		echo "$path: missing SPDX-License-Identifier: Apache-2.0" >&2
		missing=1
	fi
done < <(
	git ls-files -z \
		'*.go' '*.sh' '*.py' '*.js' '*.ts' '*.rs' \
		'Dockerfile' 'Dockerfile.*'
)

if ((missing != 0)); then
	echo "source-headers: FAILED" >&2
	exit 1
fi

echo "source-headers: OK"
