#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# NOTICE declares licensing by directory, and the build system declares it by
# tag, so a file is enterprise-tier when either says so. Path alone would miss
# the enterprise-tagged sources under cmd/ and internal/; tag alone would miss
# the untagged dashboard templates under enterprise/. Stripping the negated
# form first keeps `//go:build !enterprise` core stubs out: they carry the
# Apache identifier and must keep it. Matching the constraint line anchored
# also keeps prose that merely mentions the tag from being misread as a tag.
is_enterprise_tier() {
	local path="$1" constraint
	case "$path" in
	enterprise/*) return 0 ;;
	esac
	constraint="$(grep -m1 -E '^//go:build ' "$path" || true)"
	constraint="${constraint//\!enterprise/}"
	# `enterprise` is a build-tag term, not a substring: an unrelated tag such
	# as `enterprisefoo` must not turn an Apache-licensed core source into an
	# ELv2 source.
	if [[ "$constraint" =~ (^|[^[:alnum:]_])enterprise([^[:alnum:]_]|$) ]]; then
		return 0
	fi
	return 1
}

missing=0
while IFS= read -r -d '' path; do
	if ! grep -q 'Copyright' "$path"; then
		echo "$path: missing copyright statement" >&2
		missing=1
	fi

	# Enterprise-tier sources carry the repository's ELv2 notice instead of
	# the Apache SPDX identifier used by the open-source core. Declaring the
	# Apache identifier on ELv2 code is the failure that matters: it marks
	# paid-tier code as permissively licensed, contradicting NOTICE, and no
	# amount of correct prose elsewhere in the file undoes that claim.
	if is_enterprise_tier "$path"; then
		if grep -q 'SPDX-License-Identifier: Apache-2.0' "$path"; then
			echo "$path: enterprise-tier source declares SPDX-License-Identifier: Apache-2.0; NOTICE licenses it under the Elastic License 2.0" >&2
			missing=1
		fi
		if ! grep -q 'Licensed under the Elastic License 2.0' "$path"; then
			echo "$path: enterprise-tier source missing Elastic License 2.0 notice" >&2
			missing=1
		fi
		continue
	fi

	if ! grep -q 'SPDX-License-Identifier: Apache-2.0' "$path"; then
		echo "$path: missing SPDX-License-Identifier: Apache-2.0" >&2
		missing=1
	fi
done < <(
	git ls-files -z \
		'*.go' '*.sh' '*.py' '*.js' '*.mjs' '*.ts' '*.rs' '*.html' '*.tpl' \
		'Dockerfile' 'Dockerfile.*'
)

if ((missing != 0)); then
	echo "source-headers: FAILED" >&2
	exit 1
fi

echo "source-headers: OK"
