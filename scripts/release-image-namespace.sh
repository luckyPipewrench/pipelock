#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Print the container registry namespace a release publishes to, given the
# GitHub repository that runs the release workflow.
#
# Exactly two repositories may publish: the ones whose release-workflow
# signatures installed binaries accept (internal/cli/selfupdate/update.go,
# releaseWorkflowIdentity and orgReleaseWorkflowIdentity). Anything else is a
# fork or a misconfiguration and must not push images under any name, so it
# fails here, before a build starts. The match is exact and case-sensitive,
# like the signer identity it mirrors.

set -euo pipefail

if [[ $# -ne 1 ]]; then
	printf 'usage: %s OWNER/REPOSITORY\n' "${0##*/}" >&2
	exit 2
fi

case "$1" in
	luckyPipewrench/pipelock) printf 'ghcr.io/luckypipewrench\n' ;;
	pipelab-org/pipelock) printf 'ghcr.io/pipelab-org\n' ;;
	*)
		printf 'release image namespace: %s is not a Pipelock release repository\n' "$1" >&2
		exit 1
		;;
esac
