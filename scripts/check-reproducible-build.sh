#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

for command in git go cmp sha256sum; do
	if ! command -v "$command" >/dev/null 2>&1; then
		echo "reproducible-build: required command not found: $command" >&2
		exit 1
	fi
done

version="${VERSION:-$(git describe --tags --always --dirty | sed 's/^v//')}"
build_date="$(git show -s --format=%cI HEAD)"
git_commit="$(git rev-parse --short HEAD)"
go_version="$(go env GOVERSION)"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/pipelock-repro.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

ldflags="-s -w
	-X github.com/luckyPipewrench/pipelock/internal/cliutil.Version=$version
	-X github.com/luckyPipewrench/pipelock/internal/cliutil.BuildDate=$build_date
	-X github.com/luckyPipewrench/pipelock/internal/cliutil.GitCommit=$git_commit
	-X github.com/luckyPipewrench/pipelock/internal/cliutil.GoVersion=$go_version
	-X github.com/luckyPipewrench/pipelock/internal/proxy.Version=$version"

build() {
	local output="$1"
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$ldflags" \
		-o "$output" ./cmd/pipelock
}

build "$tmp_dir/pipelock-a"
build "$tmp_dir/pipelock-b"

if ! cmp -s "$tmp_dir/pipelock-a" "$tmp_dir/pipelock-b"; then
	echo "reproducible-build: repeated builds produced different bytes" >&2
	sha256sum "$tmp_dir/pipelock-a" "$tmp_dir/pipelock-b" >&2
	exit 1
fi

digest="$(sha256sum "$tmp_dir/pipelock-a" | cut -d' ' -f1)"
echo "reproducible-build: OK sha256:$digest"
