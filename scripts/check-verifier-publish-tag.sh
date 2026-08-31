#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "${1:-}" == "--root" ]]; then
	ROOT_DIR="${2:-}"
	shift 2
fi
TAG="${1:-}"
if [[ -z "$TAG" ]]; then
	printf 'usage: %s [--root DIR] verifier-vX.Y.Z\n' "$0" >&2
	exit 2
fi

ts_version="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' "$ROOT_DIR/sdk/verifiers/ts/package.json")"
rust_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT_DIR/sdk/verifiers/rust/Cargo.toml" | head -n 1)"

if [[ -z "$ts_version" || -z "$rust_version" ]]; then
	printf 'verifier publish tag check: could not read both package versions\n' >&2
	exit 2
fi
if [[ "$ts_version" != "$rust_version" ]]; then
	printf 'verifier publish tag check: TypeScript %s does not match Rust %s\n' "$ts_version" "$rust_version" >&2
	exit 1
fi
if [[ "$TAG" != "verifier-v$ts_version" ]]; then
	printf 'verifier publish tag check: tag %s does not match package version %s\n' "$TAG" "$ts_version" >&2
	exit 1
fi

printf 'verifier publish tag check: %s matches both package manifests\n' "$TAG"
