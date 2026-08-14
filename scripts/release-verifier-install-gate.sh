#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

# Install every customer-facing verifier into an empty directory, then require
# each one to accept a receipt emitted by this candidate and reject a changed
# copy. This is intentionally separate from source-tree conformance: a green
# local build does not prove that the package a customer receives works.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INVENTORY="$ROOT_DIR/release/verifier-installers.json"
# shellcheck source=scripts/release-verifier-install-gate-lib.sh
source "$ROOT_DIR/scripts/release-verifier-install-gate-lib.sh"

usage() {
	cat <<'EOF'
Usage: scripts/release-verifier-install-gate.sh --tag vX.Y.Z [--inventory-only]

Builds a signed receipt with the checked-out candidate, installs each public
verifier into an empty directory, and proves every verifier accepts the
candidate receipt while rejecting its tampered copy.
EOF
}

tag=""
inventory_only=0
while (($#)); do
	case "$1" in
		--tag)
			(($# >= 2)) || { usage >&2; exit 64; }
			tag="$2"
			shift 2
			;;
		--inventory-only)
			inventory_only=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			printf 'release verifier install gate: unknown argument: %s\n' "$1" >&2
			usage >&2
			exit 64
			;;
	esac
done

if [[ ! "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]]; then
	printf 'release verifier install gate: --tag must be a release tag such as v3.4.0\n' >&2
	exit 64
fi
if [[ ! -f "$INVENTORY" ]]; then
	printf 'release verifier install gate: inventory is missing: %s\n' "$INVENTORY" >&2
	exit 2
fi

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		printf 'release verifier install gate: required command is unavailable: %s\n' "$1" >&2
		exit 127
	fi
}

require_command python3

inventory_rows() {
	python3 - "$INVENTORY" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    inventory = json.load(fh)

if inventory.get("schema_version") != 1:
    raise SystemExit("unsupported verifier installer inventory schema")

required_languages = {"Go", "TypeScript", "Rust", "Python"}
expected = {
    "Go": {
        "package": "pipelock-verifier",
        "install_source": "candidate source build",
        "repository": "luckyPipewrench/pipelock",
        "workflow": ".github/workflows/release.yaml",
        "environment": "tagged product release",
    },
    "TypeScript": {
        "package": "@pipelock/verifier-ts",
        "install_source": "npm",
        "repository": "luckyPipewrench/pipelock",
        "workflow": ".github/workflows/publish-verifiers.yaml",
        "environment": "verifier-release",
    },
    "Rust": {
        "package": "pipelock-verifier-rs",
        "install_source": "crates.io",
        "repository": "luckyPipewrench/pipelock",
        "workflow": ".github/workflows/publish-verifiers.yaml",
        "environment": "verifier-release",
    },
    "Python": {
        "package": "pipelock-verify",
        "install_source": "PyPI",
        "repository": "luckyPipewrench/pipelock-verify-python",
        "workflow": ".github/workflows/release.yml",
        "environment": "pypi",
    },
}
seen = set()
for entry in inventory.get("verifiers", []):
    publisher = entry.get("publisher", {})
    language = entry.get("language", "")
    required = ("package", "version", "install_source", "artifact_digest")
    if language not in required_languages or any(not entry.get(key) for key in required):
        raise SystemExit(f"invalid verifier inventory entry: {entry!r}")
    if language in seen or any(
        not publisher.get(key)
        for key in ("repository", "workflow", "environment", "source_ref", "source_commit")
    ):
        raise SystemExit(f"incomplete or duplicate verifier inventory entry: {entry!r}")
    contract = expected[language]
    actual = {
        "package": entry["package"],
        "install_source": entry["install_source"],
        "repository": publisher["repository"],
        "workflow": publisher["workflow"],
        "environment": publisher["environment"],
    }
    if actual != contract:
        raise SystemExit(f"unexpected {language} verifier publication contract: {actual!r}")
    seen.add(language)
    print("\t".join((
        language,
        entry["package"],
        entry["version"],
        entry["install_source"],
        entry["artifact_digest"],
        publisher["repository"],
        publisher["workflow"],
        publisher["environment"],
        publisher["source_ref"],
        publisher["source_commit"],
    )))

if seen != required_languages:
    missing = ", ".join(sorted(required_languages - seen))
    raise SystemExit(f"verifier inventory missing: {missing}")
PY
}

if ! inventory_output="$(inventory_rows)"; then
	printf 'release verifier install gate: verifier inventory validation failed\n' >&2
	exit 2
fi
mapfile -t rows <<<"$inventory_output"
if ((${#rows[@]} != 4)); then
	printf 'release verifier install gate: expected four verifier inventory entries\n' >&2
	exit 2
fi

printf 'Customer-installable verifier inventory for %s:\n' "$tag"
printf '%-11s %-28s %-16s %-24s %-46s %s\n' LANGUAGE PACKAGE VERSION ARTIFACT_DIGEST INSTALL_SOURCE TRUSTED_PUBLISHER
for row in "${rows[@]}"; do
	IFS=$'\t' read -r language package version install_source artifact_digest repository workflow environment source_ref source_commit <<<"$row"
	if [[ "$language" == "Go" ]]; then
		version="$tag"
		source_ref="$tag"
		source_commit="$(git -C "$ROOT_DIR" rev-parse HEAD)"
	fi
	printf '%-11s %-28s %-16s %-24s %-46s %s via %s (%s)\n' \
		"$language" "$package" "$version" "$artifact_digest" "$install_source" "$repository" "$workflow" "$environment; $source_ref@$source_commit"
done

inventory_field() {
	local wanted_language="$1"
	local wanted_field="$2"
	local row
	for row in "${rows[@]}"; do
		local row_language package version install_source artifact_digest repository workflow environment source_ref source_commit
		IFS=$'\t' read -r row_language package version install_source artifact_digest repository workflow environment source_ref source_commit <<<"$row"
		if [[ "$row_language" != "$wanted_language" ]]; then
			continue
		fi
		case "$wanted_field" in
			version) printf '%s\n' "$version" ;;
			artifact_digest) printf '%s\n' "$artifact_digest" ;;
			repository) printf '%s\n' "$repository" ;;
			source_ref) printf '%s\n' "$source_ref" ;;
			source_commit) printf '%s\n' "$source_commit" ;;
			*) return 2 ;;
		esac
		return 0
	done
	return 1
}

ts_version="$(inventory_field TypeScript version)"
rust_version="$(inventory_field Rust version)"
ts_ref="$(inventory_field TypeScript source_ref)"
rust_ref="$(inventory_field Rust source_ref)"
ts_source_commit="$(inventory_field TypeScript source_commit)"
rust_source_commit="$(inventory_field Rust source_commit)"
ts_artifact_digest="$(inventory_field TypeScript artifact_digest)"
rust_artifact_digest="$(inventory_field Rust artifact_digest)"
python_version="$(inventory_field Python version)"
python_artifact_digest="$(inventory_field Python artifact_digest)"
python_repository="$(inventory_field Python repository)"
python_ref="$(inventory_field Python source_ref)"
python_source_commit="$(inventory_field Python source_commit)"

tree_ts_version="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["version"])' "$ROOT_DIR/sdk/verifiers/ts/package.json")"
tree_ts_lock_version="$(python3 -c 'import json, sys; lock=json.load(open(sys.argv[1], encoding="utf-8")); print(lock["version"]); lock["packages"][""]["version"] == lock["version"] or sys.exit("package-lock root version mismatch")' "$ROOT_DIR/sdk/verifiers/ts/package-lock.json")"
tree_rust_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$ROOT_DIR/sdk/verifiers/rust/Cargo.toml" | head -n 1)"
tree_rust_lock_version="$(awk '
	$0 == "name = \"pipelock-verifier-rs\"" { found = 1; next }
	found && /^version = / { gsub(/version = |"/, ""); print; exit }
' "$ROOT_DIR/sdk/verifiers/rust/Cargo.lock")"
if [[ "$tree_ts_version" != "$ts_version" || "$tree_ts_lock_version" != "$ts_version" \
	|| "$tree_rust_version" != "$rust_version" || "$tree_rust_lock_version" != "$rust_version" ]]; then
	printf 'release verifier install gate: source manifests declare TS %s/%s and Rust %s/%s, inventory requires %s/%s\n' \
		"$tree_ts_version" "$tree_ts_lock_version" "$tree_rust_version" "$tree_rust_lock_version" "$ts_version" "$rust_version" >&2
	exit 2
fi

if ((inventory_only)); then
	exit 0
fi

require_command git

# A product candidate may only certify the verifier package that contains its
# verifier changes. The verifier tag must name the inventory version, resolve
# to one commit, be reachable from this candidate, and carry matching TS and
# Rust manifests. This makes a stale registry package or a stray tag fail
# before any customer-install simulation starts.
if [[ "$ts_version" != "$rust_version" || "$ts_ref" != "$rust_ref" ]]; then
	printf 'release verifier install gate: TypeScript and Rust inventory entries must name one shared verifier release\n' >&2
	exit 2
fi
if [[ "$ts_ref" != "verifier-v$ts_version" ]]; then
	printf 'release verifier install gate: verifier source ref %s does not match inventory version %s\n' "$ts_ref" "$ts_version" >&2
	exit 2
fi
if ! verifier_commit="$(git -C "$ROOT_DIR" rev-parse --verify "$ts_ref^{}" 2>/dev/null)"; then
	printf 'release verifier install gate: required verifier release tag is missing: %s\n' "$ts_ref" >&2
	exit 2
fi
if [[ ! "$ts_source_commit" =~ ^[0-9a-f]{40}$ || ! "$rust_source_commit" =~ ^[0-9a-f]{40}$ ]]; then
	printf 'release verifier install gate: inventory must pin the 40-character peeled commit for %s before the product release can proceed\n' "$ts_ref" >&2
	exit 2
fi
if [[ "$ts_source_commit" != "$rust_source_commit" || "$ts_source_commit" != "$verifier_commit" ]]; then
	printf 'release verifier install gate: inventory source commit does not equal the peeled %s commit\n' "$ts_ref" >&2
	exit 2
fi
if ! git -C "$ROOT_DIR" merge-base --is-ancestor "$verifier_commit" HEAD; then
	printf 'release verifier install gate: verifier tag %s (%s) is not part of this product candidate\n' "$ts_ref" "$verifier_commit" >&2
	exit 2
fi
mapfile -t tagged_versions < <(
	git -C "$ROOT_DIR" show "$verifier_commit:sdk/verifiers/ts/package.json" | python3 -c 'import json, sys; print(json.load(sys.stdin)["version"])'
	git -C "$ROOT_DIR" show "$verifier_commit:sdk/verifiers/ts/package-lock.json" | python3 -c 'import json, sys; lock=json.load(sys.stdin); print(lock["version"]); lock["packages"][""]["version"] == lock["version"] or sys.exit("package-lock root version mismatch")'
	git -C "$ROOT_DIR" show "$verifier_commit:sdk/verifiers/rust/Cargo.toml" | sed -n 's/^version = "\([^"]*\)"/\1/p' | head -n 1
	git -C "$ROOT_DIR" show "$verifier_commit:sdk/verifiers/rust/Cargo.lock" | awk '
		$0 == "name = \"pipelock-verifier-rs\"" { found = 1; next }
		found && /^version = / { gsub(/version = |"/, ""); print; exit }
	'
)
if ((${#tagged_versions[@]} != 4)); then
	printf 'release verifier install gate: could not read TS/Rust manifest and lockfile versions from %s\n' "$ts_ref" >&2
	exit 2
fi
tagged_ts_version="${tagged_versions[0]}"
tagged_ts_lock_version="${tagged_versions[1]}"
tagged_rust_version="${tagged_versions[2]}"
tagged_rust_lock_version="${tagged_versions[3]}"
if [[ "$tagged_ts_version" != "$ts_version" || "$tagged_ts_lock_version" != "$ts_version" \
	|| "$tagged_rust_version" != "$rust_version" || "$tagged_rust_lock_version" != "$rust_version" ]]; then
	printf 'release verifier install gate: %s manifest/lock versions are TS %s/%s and Rust %s/%s, expected %s/%s\n' \
		"$ts_ref" "$tagged_ts_version" "$tagged_ts_lock_version" "$tagged_rust_version" "$tagged_rust_lock_version" "$ts_version" "$rust_version" >&2
	exit 2
fi

# The release workflow and these checks use the same source of truth. Refuse a
# quiet inventory/workflow drift before talking to a registry.
if ! publisher_workflow="$(git -C "$ROOT_DIR" show "$verifier_commit:.github/workflows/publish-verifiers.yaml")"; then
	printf 'release verifier install gate: %s does not contain the trusted-publisher workflow\n' "$ts_ref" >&2
	exit 2
fi
if ! grep -Fq 'environment: verifier-release' <<<"$publisher_workflow" \
	|| ! grep -Fq 'id-token: write' <<<"$publisher_workflow"; then
	printf 'release verifier install gate: tagged TypeScript/Rust trusted-publisher workflow contract is missing\n' >&2
	exit 2
fi

if [[ "$python_ref" != "v$python_version" || ! "$python_source_commit" =~ ^[0-9a-f]{40}$ ]]; then
	printf 'release verifier install gate: Python source ref or commit does not match version %s\n' "$python_version" >&2
	exit 2
fi
if ! python_tag_refs="$(git ls-remote --tags "https://github.com/$python_repository.git" \
	"refs/tags/$python_ref" "refs/tags/$python_ref^{}")"; then
	printf 'release verifier install gate: could not resolve Python source tag %s from %s\n' "$python_ref" "$python_repository" >&2
	exit 2
fi
python_tag_commit="$(awk '/\^\{\}$/ { print $1; found=1 } END { if (!found && NR == 1) print first } NR == 1 { first=$1 }' <<<"$python_tag_refs")"
if [[ "$python_tag_commit" != "$python_source_commit" ]]; then
	printf 'release verifier install gate: Python source tag %s resolves to %s, inventory requires %s\n' \
		"$python_ref" "${python_tag_commit:-missing}" "$python_source_commit" >&2
	exit 2
fi

require_command npm
require_command curl

if [[ ! "$ts_artifact_digest" =~ ^sha512-[A-Za-z0-9+/]+={0,2}$ ]]; then
	printf 'release verifier install gate: inventory must pin npm dist.integrity for @pipelock/verifier-ts@%s\n' "$ts_version" >&2
	exit 2
fi
published_ts_digest="$(npm view "@pipelock/verifier-ts@$ts_version" dist.integrity)"
if [[ "$published_ts_digest" != "$ts_artifact_digest" ]]; then
	printf 'release verifier install gate: npm integrity for @pipelock/verifier-ts@%s is %s, inventory requires %s\n' \
		"$ts_version" "${published_ts_digest:-missing}" "$ts_artifact_digest" >&2
	exit 2
fi

if [[ ! "$rust_artifact_digest" =~ ^[0-9a-f]{64}$ ]]; then
	printf 'release verifier install gate: inventory must pin the crates.io checksum for pipelock-verifier-rs@%s\n' "$rust_version" >&2
	exit 2
fi
published_rust_digest="$(curl -fsSL https://index.crates.io/pi/pe/pipelock-verifier-rs | python3 -c '
import json, sys
version = sys.argv[1]
matches = [row for line in sys.stdin if (row := json.loads(line)).get("vers") == version]
if len(matches) != 1:
    raise SystemExit(f"expected one crates.io index row for {version}, found {len(matches)}")
print(matches[0]["cksum"])
' "$rust_version")"
if [[ "$published_rust_digest" != "$rust_artifact_digest" ]]; then
	printf 'release verifier install gate: crates.io checksum for pipelock-verifier-rs@%s is %s, inventory requires %s\n' \
		"$rust_version" "${published_rust_digest:-missing}" "$rust_artifact_digest" >&2
	exit 2
fi

if [[ ! "$python_artifact_digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
	printf 'release verifier install gate: inventory must pin the PyPI wheel SHA-256 for pipelock-verify@%s\n' "$python_version" >&2
	exit 2
fi

for command in go node cargo sha256sum find; do
	require_command "$command"
done

scratch_dir="$(mktemp -d "${TMPDIR:-/tmp}/pipelock-verifier-install.XXXXXX")"
cleanup() {
	# Go marks downloaded modules read-only. Restore write permission before
	# removal so a successful verification cannot be reported as failed merely
	# because the disposable cache is protected.
	chmod -R u+w "$scratch_dir" 2>/dev/null || true
	rm -rf "$scratch_dir" || true
}
trap cleanup EXIT

fixture_dir="$scratch_dir/fixture"
go_cache="$scratch_dir/go-cache"
go_mod_cache="$scratch_dir/go-mod-cache"
go_bin_dir="$scratch_dir/go/bin"
mkdir -p "$fixture_dir" "$go_cache" "$go_mod_cache" "$go_bin_dir"
candidate_commit="$(git -C "$ROOT_DIR" rev-parse HEAD)"
candidate_short_commit="$(git -C "$ROOT_DIR" rev-parse --short HEAD)"
candidate_date="$(git -C "$ROOT_DIR" log -1 --format=%cI)"
go_version="$(go env GOVERSION)"

# This is the exact candidate source. The Go binary uses the same standalone
# command and release flags as GoReleaser, then is placed in an otherwise empty
# customer-style bin directory.
GOCACHE="$go_cache" GOMODCACHE="$go_mod_cache" go run "$ROOT_DIR/scripts/release-verifier-fixture.go" --out-dir "$fixture_dir"
GOCACHE="$go_cache" GOMODCACHE="$go_mod_cache" go build -trimpath -buildvcs=false \
	-ldflags "-s -w \
	-X github.com/luckyPipewrench/pipelock/internal/cliutil.Version=${tag#v} \
	-X github.com/luckyPipewrench/pipelock/internal/cliutil.BuildDate=$candidate_date \
	-X github.com/luckyPipewrench/pipelock/internal/cliutil.GitCommit=$candidate_short_commit \
	-X github.com/luckyPipewrench/pipelock/internal/cliutil.GoVersion=$go_version" \
	-o "$go_bin_dir/pipelock-verifier" "$ROOT_DIR/cmd/pipelock-verifier"

receipt="$fixture_dir/candidate-receipt.json"
tampered="$fixture_dir/candidate-receipt-tampered.json"
key="$(tr -d '[:space:]' < "$fixture_dir/candidate-receipt-public-key.txt")"
if [[ ! "$key" =~ ^[0-9a-f]{64}$ ]]; then
	printf 'release verifier install gate: candidate fixture did not produce a valid public key\n' >&2
	exit 2
fi

# No global package manager state is reused. Each installer gets a new prefix,
# cache, and interpreter environment, so this detects bad package contents,
# entrypoints, and runtime dependencies instead of exercising our source tree.
npm_config_cache="$scratch_dir/npm-cache" npm install --ignore-scripts --omit=dev --no-save --prefix "$scratch_dir/typescript" "@pipelock/verifier-ts@$ts_version"
if [[ ! -f "$scratch_dir/typescript/package-lock.json" ]]; then
	printf 'release verifier install gate: npm install did not produce the lockfile required for signature auditing\n' >&2
	exit 2
fi
npm_config_cache="$scratch_dir/npm-cache" npm audit signatures --prefix "$scratch_dir/typescript"
CARGO_HOME="$scratch_dir/cargo-home" cargo install --locked --root "$scratch_dir/rust" "pipelock-verifier-rs@$rust_version"
python3 -m venv "$scratch_dir/python"
mkdir -p "$scratch_dir/python-dist"
PIP_DISABLE_PIP_VERSION_CHECK=1 "$scratch_dir/python/bin/python" -m pip download --isolated --no-deps \
	--only-binary=:all: --dest "$scratch_dir/python-dist" "pipelock-verify==$python_version"
mapfile -t python_wheels < <(find "$scratch_dir/python-dist" -maxdepth 1 -type f -name '*.whl')
if ((${#python_wheels[@]} != 1)); then
	printf 'release verifier install gate: expected one Python wheel, found %d\n' "${#python_wheels[@]}" >&2
	exit 2
fi
printf '%s  %s\n' "${python_artifact_digest#sha256:}" "${python_wheels[0]}" | sha256sum --check --status
PIP_DISABLE_PIP_VERSION_CHECK=1 "$scratch_dir/python/bin/python" -m pip install --isolated "${python_wheels[0]}"

go_reported_version="$($go_bin_dir/pipelock-verifier --version)"
if [[ "$go_reported_version" != "pipelock-verifier ${tag#v} "* ]]; then
	printf 'release verifier install gate: Go verifier reports unexpected version: %s\n' "$go_reported_version" >&2
	exit 2
fi
ts_installed_version="$(node -p "require('$scratch_dir/typescript/node_modules/@pipelock/verifier-ts/package.json').version")"
if [[ "$ts_installed_version" != "$ts_version" ]]; then
	printf 'release verifier install gate: installed TypeScript verifier reports %s, expected %s\n' "$ts_installed_version" "$ts_version" >&2
	exit 2
fi
mapfile -t rust_manifests < <(find "$scratch_dir/cargo-home/registry/src" -type f -path "*/pipelock-verifier-rs-$rust_version/Cargo.toml")
if ((${#rust_manifests[@]} != 1)); then
	printf 'release verifier install gate: expected one installed Rust manifest, found %d\n' "${#rust_manifests[@]}" >&2
	exit 2
fi
rust_installed_version="$(sed -n 's/^version = "\([^"]*\)"/\1/p' "${rust_manifests[0]}" | head -n 1)"
if [[ "$rust_installed_version" != "$rust_version" ]]; then
	printf 'release verifier install gate: installed Rust verifier reports %s, expected %s\n' "$rust_installed_version" "$rust_version" >&2
	exit 2
fi
rust_vcs_info="$(dirname "${rust_manifests[0]}")/.cargo_vcs_info.json"
rust_source_sha="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["git"]["sha1"])' "$rust_vcs_info")"
if [[ "$rust_source_sha" != "$rust_source_commit" ]]; then
	printf 'release verifier install gate: installed Rust crate records source %s, expected %s\n' \
		"$rust_source_sha" "$rust_source_commit" >&2
	exit 2
fi
python_installed_version="$($scratch_dir/python/bin/python -c 'import importlib.metadata; print(importlib.metadata.version("pipelock-verify"))')"
if [[ "$python_installed_version" != "$python_version" ]]; then
	printf 'release verifier install gate: installed Python verifier reports %s, expected %s\n' "$python_installed_version" "$python_version" >&2
	exit 2
fi

verify_accepts_and_rejects Go "$receipt" "$tampered" "$key" "$go_bin_dir/pipelock-verifier" receipt
verify_accepts_and_rejects TypeScript "$receipt" "$tampered" "$key" "$scratch_dir/typescript/node_modules/.bin/pipelock-verifier-ts" receipt
verify_accepts_and_rejects Rust "$receipt" "$tampered" "$key" "$scratch_dir/rust/bin/pipelock-verifier-rs" receipt
verify_accepts_and_rejects Python "$receipt" "$tampered" "$key" "$scratch_dir/python/bin/pipelock-verify"

printf 'release verifier install gate: OK (%s at %s)\n' "$tag" "$candidate_commit"
