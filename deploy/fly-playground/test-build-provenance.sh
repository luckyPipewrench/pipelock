#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
server_pid=""
cleanup() {
	if [ -n "${server_pid}" ]; then kill "${server_pid}" 2>/dev/null || true; fi
	rm -rf -- "${tmp}"
}
trap cleanup EXIT

mkdir -p "${tmp}/source/deploy/fly-playground" "${tmp}/source/deploy/wasm-verify" "${tmp}/source/scripts" "${tmp}/site/static/playground/demo" "${tmp}/bin" "${tmp}/capture"
printf '.git\npipelock\ndocs\n' > "${tmp}/source/.dockerignore"
cp "${script_dir}/viewer-generated.sh" "${tmp}/source/deploy/fly-playground/viewer-generated.sh"
cp "${script_dir}/build-images.sh" "${tmp}/source/deploy/fly-playground/build-images.sh"
cat > "${tmp}/source/scripts/git-version.sh" <<'SCRIPT'
#!/usr/bin/env bash
echo v-test
SCRIPT
cat > "${tmp}/source/deploy/wasm-verify/build.sh" <<'SCRIPT'
#!/usr/bin/env bash
set -eu
if [ "${PROVENANCE_VERSION_PROBE:-}" = 1 ]; then
	go list -m -f '{{.Version}}' version.example/dep > "$1/pipelock-verifier.wasm"
else
	printf 'fresh wasm' > "$1/pipelock-verifier.wasm"
fi
printf 'fresh shim' > "$1/wasm_exec.js"
SCRIPT
cat > "${tmp}/bin/docker" <<'SCRIPT'
#!/usr/bin/env bash
set -eu
printf '%s\n' "$*" >> "${DOCKER_LOG}"
if [ "$1" = build ]; then
	for arg in "$@"; do
		case "${arg}" in
		type=local,dest=*)
			if [ "${DOCKER_CONTEXT_FAIL:-}" = 1 ]; then exit 1; fi
			context="${arg#type=local,dest=}"
			mkdir -p "${context}"
			cp -a . "${context}/"
			rm -rf -- "${context}/.git" "${context}/pipelock" "${context}/docs" "${context}/go.work" "${context}/go.work.sum"
			exit 0 ;;
		esac
	done
	while [ "$#" -gt 0 ]; do
		if [ "$1" = --build-context ]; then
			shift
			cp -a "${1#ui=}/." "${CAPTURE_DIR}/"
			if [ -n "${DOCKER_EDIT_DURING_BUILD:-}" ]; then printf 'edited mid-build\n' >> "${DOCKER_EDIT_DURING_BUILD}"; fi
			break
		fi
		shift
	done
fi
SCRIPT
chmod +x "${tmp}/source/scripts/git-version.sh" "${tmp}/source/deploy/wasm-verify/build.sh" "${tmp}/bin/docker"
printf '<!doctype html><title>viewer</title>\n' > "${tmp}/site/static/playground/demo/index.html"
printf 'viewer asset\n' > "${tmp}/site/static/playground/demo/asset file.txt"
mkdir -p "${tmp}/source/cmd/pipelock-verifier-wasm"
printf 'module fixture.example\n\ngo 1.26\n' > "${tmp}/source/go.mod"
printf 'package main\nfunc main() {}\n' > "${tmp}/source/cmd/pipelock-verifier-wasm/main.go"
git -C "${tmp}/source" init -q
git -C "${tmp}/source" -c user.name=Test -c user.email=test@example.invalid add .
git -C "${tmp}/source" -c user.name=Test -c user.email=test@example.invalid commit -qm fixture
git -C "${tmp}/site" init -q
git -C "${tmp}/site" -c user.name=Test -c user.email=test@example.invalid add .
git -C "${tmp}/site" -c user.name=Test -c user.email=test@example.invalid commit -qm fixture

export PATH="${tmp}/bin:${PATH}" PLAYGROUND_REGISTRY=registry.example/playground
export PLAYGROUND_UI_DIR="${tmp}/site/static/playground/demo" DOCKER_LOG="${tmp}/docker.log" CAPTURE_DIR="${tmp}/capture"
"${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/clean.out"
cp -a "${tmp}/capture" "${tmp}/clean-capture"
python3 -m json.tool "${tmp}/clean-capture/build-info.json" > /dev/null
python3 - "${tmp}/clean-capture" "${tmp}/site/static/playground/demo" <<'PY'
import hashlib
import json
import pathlib
import sys

viewer = pathlib.Path(sys.argv[1])
site = pathlib.Path(sys.argv[2])
info = json.loads((viewer / "build-info.json").read_text())
assert info["schema_version"] == 1 and info["dirty"] is False
assert info["pipelock_version"] == "v-test"
assert len(info["pipelock_commit"]) == len(info["site_commit"]) == 40
assert info["built_at"].endswith("Z")
assert info["viewer_path"] == "static/playground/demo"
assert list(info["files"]) == sorted(info["files"])
for name, digest in info["files"].items():
    assert hashlib.sha256((viewer / name).read_bytes()).hexdigest() == digest
assert "build-info.json" not in info["files"]
assert not (site / "build-info.json").exists()
assert not (site / "pipelock-verifier.wasm").exists()
assert not (site / "wasm_exec.js").exists()
PY
if ! grep -q 'IMAGE_REFS vm=- broker=registry.example/playground:broker-' "${tmp}/clean.out"; then
	echo 'missing immutable broker ref' >&2
	exit 1
fi
if grep -Eq '(^| )-t registry.example/playground:(vm|broker)( |$)' "${tmp}/docker.log"; then
	echo 'floating image tag created' >&2
	exit 1
fi
for label in org.opencontainers.image.revision org.opencontainers.image.version org.opencontainers.image.source org.pipelab.playground.site-revision; do
	if ! grep -q -- "--label ${label}=" "${tmp}/docker.log"; then
		echo "missing image label: ${label}" >&2
		exit 1
	fi
done

# A hidden executable-bit change is still a change to the recorded tree.
for hide in skip-worktree assume-unchanged; do
	for tree_path in "source/scripts/git-version.sh" "site/static/playground/demo/asset file.txt"; do
		tree="${tree_path%%/*}"; path="${tree_path#*/}"
		cp -p "${tmp}/${tree_path}" "${tmp}/mode-original"
		git -C "${tmp}/${tree}" update-index "--${hide}" -- "${path}"
		if [ -x "${tmp}/${tree_path}" ]; then chmod -x "${tmp}/${tree_path}"; else chmod +x "${tmp}/${tree_path}"; fi
		if bash "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/mode.out" 2>&1; then
			echo "hidden mode change accepted: ${tree_path}/${hide}" >&2; exit 1
		fi
		cp -p "${tmp}/mode-original" "${tmp}/${tree_path}"
		git -C "${tmp}/${tree}" update-index "--no-${hide}" -- "${path}"
	done
done
# Git's clean conversion must not hide raw bytes copied into the image.
mkdir -p "${tmp}/site/.git/info"
printf '*.txt text\n' > "${tmp}/site/.git/info/attributes"
git -C "${tmp}/site" update-index --skip-worktree -- "static/playground/demo/asset file.txt"
printf 'viewer asset\r\n' > "${PLAYGROUND_UI_DIR}/asset file.txt"
if "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/filters.out" 2>&1; then
	echo 'Git clean conversion hid copied CRLF bytes' >&2; exit 1
fi
printf 'viewer asset\n' > "${PLAYGROUND_UI_DIR}/asset file.txt"
git -C "${tmp}/site" update-index --no-skip-worktree -- "static/playground/demo/asset file.txt"
rm -f -- "${tmp}/site/.git/info/attributes"
# Any GOFLAGS value can change what the host compiles, so a clean record needs none.
if GOFLAGS=-trimpath "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/goflags.out" 2>&1; then
	echo 'a GOFLAGS value was accepted as clean' >&2; exit 1
fi
grep -q 'GOFLAGS is set' "${tmp}/goflags.out" || { echo 'GOFLAGS refusal does not name GOFLAGS' >&2; exit 1; }
GOFLAGS=-trimpath PLAYGROUND_ALLOW_DIRTY=1 "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > /dev/null 2>&1
python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); sys.exit(0 if d["dirty"] and d["pipelock_dirty"] else 1)' "${tmp}/capture/build-info.json" ||
	{ echo 'GOFLAGS diagnostic build was not recorded dirty' >&2; exit 1; }
# An edit made while the images build must not ship under a clean record.
for edited in "${tmp}/source/scripts/git-version.sh" "${PLAYGROUND_UI_DIR}/asset file.txt"; do
	cp -p "${edited}" "${tmp}/edit-original"
	if DOCKER_EDIT_DURING_BUILD="${edited}" "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/midbuild.out" 2>&1; then
		echo "an edit during the build was accepted as clean: ${edited}" >&2; exit 1
	fi
	grep -q 'source changed during the build' "${tmp}/midbuild.out" || { echo "mid-build edit refused for another reason: ${edited}" >&2; cat "${tmp}/midbuild.out" >&2; exit 1; }
	cp -p "${tmp}/edit-original" "${edited}"
done
"${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > /dev/null

mkdir -p "${tmp}/source/configs" "${tmp}/source/.git/info"
printf '/ignored.go\n/configs/extra.yaml\n/pipelock\n' >> "${tmp}/source/.git/info/exclude"
for input in ignored.go configs/extra.yaml; do
	printf 'unrecorded build input\n' > "${tmp}/source/${input}"
	if "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/context.out" 2>&1; then
		echo "ignored Docker input accepted as clean: ${input}" >&2; exit 1
	fi
	PLAYGROUND_ALLOW_DIRTY=1 "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/context.out" 2>&1
	jq -e '.dirty == true and .pipelock_dirty == true' "${tmp}/capture/build-info.json" > /dev/null
	rm -f -- "${tmp}/source/${input}"
done
# Host WASM compilation consumes these even when Docker excludes docs/.
mkdir -p "${tmp}/source/docs/wasm"
printf 'package main\nimport _ "fixture.example/docs/wasm"\nfunc main() {}\n' > "${tmp}/source/cmd/pipelock-verifier-wasm/main.go"
printf 'package wasm\nimport "embed"\n//go:embed *.yaml\nvar config embed.FS\n' > "${tmp}/source/docs/wasm/embed.go"
printf 'base\n' > "${tmp}/source/docs/wasm/base.yaml"
git -C "${tmp}/source" add cmd/pipelock-verifier-wasm/main.go docs/wasm/embed.go docs/wasm/base.yaml
git -C "${tmp}/source" -c user.name=Test -c user.email=test@example.invalid commit -qm 'host wasm fixture'
printf '/docs/wasm/extra.go\n/docs/wasm/extra.yaml\n' >> "${tmp}/source/.git/info/exclude"
for input in extra.go extra.yaml; do
	if [ "${input}" = extra.go ]; then printf 'package wasm\n'; else printf 'extra\n'; fi > "${tmp}/source/docs/wasm/${input}"
	if "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/host.out" 2>&1; then
		echo "ignored host WASM input accepted: ${input}" >&2; exit 1
	fi
	# VM-only does not compile the browser verifier and Docker excludes docs/.
	"${tmp}/source/deploy/fly-playground/build-images.sh" --only vm > "${tmp}/host-vm.out" 2>&1
	rm -f -- "${tmp}/source/docs/wasm/${input}"
done
# GOFLAGS can select replacement source or module bytes outside either tree.
printf '{"Replace":{}}\n' > "${tmp}/overlay.json"
if GOFLAGS="-overlay=${tmp}/overlay.json" "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/overlay.out" 2>&1; then
	echo 'source overlay was recorded as clean' >&2; exit 1
fi
PLAYGROUND_ALLOW_DIRTY=1 GOFLAGS="-overlay=${tmp}/overlay.json" "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/overlay.out" 2>&1
jq -e '.dirty == true and .pipelock_dirty == true' "${tmp}/capture/build-info.json" > /dev/null
# A workspace can select another cached version without introducing an outside
# source path. Use Go's file proxy protocol so this test needs no network.
(
	export GOPROXY="file://${tmp}/module-proxy" GOSUMDB=off GOMODCACHE="${tmp}/module-cache" GOWORK=off
	cp -a "${tmp}/source" "${tmp}/version-source"
	mkdir -p "${tmp}/version-extra"
	python3 - "${tmp}/module-proxy" <<'MODULES'
import json
import pathlib
import sys
import zipfile

root = pathlib.Path(sys.argv[1]) / "version.example/dep/@v"
root.mkdir(parents=True)
for version in ("v1.0.0", "v1.1.0"):
    mod = "module version.example/dep\n\ngo 1.26\n"
    (root / (version + ".mod")).write_text(mod)
    (root / (version + ".info")).write_text(json.dumps({"Version": version, "Time": "2026-01-01T00:00:00Z"}))
    with zipfile.ZipFile(root / (version + ".zip"), "w") as archive:
        prefix = "version.example/dep@" + version + "/"
        archive.writestr(prefix + "go.mod", mod)
        archive.writestr(prefix + "dep.go", 'package dep\nconst Version = "' + version + '"\n')
(root / "list").write_text("v1.0.0\nv1.1.0\n")
MODULES
	printf '\nrequire version.example/dep v1.0.0\n' >> "${tmp}/version-source/go.mod"
	printf 'package main\nimport dep "version.example/dep"\nfunc main() { println(dep.Version) }\n' > "${tmp}/version-source/cmd/pipelock-verifier-wasm/main.go"
	printf 'go.work\ngo.work.sum\n' > "${tmp}/version-source/.gitignore"
	printf 'go.work\ngo.work.sum\n' >> "${tmp}/version-source/.dockerignore"
	(cd "${tmp}/version-source" && GOFLAGS=-modcacherw go mod download version.example/dep@v1.0.0 version.example/dep@v1.1.0)
	git -C "${tmp}/version-source" add go.mod go.sum .gitignore .dockerignore cmd/pipelock-verifier-wasm/main.go
	git -C "${tmp}/version-source" -c user.name=Test -c user.email=test@example.invalid commit -qm 'cached module fixture'
	printf 'module extra.example\n\ngo 1.26\n\nrequire version.example/dep v1.1.0\n' > "${tmp}/version-extra/go.mod"
	printf 'go 1.26\n\nuse (\n%s\n%s\n)\n' "${tmp}/version-source" "${tmp}/version-extra" > "${tmp}/version-source/go.work"
	cp "${tmp}/version-source/go.work" "${tmp}/external.work"
	selected="$(cd "${tmp}/version-source" && GOWORK=auto go list -m -f '{{.Version}}' version.example/dep)"
	[ "${selected}" = v1.1.0 ] || { echo 'workspace fixture did not select the higher cached version' >&2; exit 1; }
	PROVENANCE_VERSION_PROBE=1 "${tmp}/version-source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/version.out" 2>&1
	cp "${tmp}/capture/pipelock-verifier.wasm" "${tmp}/recorded-version.wasm"
	grep -qx v1.0.0 "${tmp}/recorded-version.wasm"
	for workspace in auto "${tmp}/external.work"; do
		GOWORK="${workspace}" PROVENANCE_VERSION_PROBE=1 "${tmp}/version-source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/version.out" 2>&1
		if ! cmp -s "${tmp}/recorded-version.wasm" "${tmp}/capture/pipelock-verifier.wasm"; then
			echo "workspace changed verifier output: ${workspace}" >&2; exit 1
		fi
		jq -e '.dirty == false and .pipelock_dirty == false' "${tmp}/capture/build-info.json" > /dev/null
	done
)

# Workspaces are ignored even when their replacements name unrecorded source.
# Recorded go.mod replacements and GOPATH mode still need input checks.
mkdir -p "${tmp}/source/third_party/dep" "${tmp}/elsewhere/dep" "${tmp}/gopath/src/dep.example" "${tmp}/gopath/src/fixture.example/docs"
printf 'module dep.example\n\ngo 1.26\n' > "${tmp}/source/third_party/dep/go.mod"
printf 'package dep\n' > "${tmp}/source/third_party/dep/dep.go"
printf 'require dep.example v0.0.0\n\nreplace dep.example => ./third_party/dep\n' >> "${tmp}/source/go.mod"
printf 'package main\nimport _ "fixture.example/docs/wasm"\nimport _ "dep.example"\nfunc main() {}\n' > "${tmp}/source/cmd/pipelock-verifier-wasm/main.go"
git -C "${tmp}/source" add go.mod third_party cmd/pipelock-verifier-wasm/main.go
git -C "${tmp}/source" -c user.name=Test -c user.email=test@example.invalid commit -qm 'module dependency fixture'
cp "${tmp}/source/third_party/dep/go.mod" "${tmp}/elsewhere/dep/go.mod"
printf 'package dep\n// not the recorded source\n' > "${tmp}/elsewhere/dep/dep.go"
printf 'go 1.26\n\nuse %s\n' "${tmp}/source" > "${tmp}/own.work"
GOWORK="${tmp}/own.work" "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/work.out" 2>&1
jq -e '.dirty == false and .pipelock_dirty == false' "${tmp}/capture/build-info.json" > /dev/null
# Keep exercising source-path validation independently of ignored workspaces.
check_unrecorded_replacement() {
	local replacement="$1"
	cp "${tmp}/source/go.mod" "${tmp}/recorded.mod"
	GOWORK=off go -C "${tmp}/source" mod edit "-replace=dep.example=${replacement}"
	git -C "${tmp}/source" add go.mod
	git -C "${tmp}/source" -c user.name=Test -c user.email=test@example.invalid commit -qm 'replacement source fixture'
	if "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/replacement.out" 2>&1; then
		echo 'unrecorded go.mod replacement was accepted as clean source' >&2; exit 1
	fi
	grep -Eq 'outside the recorded tree|recorded commit does not contain' "${tmp}/replacement.out"
	PLAYGROUND_ALLOW_DIRTY=1 "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/replacement.out" 2>&1
	jq -e '.dirty == true and .pipelock_dirty == true' "${tmp}/capture/build-info.json" > /dev/null
	cp "${tmp}/recorded.mod" "${tmp}/source/go.mod"
	git -C "${tmp}/source" add go.mod
	git -C "${tmp}/source" -c user.name=Test -c user.email=test@example.invalid commit -qm 'restore recorded dependency fixture'
}
# Go retains directory-replace symlinks in its selected source paths. A link
# under Docker-excluded docs must not make outside source look recorded.
ln -s "${tmp}/elsewhere/dep" "${tmp}/source/docs/linked-dep"
printf '/docs/linked-dep\n' >> "${tmp}/source/.git/info/exclude"
printf 'replace dep.example => %s\n' "${tmp}/source/docs/linked-dep" | cat "${tmp}/own.work" - > "${tmp}/linked.work"
GOWORK="${tmp}/linked.work" "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/linked.out" 2>&1
jq -e '.dirty == false and .pipelock_dirty == false' "${tmp}/capture/build-info.json" > /dev/null
check_unrecorded_replacement "${tmp}/source/docs/linked-dep"
rm -f -- "${tmp}/source/docs/linked-dep"
# Git lists an ignored nested clone as one directory, never its files, so a
# dependency checked out there is inside the tree but not in the record.
git init -q "${tmp}/source/docs/nested-dep"
cp "${tmp}/elsewhere/dep/go.mod" "${tmp}/elsewhere/dep/dep.go" "${tmp}/source/docs/nested-dep/"
printf '/docs/nested-dep/\n' >> "${tmp}/source/.git/info/exclude"
printf 'replace dep.example => %s\n' "${tmp}/source/docs/nested-dep" | cat "${tmp}/own.work" - > "${tmp}/nested.work"
GOWORK="${tmp}/nested.work" "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/nested.out" 2>&1
jq -e '.dirty == false and .pipelock_dirty == false' "${tmp}/capture/build-info.json" > /dev/null
check_unrecorded_replacement "${tmp}/source/docs/nested-dep"
rm -rf -- "${tmp}/source/docs/nested-dep"
# Equivalent physical roots remain clean, including a symlinked checkout.
ln -s "${tmp}/source" "${tmp}/source-link"
ln -s "$(go env GOROOT)" "${tmp}/goroot-link"
for root in "${tmp}/goroot-link" "$(go env GOROOT)/" "$(go env GOROOT)/../$(basename "$(go env GOROOT)")"; do
	GOROOT="${root}" "${tmp}/source-link/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/roots.out" 2>&1
	jq -e '.dirty == false and .pipelock_dirty == false' "${tmp}/capture/build-info.json" > /dev/null
done
printf 'replace dep.example => %s\n' "${tmp}/elsewhere/dep" | cat "${tmp}/own.work" - > "${tmp}/replace.work"
GOWORK="${tmp}/replace.work" "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/work.out" 2>&1
jq -e '.dirty == false and .pipelock_dirty == false' "${tmp}/capture/build-info.json" > /dev/null
check_unrecorded_replacement "${tmp}/elsewhere/dep"
cp "${tmp}/elsewhere/dep/dep.go" "${tmp}/gopath/src/dep.example/dep.go"
cp -R "${tmp}/source/docs/wasm" "${tmp}/gopath/src/fixture.example/docs/wasm"
if GO111MODULE=off GOPATH="${tmp}/gopath" "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/gopath.out" 2>&1; then
	echo 'GOPATH-mode source outside the tree was recorded as clean' >&2; exit 1
fi
grep -q 'outside the recorded tree' "${tmp}/gopath.out"
printf 'excluded binary\n' > "${tmp}/source/pipelock"
"${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/excluded.out" 2>&1
jq -e '.dirty == false and .pipelock_dirty == false' "${tmp}/capture/build-info.json" > /dev/null
for failure in docker go-list; do
	if [ "${failure}" = docker ]; then
		failure_env=(DOCKER_CONTEXT_FAIL=1)
	else
		# A go that fails only for `list`; GOFLAGS cannot inject this any more
		# because any GOFLAGS value already refuses a clean record.
		mkdir -p "${tmp}/failgo"
		printf '#!/usr/bin/env bash\nif [ "$1" = list ]; then exit 1; fi\nexec %q "$@"\n' "$(command -v go)" > "${tmp}/failgo/go"
		chmod +x "${tmp}/failgo/go"
		failure_env=(PATH="${tmp}/failgo:${PATH}")
	fi
	if env "${failure_env[@]}" PLAYGROUND_ALLOW_DIRTY=1 "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/inspection.out" 2>&1; then
		echo "${failure} inspection error was accepted" >&2; exit 1
	fi
	grep -q 'cannot inspect Docker build context' "${tmp}/inspection.out"
done
rm -f -- "${tmp}/source/pipelock"

# Ignored files are still copied into the viewer image and need dirty provenance.
mkdir -p "${tmp}/site/.git/info"
printf '/static/playground/demo/test-bundle.tar.gz\n' > "${tmp}/site/.git/info/exclude"
printf 'unrecorded bundle\n' > "${PLAYGROUND_UI_DIR}/test-bundle.tar.gz"
if "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/ignored.out" 2>&1; then
	echo 'ignored viewer file was accepted as clean source' >&2
	exit 1
fi
PLAYGROUND_ALLOW_DIRTY=1 "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/ignored.out"
python3 - "${tmp}/capture/build-info.json" <<'CHECK'
import json
import sys
info = json.load(open(sys.argv[1], encoding="utf-8"))
assert info["dirty"] is True and info["site_dirty"] is True
assert "test-bundle.tar.gz" in info["files"]
CHECK
mv "${PLAYGROUND_UI_DIR}/test-bundle.tar.gz" "${tmp}/ignored-bundle.tar.gz"

# Generated outputs are replaced in staging and must not make a clean build dirty.
for generated in pipelock-verifier.wasm wasm_exec.js build-info.json; do
	printf '/static/playground/demo/%s\n' "${generated}" >> "${tmp}/site/.git/info/exclude"
	printf 'stale output\n' > "${PLAYGROUND_UI_DIR}/${generated}"
done
"${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/generated.out"
python3 - "${tmp}/capture/build-info.json" <<'CHECK'
import json
import sys
info = json.load(open(sys.argv[1], encoding="utf-8"))
assert info["dirty"] is False and info["site_dirty"] is False
CHECK
for generated in pipelock-verifier.wasm wasm_exec.js build-info.json; do
	mv "${PLAYGROUND_UI_DIR}/${generated}" "${tmp}/${generated}"
done

# A nested ignored directory, and an ignored file whose name matches a staging
# output only in a subdirectory, are still copied. The top-level exclude must
# not hide them. Brackets in the viewer directory are literal path characters.
mkdir -p "${PLAYGROUND_UI_DIR}/nested/deeper" "${PLAYGROUND_UI_DIR}/sub"
printf '/static/playground/demo/nested/\n/static/playground/demo/sub/pipelock-verifier.wasm\n' >> "${tmp}/site/.git/info/exclude"
printf 'secret\n' > "${PLAYGROUND_UI_DIR}/nested/deeper/secret.txt"
printf 'not wasm\n' > "${PLAYGROUND_UI_DIR}/sub/pipelock-verifier.wasm"
if "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/nested-ignored.out" 2>&1; then
	echo 'nested ignored viewer file was accepted as clean source' >&2
	exit 1
fi
rm -rf -- "${PLAYGROUND_UI_DIR}/nested" "${PLAYGROUND_UI_DIR}/sub"
bracket_dir="${tmp}/site/static/playground/demo[v1]"
mkdir -p "${bracket_dir}"
printf '<!doctype html><title>viewer</title>\n' > "${bracket_dir}/index.html"
git -C "${tmp}/site" add -- ":(literal)static/playground/demo[v1]/index.html"
git -C "${tmp}/site" -c user.name=Test -c user.email=test@example.invalid commit -qm 'bracket viewer'
printf '/static/playground/demo\[v1\]/hidden.txt\n' >> "${tmp}/site/.git/info/exclude"
printf 'hidden\n' > "${bracket_dir}/hidden.txt"
if PLAYGROUND_UI_DIR="${bracket_dir}" "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/bracket.out" 2>&1; then
	echo 'ignored file under a viewer path with brackets was accepted as clean source' >&2
	exit 1
fi
rm -f -- "${bracket_dir}/hidden.txt"

# git status does not list these edits, but cp still copies the changed bytes.
for hide in skip-worktree assume-unchanged; do
	git -C "${tmp}/site" update-index "--${hide}" -- "static/playground/demo/asset file.txt"
	printf 'hidden change\n' > "${PLAYGROUND_UI_DIR}/asset file.txt"
	if "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/hidden.out" 2>&1; then
		echo "viewer change hidden by ${hide} was accepted as clean source" >&2
		exit 1
	fi
	PLAYGROUND_ALLOW_DIRTY=1 "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/hidden.out"
	python3 - "${tmp}/capture/build-info.json" "${tmp}/capture/asset file.txt" <<'CHECK'
import json
import pathlib
import sys
info = json.load(open(sys.argv[1], encoding="utf-8"))
assert info["dirty"] is True and info["site_dirty"] is True and info["pipelock_dirty"] is False
assert "hidden change" in pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
CHECK
	git -C "${tmp}/site" update-index "--no-${hide}" -- "static/playground/demo/asset file.txt"
	git -C "${tmp}/site" checkout -q -- "static/playground/demo/asset file.txt"
done

printf 'changed\n' >> "${PLAYGROUND_UI_DIR}/index.html"
if "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/dirty.out" 2>&1; then
	echo 'dirty site viewer was accepted' >&2
	exit 1
fi
PLAYGROUND_ALLOW_DIRTY=1 "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/dirty.out"
python3 - "${tmp}/capture/build-info.json" <<'PY'
import json
import sys
info = json.load(open(sys.argv[1], encoding="utf-8"))
assert info["dirty"] is True and info["site_dirty"] is True
PY
grep -q -- '-dirty$' "${tmp}/dirty.out"

git -C "${tmp}/source" update-index --skip-worktree -- scripts/git-version.sh
printf 'changed\n' >> "${tmp}/source/scripts/git-version.sh"
if "${tmp}/source/deploy/fly-playground/build-images.sh" --only vm > "${tmp}/dirty.out" 2>&1; then
	echo 'Pipelock change hidden by skip-worktree was accepted' >&2
	exit 1
fi
git -C "${tmp}/source" update-index --no-skip-worktree -- scripts/git-version.sh
if "${tmp}/source/deploy/fly-playground/build-images.sh" --only vm > "${tmp}/dirty.out" 2>&1; then
	echo 'dirty Pipelock tree was accepted' >&2
	exit 1
fi
PLAYGROUND_ALLOW_DIRTY=1 "${tmp}/source/deploy/fly-playground/build-images.sh" --only vm > "${tmp}/dirty.out"
grep -q -- 'vm-.*-dirty broker=-' "${tmp}/dirty.out"
mkdir -p "${tmp}/not-a-repo"
printf '<!doctype html>\n' > "${tmp}/not-a-repo/index.html"
if PLAYGROUND_UI_DIR="${tmp}/not-a-repo" PLAYGROUND_ALLOW_DIRTY=1 "${tmp}/source/deploy/fly-playground/build-images.sh" --only broker > "${tmp}/dirty.out" 2>&1; then
	echo 'non-git viewer was accepted' >&2
	exit 1
fi
git -C "${tmp}/site" show HEAD:static/playground/demo/index.html > "${PLAYGROUND_UI_DIR}/index.html"

mkdir -p "${tmp}/web/api/live"
cp -a "${tmp}/clean-capture/." "${tmp}/web/"
printf '{"ok":true}\n' > "${tmp}/web/api/live/health"
python3 - "${tmp}/web" "${tmp}/port" <<'PY' &
import http.server
import os
import sys

os.chdir(sys.argv[1])
class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format, *_args):
        pass

    def do_GET(self):
        if self.path == "/index.html":
            self.send_response(301)
            self.send_header("Location", "/")
            self.end_headers()
            return
        return super().do_GET()

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
with open(sys.argv[2], "w", encoding="utf-8") as stream:
    stream.write(str(server.server_port))
server.serve_forever()
PY
server_pid=$!
for _ in {1..50}; do
	if [ -s "${tmp}/port" ]; then break; fi
	sleep 0.1
done
if [ ! -s "${tmp}/port" ]; then
	echo 'local test server did not start' >&2
	exit 1
fi
origin="http://127.0.0.1:$(cat "${tmp}/port")"
"${script_dir}/check-live.sh" "${origin}" "${tmp}/site/static/playground/demo" v-test > "${tmp}/check.out" || {
	cat "${tmp}/check.out" >&2
	exit 1
}
if "${script_dir}/check-live.sh" "${origin}" - wrong-version > "${tmp}/check.out" 2>&1; then
	echo 'wrong version was accepted' >&2
	exit 1
fi
printf 'local only\n' > "${PLAYGROUND_UI_DIR}/extra.txt"
if "${script_dir}/check-live.sh" "${origin}" "${PLAYGROUND_UI_DIR}" > "${tmp}/check.out" 2>&1; then
	echo 'local-only file was accepted' >&2
	exit 1
fi
mv "${PLAYGROUND_UI_DIR}/extra.txt" "${tmp}/extra.txt"
ln -s "asset file.txt" "${PLAYGROUND_UI_DIR}/extra-link"
if "${script_dir}/check-live.sh" "${origin}" "${PLAYGROUND_UI_DIR}" > "${tmp}/check.out" 2>&1; then
	echo 'local-only symlink was accepted as matching source' >&2; exit 1
fi
rm -f -- "${PLAYGROUND_UI_DIR}/extra-link"
git -C "${tmp}/site" -c user.name=Test -c user.email=test@example.invalid commit --allow-empty -qm moved
# A site commit that leaves the viewer untouched is not drift; the files decide.
if ! "${script_dir}/check-live.sh" "${origin}" "${PLAYGROUND_UI_DIR}" > "${tmp}/check.out" 2>&1; then
	echo 'site commit outside the viewer was reported as drift' >&2
	cat "${tmp}/check.out" >&2
	exit 1
fi
if ! grep -q 'site has moved past the built commit' "${tmp}/check.out"; then
	echo 'moved site commit was not noted' >&2
	exit 1
fi
# A trailing slash names the same directory and must not turn every file into drift.
if ! "${script_dir}/check-live.sh" "${origin}" "${PLAYGROUND_UI_DIR}//" > "${tmp}/check.out" 2>&1; then
	echo 'viewer directory with a trailing slash was reported as drift' >&2
	cat "${tmp}/check.out" >&2
	exit 1
fi
# An argument naming no directory must refuse, never fall back to a served-only pass.
for empty_dir in '' '/' '//'; do
	if "${script_dir}/check-live.sh" "${origin}" "${empty_dir}" > "${tmp}/check.out" 2>&1; then
		echo "viewer directory argument '${empty_dir}' skipped the local comparison" >&2
		exit 1
	fi
	if ! grep -q 'names no directory' "${tmp}/check.out"; then
		echo "viewer directory argument '${empty_dir}' failed for the wrong reason" >&2
		cat "${tmp}/check.out" >&2
		exit 1
	fi
done
printf 'tampered\n' > "${tmp}/web/asset file.txt"
if "${script_dir}/check-live.sh" "${origin}" > "${tmp}/check.out" 2>&1; then
	echo 'tampered served file was accepted' >&2
	exit 1
fi
printf 'viewer asset\n' > "${tmp}/web/asset file.txt"
python3 - "${tmp}/web/build-info.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    info = json.load(stream)
info["files"]["../outside"] = "0" * 64
with open(sys.argv[1], "w", encoding="utf-8") as stream:
    json.dump(info, stream)
PY
if "${script_dir}/check-live.sh" "${origin}" > "${tmp}/check.out" 2>&1; then
	echo 'unsafe manifest path was accepted' >&2
	exit 1
fi
cp "${tmp}/clean-capture/build-info.json" "${tmp}/web/build-info.json"
# A record that admits its tree did not match the named commit is a diagnostic
# image; the drift check must refuse it whichever flag says so.
for flag in dirty pipelock_dirty site_dirty; do
	python3 - "${tmp}/clean-capture/build-info.json" "${tmp}/web/build-info.json" "${flag}" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    info = json.load(stream)
info[sys.argv[3]] = True
with open(sys.argv[2], "w", encoding="utf-8") as stream:
    json.dump(info, stream)
PY
	if "${script_dir}/check-live.sh" "${origin}" > "${tmp}/check.out" 2>&1; then
		echo "build record with ${flag}=true was accepted" >&2
		exit 1
	fi
	if ! grep -q 'build record is marked dirty' "${tmp}/check.out"; then
		echo "build record with ${flag}=true failed for the wrong reason" >&2
		cat "${tmp}/check.out" >&2
		exit 1
	fi
done
cp "${tmp}/clean-capture/build-info.json" "${tmp}/web/build-info.json"
printf '{"ok":false}\n' > "${tmp}/web/api/live/health"
if "${script_dir}/check-live.sh" "${origin}" > "${tmp}/check.out" 2>&1; then
	echo 'unhealthy broker was accepted' >&2
	exit 1
fi
printf '{"ok":true}\n' > "${tmp}/web/api/live/health"
mv "${tmp}/web/build-info.json" "${tmp}/web/removed-build-info.json"
if "${script_dir}/check-live.sh" "${origin}" > "${tmp}/check.out" 2>&1; then
	echo 'missing build info was accepted' >&2
	exit 1
fi
echo 'PASS: clean/dirty build provenance and live drift checks'
