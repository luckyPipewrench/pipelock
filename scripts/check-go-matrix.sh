#!/usr/bin/env bash
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0
#
# Pull-request CI runs only the Go floor version (see ci.yaml's
# test-oss-go126/test-enterprise-go126/test-replay-go126 jobs, which are
# skipped on pull_request unless the diff touches CI/Go-pin files). Pushes to
# main and the release workflow are the only two places every supported Go
# minor is still exercised together, and AGENTS.md promises "CI tests Go 1.25
# and 1.26". This asserts release.yaml's release-tests matrix is a superset of
# the Go minors ci.yaml's producer jobs actually install, so trimming a
# version from one workflow without the other fails here.
#
# Structural, not name-based: an earlier version of this guard inferred each
# CI job's Go minor from its job-ID suffix (test-oss-go126 -> 1.26), so
# bumping a producer's actual `go-version:` to 1.27 while leaving its ID
# `-go126` would false-green. This reads each job's real setup-go
# `go-version:` (resolving `${{ matrix.* }}` against that job's own
# `strategy.matrix` when the pin is templated, as release-tests's is), never
# the job name.
#
# Minor versions only (1.25, 1.26), not exact patches: release.yaml
# intentionally pins an exact patch and that patch drifts independently of
# this guard (see the comment on that pin).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CI_WORKFLOW="$ROOT/.github/workflows/ci.yaml"
RELEASE_WORKFLOW="$ROOT/.github/workflows/release.yaml"

for f in "$CI_WORKFLOW" "$RELEASE_WORKFLOW"; do
	if [[ ! -f "$f" ]]; then
		printf 'check-go-matrix: cannot read %s\n' "$f" >&2
		exit 2
	fi
done

python3 - "$CI_WORKFLOW" "$RELEASE_WORKFLOW" <<'PYEOF'
import re
import sys

import yaml

ci_path, release_path = sys.argv[1], sys.argv[2]

# Fail-closed: these are the six producer jobs pull-request CI is allowed to
# skip. If any is renamed or removed, this guard must fail rather than
# silently checking fewer lanes than it was written for.
EXPECTED_CI_JOBS = [
	"test-oss-go125",
	"test-oss-go126",
	"test-enterprise-go125",
	"test-enterprise-go126",
	"test-replay-go125",
	"test-replay-go126",
]

MAJOR_MINOR_RE = re.compile(r"^(\d+)\.(\d+)")


def load(path):
	with open(path, encoding="utf-8") as fh:
		doc = yaml.safe_load(fh)
	if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
		print(f"check-go-matrix: {path} has no parseable jobs map", file=sys.stderr)
		sys.exit(2)
	return doc["jobs"]


def resolve_expr(value, matrix):
	"""Resolve a `${{ matrix.x.y }}` (or literal) go-version value.

	`matrix` is the job's own `strategy.matrix` mapping. When a pin is
	templated, every combination the matrix produces is expanded and returned;
	a literal value is returned as a single-element list.
	"""
	if not isinstance(value, str):
		return []
	m = re.fullmatch(r"\$\{\{\s*matrix\.([\w.]+)\s*\}\}", value.strip())
	if not m:
		return [value]
	path = m.group(1).split(".")

	def walk(node, remaining):
		if not remaining:
			return [node]
		key = remaining[0]
		if isinstance(node, list):
			out = []
			for item in node:
				out.extend(walk(item, remaining))
			return out
		if isinstance(node, dict) and key in node:
			return walk(node[key], remaining[1:])
		return []

	root = matrix.get(path[0]) if matrix else None
	if root is None:
		return []
	return walk(root, path[1:])


def go_versions_for_job(job):
	"""Every go-version string a job's setup-go steps install, expanded across
	that job's own matrix (never a sibling job's matrix)."""
	if not isinstance(job, dict):
		return []
	matrix = {}
	strategy = job.get("strategy")
	if isinstance(strategy, dict) and isinstance(strategy.get("matrix"), dict):
		matrix = strategy["matrix"]
	versions = []
	for step in job.get("steps") or []:
		if not isinstance(step, dict):
			continue
		uses = step.get("uses", "")
		if not isinstance(uses, str) or "actions/setup-go" not in uses:
			continue
		with_block = step.get("with")
		if not isinstance(with_block, dict):
			continue
		versions.extend(resolve_expr(with_block.get("go-version"), matrix))
	return versions


def minors(versions):
	out = set()
	for v in versions:
		m = MAJOR_MINOR_RE.match(str(v))
		if m:
			out.add(f"{m.group(1)}.{m.group(2)}")
	return out


ci_jobs = load(ci_path)
missing_jobs = [name for name in EXPECTED_CI_JOBS if name not in ci_jobs]
if missing_jobs:
	print(
		f"check-go-matrix: expected producer job(s) missing from {ci_path}: "
		f"{', '.join(missing_jobs)}; this guard's job list is out of date with "
		"the workflow, or a producer was renamed/removed without updating it",
		file=sys.stderr,
	)
	sys.exit(2)

ci_minors = set()
for name in EXPECTED_CI_JOBS:
	job_minors = minors(go_versions_for_job(ci_jobs[name]))
	if not job_minors:
		print(
			f"check-go-matrix: could not read a go-version from {ci_path} job "
			f"{name!r}; parse broke",
			file=sys.stderr,
		)
		sys.exit(2)
	ci_minors |= job_minors

release_jobs = load(release_path)
if "release-tests" not in release_jobs:
	print(f"check-go-matrix: no 'release-tests' job in {release_path}", file=sys.stderr)
	sys.exit(2)
release_minors = minors(go_versions_for_job(release_jobs["release-tests"]))
if not release_minors:
	print(
		f"check-go-matrix: found no release-tests go matrix versions in "
		f"{release_path}; parse broke",
		file=sys.stderr,
	)
	sys.exit(2)

print(f"ci.yaml producer-job Go minors: {' '.join(sorted(ci_minors))}")
print(f"release.yaml release-tests Go minors: {' '.join(sorted(release_minors))}")

missing = sorted(ci_minors - release_minors)
if missing:
	print(
		"check-go-matrix: release.yaml is missing Go minor(s) that ci.yaml's "
		f"producer jobs install: {' '.join(missing)}",
		file=sys.stderr,
	)
	print(
		"check-go-matrix: a tag would ship having been proven on fewer Go "
		"versions than main is.",
		file=sys.stderr,
	)
	sys.exit(1)

print("check-go-matrix: release.yaml covers every Go minor ci.yaml's producer jobs install.")
PYEOF
