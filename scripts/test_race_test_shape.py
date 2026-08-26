# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Contract tests for the repository-owned race-test invocation shape."""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "run-race-test.sh"
CI_RACE_PRODUCERS = (
    "test-oss-go125",
    "test-oss-go126",
    "test-enterprise-go125",
    "test-enterprise-go126",
)
LEGACY_CI_RACE_PRODUCERS = ("test-oss", "test-enterprise")
RUNNER_COMMAND = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_]*=\S+\s+)*(?:bash\s+)?scripts/run-race-test\.sh(?:\s|$)"
)
DIRECT_RACE_COMMAND = re.compile(r"(?:^|[;&|]\s*)go test\b.*(?:^|\s)-race(?:\s|$)")


def printed_command(*args: str) -> str:
    result = subprocess.run(
        ["bash", str(RUNNER), *args, "--print-command"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    return result.stdout.strip()


def job_block(workflow: str, name: str) -> str:
    marker = f"  {name}:\n"
    start = workflow.index(marker)
    next_job = re.search(r"(?m)^  [A-Za-z0-9_-]+:\n", workflow[start + len(marker) :])
    end = len(workflow) if next_job is None else start + len(marker) + next_job.start()
    return workflow[start:end]


def race_execution_counts(block: str) -> tuple[int, int]:
    runner_count = 0
    direct_count = 0
    for line in block.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if RUNNER_COMMAND.search(stripped):
            runner_count += 1
        if DIRECT_RACE_COMMAND.search(stripped):
            direct_count += 1
    return runner_count, direct_count


def make_target_block(makefile: str, name: str) -> str:
    marker = f"{name}:"
    start = makefile.index(marker)
    next_target = re.search(
        r"(?m)^[A-Za-z0-9_.%/-]+(?:\s[^:]*)?:",
        makefile[start + len(marker) :],
    )
    end = len(makefile) if next_target is None else start + len(marker) + next_target.start()
    return makefile[start:end]


def workflow_step_block(workflow: str, name: str) -> str:
    marker = f"      - name: {name}\n"
    start = workflow.index(marker)
    next_step = workflow.find("\n      - ", start + len(marker))
    return workflow[start:] if next_step == -1 else workflow[start:next_step]


def ci_race_shape_errors(ci: str) -> list[str]:
    """Return CI race-shape contract breaks so synthetic drift can fail closed."""
    errors = []
    delegated: list[str] = []
    inline: list[str] = []
    drifted: list[str] = []
    mixed: list[str] = []
    split_topology = any(f"  {name}:\n" in ci for name in CI_RACE_PRODUCERS)
    producer_names = CI_RACE_PRODUCERS if split_topology else LEGACY_CI_RACE_PRODUCERS
    for name in producer_names:
        try:
            job = job_block(ci, name)
        except ValueError:
            errors.append(f"missing {name}")
            continue
        runner_count, direct_count = race_execution_counts(job)
        if runner_count and direct_count:
            mixed.append(name)
            continue
        if runner_count:
            delegated.append(name)
            continue
        if (
            direct_count
            and '-p="$package_parallelism" -parallel=2' in job
            and "-timeout=15m -count=1" in job
        ):
            inline.append(name)
        else:
            drifted.append(name)
    if mixed:
        errors.append(f"CI race jobs mixed runner delegation with direct race execution: {mixed}")
    if drifted:
        errors.append(f"CI race jobs drifted from shared shape: {drifted}")
    if delegated and inline:
        errors.append("CI race jobs mixed runner delegation with inline shape")
    if not delegated and not inline and not drifted:
        errors.append("CI race producers were not found")
    return errors


class TestRaceTestShape(unittest.TestCase):
    def test_oss_proxy_shape_limits_package_fanout(self) -> None:
        command = printed_command("--shard", "proxy")

        self.assertIn("go test -race -p=1 -parallel=2 -count=1 -timeout=15m", command)
        self.assertIn("github.com/luckyPipewrench/pipelock/internal/proxy", command)

    def test_enterprise_rest_shape_uses_common_limits(self) -> None:
        command = printed_command("--shard", "rest-0", "--tags", "enterprise")

        self.assertIn("go test -race -p=2 -parallel=2 -count=1 -timeout=15m", command)
        self.assertIn("-tags enterprise", command)

    def test_named_package_selection_cannot_bypass_common_limits(self) -> None:
        command = printed_command("--packages", "./internal/config ./internal/mcp")

        self.assertIn("go test -race -p=2 -parallel=2 -count=1 -timeout=15m", command)
        self.assertIn("./internal/config ./internal/mcp", command)

    def test_local_and_release_targets_delegate_to_the_runner(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        release = (ROOT / ".github/workflows/release.yaml").read_text(encoding="utf-8")

        test_target = make_target_block(makefile, "test")
        self.assertEqual(test_target.count("$(MAKE) --no-print-directory test-sharded"), 1)
        for target in (
            "test-runtime-critical",
            "test-shard-%",
            "test-shard-enterprise-%",
            "test-sharded",
            "test-sharded-enterprise",
        ):
            with self.subTest(target=target):
                self.assertEqual(
                    race_execution_counts(make_target_block(makefile, target)),
                    (1, 0),
                )
        self.assertEqual(
            race_execution_counts(workflow_step_block(release, "Run tests")),
            (1, 0),
        )

    def test_ci_keeps_the_same_race_shape_until_it_delegates_to_the_runner(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yaml").read_text(encoding="utf-8")
        self.assertEqual(ci_race_shape_errors(ci), [])

    def test_one_drifted_ci_race_job_fails_the_contract(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yaml").read_text(encoding="utf-8")
        first_producer = "test-oss-go125" if "  test-oss-go125:\n" in ci else "test-oss"
        drifted = ci.replace(
            'go test -race -p="$package_parallelism" -parallel=2 -timeout=15m -count=1 -json \\',
            "go test -race -p=8 -parallel=8 -timeout=15m -count=1 -json \\",
            1,
        )
        self.assertIn(
            f"CI race jobs drifted from shared shape: ['{first_producer}']",
            ci_race_shape_errors(drifted),
        )

    def test_comment_mention_of_the_runner_does_not_disable_the_shape_contract(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yaml").read_text(encoding="utf-8")
        commented = "  # later: scripts/run-race-test.sh\n" + ci.replace(
            '-p="$package_parallelism" -parallel=2',
            "-p=8 -parallel=8",
        )
        errors = ci_race_shape_errors(commented)
        self.assertTrue(any("drifted from shared shape" in error for error in errors), errors)

    def test_non_command_runner_mention_does_not_disable_the_shape_contract(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yaml").read_text(encoding="utf-8")
        mentioned = ci.replace(
            "          set -o pipefail",
            '          echo "scripts/run-race-test.sh is the preferred path"\n          set -o pipefail',
            1,
        ).replace('-p="$package_parallelism" -parallel=2', "-p=8 -parallel=8")
        errors = ci_race_shape_errors(mentioned)
        self.assertTrue(any("drifted from shared shape" in error for error in errors), errors)

    def test_partial_runner_delegation_fails_the_contract(self) -> None:
        ci = (ROOT / ".github/workflows/ci.yaml").read_text(encoding="utf-8")
        first_producer = "test-oss-go125" if "  test-oss-go125:\n" in ci else "test-oss"
        mixed = ci.replace(
            "          set -o pipefail",
            "          scripts/run-race-test.sh --shard proxy\n          set -o pipefail",
            1,
        )
        self.assertIn(
            f"CI race jobs mixed runner delegation with direct race execution: ['{first_producer}']",
            ci_race_shape_errors(mixed),
        )

    def test_invalid_selection_fails_before_running_go(self) -> None:
        result = subprocess.run(
            ["bash", str(RUNNER), "--shard", "mcp", "--packages", "./internal/mcp"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("exactly one", result.stderr)

    def test_release_check_does_not_repeat_packages_covered_by_test(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        release_check = next(
            line for line in makefile.splitlines() if line.startswith("release-check:")
        )

        self.assertEqual(
            release_check,
            "release-check: test lint release-audit runtime-policy-audit",
        )
        self.assertIn("test-replay-harness:", makefile)
        self.assertIn("test-runtime-critical:", makefile)

    def test_ordinary_coverage_is_not_a_second_race_suite(self) -> None:
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        coverage_target = makefile.split("test-cover:", 1)[1].split("\n\n", 1)[0]

        self.assertIn("go test -count=1 -coverprofile=coverage.out ./...", coverage_target)
        self.assertNotIn("-race", coverage_target)


if __name__ == "__main__":
    unittest.main()
