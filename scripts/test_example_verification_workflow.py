#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Structural tests for the advisory example and installation verification."""

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "example-verification.yaml"
RUNNER = ROOT / "scripts" / "verify-examples.sh"


def event_paths(workflow: str, event: str) -> list[str]:
    marker = f"  {event}:\n"
    start = workflow.index(marker) + len(marker)
    next_event = re.search(r"(?m)^  [a-z_]+:\n", workflow[start:])
    block = workflow[start:] if next_event is None else workflow[start : start + next_event.start()]
    paths_start = block.index("    paths:\n") + len("    paths:\n")
    paths = []
    for line in block[paths_start:].splitlines():
        if not line.startswith("      - "):
            break
        paths.append(line.removeprefix("      - ").strip("'"))
    return paths


class ExampleVerificationWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.runner = RUNNER.read_text(encoding="utf-8")

    def test_every_shipped_verifier_is_in_the_runner_contract(self):
        example_scripts = sorted(ROOT.glob("examples/*/verify.sh"))
        self.assertEqual(len(example_scripts), 17)
        self.assertIn("find \"$ROOT_DIR/examples\"", self.runner)
        self.assertIn("-name verify.sh", self.runner)
        for path in sorted((ROOT / "scripts" / "e2e").glob("*-install.sh")):
            self.assertIn(f'run_case "{path.relative_to(ROOT)}"', self.runner)
        for path in sorted((ROOT / "scripts" / "e2e").glob("*-mcp-runtime.py")):
            self.assertIn(f'run_case "{path.relative_to(ROOT)}"', self.runner)

    def test_make_target_is_the_workflow_entrypoint(self):
        makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("verify-examples: build\n", makefile)
        self.assertIn("scripts.test_e2e_hermetic scripts.test_example_verification_workflow", makefile)
        self.assertIn('./scripts/verify-examples.sh', makefile)
        self.assertIn("run: make verify-examples", self.workflow)

    def test_push_and_pull_request_filters_match(self):
        push_paths = event_paths(self.workflow, "push")
        pull_request_paths = event_paths(self.workflow, "pull_request")
        self.assertEqual(push_paths, pull_request_paths)
        self.assertIn("examples/**", push_paths)
        self.assertIn("scripts/e2e/**", push_paths)
        self.assertIn("internal/**", push_paths)
        self.assertIn("scripts/test_e2e_hermetic.py", push_paths)
        self.assertIn("scripts/test_example_verification_workflow.py", push_paths)
        self.assertNotIn("docs/**", push_paths)

    def test_verification_failure_is_visible_and_job_does_not_claim_otherwise(self):
        # The job fails on purpose so failures are visible. Assert the durable
        # intent rather than the exact warning prose: the failure must surface,
        # and the job must not describe itself as something that cannot fail,
        # because a name promising one thing while the step does another is how
        # a check ends up in branch protection by mistake.
        verify_job = self.workflow[self.workflow.index("  verify:\n") :]
        self.assertEqual(verify_job.count("continue-on-error: true"), 1)
        self.assertIn("id: verification", verify_job)
        self.assertIn("VERIFICATION_OUTCOME: ${{ steps.verification.outcome }}", verify_job)
        self.assertIn("must not be added to branch protection", verify_job)
        self.assertIn("exit 1", verify_job)
        job_name = next(
            line for line in verify_job.splitlines() if line.strip().startswith("name:")
        )
        self.assertNotIn("report-only", job_name.lower())

    def test_skips_are_counted_separately_from_passes(self):
        self.assertIn("/^SKIP: [0-9]+$/", self.runner)
        self.assertIn('RESULT: SKIP', self.runner)
        self.assertIn("Skipped checks (not covered by this run)", self.runner)
        for path in (
            ROOT / "scripts" / "e2e" / "cline-mcp-runtime.py",
            ROOT / "scripts" / "e2e" / "opencode-mcp-runtime.py",
            ROOT / "examples" / "docker-compose-proxy" / "verify.sh",
        ):
            body = path.read_text(encoding="utf-8")
            self.assertIn('SKIP: ', body, path)

    def test_missing_npx_is_an_explicit_runtime_skip(self):
        env = os.environ.copy()
        env["PATH"] = ""
        env["PIPELOCK_E2E_LIVE_UPSTREAM"] = "1"
        for path in sorted((ROOT / "scripts" / "e2e").glob("*-mcp-runtime.py")):
            result = subprocess.run(
                [sys.executable, str(path)],
                check=False,
                capture_output=True,
                text=True,
                env=env,
            )
            self.assertEqual(result.returncode, 0, (path, result.stderr))
            self.assertIn("SKIP: runtime MCP E2E (npx is not available)", result.stdout)
            self.assertRegex(result.stdout, r"(?m)^PASS: 0$")
            self.assertRegex(result.stdout, r"(?m)^FAIL: 0$")
            self.assertRegex(result.stdout, r"(?m)^SKIP: 1$")

    def test_quickstart_runs_the_binary_built_from_this_tree(self):
        self.assertIn('local go_binary="${PIPELOCK_VERIFY_GO:-go}"', self.runner)
        self.assertIn('CGO_ENABLED=0 "$go_binary" build -trimpath', self.runner)
        self.assertIn("internal/cliutil.GitCommit=$expected_commit", self.runner)
        self.assertEqual(self.runner.count('"%s:/pipelock:ro,Z"'), 2)
        self.assertIn("PIPELOCK_VERIFY_COMMIT", self.runner)
        quickstart = (ROOT / "examples" / "quickstart" / "verify.sh").read_text(encoding="utf-8")
        self.assertIn('grep -Fq "git commit: $PIPELOCK_VERIFY_COMMIT"', quickstart)

    def test_actions_are_pinned_and_checkout_drops_credentials(self):
        actions = re.findall(r"uses:\s+([^@\s]+)@([^\s]+)", self.workflow)
        self.assertTrue(actions)
        for action, revision in actions:
            self.assertRegex(revision, r"^[0-9a-f]{40}$", action)
        self.assertEqual(
            self.workflow.count("persist-credentials: false"),
            self.workflow.count("uses: actions/checkout@"),
        )

    def test_docker_preflight_does_not_bypass_verifier_skip_reporting(self):
        self.assertNotIn("command -v docker", self.workflow)
        self.assertNotIn("docker compose version", self.workflow)


if __name__ == "__main__":
    unittest.main()
