# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Contract tests for the CI job that checks the agent review caller."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from test_ci_security_workflow import WORKFLOW, job_block, step_script


ROOT = Path(__file__).resolve().parents[1]
CALLER = ROOT / ".github" / "workflows" / "agent-review.yaml"
JOB = "agent-review-contract"
ENGINE = "pipelab-org/agent-review"
# The checkout pin every other ci.yaml job uses.
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
VALIDATE = 'python3 -I engine/scripts/agent_review_contract.py --root caller --source-sha "$PIN"'


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, text=True, capture_output=True
    ).stdout.strip()


class AgentReviewContractJobTest(unittest.TestCase):
    def setUp(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.document = yaml.safe_load(text)
        self.block = job_block(text, JOB)
        self.job = self.document["jobs"][JOB]
        self.steps = self.job["steps"]

    def step(self, name: str) -> dict:
        return next(step for step in self.steps if step.get("name") == name)

    def test_job_is_secretless_read_only_and_never_skips(self) -> None:
        self.assertEqual({"contents": "read"}, self.job["permissions"])
        self.assertEqual({"contents": "read"}, self.document["permissions"])
        self.assertNotIn("secrets", self.block)
        self.assertNotIn("if", self.job)
        self.assertEqual(["security-scan"], self.job["needs"])
        # YAML reads the bare `on` key as True.
        self.assertEqual({"push", "pull_request"}, set(self.document[True]))

    def test_checkouts_are_pinned_and_hold_no_credentials(self) -> None:
        checkouts = [step for step in self.steps if "uses" in step]
        self.assertEqual(3, len(checkouts))
        for step in checkouts:
            self.assertEqual(CHECKOUT, step["uses"])
            self.assertIs(False, step["with"]["persist-credentials"])
        caller, engine, base = checkouts
        # The base branch's caller, read only on pull requests, supplies the pin
        # the new one must descend from. Its ref is GitHub's base commit, never a
        # name the pull request controls.
        self.assertEqual("github.event_name == 'pull_request'", base["if"])
        self.assertEqual(
            {
                "ref": "${{ github.event.pull_request.base.sha }}",
                "path": "base",
                "persist-credentials": False,
                "sparse-checkout": ".github/workflows/agent-review.yaml\n",
                "sparse-checkout-cone-mode": False,
            },
            base["with"],
        )
        self.assertNotIn("repository", caller["with"])
        self.assertNotIn("ref", caller["with"])
        self.assertEqual("caller", caller["with"]["path"])
        self.assertEqual(
            {".github/workflows/agent-review.yaml", ".github/agent-review.toml"},
            set(caller["with"]["sparse-checkout"].split()),
        )
        # The engine comes from its main branch; the pin selects a commit on it.
        self.assertEqual(
            {"repository": ENGINE, "ref": "main", "fetch-depth": 0, "path": "engine", "persist-credentials": False},
            engine["with"],
        )

    def test_engine_validator_runs_at_the_parsed_pin(self) -> None:
        pin = "${{ steps.pin.outputs.sha }}"
        self.assertEqual("pin", self.step("Read the pinned engine revision")["id"])
        self.assertEqual(pin, self.step("Require the pin on the engine main branch")["env"]["PIN"])
        validate = self.step("Validate the caller with the pinned engine contract")
        self.assertEqual(pin, validate["env"]["PIN"])
        self.assertEqual(
            "${{ github.repository }}/.github/workflows/agent-review.yaml"
            "@refs/heads/${{ github.event.repository.default_branch }}",
            validate["env"]["CALLER_WORKFLOW_REF"],
        )
        self.assertIn(VALIDATE, validate["run"].splitlines())
        names = [step.get("name") for step in self.steps]
        self.assertLess(
            names.index("Require the pin on the engine main branch"),
            names.index("Validate the caller with the pinned engine contract"),
        )

    def test_build_gate_requires_the_contract(self) -> None:
        build = self.document["jobs"]["build"]
        self.assertIn(JOB, build["needs"])
        env = build["steps"][0]["env"]
        self.assertEqual("${{ needs.agent-review-contract.result }}", env["AGENT_REVIEW_CONTRACT_RESULT"])

    def read_pin(self, caller: str | None) -> tuple[subprocess.CompletedProcess, str]:
        script = step_script(self.block, "Read the pinned engine revision")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            if caller is not None:
                path = temp / "caller" / ".github" / "workflows" / "agent-review.yaml"
                path.parent.mkdir(parents=True)
                path.write_text(caller, encoding="utf-8")
            output = temp / "output"
            output.touch()
            result = subprocess.run(
                ["bash", "-euo", "pipefail", "-c", script],
                check=False,
                cwd=temp,
                env=os.environ | {"GITHUB_OUTPUT": str(output)},
                text=True,
                capture_output=True,
            )
            return result, output.read_text(encoding="utf-8")

    def test_pin_parsing_accepts_the_real_caller(self) -> None:
        caller = CALLER.read_text(encoding="utf-8")
        result, output = self.read_pin(caller)
        self.assertEqual(0, result.returncode, result.stderr)
        uses = next(line for line in caller.splitlines() if line.strip().startswith("uses:"))
        self.assertEqual(f"sha={uses.split('@')[1].split()[0]}\n", output)

    def test_pin_parsing_refuses_anything_but_one_engine_commit(self) -> None:
        caller = CALLER.read_text(encoding="utf-8")
        uses = next(line for line in caller.splitlines() if line.strip().startswith("uses:"))
        sha = uses.split("@")[1].split()[0]
        target = uses.split("@")[0]
        mutations = {
            "branch": caller.replace(uses, f"{target}@main # main"),
            "tag": caller.replace(uses, f"{target}@v1.0.0 # main"),
            "short sha": caller.replace(uses, f"{target}@{sha[:12]} # main"),
            "uppercase sha": caller.replace(uses, f"{target}@{sha.upper()} # main"),
            "41 hex": caller.replace(uses, f"{target}@{sha}0 # main"),
            "other owner": caller.replace(uses, uses.replace("pipelab-org/", "someone-else/")),
            "lookalike repository": caller.replace(uses, uses.replace("/agent-review/", "/agent-review-fork/")),
            "other workflow": caller.replace(uses, uses.replace("agent-review-reusable.yaml", "other.yaml")),
            "local workflow": caller.replace(uses, "    uses: ./.github/workflows/agent-review-reusable.yaml"),
            "second call": caller + "  extra:\n" + uses + "\n",
            "step call": caller + "      - uses: actions/checkout@" + sha + "\n",
            "no call": caller.replace(uses + "\n", ""),
        }
        for name, mutated in mutations.items():
            with self.subTest(mutation=name):
                self.assertNotEqual(caller, mutated)
                result, output = self.read_pin(mutated)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual("", output)
        with self.subTest(mutation="missing caller"):
            result, output = self.read_pin(None)
            self.assertNotEqual(0, result.returncode)
            self.assertEqual("", output)

    def test_base_pin_read_distinguishes_absence_from_errors(self) -> None:
        step = self.step("Read the base branch engine revision")
        self.assertEqual("base_pin", step["id"])
        self.assertEqual("github.event_name == 'pull_request'", step["if"])
        self.assertEqual(
            "${{ steps.base_pin.outputs.sha }}",
            self.step("Require the pin on the engine main branch")["env"]["BASE_PIN"],
        )
        script = step["run"]
        caller = CALLER.read_text(encoding="utf-8")
        uses = next(line for line in caller.splitlines() if line.strip().startswith("uses:"))
        sha = uses.split("@")[1].split()[0]
        legacy = caller.replace(uses, "    uses: ./.github/workflows/agent-review-reusable.yaml")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            path = temp / "base" / ".github" / "workflows" / "agent-review.yaml"
            path.parent.mkdir(parents=True)
            output = temp / "output"
            for name, content, prefix, expected_code, expected_output in (
                ("pinned", caller, "", 0, f"sha={sha}\n"),
                ("legacy local caller", legacy, "", 0, ""),
                ("missing caller", None, "", 0, ""),
                ("read error", caller, "grep() { return 2; };\n", 1, ""),
                ("command error", caller, "grep() { return 127; };\n", 1, ""),
            ):
                with self.subTest(state=name):
                    if content is None:
                        path.unlink(missing_ok=True)
                    else:
                        path.write_text(content, encoding="utf-8")
                    output.write_text("", encoding="utf-8")
                    result = subprocess.run(
                        ["bash", "-euo", "pipefail", "-c", prefix + script],
                        check=False,
                        cwd=temp,
                        env=os.environ | {"GITHUB_OUTPUT": str(output)},
                        text=True,
                        capture_output=True,
                        timeout=10,
                    )
                    self.assertEqual(expected_code, result.returncode, result.stderr)
                    self.assertEqual(expected_output, output.read_text(encoding="utf-8"))
                    if expected_code:
                        self.assertIn("base agent review caller could not be read", result.stderr)

    def test_pin_must_be_a_commit_on_engine_main(self) -> None:
        script = step_script(self.block, "Require the pin on the engine main branch")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)
            engine = temp / "engine"
            engine.mkdir()
            git(engine, "init", "--quiet", "--initial-branch=main")
            git(engine, "config", "user.email", "ci@example.invalid")
            git(engine, "config", "user.name", "ci")
            git(engine, "commit", "--quiet", "--allow-empty", "-m", "old")
            old = git(engine, "rev-parse", "HEAD")
            git(engine, "switch", "--quiet", "-c", "side")
            git(engine, "commit", "--quiet", "--allow-empty", "-m", "side")
            side = git(engine, "rev-parse", "HEAD")
            git(engine, "switch", "--quiet", "main")
            git(engine, "commit", "--quiet", "--allow-empty", "-m", "new")
            new = git(engine, "rev-parse", "HEAD")

            def run(pin: str, base: str | None = None) -> subprocess.CompletedProcess:
                git(engine, "switch", "--quiet", "main")
                env = os.environ | {"PIN": pin}
                env.pop("BASE_PIN", None)
                if base is not None:
                    env["BASE_PIN"] = base
                return subprocess.run(
                    ["bash", "-euo", "pipefail", "-c", script],
                    check=False,
                    cwd=temp,
                    env=env,
                    text=True,
                    capture_output=True,
                )

            accepted = run(old)
            self.assertEqual(0, accepted.returncode, accepted.stderr)
            self.assertEqual(old, git(engine, "rev-parse", "HEAD"))
            for name, pin in {"off main": side, "unknown": "f" * 40, "empty": ""}.items():
                with self.subTest(pin=name):
                    refused = run(pin)
                    self.assertNotEqual(0, refused.returncode)
                    self.assertEqual("main", git(engine, "branch", "--show-current"))

            # A pull request may move the pin forward or keep it, never back.
            for name, pin, base in (("forward", new, old), ("same", new, new), ("no base pin", new, "")):
                with self.subTest(move=name):
                    moved = run(pin, base)
                    self.assertEqual(0, moved.returncode, moved.stderr)
            for name, pin, base in (("backward", old, new), ("base off main", new, side), ("base unknown", new, "e" * 40)):
                with self.subTest(move=name):
                    refused = run(pin, base)
                    self.assertNotEqual(0, refused.returncode)
                    self.assertEqual("main", git(engine, "branch", "--show-current"))


if __name__ == "__main__":
    unittest.main()
