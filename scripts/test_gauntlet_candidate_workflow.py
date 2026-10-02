#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Structural tests for the Pipelock-owned candidate-only Gauntlet lane."""

import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
WORKFLOW = ROOT / ".github" / "workflows" / "continuous-gauntlet.yaml"
RELEASE_PIN = ROOT / "benchmark" / "gauntlet-release.env"
BASELINE = ROOT / "benchmark" / "gauntlet-baseline.json"
ACCEPTANCE = ROOT / "benchmark" / "gauntlet-acceptance.json"
EXPECTED_AEB_REF = "79a51f084fc4f4cd5254e4ec15a273c556c280d5"
EXPECTED_AEB_RELEASE_TAG = "v1.1.0"
GAUNTLET_WORKFLOW_URL = (
    "https://github.com/luckyPipewrench/pipelock/actions/workflows/continuous-gauntlet.yaml"
)
GAUNTLET_BADGE_URL = GAUNTLET_WORKFLOW_URL + "/badge.svg"
PLAYGROUND_PAGE_URL = "https://pipelab.org/playground"
PLAYGROUND_BROKER_ORIGIN = "https://playground.pipelab.org"
PUBLIC_RESULTS_URL = "https://pipelab.org/gauntlet/results/"
EVIDENCE_FILES = (
    "continuous-gauntlet-pipelock.json",
    "promotion-decision.json",
    "execution-decision.json",
    "run-bundle.json",
    "run-metadata.json",
    "pipelock-release.json",
    "pipelock-version.txt",
    "corpus-manifest.txt",
    "checksums.txt",
    "entrypoint-command.txt",
    "entrypoint.stderr",
    "entrypoint-exit.txt",
    "raw-summary.json",
    "results.jsonl",
    "runner.stderr",
    "command.txt",
    "make-stats.txt",
    "case-index.json",
    "tool-profile.json",
    "capability-registry.json",
    "receipt-profile.json",
)


def step_block(workflow, name):
    marker = f"      - name: {name}\n"
    start = workflow.find(marker)
    if start < 0:
        raise AssertionError(f"missing workflow step: {name}")
    next_step = workflow.find("\n      - name:", start + len(marker))
    return workflow[start:] if next_step < 0 else workflow[start:next_step]


def step_run_script(workflow, name):
    block = step_block(workflow, name)
    lines = block.split("        run: |\n", 1)[1].splitlines()
    return "\n".join(line[10:] if line else "" for line in lines)


class GauntletCandidateWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow = WORKFLOW.read_text(encoding="utf-8")
        self.release_pin = RELEASE_PIN.read_text(encoding="utf-8")

    def test_benchmark_checkout_is_immutable_and_verified(self):
        self.assertIn(f"AEB_REF: {EXPECTED_AEB_REF}", self.workflow)
        checkout = step_block(self.workflow, "Check out pinned Agent Egress Bench")
        self.assertIn("repository: luckyPipewrench/agent-egress-bench", checkout)
        self.assertIn("ref: ${{ env.AEB_REF }}", checkout)
        self.assertNotRegex(checkout, r"ref:\s+(main|master|v[0-9])")
        # The checkout needs full history for the tag resolution below to be possible.
        self.assertIn("fetch-depth: 0", checkout)
        verify = step_block(self.workflow, "Verify immutable inputs")
        self.assertIn('git -C "$AEB_ROOT" rev-parse HEAD', verify)
        self.assertIn('= "$AEB_REF"', verify)

    def test_benchmark_release_tag_is_bound_to_the_pinned_commit(self):
        """The release label must be checked, not asserted.

        Naming a release in the workflow proves nothing on its own: the value
        can name any release, or one that never existed, while the checkout
        still uses the pinned commit. The workflow resolves the tag and
        compares it, so this asserts both the declared tag and the comparison.
        Without the comparison assertion, deleting that line leaves the label
        as a comment and no test fails.
        """
        self.assertIn(f"AEB_RELEASE_TAG: {EXPECTED_AEB_RELEASE_TAG}", self.workflow)
        verify = step_block(self.workflow, "Verify immutable inputs")
        self.assertIn(
            'git -C "$AEB_ROOT" rev-parse "refs/tags/$AEB_RELEASE_TAG^{commit}"',
            verify,
        )
        self.assertIn('= "$AEB_REF"', verify)

    def test_only_reviewed_pipelock_main_can_produce_a_candidate(self):
        verify = step_block(self.workflow, "Verify immutable inputs")
        self.assertIn('test "$GITHUB_REF" = "refs/heads/main"', verify)
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', verify)
        budget = step_block(self.workflow, "Record job budget start")
        self.assertIn("AEB_ROOT=$GITHUB_WORKSPACE/_agent-egress-bench", budget)
        self.assertIn("GAUNTLET_ARTIFACT_DIR=$RUNNER_TEMP/pipelock-gauntlet-candidate", budget)
        self.assertIn("PIPELOCK_RELEASE_PIN=$GITHUB_WORKSPACE/benchmark/gauntlet-release.env", budget)
        workflow_env = self.workflow[self.workflow.index("env:") : self.workflow.index("jobs:")]
        self.assertNotIn("runner.temp", workflow_env)

    def test_release_identity_has_exact_data_contract(self):
        assignments = {}
        for line in self.release_pin.splitlines():
            if not line or line.startswith("#"):
                continue
            key, separator, value = line.partition("=")
            self.assertEqual(separator, "=", line)
            self.assertNotIn(key, assignments)
            assignments[key] = value
        self.assertEqual(
            assignments,
            {
                "PIPELOCK_REPO": "luckyPipewrench/pipelock",
                "PIPELOCK_TAG": "v3.5.0",
                "PIPELOCK_VERSION": "3.5.0",
                "PIPELOCK_ASSET_SHA256_AMD64": (
                    "0e9fe1461107e8fc6a7f7969c87e7810824b019eaabd6fa7318f642ca9e4b858"
                ),
                "PIPELOCK_ASSET_SHA256_ARM64": (
                    "e7a72741ef6ac679d74656ae438262b5638934a34616adb6ac87d2c8634216c6"
                ),
            },
        )
        self.assertEqual(assignments["PIPELOCK_TAG"], "v" + assignments["PIPELOCK_VERSION"])
        self.assertRegex(assignments["PIPELOCK_ASSET_SHA256_AMD64"], r"^[0-9a-f]{64}$")
        self.assertRegex(assignments["PIPELOCK_ASSET_SHA256_ARM64"], r"^[0-9a-f]{64}$")
        self.assertNotIn("v3.3.0", self.workflow)

    def test_acceptance_policy_is_owned_by_pipelock_not_the_benchmark(self):
        """Product acceptance must never be read from the neutral benchmark repo."""
        self.assertNotIn("ci/gauntlet-baseline.json", self.workflow)
        self.assertNotIn("$AEB_ROOT/ci/", self.workflow)
        for policy in (BASELINE, ACCEPTANCE):
            self.assertTrue(policy.is_file(), policy)
            self.assertEqual(policy.parent.name, "benchmark")
        self.assertIn(
            'PIPELOCK_GAUNTLET_BASELINE=$GITHUB_WORKSPACE/benchmark/gauntlet-baseline.json',
            self.workflow,
        )
        self.assertIn(
            'PIPELOCK_GAUNTLET_ACCEPTANCE=$GITHUB_WORKSPACE/benchmark/gauntlet-acceptance.json',
            self.workflow,
        )
        verify = step_block(self.workflow, "Verify immutable inputs")
        for variable in ("$PIPELOCK_GAUNTLET_BASELINE", "$PIPELOCK_GAUNTLET_ACCEPTANCE"):
            self.assertIn(variable, verify)
        for step in (
            "Evaluate candidate without publishing",
            "Ensure fail-closed decision exists",
            "Enforce candidate decision",
            "Render owner-facing run summary",
        ):
            self.assertIn('--baseline "$PIPELOCK_GAUNTLET_BASELINE"', step_block(self.workflow, step))

    def test_acceptance_contract_is_enforced_after_evidence_upload(self):
        """A blocked acceptance result must still leave the evidence inspectable."""
        upload = self.workflow.index("      - name: Upload candidate evidence")
        enforce = self.workflow.index("      - name: Enforce Pipelock acceptance contract")
        self.assertLess(upload, enforce)
        block = step_block(self.workflow, "Enforce Pipelock acceptance contract")
        self.assertIn("set -euo pipefail", block)
        self.assertIn("scripts/check_gauntlet_acceptance.py", block)
        self.assertIn('--contract "$PIPELOCK_GAUNTLET_ACCEPTANCE"', block)
        self.assertIn('--results "$GAUNTLET_ARTIFACT_DIR/results.jsonl"', block)

    def test_owned_policy_files_agree_with_each_other_and_the_release_pin(self):
        """Two files state the same result; nothing fails when they disagree unless checked."""
        baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
        acceptance = json.loads(ACCEPTANCE.read_text(encoding="utf-8"))
        self.assertEqual(baseline["pipelock_version"], acceptance["pipelock_version"])
        self.assertIn(
            "PIPELOCK_VERSION=" + baseline["pipelock_version"], self.release_pin
        )
        self.assertEqual(baseline["corpus_version"], acceptance["corpus_version"])
        self.assertEqual(baseline["corpus_git_sha"], acceptance["bench_commit"])
        self.assertEqual(baseline["corpus_git_sha"], EXPECTED_AEB_REF)
        self.assertEqual(
            baseline["observed_case_count"]["total"], acceptance["active_case_count"]
        )
        self.assertEqual(
            baseline["observed_case_count"]["applicable"], acceptance["active_case_count"]
        )
        containment = acceptance["containment"]
        false_positives = acceptance["false_positives"]
        self.assertEqual(
            len(acceptance["accepted_containment_misses"]),
            containment["denominator"] - containment["numerator"],
        )
        self.assertEqual(
            len(acceptance["accepted_false_positives"]), false_positives["numerator"]
        )
        for scope in ("full", "applicable"):
            self.assertAlmostEqual(
                baseline["score_floors"][scope]["containment"],
                containment["numerator"] / containment["denominator"],
            )
        self.assertAlmostEqual(
            baseline["score_ceilings"]["applicable"]["false_positive_rate"],
            false_positives["numerator"] / false_positives["denominator"],
        )

    def test_shipped_portable_runner_is_the_only_execution_path(self):
        run = step_block(self.workflow, "Run portable canonical benchmark")
        self.assertIn('cd "$AEB_ROOT"', run)
        self.assertIn("./scripts/run-pipelock-gauntlet.sh", run)
        self.assertIn('--release-pin "$PIPELOCK_RELEASE_PIN"', run)
        self.assertIn('--output-dir "$GAUNTLET_ARTIFACT_DIR"', run)
        self.assertIn("--deadline-epoch", run)
        self.assertNotIn("go build", self.workflow)
        self.assertNotIn("--development", self.workflow)

    def test_entrypoint_diagnostics_preserve_exit_and_result_presence(self):
        self.assertIn("id: portable_runner", step_block(self.workflow, "Run portable canonical benchmark"))
        self.assertIn("PORTABLE_RUNNER_OUTCOME: ${{ steps.portable_runner.outcome }}",
                      step_block(self.workflow, "Render owner-facing run summary"))
        cases = ((0, True, "success"), (22, False, "early"),
                 (9, True, "later"), (127, False, "missing-script"),
                 (1, False, "missing-root"), (22, False, "capture-failure"),
                 (0, True, "capture-failure-success"))
        for exit_code, results, scenario in cases:
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                bench = root / "bench"
                scripts = bench / "scripts"
                scripts.mkdir(parents=True)
                artifacts = root / "artifacts"
                (root / "runner").mkdir()
                runner = scripts / "run-pipelock-gauntlet.sh"
                if scenario != "missing-script":
                    runner.write_text(
                        "#!/bin/bash\n"
                        "echo fixture-entrypoint-diagnostic >&2\n"
                        "echo fixture-entrypoint-stdout\n"
                        # Mirrors the real entrypoint contract: it creates the
                        # output directory itself and refuses an existing one.
                        '[[ ! -e "$GAUNTLET_ARTIFACT_DIR" ]] || '
                        '{ echo "output directory must not already exist" >&2; exit 97; }\n'
                        'mkdir "$GAUNTLET_ARTIFACT_DIR"\n'
                        + ('echo fixture-result > "$GAUNTLET_ARTIFACT_DIR/results.jsonl"\n' if results else "")
                        + f"exit {exit_code}\n", encoding="utf-8")
                    runner.chmod(0o700)
                # The renderer is a local fixture; neither step contacts the
                # benchmark service or downloads a release.
                (scripts / "render_gauntlet_run_summary.py").write_text(
                    'print("Fixture owner summary")\n', encoding="utf-8")
                env = os.environ | {
                    "AEB_ROOT": str(root / "absent" if scenario == "missing-root" else bench),
                    "GAUNTLET_ARTIFACT_DIR": str(artifacts),
                    "JOB_STARTED_EPOCH": "100", "JOB_TIMEOUT_MINUTES": "35",
                    "PIPELOCK_RELEASE_PIN": str(root / "release.env"),
                    "PIPELOCK_GAUNTLET_BASELINE": str(root / "baseline.json"),
                    "GITHUB_REPOSITORY": "example/project", "GITHUB_RUN_ID": "1",
                    "GITHUB_STEP_SUMMARY": str(root / "summary.md"),
                    "RUNNER_TEMP": str(root / "runner"),
                }
                if scenario.startswith("capture-failure"):
                    tools = root / "tools"
                    tools.mkdir()
                    tee = tools / "tee"
                    tee.write_text(
                        '#!/bin/bash\n/usr/bin/tee "$@"\nexit 42\n', encoding="utf-8"
                    )
                    tee.chmod(0o700)
                    env["PATH"] = str(tools) + os.pathsep + env["PATH"]
                run = subprocess.run(
                    ["bash", "-eu", "-o", "pipefail", "-c",
                     step_run_script(self.workflow, "Run portable canonical benchmark")],
                    cwd=root, env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(run.returncode, 42 if scenario == "capture-failure-success" else exit_code, run.stderr)
                self.assertEqual((artifacts / "entrypoint-exit.txt").read_text().strip(), str(exit_code))
                diagnostic = (artifacts / "entrypoint.stderr").read_text()
                self.assertTrue(diagnostic)
                self.assertIn(diagnostic, run.stderr)
                if scenario not in ("missing-script", "missing-root"):
                    self.assertIn("fixture-entrypoint-stdout\n", run.stdout)
                    self.assertNotIn("fixture-entrypoint-stdout", run.stderr)
                else:
                    self.assertEqual(run.stdout, "")
                self.assertEqual((artifacts / "results.jsonl").exists(), results)
                self.assertFalse((artifacts / "continuous-gauntlet-pipelock.json").exists())
                env["PORTABLE_RUNNER_OUTCOME"] = "failure" if run.returncode else "success"
                summary = subprocess.run(
                    ["bash", "-eu", "-o", "pipefail", "-c",
                     step_run_script(self.workflow, "Render owner-facing run summary")],
                    cwd=root, env=env, capture_output=True, text=True, timeout=10)
                text = (root / "summary.md").read_text()
                self.assertEqual(summary.returncode, 0 if run.returncode == 0 else 1, summary.stderr)
                if run.returncode:
                    self.assertTrue(text.startswith("## Pipelock Gauntlet workflow: FAILED"), text)
                    self.assertIn("Diagnostics may be incomplete", text)
                else:
                    self.assertNotIn("workflow: FAILED", text)
                if exit_code:
                    self.assertIn(f"Portable runner exit status: {exit_code}", text)
                    self.assertIn("Result records are available" if results else "No result records were produced", text)
                    self.assertIn("not a product verdict" if not results else "does not establish a product verdict", text)
                    self.assertNotIn("release acquisition", text)
                else:
                    self.assertNotIn("Portable runner failed", text)
                    self.assertIn("Fixture owner summary", text)

    def test_failure_evidence_steps_run_after_runner_failure(self):
        for name in (
            "Ensure fail-closed decision exists",
            "Upload candidate evidence",
            "Render owner-facing run summary",
            "Upload owner review artifact",
        ):
            with self.subTest(step=name):
                self.assertRegex(
                    step_block(self.workflow, name),
                    r"(?m)^        if: \$\{\{ !cancelled\(\) \}\}$",
                )

    def test_summary_rejects_incomplete_step_without_diagnostic_files(self):
        for outcome in ("failure", "skipped", "cancelled", "", "unknown"):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                scripts = root / "bench" / "scripts"
                scripts.mkdir(parents=True)
                (scripts / "render_gauntlet_run_summary.py").write_text(
                    'print("Fixture successful result")\n', encoding="utf-8")
                env = os.environ | {
                    "AEB_ROOT": str(scripts.parent), "GAUNTLET_ARTIFACT_DIR": str(root / "artifacts"),
                    "PIPELOCK_GAUNTLET_BASELINE": str(root / "baseline.json"),
                    "GITHUB_REPOSITORY": "example/project", "GITHUB_RUN_ID": "1",
                    "GITHUB_STEP_SUMMARY": str(root / "summary.md"),
                    "PORTABLE_RUNNER_OUTCOME": outcome,
                }
                result = subprocess.run(
                    ["bash", "-eu", "-o", "pipefail", "-c",
                     step_run_script(self.workflow, "Render owner-facing run summary")],
                    cwd=root, env=env, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 1, result.stderr)
                text = (root / "summary.md").read_text()
                self.assertTrue(text.startswith("## Pipelock Gauntlet workflow: FAILED"), text)
                self.assertIn("Diagnostics may be incomplete", text)
                self.assertEqual(text, (root / "artifacts" / "owner-summary.md").read_text())

    def test_workflow_cannot_publish_or_modify_repositories(self):
        permissions = self.workflow[
            self.workflow.index("permissions:") : self.workflow.index("env:")
        ]
        self.assertEqual(permissions.strip(), "permissions:\n  contents: read")
        self.assertNotIn("contents: write", self.workflow)
        self.assertNotIn("pull-requests:", self.workflow)
        self.assertNotIn("GH_TOKEN", self.workflow)
        self.assertNotIn("gh pr", self.workflow)
        self.assertNotIn("promote_gauntlet_candidate.py", self.workflow)
        self.assertNotIn("pipelab.org", self.workflow)
        self.assertNotIn("continue-on-error", self.workflow)

    def test_only_manual_and_scheduled_events_can_run(self):
        trigger = self.workflow[self.workflow.index("on:") : self.workflow.index("concurrency:")]
        self.assertIn("workflow_dispatch:", trigger)
        self.assertIn("schedule:", trigger)
        self.assertNotIn("pull_request", trigger)
        self.assertNotRegex(trigger, r"(?m)^\s+push:")

    def test_readme_exposes_gauntlet_candidate_badge(self):
        readme = README.read_text(encoding="utf-8")
        self.assertTrue(
            GAUNTLET_BADGE_URL in readme,
            "README missing Gauntlet candidate badge URL",
        )
        self.assertTrue(
            f'href="{GAUNTLET_WORKFLOW_URL}"' in readme,
            "README missing Gauntlet candidate workflow link",
        )
        self.assertTrue('alt="Gauntlet exam"' in readme, "README missing Gauntlet exam badge alt text")
        self.assertNotIn(
            'alt="Agent Egress Bench"',
            readme,
            "the scheduled-exam badge must not use the corpus repo name",
        )
        self.assertTrue(
            "does not auto-publish a public score" in readme,
            "README missing candidate-exam non-publish sentence",
        )
        self.assertTrue(
            PLAYGROUND_PAGE_URL in readme,
            "README missing the public playground page",
        )
        self.assertNotIn(
            PLAYGROUND_BROKER_ORIGIN,
            readme,
            "README must not send people to the playground broker origin",
        )
        self.assertTrue(
            PUBLIC_RESULTS_URL in readme,
            "README missing the public Gauntlet results page",
        )
        self.assertIsNone(
            re.search(r"https://pipelab\.org/gauntlet/(?!results/)", readme),
            "README still has a Gauntlet link that is not /gauntlet/results/",
        )
        self.assertNotRegex(readme, r"(?i)\bnightly\b")

    def test_checkout_credentials_and_actions_are_pinned(self):
        checkout_count = self.workflow.count("uses: actions/checkout@")
        self.assertEqual(checkout_count, 2)
        self.assertEqual(self.workflow.count("persist-credentials: false"), checkout_count)
        for action, revision in re.findall(r"uses:\s+([^@\s]+)@([^\s]+)", self.workflow):
            self.assertRegex(revision, r"^[0-9a-f]{40}$", action)

    def test_benchmark_runner_and_go_patch_are_fixed(self):
        candidate_job = self.workflow[self.workflow.index("  candidate:") :]
        self.assertIn("runs-on: ubuntu-24.04", candidate_job)
        self.assertNotIn("ubuntu-latest", candidate_job)
        setup = step_block(self.workflow, "Set up Go")
        self.assertIn('go-version: "1.26.8"', setup)
        self.assertNotIn('go-version: "1.26"', setup)

    def test_each_run_attempt_keeps_its_own_evidence_identity(self):
        for name in ("Upload candidate evidence", "Upload owner review artifact"):
            upload = step_block(self.workflow, name)
            self.assertIn("attempt-${{ github.run_attempt }}", upload, name)
        finalize = step_block(self.workflow, "Finalize GitHub provenance artifact")
        self.assertIn("${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT}", finalize)

    def test_fail_closed_decision_precedes_upload_and_enforcement(self):
        ensure = self.workflow.index("      - name: Ensure fail-closed decision exists")
        upload = self.workflow.index("      - name: Upload candidate evidence")
        enforce = self.workflow.index("      - name: Enforce candidate decision")
        summary = self.workflow.index("      - name: Render owner-facing run summary")
        review_upload = self.workflow.index("      - name: Upload owner review artifact")
        self.assertLess(ensure, upload)
        self.assertLess(upload, enforce)
        self.assertLess(enforce, summary)
        self.assertLess(summary, review_upload)
        for name in (
            "Ensure fail-closed decision exists",
            "Upload candidate evidence",
            "Enforce candidate decision",
            "Render owner-facing run summary",
            "Upload owner review artifact",
        ):
            self.assertIn("if: ${{ !cancelled() }}", step_block(self.workflow, name))

    def test_evaluator_failure_is_converted_to_an_atomic_blocked_decision(self):
        ensure = step_block(self.workflow, "Ensure fail-closed decision exists")
        self.assertIn("evaluation_exit=0", ensure)
        self.assertIn("|| evaluation_exit=$?", ensure)
        self.assertIn('rm -f "$decision_path"', ensure)
        self.assertGreaterEqual(ensure.count('if [[ ! -f "$decision_path" ]]'), 2)
        self.assertIn('jq -n --arg failure "$fallback_failure"', ensure)
        self.assertIn("failures: [$failure]", ensure)
        self.assertLess(ensure.index("|| evaluation_exit=$?"), ensure.rindex("jq -n"))
        self.assertLess(ensure.rindex("jq -n"), ensure.index('mv "$temporary_decision" "$decision_path"'))

    def test_candidate_upload_retains_every_verification_input(self):
        upload = step_block(self.workflow, "Upload candidate evidence")
        self.assertIn("if-no-files-found: error", upload)
        self.assertNotIn("env.GAUNTLET_ARTIFACT_DIR", upload)
        for filename in EVIDENCE_FILES:
            self.assertIn(
                f"${{{{ runner.temp }}}}/pipelock-gauntlet-candidate/{filename}", upload
            )
        evaluate = step_block(self.workflow, "Evaluate candidate without publishing")
        enforce = step_block(self.workflow, "Enforce candidate decision")
        for label in (
            "raw_summary",
            "results",
            "runner_stderr",
            "command",
            "stats",
            "case_index",
            "entrypoint_command",
            "run_metadata",
            "pipelock_release",
            "release_checksums",
            "pipelock_version_output",
            "corpus_manifest",
            "tool_profile",
            "capability_registry",
            "receipt_profile",
            "execution_decision",
            "run_bundle",
        ):
            self.assertIn(f'--evidence "{label}=', evaluate)
            self.assertIn(f'--evidence "{label}=', enforce)

    def test_owner_review_upload_uses_runner_temp_context(self):
        upload = step_block(self.workflow, "Upload owner review artifact")
        self.assertIn("if-no-files-found: error", upload)
        self.assertNotIn("env.GAUNTLET_ARTIFACT_DIR", upload)
        for filename in ("enforcement-result.json", "owner-summary.md"):
            self.assertIn(
                f"${{{{ runner.temp }}}}/pipelock-gauntlet-candidate/{filename}", upload
            )

    def test_provenance_names_the_pipelock_actions_run(self):
        finalize = step_block(self.workflow, "Finalize GitHub provenance artifact")
        self.assertIn(
            '--artifact-id "github-actions:${GITHUB_REPOSITORY}:${GITHUB_RUN_ID}:${GITHUB_RUN_ATTEMPT}"',
            finalize,
        )
        self.assertIn(
            '--canonical-url "https://github.com/${GITHUB_REPOSITORY}'
            '/actions/runs/${GITHUB_RUN_ID}/attempts/${GITHUB_RUN_ATTEMPT}"',
            finalize,
        )


if __name__ == "__main__":
    unittest.main()
