#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Structural tests for the Pipelock-owned candidate-only Gauntlet lane."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
WORKFLOW = ROOT / ".github" / "workflows" / "continuous-gauntlet.yaml"
RELEASE_PIN = ROOT / "benchmark" / "gauntlet-release.env"
EXPECTED_AEB_REF = "2d6cb1d6e1a6d8a11b8e5a1649e7dee1c6e56aea"
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
        verify = step_block(self.workflow, "Verify immutable inputs")
        self.assertIn('git -C "$AEB_ROOT" rev-parse HEAD', verify)
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
                "PIPELOCK_TAG": "v3.4.0",
                "PIPELOCK_VERSION": "3.4.0",
                "PIPELOCK_ASSET_SHA256_AMD64": (
                    "37c267a9c7a5472324e3bb07def179e810a5ae7c8e761537ad1e9b2e32e9abac"
                ),
                "PIPELOCK_ASSET_SHA256_ARM64": (
                    "9f956e9bee7c7a8dc7530addd9017fb96cf88ba68075b55ad54c870ad99ab9ac"
                ),
            },
        )
        self.assertEqual(assignments["PIPELOCK_TAG"], "v" + assignments["PIPELOCK_VERSION"])
        self.assertRegex(assignments["PIPELOCK_ASSET_SHA256_AMD64"], r"^[0-9a-f]{64}$")
        self.assertRegex(assignments["PIPELOCK_ASSET_SHA256_ARM64"], r"^[0-9a-f]{64}$")
        self.assertNotIn("v3.3.0", self.workflow)

    def test_shipped_portable_runner_is_the_only_execution_path(self):
        run = step_block(self.workflow, "Run portable canonical benchmark")
        self.assertIn('cd "$AEB_ROOT"', run)
        self.assertIn("./scripts/run-pipelock-gauntlet.sh", run)
        self.assertIn('--release-pin "$PIPELOCK_RELEASE_PIN"', run)
        self.assertIn('--output-dir "$GAUNTLET_ARTIFACT_DIR"', run)
        self.assertIn("--deadline-epoch", run)
        self.assertNotIn("go build", self.workflow)
        self.assertNotIn("--development", self.workflow)

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
        self.assertIn('go-version: "1.25.12"', setup)
        self.assertNotIn('go-version: "1.25"', setup)

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
