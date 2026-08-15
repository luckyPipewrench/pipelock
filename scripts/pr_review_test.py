#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the Pipelock composite PR-review action."""

import importlib.util
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

try:
    import yaml
except ImportError:  # pragma: no cover
    # Absent PyYAML fails the tests that need it and nothing else. Raising here
    # would abort collection for this whole module, taking down every unrelated
    # assertion in it, and a skip would quietly drop the coverage instead. The
    # job that runs these tests installs no packages, so whether PyYAML is
    # present on the runner is an open question that CI answers directly.
    yaml = None


ROOT = pathlib.Path(__file__).parents[1]
ACTION_DIR = ROOT / ".github" / "actions" / "pr-review"
SCRIPT_PATH = ACTION_DIR / "pr_review.py"
CALLER_WORKFLOW = ROOT / ".github" / "workflows" / "pr-review.yaml"
REUSABLE_WORKFLOW = ROOT / ".github" / "workflows" / "pr-review-reusable.yaml"
ACTION_YAML = ACTION_DIR / "action.yml"
SPEC = importlib.util.spec_from_file_location("pr_review", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed to load {SCRIPT_PATH}")
pr_review = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pr_review
SPEC.loader.exec_module(pr_review)


def parse_yaml(text: str) -> dict[str, object]:
    """Parse workflow YAML without YAML 1.1 coercing GitHub's `on` key."""
    if yaml is None:  # pragma: no cover
        # A failure, never a skip. A skipped structural check reports the same
        # green as a passing one, which is the exact class of defect these
        # tests exist to catch.
        raise AssertionError("PyYAML is required to verify workflow structure and is not installed here")
    # BaseLoader constructs nothing but strings, lists and dicts, so it cannot
    # instantiate arbitrary Python the way the default loader can. It is also
    # the only loader that leaves GitHub's `on:` key alone, which YAML 1.1
    # otherwise reads as the boolean true.
    document = yaml.load(text, Loader=yaml.BaseLoader)
    if not isinstance(document, dict):
        raise RuntimeError("expected a YAML mapping")
    return document


def load_yaml(path: pathlib.Path) -> dict[str, object]:
    return parse_yaml(path.read_text(encoding="utf-8"))


def unit(identifier: int, path: str, category: str, *, additions: int = 1, tokens: int = 2) -> object:
    return pr_review.DiffUnit(
        identifier=identifier,
        path=path,
        hunk_header="@@ -1 +1 @@",
        body="+change",
        category=category,
        additions=additions,
        estimated_tokens=tokens,
    )


class WorkflowPackagingTest(unittest.TestCase):
    def test_caller_authorizes_comments_and_dispatches_to_the_same_identity(self) -> None:
        # Exercise the parsed workflow shape. String searches against a YAML
        # file were bypassed before by a comment or an unrelated scalar with
        # the same words.
        caller = load_yaml(CALLER_WORKFLOW)
        events = caller["on"]
        self.assertEqual(events["issue_comment"]["types"], ["created"])
        dispatch = events["workflow_dispatch"]
        self.assertEqual(dispatch["inputs"]["pr_number"]["required"], "true")
        self.assertEqual(dispatch["inputs"]["review_mode"]["type"], "choice")
        self.assertEqual(dispatch["inputs"]["review_mode"]["options"], ["default", "deep"])

        review = caller["jobs"]["review"]
        self.assertEqual(review["uses"], "./.github/workflows/pr-review-reusable.yaml")
        # The WHOLE expression, not its parts. Requiring only substrings would
        # accept a gate rewritten as "dispatch || (everything else)", which
        # still contains every required string while letting an unauthorized
        # manual dispatch through. Authorization is a property of the
        # expression's structure, so the assertion has to be the expression.
        expected = (
            "github.actor == 'luckyPipewrench' && "
            "github.triggering_actor == 'luckyPipewrench' && "
            "((github.event_name == 'issue_comment' && "
            "github.event.comment.user.login == 'luckyPipewrench' && "
            "github.event.comment.author_association == 'OWNER' && "
            "github.event.issue.pull_request && "
            "(github.event.comment.body == '/review' || "
            "github.event.comment.body == '/review deep')) || "
            "github.event_name == 'workflow_dispatch')"
        )
        self.assertEqual(" ".join(review["if"].split()), expected)
        self.assertIn("inputs.pr_number", review["with"]["pr_number"])
        self.assertIn("inputs.review_mode", review["with"]["review_mode"])

    def test_reusable_workflow_uses_non_cancelling_pr_concurrency(self) -> None:
        workflow = load_yaml(REUSABLE_WORKFLOW)
        admit = workflow["jobs"]["admit"]
        self.assertEqual(admit["concurrency"]["group"], "pr-review-${{ github.repository }}-${{ inputs.pr_number }}")
        self.assertEqual(admit["concurrency"]["cancel-in-progress"], "false")
        self.assertTrue(any(step.get("name") == "Claim review status" for step in admit["steps"]))

        review = workflow["jobs"]["review"]
        self.assertEqual(review["needs"], "admit")
        # One provider remains. A second was carried for a gateway no
        # repository ever configured, so its branch never ran.
        self.assertIn("HAS_OPENAI", review["env"])
        self.assertNotIn("HAS_LITELLM", review["env"])
        checkout = review["steps"][0]
        self.assertEqual(checkout["with"]["repository"], "luckyPipewrench/pipelock")
        self.assertEqual(checkout["with"]["ref"], "${{ inputs.reviewer_sha }}")
        # Finalization is its own job, not a step inside review. As a step it
        # was skipped in the case it most needs to cover: admission claims the
        # status comment and the review job never starts, leaving the comment
        # reading running until its stale timeout blocks later reviews.
        finalize = workflow["jobs"]["finalize"]
        self.assertEqual(finalize["needs"], ["admit", "review"])
        self.assertIn("always()", finalize["if"])
        self.assertNotIn("Finalize an abandoned review", [step.get("name") for step in review["steps"]])

        # Coverage is a separate check from whether the runner published. One
        # signal cannot carry both: collapsing them either makes a working
        # review look crashed, or lets an incomplete review show an all-green
        # pull request, which reads as reviewed when it was not.
        completeness = workflow["jobs"]["completeness"]
        self.assertEqual(completeness["needs"], ["admit", "review"])
        self.assertIn("always()", completeness["if"])
        # Every step that can run a review must feed both outputs. A hard-coded
        # count went stale the moment a provider was removed, and a count is the
        # wrong assertion anyway: it cannot tell which step was dropped. Derive
        # the expected identifiers from the steps themselves, so adding or
        # removing a provider without wiring its outputs fails here.
        provider_ids = {
            step["id"]
            for step in review["steps"]
            if step.get("id") and str(step.get("uses", "")).endswith("/actions/pr-review")
        }
        self.assertTrue(provider_ids, "the review job must run the review action")
        for output in ("state", "complete"):
            referenced = {
                identifier
                for identifier in provider_ids
                if f"steps.{identifier}.outputs.{output}" in review["outputs"][output]
            }
            self.assertEqual(
                referenced,
                provider_ids,
                f"every provider step must contribute to the {output} output",
            )
        for step in review["steps"]:
            self.assertNotIn("secrets.", step.get("if", ""))

    def test_permission_reader_ignores_nested_entries_and_comments(self) -> None:
        # A deeper entry reusing a permission name must not mask the real
        # top-level value, and a permission named only in a comment must not
        # count as set. Both would let the guard below pass on a workflow that
        # cannot post comments.
        document = "\n".join(
            [
                "permissions:",
                "  pull-requests: none",
                "  nested:",
                "    pull-requests: write",
                "  # pull-requests: write in prose only",
                "",
                "jobs:",
                "  build:",
                "    permissions:",
                "      pull-requests: write",
            ]
        )
        self.assertEqual(parse_yaml(document)["permissions"].get("pull-requests"), "none")

    def test_both_workflows_keep_pull_request_write_for_comment_creation(self) -> None:
        # Posting a comment on a pull request needs pull-requests: write even
        # though the call targets the issue-comments endpoint. Reducing this to
        # read reads like least privilege and returned 403 on comment-create,
        # which broke /review across the whole repository until it was restored.
        # This reads the parsed mapping rather than searching the file, because
        # the comment above the key contains the same words and a substring
        # search passed with the real key deleted.
        for path in (CALLER_WORKFLOW, REUSABLE_WORKFLOW):
            permissions = load_yaml(path)["permissions"]
            self.assertEqual(
                permissions.get("pull-requests"),
                "write",
                f"{path.name} must set permissions.pull-requests to write",
            )
            self.assertEqual(
                permissions.get("issues"),
                "write",
                f"{path.name} must set permissions.issues to write",
            )

    def test_composite_action_owns_runner_requirements_and_single_provider_inputs(self) -> None:
        action = load_yaml(ACTION_YAML)
        self.assertTrue((ACTION_DIR / "requirements.txt").is_file())
        self.assertEqual(action["inputs"]["operation"]["default"], "review")
        for name in ("status-comment-id", "operation", "openai-api-key", "model-fast", "model-deep"):
            self.assertIn(name, action["inputs"])
        # Either cache key breaks setup for this action and stops every review
        # before it starts, so this asserts against the parsed document rather
        # than the file's text. Four text-matching versions were each bypassed
        # a different way: by the comment that named the key, by a quoted
        # value, by a flow mapping, and by whitespace before the colon. Those
        # are parser differentials, and the answer to a parser differential is
        # a parser.
        #
        for step in action["runs"]["steps"]:
            settings = step.get("with") or {}
            self.assertNotIn("cache", settings, f"{step.get('name')} must not enable pip caching")
            self.assertNotIn("cache-dependency-path", settings, f"{step.get('name')} must not set a cache path")


class StateMachineTest(unittest.TestCase):
    def test_diff_fetch_failure_is_failed(self) -> None:
        progress = pr_review.ReviewProgress(fetch_failed=True)
        self.assertEqual(pr_review.derive_state(progress), "failed")

    def test_timeout_after_some_review_is_partial(self) -> None:
        progress = pr_review.ReviewProgress(expected_units=2, reviewed_units=1, timed_out=True)
        self.assertEqual(pr_review.derive_state(progress), "partial")

    def test_timeout_before_any_review_is_failed(self) -> None:
        progress = pr_review.ReviewProgress(expected_units=1, reviewed_units=0, timed_out=True)
        self.assertEqual(pr_review.derive_state(progress), "failed")

    def test_unrepresentable_or_omitted_unit_is_partial(self) -> None:
        progress = pr_review.ReviewProgress(
            expected_units=1,
            reviewed_units=1,
            incomplete_reasons=["one or more units were omitted or unrepresentable"],
        )
        self.assertEqual(pr_review.derive_state(progress), "partial")

    def test_truncated_or_invalid_aggregate_is_partial(self) -> None:
        progress = pr_review.ReviewProgress(expected_units=1, reviewed_units=1, aggregation_failed=True)
        self.assertEqual(pr_review.derive_state(progress), "partial")

    def test_changed_head_is_superseded(self) -> None:
        progress = pr_review.ReviewProgress(expected_units=1, reviewed_units=1, head_changed=True)
        self.assertEqual(pr_review.derive_state(progress), "superseded")

    def test_complete_review_is_clean_or_findings_only(self) -> None:
        clean = pr_review.ReviewProgress(expected_units=1, reviewed_units=1)
        finding = pr_review.ReviewProgress(
            expected_units=1,
            reviewed_units=1,
            findings=[pr_review.Finding("high", "internal/a.go", 4, "title", "why", "fix")],
        )
        self.assertEqual(pr_review.derive_state(clean), "clean")
        self.assertEqual(pr_review.derive_state(finding), "findings")


class ExitSemanticsTest(unittest.TestCase):
    def test_every_published_outcome_is_green_but_an_unknown_state_is_red(self) -> None:
        # A terminal verdict is useful even when it is partial, superseded, or
        # failed. The status comment is its authoritative surface; the runner
        # goes red only if it cannot publish a known verdict.
        expected = {"already-running", "clean", "failed", "findings", "partial", "superseded"}
        self.assertEqual(pr_review.PUBLISHED_REVIEW_STATES, expected)
        for state in expected:
            self.assertEqual(pr_review.exit_code_for_state(state), 0, state)
        self.assertEqual(pr_review.exit_code_for_state("unexpected"), 1)

    def test_only_a_whole_diff_review_counts_as_complete(self) -> None:
        # The green exit says the runner published. This says the review
        # covered the diff. Every state that left something unreviewed must
        # report incomplete, however cleanly it reported that, or a partial
        # review shows an all-green pull request and reads as reviewed.
        self.assertEqual(pr_review.COMPLETE_REVIEW_STATES, {"clean", "findings"})
        for state in pr_review.PUBLISHED_REVIEW_STATES - pr_review.COMPLETE_REVIEW_STATES:
            self.assertNotIn(state, pr_review.COMPLETE_REVIEW_STATES, state)
        # partial and superseded both publish a verdict and both left work
        # undone, so they are green to run and not complete.
        for state in ("partial", "superseded", "failed", "already-running"):
            self.assertEqual(pr_review.exit_code_for_state(state), 0, state)
            self.assertNotIn(state, pr_review.COMPLETE_REVIEW_STATES, state)

    def test_main_accepts_each_published_review_outcome(self) -> None:
        environment = {
            "GITHUB_TOKEN": "token",
            "REPO": "owner/repo",
            "PR_NUMBER": "42",
            "REVIEW_MODE": "default",
            "REVIEWER_SHA": "a" * 40,
            "REVIEW_OPERATION": "review",
        }
        for state in pr_review.PUBLISHED_REVIEW_STATES:
            with self.subTest(state=state), mock.patch.dict(pr_review.os.environ, environment, clear=True), mock.patch.object(
                pr_review, "run_review", return_value=(state, pr_review.ReviewProgress())
            ):
                self.assertIsNone(pr_review.main())


class CompressionAndClassificationTest(unittest.TestCase):
    def test_deep_plan_covers_321_small_units_in_six_chunks(self) -> None:
        # The old global cap (20 units x 8 chunks) made a 321-unit review
        # partial even when every hunk fit the token budget. Deep mode now
        # admits 60 units per chunk, so the observed PR shape fits in six
        # provider calls and still leaves two chunk slots for larger diffs.
        # 800 tokens per unit is exactly the old 20-unit, 16k-token ceiling;
        # this proves the new count and token limits work together rather than
        # only exercising an unrealistically tiny hunk.
        units = [unit(index, f"internal/item_{index}.go", "source:go", tokens=800) for index in range(1, 322)]
        chunks, omitted = pr_review.plan_chunks(units, "deep")
        self.assertEqual([len(chunk) for chunk in chunks], [60, 60, 60, 60, 60, 21])
        self.assertEqual(omitted, [])
        self.assertEqual(pr_review.DEEP_INPUT_TOKEN_BUDGET, 48_000)
        self.assertEqual(pr_review.DEEP_MAX_UNITS_PER_CHUNK, 60)
        self.assertEqual(pr_review.DEEP_MAX_CHUNKS, 8)

    def test_primary_language_and_additions_outrank_test_config_and_docs(self) -> None:
        ranked = pr_review.rank_units(
            [
                unit(1, "docs/late.md", "docs", additions=100),
                unit(2, "configs/policy.yaml", "config", additions=100),
                unit(3, "internal/check_test.go", "test", additions=100),
                unit(4, "internal/enforce.go", "source:go", additions=1),
                unit(5, "cmd/helper.py", "source:other", additions=100),
                unit(6, "internal/important.go", "source:go", additions=9),
            ]
        )
        self.assertEqual([entry.identifier for entry in ranked], [6, 4, 5, 3, 2, 1])

    def test_budget_drops_by_priority_not_diff_position(self) -> None:
        docs_first = unit(1, "docs/first.md", "docs", tokens=8)
        source_later = unit(2, "internal/later.go", "source:go", tokens=8)
        with mock.patch.object(pr_review, "input_limits", return_value=(10, 1)):
            chunks, omitted = pr_review.plan_chunks([docs_first, source_later], "default")
        self.assertEqual([[entry.path for entry in chunk] for chunk in chunks], [["internal/later.go"]])
        self.assertEqual([entry.path for entry in omitted], ["docs/first.md"])
        self.assertEqual(omitted[0].omission_reason, "priority-token-budget")

    def test_large_deletion_hunk_is_explicitly_collapsed(self) -> None:
        deleted = "\n".join(f"-line {number}" for number in range(40))
        diff = "\n".join(
            [
                "diff --git a/internal/a.go b/internal/a.go",
                "--- a/internal/a.go",
                "+++ b/internal/a.go",
                "@@ -1,40 +1 @@",
                deleted,
                "+new",
            ]
        )
        units, errors = pr_review.parse_diff(diff)
        self.assertEqual(errors, [])
        self.assertEqual(len(units), 1)
        self.assertGreater(units[0].collapsed_deletions, 0)
        self.assertIn("deletion lines collapsed", units[0].body)

    def test_mixed_test_heavy_diff_keeps_production_security_classification(self) -> None:
        units = [unit(index, f"internal/item_{index}_test.go", "test") for index in range(1, 11)]
        units.append(unit(11, "internal/proxy/enforce.go", "source:go"))
        self.assertEqual(pr_review.classify_units(units), ["source:go", "test"])
        system, _ = pr_review.build_review_prompt(pr_review.classify_units(units), units[:2])
        self.assertIn("material security and correctness", system)
        self.assertIn("For tests", system)


class ImmutableBindingTest(unittest.TestCase):
    def test_identity_contains_base_head_reviewer_and_rubric_version(self) -> None:
        binding = pr_review.PullBinding("a" * 40, "b" * 40, "c" * 40, pr_review.RUBRIC_VERSION)
        self.assertIn("aaaaaaaaaaaa", binding.correlation)
        self.assertIn("bbbbbbbbbbbb", binding.correlation)
        self.assertIn("cccccccccccc", binding.correlation)
        self.assertIn(pr_review.RUBRIC_VERSION, binding.correlation)

    def test_run_marks_review_superseded_when_head_moves_before_finalization(self) -> None:
        original = pr_review.PullBinding("a" * 40, "b" * 40, "c" * 40, pr_review.RUBRIC_VERSION)
        moved = pr_review.PullBinding("a" * 40, "d" * 40, "c" * 40, pr_review.RUBRIC_VERSION)
        diff = "\n".join(
            [
                "diff --git a/internal/a.go b/internal/a.go",
                "--- a/internal/a.go",
                "+++ b/internal/a.go",
                "@@ -1 +1 @@",
                "-old",
                "+new",
            ]
        )
        review_payload = {
            "findings": [],
            "changes": [{"path": "internal/a.go", "summary": "changes enforcement"}],
        }
        # The head moves immediately, so the run must stop before spending the
        # provider budget on a commit whose result can only be historical.
        with mock.patch.object(pr_review, "get_pull_binding", side_effect=[original, moved, moved]), mock.patch.object(
            pr_review, "find_running_comment", return_value=(None, True)
        ), mock.patch.object(pr_review, "create_comment", return_value={"id": 7}), mock.patch.object(
            pr_review, "fetch_bound_diff", return_value=diff
        ), mock.patch.object(
            pr_review, "call_model", side_effect=[review_payload, {"findings": []}]
        ) as call_model, mock.patch.object(pr_review, "update_comment"), mock.patch.object(
            pr_review, "provider_configuration", return_value=("https://provider.example/v1/chat/completions", "key")
        ), mock.patch.object(pr_review, "compare_incompleteness", return_value=None):
            state, progress = pr_review.run_review("owner/repo", "42", "token", "default", "c" * 40)
        self.assertEqual(state, "superseded")
        self.assertTrue(progress.head_changed)
        self.assertEqual(call_model.call_count, 0, "a moved head must not spend a provider call")

    def test_claim_persists_binding_and_one_status_comment_id(self) -> None:
        binding = pr_review.PullBinding("a" * 40, "b" * 40, "c" * 40, pr_review.RUBRIC_VERSION)
        with tempfile.NamedTemporaryFile() as output, mock.patch.dict(
            pr_review.os.environ, {"GITHUB_OUTPUT": output.name}, clear=False
        ), mock.patch.object(pr_review, "get_pull_binding", return_value=binding), mock.patch.object(
            pr_review, "find_running_comment", return_value=(None, True)
        ), mock.patch.object(pr_review, "create_comment", return_value={"id": 17}) as create:
            pr_review.claim_review("owner/repo", "42", "token", "default", "c" * 40)
            output.seek(0)
            values = output.read().decode("utf-8")
        self.assertIn("claimed=true", values)
        self.assertIn("base_sha=" + "a" * 40, values)
        self.assertIn("head_sha=" + "b" * 40, values)
        self.assertIn("status_comment_id=17", values)
        self.assertEqual(create.call_count, 1)


class ProviderConfigurationFinalizationTest(unittest.TestCase):
    def test_missing_credential_finalizes_the_comment_instead_of_leaving_it_running(self) -> None:
        # Raising outside the protected scope skipped finalization and stranded
        # the claimed comment on running, which then refused later reviews.
        binding = pr_review.PullBinding("a" * 40, "b" * 40, "c" * 40, pr_review.RUBRIC_VERSION)
        with mock.patch.object(pr_review, "get_pull_binding", return_value=binding), mock.patch.object(
            pr_review, "find_running_comment", return_value=(None, True)
        ), mock.patch.object(pr_review, "create_comment", return_value={"id": 7}), mock.patch.object(
            pr_review, "provider_configuration", side_effect=pr_review.ProviderConfigurationError("none")
        ), mock.patch.object(pr_review, "update_comment") as update:
            state, progress = pr_review.run_review("owner/repo", "42", "token", "default", "c" * 40)
        self.assertEqual(state, "failed")
        self.assertEqual(update.call_count, 1)
        self.assertIn("state=failed", update.call_args.args[3])
        self.assertTrue(any("provider credential" in reason for reason in progress.incomplete_reasons))


class CompareCompletenessTest(unittest.TestCase):
    def _response(self, payload: object, status: int = 200) -> object:
        class Response:
            status_code = status

            def json(self) -> object:
                return payload

        return Response()

    def test_a_capped_file_list_is_reported_as_possibly_truncated(self) -> None:
        # The compare endpoint silently truncates, and the diff media type gives
        # no sign of it. Reviewing the surviving subset and calling it clean is
        # the failure this guards.
        payload = {"files": [{"filename": f"f{i}.go"} for i in range(pr_review.COMPARE_FILE_LIMIT)]}
        with mock.patch.object(pr_review.requests, "get", return_value=self._response(payload)):
            reason = pr_review.compare_incompleteness("owner/repo", self._binding(), "token")
        self.assertIsNotNone(reason)
        self.assertIn("truncated", reason)

    def test_an_unreachable_comparison_fails_closed(self) -> None:
        with mock.patch.object(pr_review.requests, "get", side_effect=pr_review.requests.RequestException()):
            self.assertIsNotNone(pr_review.compare_incompleteness("owner/repo", self._binding(), "token"))

    def test_a_whole_comparison_reports_no_reason(self) -> None:
        payload = {"files": [{"filename": "a.go"}], "total_commits": 3}
        with mock.patch.object(pr_review.requests, "get", return_value=self._response(payload)):
            self.assertIsNone(pr_review.compare_incompleteness("owner/repo", self._binding(), "token"))

    def _binding(self) -> object:
        return pr_review.PullBinding("a" * 40, "b" * 40, "c" * 40, pr_review.RUBRIC_VERSION)


class JudgeContextAddressingTest(unittest.TestCase):
    def test_url_significant_characters_in_a_path_are_encoded(self) -> None:
        captured: dict[str, str] = {}

        class Response:
            status_code = 200

            def json(self) -> object:
                return {"encoding": "base64", "content": "", "path": "weird?name#1.go"}

        def fake_get(url: str, **kwargs: object) -> object:
            captured["url"] = url
            return Response()

        with mock.patch.object(pr_review.requests, "get", side_effect=fake_get):
            pr_review.fetch_file_context("owner/repo", "weird?name#1.go", "b" * 40, "token", "corr")
        self.assertIn("weird%3Fname%231.go", captured["url"])

    def test_a_mismatched_returned_path_yields_no_context(self) -> None:
        class Response:
            status_code = 200

            def json(self) -> object:
                return {"encoding": "base64", "content": "", "path": "some/other.go"}

        with mock.patch.object(pr_review.requests, "get", return_value=Response()):
            self.assertIsNone(pr_review.fetch_file_context("owner/repo", "internal/a.go", "b" * 40, "token", "corr"))


class FinalizerIndependenceTest(unittest.TestCase):
    def test_finalizer_does_not_depend_on_the_review_checkout(self) -> None:
        # A failed checkout is one of the cases the finalizer exists to survive,
        # so it must not resolve the locally checked-out action.
        workflow = REUSABLE_WORKFLOW.read_text(encoding="utf-8")
        finalize = workflow.split("Finalize an abandoned review", 1)[1]
        self.assertIn("if: always()", finalize)
        self.assertNotIn("trusted-pr-review", finalize)
        self.assertIn("needs.admit.outputs.status_comment_id", finalize)

    def test_finalizer_matches_the_claimed_identity_not_a_rebuilt_one(self) -> None:
        # Rebuilding the identity in shell would drift from PullBinding.correlation,
        # and matching on state alone would let this edit land on another review's
        # comment. It uses the identity the admission step published.
        workflow = REUSABLE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("correlation: ${{ steps.claim.outputs.correlation }}", workflow)
        finalize = workflow.split("Finalize an abandoned review", 1)[1]
        self.assertIn("IDENTITY: ${{ needs.admit.outputs.correlation }}", finalize)
        self.assertIn("state=running identity=${IDENTITY}", finalize)

    def test_finalizer_marker_matches_the_runner_status_marker(self) -> None:
        # The finalizer writes the marker in shell while the admission check
        # reads it in Python. If these drift, a finalized comment still reads as
        # running and wedges later reviews.
        workflow = REUSABLE_WORKFLOW.read_text(encoding="utf-8")
        finalize = workflow.split("Finalize an abandoned review", 1)[1]
        self.assertIn(f"<!-- {pr_review.STATUS_MARKER} state=running", finalize)
        self.assertIn(f"<!-- {pr_review.STATUS_MARKER} state=failed", finalize)
        self.assertIn("**Verdict:** `failed`", finalize)
        self.assertIn("<summary>Review details: binding and identity</summary>", finalize)


class AdmissionMarkerTest(unittest.TestCase):
    def _page(self, body: str, created: str) -> list[dict[str, object]]:
        return [{"user": {"login": "github-actions[bot]"}, "body": body, "created_at": created, "id": 5}]

    def test_running_marker_is_found_on_a_later_page(self) -> None:
        # Issue comments come back oldest first, so an unpaginated read holds the
        # OLDEST hundred and would miss an active review on a busy pull request.
        marker = f"<!-- {pr_review.STATUS_MARKER} state=running -->"
        fresh = pr_review.datetime.datetime.now(pr_review.datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        page1 = [{"user": {"login": "someone"}, "body": "chatter", "created_at": fresh, "id": 1}] * 100
        page2 = self._page(marker, fresh)

        class Response:
            status_code = 200

            def __init__(self, payload: object) -> None:
                self._payload = payload

            def json(self) -> object:
                return self._payload

        with mock.patch.object(pr_review.requests, "get", side_effect=[Response(page1), Response(page2)]) as get:
            found, scanned = pr_review.find_running_comment("owner/repo", "42", "token", "corr")
        self.assertIsNotNone(found)
        self.assertTrue(scanned)
        self.assertEqual(get.call_count, 2)

    def test_an_ancient_running_marker_does_not_wedge_later_reviews(self) -> None:
        # A job killed before finalization leaves the marker behind. Without an
        # age bound it would refuse every later review on the same head forever.
        marker = f"<!-- {pr_review.STATUS_MARKER} state=running -->"
        stale = pr_review.datetime.datetime.now(pr_review.datetime.timezone.utc) - pr_review.datetime.timedelta(
            minutes=pr_review.STALE_RUNNING_MINUTES + 5
        )

        class Response:
            status_code = 200

            def json(self) -> object:
                return [
                    {
                        "user": {"login": "github-actions[bot]"},
                        "body": marker,
                        "created_at": stale.isoformat().replace("+00:00", "Z"),
                        "id": 5,
                    }
                ]

        with mock.patch.object(pr_review.requests, "get", return_value=Response()):
            found, scanned = pr_review.find_running_comment("owner/repo", "42", "token", "corr")
            self.assertIsNone(found)
            self.assertTrue(scanned)


class AdmissionFailsClosedTest(unittest.TestCase):
    def test_an_unreadable_page_reports_an_incomplete_scan(self) -> None:
        # Not finding a marker is only evidence that none exists when every
        # page was read. A transient error previously read as "nothing running"
        # and authorized a second concurrent provider run on the same head.
        with mock.patch.object(pr_review.requests, "get", side_effect=pr_review.requests.RequestException()):
            found, scanned = pr_review.find_running_comment("owner/repo", "42", "token", "corr")
        self.assertIsNone(found)
        self.assertFalse(scanned)

    def test_claim_refuses_when_the_scan_could_not_complete(self) -> None:
        binding = pr_review.PullBinding("a" * 40, "b" * 40, "c" * 40, pr_review.RUBRIC_VERSION)
        with tempfile.NamedTemporaryFile() as output, mock.patch.dict(
            pr_review.os.environ, {"GITHUB_OUTPUT": output.name}, clear=False
        ), mock.patch.object(pr_review, "get_pull_binding", return_value=binding), mock.patch.object(
            pr_review, "find_running_comment", return_value=(None, False)
        ), mock.patch.object(pr_review, "create_comment", return_value={"id": 11}):
            pr_review.claim_review("owner/repo", "42", "token", "default", "c" * 40)
            output.seek(0)
            values = output.read().decode("utf-8")
        self.assertIn("claimed=false", values)


class JudgeContextBoundTest(unittest.TestCase):
    def test_context_fetches_are_bounded_not_only_the_payload(self) -> None:
        # Context was fetched for every distinct path before the budget excluded
        # most of them, so a large candidate set could spend longer on requests
        # than the job is allowed to run and be killed before publishing partial.
        binding = pr_review.PullBinding("a" * 40, "b" * 40, "c" * 40, pr_review.RUBRIC_VERSION)
        candidates = [
            pr_review.Finding("low", f"internal/pkg{index}/a.go", 1, "t", "w", "f")
            for index in range(pr_review.MAX_JUDGE_CONTEXT_FETCHES + 25)
        ]
        judged_counts: list[int] = []
        real_prompt = pr_review.build_judge_prompt

        def record(kept: list[object], contexts: dict[str, str]) -> tuple[str, str]:
            judged_counts.append(len(kept))
            return real_prompt(kept, contexts)

        def decide(*_args: object, **_kwargs: object) -> dict[str, object]:
            return {"findings": [{"index": i, "verdict": "keep", "reason": "r"} for i in range(judged_counts[-1])]}

        with mock.patch.object(pr_review, "fetch_file_context", return_value="line\n" * 10) as fetch, mock.patch.object(
            pr_review, "build_judge_prompt", side_effect=record
        ), mock.patch.object(pr_review, "call_model", side_effect=decide):
            _, judged, excluded = pr_review.judge_findings("owner/repo", "token", binding, "deep", candidates)
        self.assertTrue(judged)
        self.assertLessEqual(fetch.call_count, pr_review.MAX_JUDGE_CONTEXT_FETCHES)
        self.assertTrue(excluded)


class JudgeFetchCapTest(unittest.TestCase):
    def test_paths_dropped_by_the_token_budget_still_count_as_fetches(self) -> None:
        # The cap previously counted payload entries, so a path fetched and then
        # dropped by the token budget was never recorded and requests kept
        # going. Measured at 60 requests against a limit of 20.
        binding = pr_review.PullBinding("a" * 40, "b" * 40, "c" * 40, pr_review.RUBRIC_VERSION)
        candidates = [pr_review.Finding("low", f"p{index}/a.go", 1, "t", "w", "f") for index in range(60)]
        with mock.patch.object(pr_review, "fetch_file_context", return_value="x" * 200_000) as fetch, mock.patch.object(
            pr_review, "call_model", return_value={"findings": [{"index": 0, "verdict": "keep", "reason": "r"}]}
        ):
            _, judged, excluded = pr_review.judge_findings("owner/repo", "token", binding, "deep", candidates)
        self.assertTrue(judged)
        self.assertEqual(fetch.call_count, pr_review.MAX_JUDGE_CONTEXT_FETCHES)
        self.assertEqual(len(excluded), len(candidates) - 1)


class TimeoutStillPublishesLaterFindingsTest(unittest.TestCase):
    def test_a_finding_from_a_chunk_after_a_timeout_is_published(self) -> None:
        # Chunks continue past a timeout, so gating the judge on timed_out
        # discarded findings that later chunks really produced while
        # completeness still counted their units as reviewed. The verdict stays
        # partial; the finding must not vanish.
        binding = pr_review.PullBinding("a" * 40, "b" * 40, "c" * 40, pr_review.RUBRIC_VERSION)
        diff = "\n".join(
            [
                "diff --git a/internal/a.go b/internal/a.go",
                "--- a/internal/a.go",
                "+++ b/internal/a.go",
                "@@ -1 +1 @@",
                "-old",
                "+new",
                "diff --git a/internal/b.go b/internal/b.go",
                "--- a/internal/b.go",
                "+++ b/internal/b.go",
                "@@ -1 +1 @@",
                "-old",
                "+new",
            ]
        )
        found = {
            "findings": [
                {
                    "severity": "high",
                    "path": "internal/b.go",
                    "line": 1,
                    "title": "unsafe",
                    "why": "why",
                    "fix": "fix",
                    "needs_verification": False,
                }
            ],
            "changes": [{"path": "internal/b.go", "summary": "changes enforcement"}],
        }
        judged = {"findings": [{"index": 0, "verdict": "keep", "reason": "confirmed"}]}
        with mock.patch.object(pr_review, "plan_chunks", side_effect=lambda units, mode: ([[units[0]], [units[1]]], [])), mock.patch.object(
            pr_review, "get_pull_binding", return_value=binding
        ), mock.patch.object(pr_review, "find_running_comment", return_value=(None, True)), mock.patch.object(
            pr_review, "create_comment", return_value={"id": 7}
        ), mock.patch.object(pr_review, "fetch_bound_diff", return_value=diff), mock.patch.object(
            pr_review, "compare_incompleteness", return_value=None
        ), mock.patch.object(
            pr_review, "provider_configuration", return_value=("https://provider.example/v1/chat/completions", "key")
        ), mock.patch.object(pr_review, "fetch_file_context", return_value="line\n" * 5), mock.patch.object(
            pr_review, "call_model", side_effect=[pr_review.ModelTimeout("slow"), found, judged]
        ), mock.patch.object(pr_review, "update_comment"):
            state, progress = pr_review.run_review("owner/repo", "42", "token", "deep", "c" * 40)
        self.assertEqual(state, "partial")
        self.assertTrue(progress.timed_out)
        self.assertEqual([finding.path for finding in progress.findings], ["internal/b.go"])


class WallClockBudgetTest(unittest.TestCase):
    def test_budget_refuses_a_call_that_cannot_finish_before_the_job_timeout(self) -> None:
        now = 1_000.0
        with mock.patch.object(pr_review.time, "monotonic", return_value=now):
            deep = pr_review.llm_timeout_for("deep")
            self.assertTrue(pr_review.budget_allows(now + deep, "deep"))
            self.assertFalse(pr_review.budget_allows(now + deep - 1, "deep"))

    def test_exhausted_budget_is_partial_and_never_clean(self) -> None:
        binding = pr_review.PullBinding("a" * 40, "b" * 40, "c" * 40, pr_review.RUBRIC_VERSION)
        diff = "\n".join(
            [
                "diff --git a/internal/a.go b/internal/a.go",
                "--- a/internal/a.go",
                "+++ b/internal/a.go",
                "@@ -1 +1 @@",
                "-old",
                "+new",
            ]
        )
        # The clock jumps past the whole budget before the first chunk, so no
        # provider call may start.  A run that reviewed nothing must not be
        # reported as clean.
        clock = iter([0.0] + [pr_review.REVIEW_WALL_CLOCK_SECONDS + 1_000.0] * 50)
        with mock.patch.object(pr_review.time, "monotonic", side_effect=lambda: next(clock)), mock.patch.object(
            pr_review, "get_pull_binding", return_value=binding
        ), mock.patch.object(pr_review, "find_running_comment", return_value=(None, True)), mock.patch.object(
            pr_review, "create_comment", return_value={"id": 7}
        ), mock.patch.object(pr_review, "fetch_bound_diff", return_value=diff), mock.patch.object(
            pr_review, "call_model"
        ) as call_model, mock.patch.object(pr_review, "update_comment"), mock.patch.object(
            pr_review, "provider_configuration", return_value=("https://provider.example/v1/chat/completions", "key")
        ), mock.patch.object(pr_review, "compare_incompleteness", return_value=None):
            state, progress = pr_review.run_review("owner/repo", "42", "token", "deep", "c" * 40)
        self.assertEqual(state, "partial")
        self.assertEqual(call_model.call_count, 0)
        self.assertTrue(any("wall-clock budget" in reason for reason in progress.incomplete_reasons))


class FailureDirectionTest(unittest.TestCase):
    def test_bound_diff_retries_once_then_fails(self) -> None:
        binding = pr_review.PullBinding("a" * 40, "b" * 40, "c" * 40, pr_review.RUBRIC_VERSION)

        class Response:
            status_code = 503
            text = "ignored"

        with mock.patch.object(pr_review.requests, "get", return_value=Response()) as get, mock.patch.object(
            pr_review.time, "sleep"
        ):
            with self.assertRaises(pr_review.FetchError):
                pr_review.fetch_bound_diff("owner/repo", binding, "token")
        # Assert the literal, not the constant. Comparing the call count to the
        # constant holds for any value of it, so the bound could be raised
        # without the test noticing.
        self.assertEqual(pr_review.DIFF_FETCH_ATTEMPTS, 2)
        self.assertEqual(get.call_count, 2)

    def test_provider_timeout_is_distinguished_from_schema_failure(self) -> None:
        with mock.patch.dict(pr_review.os.environ, {"OPENAI_API_KEY": "key"}, clear=True), mock.patch.object(
            pr_review.requests, "post", side_effect=pr_review.requests.Timeout()
        ) as post:
            with self.assertRaises(pr_review.ModelTimeout):
                pr_review.call_model("system", "user", "deep", "review-chunk-1", "correlation")
        self.assertEqual(post.call_count, 1, "an ambiguous timeout must not be retried")

    def test_connect_timeout_retries_once_with_one_provider_correlation_id(self) -> None:
        # A connect timeout is the only failure proving the request was
        # never delivered, so it is the only one safe to repeat.
        class Response:
            status_code = 200

            @staticmethod
            def json() -> object:
                return {"choices": [{"message": {"content": '{"findings":[]}'}}]}

        with mock.patch.dict(pr_review.os.environ, {"OPENAI_API_KEY": "key"}, clear=True), mock.patch.object(
            pr_review.requests, "post", side_effect=[pr_review.requests.ConnectTimeout("no route"), Response()]
        ) as post:
            self.assertEqual(pr_review.call_model("system", "user", "default", "review-chunk-1", "correlation"), {"findings": []})
        self.assertEqual(pr_review.MODEL_CONNECTION_ATTEMPTS, 2)
        self.assertEqual(post.call_count, 2)
        self.assertEqual(
            post.call_args_list[0].kwargs["headers"]["X-Client-Request-Id"],
            post.call_args_list[1].kwargs["headers"]["X-Client-Request-Id"],
        )

    def test_connect_timeout_after_retry_is_distinct_from_other_provider_failures(self) -> None:
        with mock.patch.dict(pr_review.os.environ, {"OPENAI_API_KEY": "key"}, clear=True), mock.patch.object(
            pr_review.requests, "post", side_effect=pr_review.requests.ConnectTimeout("no route")
        ) as post:
            with self.assertRaises(pr_review.ModelConnectionError):
                pr_review.call_model("system", "user", "default", "review-chunk-1", "correlation")
        self.assertEqual(post.call_count, 2)

    def test_a_dropped_connection_is_not_retried(self) -> None:
        # ConnectionError covers resets that can occur after the provider has
        # the request. Only a connect timeout proves non-delivery, so anything
        # broader would risk paying for the same review twice.
        with mock.patch.dict(pr_review.os.environ, {"OPENAI_API_KEY": "key"}, clear=True), mock.patch.object(
            pr_review.requests, "post", side_effect=pr_review.requests.ConnectionError("reset by peer")
        ) as post:
            with self.assertRaises(pr_review.ModelOutputError):
                pr_review.call_model("system", "user", "default", "review-chunk-1", "correlation")
        self.assertEqual(post.call_count, 1)

    def test_non_connection_request_error_is_not_retried(self) -> None:
        # A response-path failure can happen after the provider receives the
        # request, so unlike a connection error it must preserve the one-call
        # rule that avoids duplicate review charges.
        with mock.patch.dict(pr_review.os.environ, {"OPENAI_API_KEY": "key"}, clear=True), mock.patch.object(
            pr_review.requests, "post", side_effect=pr_review.requests.exceptions.ChunkedEncodingError("connection reset")
        ) as post:
            with self.assertRaises(pr_review.ModelOutputError):
                pr_review.call_model("system", "user", "default", "review-chunk-1", "correlation")
        self.assertEqual(post.call_count, 1)


class ChunkResilienceTest(unittest.TestCase):
    def _run_with_chunk_outcomes(self, outcomes: list[object]) -> tuple[str, object, object]:
        binding = pr_review.PullBinding("a" * 40, "b" * 40, "c" * 40, pr_review.RUBRIC_VERSION)
        units = [unit(index, f"internal/item_{index}.go", "source:go") for index in range(1, 4)]

        def payload_for(path: str) -> dict[str, object]:
            return {"findings": [], "changes": [{"path": path, "summary": "changed"}]}

        resolved = [payload_for(unit.path) if outcome == "ok" else outcome for unit, outcome in zip(units, outcomes, strict=True)]
        with mock.patch.object(pr_review, "provider_configuration", return_value=("https://provider.example/v1/chat/completions", "key")), mock.patch.object(
            pr_review, "fetch_bound_diff", return_value="ignored"
        ), mock.patch.object(pr_review, "compare_incompleteness", return_value=None), mock.patch.object(
            pr_review, "parse_diff", return_value=(units, [])
        ), mock.patch.object(pr_review, "plan_chunks", return_value=([[units[0]], [units[1]], [units[2]]], [])), mock.patch.object(
            pr_review, "head_has_moved", return_value=False
        ), mock.patch.object(pr_review, "get_pull_binding", return_value=binding), mock.patch.object(
            pr_review, "budget_allows", return_value=True
        ), mock.patch.object(
            pr_review, "call_model", side_effect=resolved
        ) as call_model, mock.patch.object(pr_review, "update_comment"):
            state, progress = pr_review.run_review(
                "owner/repo", "42", "token", "deep", "c" * 40, binding=binding, status_comment_id=7
            )
        return state, progress, call_model

    def test_invalid_chunk_response_does_not_stop_later_chunks(self) -> None:
        # A provider 500 used to break here, throwing away every later chunk.
        # The failed chunk remains missing, so the terminal state must be
        # partial even though the other two chunks were successfully reviewed.
        state, progress, call_model = self._run_with_chunk_outcomes(
            ["ok", pr_review.ModelOutputError("HTTP 500"), "ok"]
        )
        self.assertEqual(state, "partial")
        self.assertEqual(progress.reviewed_units, 2)
        self.assertFalse(progress.aggregation_failed)
        self.assertEqual(call_model.call_count, 3)
        self.assertTrue(any("chunk 2" in reason for reason in progress.incomplete_reasons))

    def test_timeout_is_not_retried_but_later_chunks_continue(self) -> None:
        # A retry would be ambiguous because the timed-out provider request can
        # still complete and be billed. Continuing with a distinct later chunk
        # preserves useful coverage without a duplicate request for chunk one.
        state, progress, call_model = self._run_with_chunk_outcomes(
            [pr_review.ModelTimeout("timeout"), "ok", "ok"]
        )
        self.assertEqual(state, "partial")
        self.assertTrue(progress.timed_out)
        self.assertEqual(progress.reviewed_units, 2)
        self.assertEqual(call_model.call_count, 3)
        self.assertTrue(any("not retried" in reason for reason in progress.incomplete_reasons))

    def test_connection_retry_exhaustion_is_partial_but_later_chunks_continue(self) -> None:
        state, progress, call_model = self._run_with_chunk_outcomes(
            [pr_review.ModelConnectionError("offline after retry"), "ok", "ok"]
        )
        self.assertEqual(state, "partial")
        self.assertEqual(progress.reviewed_units, 2)
        self.assertEqual(call_model.call_count, 3)
        self.assertTrue(any("review chunk 1 could not connect after one retry" == reason for reason in progress.incomplete_reasons))


class StructuredOutputSafetyTest(unittest.TestCase):
    def test_model_clean_sentence_cannot_set_clean_state(self) -> None:
        with self.assertRaises(pr_review.ModelOutputError):
            pr_review.parse_findings("No material issues found", {"internal/a.go"})
        incomplete = pr_review.ReviewProgress(expected_units=2, reviewed_units=1)
        self.assertEqual(pr_review.derive_state(incomplete), "partial")

    def test_schema_rejects_extra_fields_and_unknown_paths(self) -> None:
        payload = {
            "findings": [
                {
                    "severity": "high",
                    "path": "wrong.go",
                    "line": 1,
                    "title": "x",
                    "why": "y",
                    "fix": "z",
                    "needs_verification": False,
                    "confidence": 99,
                }
            ]
        }
        with self.assertRaisesRegex(pr_review.ModelOutputError, "schema"):
            pr_review.parse_findings(payload, {"internal/a.go"})

    def test_schema_rejects_a_finding_outside_the_reviewed_diff(self) -> None:
        # The extra-field case above trips the key-set check before the path is
        # ever examined, so the rejection that keeps a finding inside the
        # reviewed diff needs a payload whose keys are exactly right.
        outside = {
            "findings": [
                {
                    "severity": "high",
                    "path": "wrong.go",
                    "line": 1,
                    "title": "x",
                    "why": "y",
                    "fix": "z",
                    "needs_verification": False,
                }
            ]
        }
        with self.assertRaisesRegex(pr_review.ModelOutputError, "invalid severity or path"):
            pr_review.parse_findings(outside, {"internal/a.go"})

    def test_publication_sanitizer_removes_mentions_commands_and_markup(self) -> None:
        rendered = pr_review.sanitize_public_text(
            "@victim run /review deep <script> [click]", limit=300
        )
        self.assertNotIn("@", rendered)
        self.assertNotIn("/review", rendered)
        self.assertNotIn("<", rendered)
        self.assertNotIn("[", rendered)
        self.assertIn("mention", rendered)
        self.assertIn("command", rendered)

    def test_status_is_code_generated_and_orders_findings_by_severity(self) -> None:
        binding = pr_review.PullBinding("a" * 40, "b" * 40, "c" * 40, pr_review.RUBRIC_VERSION)
        progress = pr_review.ReviewProgress(
            expected_units=1,
            reviewed_units=1,
            findings=[
                pr_review.Finding("low", "internal/z.go", 3, "low", "why", "fix"),
                pr_review.Finding("high", "internal/a.go", 2, "@bad /approve", "why", "fix"),
            ],
        )
        status = pr_review.render_status(binding, "default", ["source:go"], progress, "findings", [])
        self.assertLess(status.index("#### 1. high"), status.index("#### 2. low"))
        self.assertNotIn("/approve", status)
        self.assertNotIn("@bad", status)
        self.assertIn("Verdict:** `findings`", status)


class StatusPresentationTest(unittest.TestCase):
    def _binding(self) -> object:
        return pr_review.PullBinding("a" * 40, "b" * 40, "c" * 40, pr_review.RUBRIC_VERSION)

    def test_partial_status_leads_with_verdict_and_caps_the_manifest(self) -> None:
        # A no-findings partial once published one line for every omitted hunk
        # before the reader saw the useful conclusion. Keep the count intact,
        # show only a bounded sample, and make partial impossible to mistake
        # for a clean result.
        manifest = [
            {
                "path": f"internal/omitted_{index}.go",
                "hunk": "@@ -1 +1 @@",
                "status": "priority-token-budget",
                "collapsed_deletions": 0,
            }
            for index in range(171)
        ]
        progress = pr_review.ReviewProgress(
            expected_units=321,
            reviewed_units=90,
            incomplete_reasons=["one or more units were omitted or unrepresentable"],
        )
        status = pr_review.render_status(self._binding(), "deep", ["source:go"], progress, "partial", manifest)
        first_details = status.index("<details>")
        lead = status[:first_details]
        self.assertIn("Verdict:** `partial`", lead)
        self.assertIn("must not be treated as a clean review", lead)
        self.assertIn("### Findings", lead)
        self.assertNotIn("**Binding:**", lead)
        self.assertNotIn("**Completeness:**", lead)
        self.assertIn("<summary>Review details: binding and coverage</summary>", status)
        self.assertIn("<summary>Why this review is incomplete</summary>", status)
        self.assertIn("<summary>Omission manifest (8 of 171 shown)</summary>", status)
        self.assertEqual(status.count("priority-token-budget"), pr_review.MAX_RENDERED_MANIFEST_ENTRIES)
        self.assertIn("- and 163 more", status)
        self.assertLess(len(status.encode("utf-8")), 2_500)

    def test_no_findings_status_is_compact_but_keeps_details_available(self) -> None:
        progress = pr_review.ReviewProgress(expected_units=1, reviewed_units=1)
        status = pr_review.render_status(self._binding(), "default", ["source:go"], progress, "clean", [])
        self.assertIn("Verdict:** `clean`", status)
        self.assertIn("Findings:** high 0, medium 0, low 0.", status)
        self.assertIn("No verified material findings were published.", status)
        self.assertIn("<summary>Review details: binding and coverage</summary>", status)
        self.assertLess(len(status.encode("utf-8")), 2_000)

    def test_running_status_keeps_binding_out_of_the_open_body(self) -> None:
        status = pr_review._initial_status(self._binding(), "deep")
        lead = status[:status.index("<details>")]
        self.assertIn("Status:** `running`", lead)
        self.assertNotIn("**Binding:**", lead)
        self.assertNotIn("**Review identity:**", lead)
        self.assertIn("<summary>Review details: binding and planned review</summary>", status)


class DeletionFidelityTest(unittest.TestCase):
    """Deleting code is a change, and deep mode is the pass that must see it."""

    @staticmethod
    def diff_with_deletions(count: int) -> str:
        removed = "\n".join(f"-old line {index}" for index in range(count))
        return (
            "diff --git a/internal/guard.go b/internal/guard.go\n"
            "--- a/internal/guard.go\n"
            "+++ b/internal/guard.go\n"
            f"@@ -1,{count} +1,1 @@\n"
            f"{removed}\n"
            "+replacement\n"
        )

    def test_deep_mode_reads_every_deleted_line(self) -> None:
        # Removing a guard reads as a deletion hunk, so summarizing deletions
        # in the mode asked for full fidelity can hide the change that matters
        # most on a security product.
        count = pr_review.MAX_DELETION_LINES_PER_HUNK * 3
        units, errors = pr_review.parse_diff(self.diff_with_deletions(count), "deep")
        self.assertEqual(errors, [])
        self.assertEqual(sum(item.collapsed_deletions for item in units), 0)
        for index in range(count):
            self.assertIn(f"-old line {index}", units[0].body)

    def test_deep_mode_splits_an_oversized_deletion_hunk_without_omission(self) -> None:
        # The prior version collapsed this hunk before it reached the deep
        # planner. Leaving it whole made it exceed that planner's per-chunk
        # input budget and therefore omitted the entire deletion. Split it
        # into bounded contiguous units instead: no deleted line is hidden or
        # dropped, but each provider call remains within its budget.
        count = 16_000
        units, errors = pr_review.parse_diff(self.diff_with_deletions(count), "deep")
        chunks, omitted = pr_review.plan_chunks(units, "deep")
        deleted_lines = [
            line
            for unit in units
            for line in unit.body.splitlines()
            if line.startswith("-old line ")
        ]
        self.assertEqual(errors, [])
        self.assertGreater(len(units), 1)
        self.assertTrue(all(unit.estimated_tokens <= pr_review.DEEP_INPUT_TOKEN_BUDGET for unit in units))
        self.assertEqual(sum(len(chunk) for chunk in chunks), len(units))
        self.assertEqual(omitted, [])
        self.assertEqual(deleted_lines, [f"-old line {index}" for index in range(count)])
        # Every piece must still be a readable diff. Emitting a continuation
        # without the hunk header hands the model file headers and a bare run
        # of changed lines, which is not a diff and carries no line context.
        for unit in units:
            body = unit.body.splitlines()
            self.assertIn(unit.hunk_header, body)
            self.assertTrue(
                body.index(unit.hunk_header) < len(body) - 1,
                "a unit must carry changed lines after its hunk header",
            )

    def test_default_mode_still_collapses_and_discloses(self) -> None:
        count = pr_review.MAX_DELETION_LINES_PER_HUNK * 3
        units, _ = pr_review.parse_diff(self.diff_with_deletions(count), "default")
        collapsed = sum(item.collapsed_deletions for item in units)
        self.assertGreater(collapsed, 0)
        self.assertIn("deletion lines collapsed", units[0].body)
        self.assertEqual(units[0].manifest()["collapsed_deletions"], collapsed)

    def test_a_collapsed_hunk_is_not_a_coverage_gap(self) -> None:
        # An observed review read 321 of 321 units, omitted nothing, and still
        # reported partial behind a failing check because six hunks were
        # collapsed. A check that fails on complete reviews gets ignored, and
        # then it protects nothing when a review really is short.
        #
        # This asserts the decision, not its consequence. Asserting that
        # derive_state returns clean for a hand-built progress cannot catch
        # this: the defect was in what the caller recorded, so a version that
        # recorded the collapse again still passed that assertion.
        units, _ = pr_review.parse_diff(
            self.diff_with_deletions(pr_review.MAX_DELETION_LINES_PER_HUNK * 3), "default"
        )
        self.assertGreater(sum(item.collapsed_deletions for item in units), 0)
        self.assertEqual(pr_review.coverage_gaps(units, [], []), [])

    def test_a_genuinely_omitted_unit_is_a_coverage_gap(self) -> None:
        units, _ = pr_review.parse_diff(self.diff_with_deletions(2), "deep")
        gaps = pr_review.coverage_gaps(units, [units[0]], [])
        self.assertEqual(gaps, ["one or more units were omitted or unrepresentable"])

    def test_a_parse_error_is_carried_through_as_a_gap(self) -> None:
        units, _ = pr_review.parse_diff(self.diff_with_deletions(2), "deep")
        self.assertEqual(pr_review.coverage_gaps(units, [], ["diff has no file headers"]),
                         ["diff has no file headers"])

    def test_an_omitted_unit_still_reports_partial(self) -> None:
        progress = pr_review.ReviewProgress()
        progress.expected_units = 4
        progress.reviewed_units = 3
        self.assertEqual(pr_review.derive_state(progress), "partial")


class SingleProviderTest(unittest.TestCase):
    def test_openai_credential_selects_the_only_provider(self) -> None:
        with mock.patch.dict(pr_review.os.environ, {"OPENAI_API_KEY": "key"}, clear=True):
            endpoint, key = pr_review.provider_configuration()
        self.assertEqual(endpoint, "https://api.openai.com/v1/chat/completions")
        self.assertEqual(key, "key")

    def test_a_stale_gateway_variable_cannot_redirect_the_provider_call(self) -> None:
        # The removed branch chose its endpoint from an environment variable.
        # A leftover value in a repository or runner must not be able to send
        # the review, its diff and its credential somewhere else.
        environment = {
            "OPENAI_API_KEY": "key",
            "LITELLM_BASE_URL": "https://attacker.vendor.example/v1",
            "LITELLM_API_KEY": "other",
        }
        with mock.patch.dict(pr_review.os.environ, environment, clear=True):
            endpoint, key = pr_review.provider_configuration()
        self.assertEqual(endpoint, "https://api.openai.com/v1/chat/completions")
        self.assertEqual(key, "key")

    def test_no_credential_is_a_configuration_failure(self) -> None:
        with mock.patch.dict(pr_review.os.environ, {}, clear=True):
            with self.assertRaises(pr_review.ProviderConfigurationError):
                pr_review.provider_configuration()

    def test_guide_does_not_advertise_removed_gateway_credentials(self) -> None:
        # The provider branch, composite inputs, and reusable-workflow secrets
        # are gone together. Leaving a gateway variable in the guide tells an
        # adopter to configure a value the action no longer consumes.
        #
        # Matched case-insensitively against the whole name, not against a
        # backtick-quoted variable. Prose reintroducing the gateway ("point
        # LiteLLM at any upstream") tells an adopter the same wrong thing as a
        # table row, and four earlier guards in this suite were each bypassed
        # by matching a narrower spelling than the thing they guarded.
        guide = (ROOT / "docs" / "guides" / "pr-review.md").read_text(encoding="utf-8")
        self.assertIn("`OPENAI_API_KEY`", guide)
        self.assertNotIn("litellm", guide.lower())


class AdoptionStubTest(unittest.TestCase):
    """The stub in the guide is what other repositories copy, so it is code.

    Six repositories each grew their own copy of this reviewer and drifted
    apart, which is what made the command work in one repository and not the
    next. Replacing the copies with a shared caller only holds if the
    instructions for writing that caller cannot fall behind the caller this
    repository actually runs. Prose cannot be relied on for that, so the
    published stub is compared against the real caller here.
    """

    # A caller outside this repository must name the reviewer by immutable
    # commit, where a same-repository call resolves it implicitly. Those two
    # keys are expected to differ; nothing else is.
    EXPECTED_DIFFERENCES = frozenset({"uses", "reviewer_sha"})
    PLACEHOLDER_LOGIN = "YOUR_GITHUB_LOGIN"
    REAL_LOGIN = "luckyPipewrench"

    def documented_stub(self) -> dict[str, object]:
        guide = (ROOT / "docs" / "guides" / "pr-review.md").read_text(encoding="utf-8")
        marker = "## Reusing the reviewer in another repository"
        self.assertIn(marker, guide, "the adoption section is what other repositories copy")
        section = guide.split(marker, 1)[1]
        blocks = section.split("```yaml")
        self.assertGreater(len(blocks), 1, "the adoption section must publish a YAML stub")
        body = blocks[1].split("```", 1)[0]
        # The stub is written for another repository, so it carries a
        # placeholder where this repository carries its own login.
        self.assertIn(self.PLACEHOLDER_LOGIN, body, "the stub must not hard-code one account")
        return parse_yaml(body.replace(self.PLACEHOLDER_LOGIN, self.REAL_LOGIN))

    @staticmethod
    def collapse(value: object) -> object:
        """Compare meaning, not line breaks, since YAML folding is free."""
        if isinstance(value, str):
            return " ".join(value.split())
        if isinstance(value, list):
            return [AdoptionStubTest.collapse(item) for item in value]
        if isinstance(value, dict):
            return {key: AdoptionStubTest.collapse(item) for key, item in value.items()}
        return value

    @staticmethod
    def triggers(document: dict[str, object]) -> object:
        """Compare what a trigger accepts, not how it describes itself.

        An input's description is text shown to whoever runs the dispatch. It
        carries no behavior, and requiring two copies of it to match word for
        word would fail on an improved wording. A guard that fails on
        harmless edits gets removed, so this compares the contract instead:
        which inputs exist, whether each is required, its type, its default
        and its permitted values.
        """
        events = AdoptionStubTest.collapse(document.get("on"))
        dispatch = events.get("workflow_dispatch") if isinstance(events, dict) else None
        if isinstance(dispatch, dict) and isinstance(dispatch.get("inputs"), dict):
            dispatch["inputs"] = {
                name: {key: value for key, value in spec.items() if key != "description"}
                for name, spec in dispatch["inputs"].items()
            }
        return events

    def test_documented_stub_matches_the_caller_this_repository_runs(self) -> None:
        stub = self.documented_stub()
        real = load_yaml(CALLER_WORKFLOW)

        self.assertEqual(
            self.triggers(stub),
            self.triggers(real),
            "the stub must offer the same triggers, including the manual dispatch that "
            "makes a change to a caller testable before it merges",
        )
        self.assertEqual(
            stub.get("permissions"),
            real.get("permissions"),
            "a called workflow cannot hold a permission its caller withheld, so a stub "
            "granting less silently strips it from the reviewer",
        )

        stub_job = stub["jobs"]["review"]
        real_job = real["jobs"]["review"]
        self.assertEqual(
            self.collapse(stub_job.get("if")),
            self.collapse(real_job.get("if")),
            "the stub must authorize exactly who the real caller authorizes",
        )
        self.assertEqual(
            stub_job.get("secrets"),
            real_job.get("secrets"),
            "every secret is mapped by name because personal accounts cannot inherit them",
        )

        stub_with = self.collapse(stub_job.get("with"))
        real_with = self.collapse(real_job.get("with"))
        self.assertEqual(
            set(stub_with), set(real_with), "the stub must pass the same inputs"
        )
        differing = {key for key in stub_with if stub_with[key] != real_with[key]}
        self.assertEqual(
            differing,
            self.EXPECTED_DIFFERENCES & set(stub_with),
            "only the reviewer pin may differ between an external stub and this caller",
        )

    def test_stub_pins_the_reviewer_by_commit_in_both_positions(self) -> None:
        stub = self.documented_stub()
        job = stub["jobs"]["review"]
        placeholder = "PINNED_PIPELOCK_REVIEW_COMMIT_SHA"
        uses = job["uses"]
        self.assertTrue(
            uses.endswith("@" + placeholder),
            "the stub must be pinned by commit; a branch or tag can move the reviewer "
            "code under the pin",
        )
        self.assertEqual(
            job["with"]["reviewer_sha"],
            placeholder,
            "the workflow and the reviewer it checks out must be pinned to one commit",
        )


if __name__ == "__main__":
    unittest.main()
