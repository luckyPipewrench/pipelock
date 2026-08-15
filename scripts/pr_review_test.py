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


def top_level_permissions(text: str) -> dict[str, str]:
    """Read a workflow's top-level permissions mapping, ignoring comments.

    Deliberately dependency-free: the CI job that runs these tests installs no
    Python packages, and an import failure there would take down the whole test
    discovery run rather than just this assertion.
    """
    permissions: dict[str, str] = {}
    inside = False
    child_indent: int | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line:
            continue
        if line == "permissions:":
            inside = True
            continue
        if inside:
            indent = len(line) - len(line.lstrip(" "))
            if indent == 0:
                break
            if child_indent is None:
                child_indent = indent
            if indent < child_indent:
                break
            # Only direct children count. A deeper entry reusing a permission
            # name would otherwise overwrite the real top-level value, so a
            # nested write could mask a top-level none.
            if indent != child_indent:
                continue
            key, _, value = line.strip().partition(":")
            permissions[key.strip()] = value.strip()
    return permissions


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
    def test_only_supported_commands_reach_the_reusable_workflow(self) -> None:
        caller = CALLER_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("github.event.comment.body == '/review'", caller)
        self.assertIn("github.event.comment.body == '/review deep'", caller)
        self.assertIn("uses: ./.github/workflows/pr-review-reusable.yaml", caller)
        self.assertIn("author_association == 'OWNER'", caller)
        self.assertIn("user.login == 'luckyPipewrench'", caller)

    def test_reusable_workflow_uses_non_cancelling_pr_concurrency(self) -> None:
        workflow = REUSABLE_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("group: pr-review-${{ github.repository }}-${{ inputs.pr_number }}", workflow)
        self.assertIn("cancel-in-progress: false", workflow)
        self.assertIn("Claim review status", workflow)
        self.assertIn("needs: admit", workflow)
        self.assertIn("repository: luckyPipewrench/pipelock", workflow)
        self.assertIn("ref: ${{ inputs.reviewer_sha }}", workflow)
        self.assertIn("HAS_LITELLM", workflow)
        self.assertNotRegex(workflow, r"(?m)^\s*if:\s*.*secrets\.")
        # The explicit mapping must not accidentally turn into a secret inherit.
        self.assertNotRegex(workflow, r"(?m)^\s*secrets:\s*inherit\s*$")

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
        self.assertEqual(top_level_permissions(document).get("pull-requests"), "none")

    def test_both_workflows_keep_pull_request_write_for_comment_creation(self) -> None:
        # Posting a comment on a pull request needs pull-requests: write even
        # though the call targets the issue-comments endpoint. Reducing this to
        # read reads like least privilege and returned 403 on comment-create,
        # which broke /review across the whole repository until it was restored.
        # This reads the parsed mapping rather than searching the file, because
        # the comment above the key contains the same words and a substring
        # search passed with the real key deleted.
        for path in (CALLER_WORKFLOW, REUSABLE_WORKFLOW):
            permissions = top_level_permissions(path.read_text(encoding="utf-8"))
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
        action = ACTION_YAML.read_text(encoding="utf-8")
        self.assertTrue((ACTION_DIR / "requirements.txt").is_file())
        self.assertIn("$GITHUB_ACTION_PATH/pr_review.py", action)
        self.assertIn("$GITHUB_ACTION_PATH/requirements.txt", action)
        self.assertIn("status_comment_id", action)
        self.assertIn("operation", action)
        self.assertIn("litellm-api-key", action)
        self.assertIn("openai-api-key", action)
        self.assertIn("PR_REVIEW_MODEL_FAST", action)
        self.assertIn("PR_REVIEW_MODEL_DEEP", action)
        self.assertIn("cache: pip", action)
        self.assertIn("cache-dependency-path: ${{ github.action_path }}/requirements.txt", action)


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
        ):
            with self.assertRaises(pr_review.ModelTimeout):
                pr_review.call_model("system", "user", "deep", "review-chunk-1", "correlation")


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


if __name__ == "__main__":
    unittest.main()
