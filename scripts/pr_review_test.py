#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for scripts/pr-review.py."""

import importlib.util
import pathlib
import unittest
from unittest import mock


SCRIPT_PATH = pathlib.Path(__file__).with_name("pr-review.py")
WORKFLOW_PATH = SCRIPT_PATH.parents[1] / ".github" / "workflows" / "pr-review.yaml"
SPEC = importlib.util.spec_from_file_location("pr_review", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed to load {SCRIPT_PATH}")
pr_review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pr_review)


class FakeResponse:
    def __init__(self, data: dict, status_code: int = 200, text: str = "") -> None:
        self._data = data
        self.status_code = status_code
        self.text = text

    def json(self) -> dict:
        return self._data


class PayloadTest(unittest.TestCase):
    def test_gpt5_models_omit_temperature(self) -> None:
        payload = pr_review.build_llm_payload("gpt-5.5", "system", "diff")
        self.assertNotIn("temperature", payload)

    def test_gpt5_models_default_to_fast_reasoning_effort(self) -> None:
        payload = pr_review.build_llm_payload("gpt-5.5", "system", "diff")
        self.assertEqual(payload["reasoning_effort"], pr_review.FAST_REASONING_EFFORT)

    def test_gpt5_deep_payload_uses_review_reasoning_effort(self) -> None:
        payload = pr_review.build_llm_payload(
            "gpt-5.5",
            "system",
            "diff",
            reasoning_effort=pr_review.DEEP_REASONING_EFFORT,
        )
        self.assertEqual(payload["reasoning_effort"], pr_review.DEEP_REASONING_EFFORT)

    def test_deep_payload_can_raise_completion_budget(self) -> None:
        payload = pr_review.build_llm_payload(
            "gpt-5.5",
            "system",
            "diff",
            max_completion_tokens=pr_review.DEEP_MAX_COMPLETION_TOKENS,
        )
        self.assertEqual(
            payload["max_completion_tokens"],
            pr_review.DEEP_MAX_COMPLETION_TOKENS,
        )

    def test_prefixed_gpt5_models_omit_temperature(self) -> None:
        payload = pr_review.build_llm_payload("openai/gpt-5.5", "system", "diff")
        self.assertNotIn("temperature", payload)
        self.assertEqual(payload["reasoning_effort"], pr_review.FAST_REASONING_EFFORT)

    def test_legacy_chat_models_keep_low_temperature(self) -> None:
        payload = pr_review.build_llm_payload("gpt-4.1", "system", "diff")
        self.assertEqual(payload["temperature"], pr_review.DEFAULT_TEMPERATURE)
        self.assertNotIn("reasoning_effort", payload)


class ModelRoutingTest(unittest.TestCase):
    def test_defaults_use_cost_routed_gpt56_models(self) -> None:
        self.assertEqual(pr_review.DEFAULT_MODEL_FAST, "gpt-5.6-luna")
        self.assertEqual(pr_review.DEFAULT_MODEL_DEEP, "gpt-5.6-terra")

    def test_empty_overrides_fall_back_to_python_defaults(self) -> None:
        with mock.patch.dict(
            pr_review.os.environ,
            {"PR_REVIEW_MODEL_FAST": "", "PR_REVIEW_MODEL_DEEP": ""},
            clear=True,
        ):
            self.assertEqual(pr_review.model_for_mode("default"), "gpt-5.6-luna")
            self.assertEqual(pr_review.model_for_mode("deep"), "gpt-5.6-terra")

    def test_nonempty_overrides_are_honored(self) -> None:
        with mock.patch.dict(
            pr_review.os.environ,
            {
                "PR_REVIEW_MODEL_FAST": "provider/ordinary",
                "PR_REVIEW_MODEL_DEEP": "provider/deep",
            },
            clear=True,
        ):
            self.assertEqual(pr_review.model_for_mode("default"), "provider/ordinary")
            self.assertEqual(pr_review.model_for_mode("deep"), "provider/deep")

    def test_workflow_delegates_defaults_to_runner(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "PR_REVIEW_MODEL_FAST: ${{ vars.PR_REVIEW_MODEL_FAST }}",
            workflow,
        )
        self.assertIn(
            "PR_REVIEW_MODEL_DEEP: ${{ vars.PR_REVIEW_MODEL_DEEP }}",
            workflow,
        )
        self.assertNotRegex(workflow, r"PR_REVIEW_MODEL_(?:FAST|DEEP): gpt-")

    def test_deep_review_has_distinct_adversarial_prompt(self) -> None:
        self.assertIsNot(pr_review.PROMPT_DEEP, pr_review.PROMPT_SECURITY)
        for section in (
            "1. STATES",
            "2. DIRECTION",
            "3. BLAST RADIUS",
            "4. APPROACH",
            "5. CLASS",
            "6. VACUITY",
            "7. PREDECESSOR",
            "8. OUR OWN ARTIFACTS",
            "9. AVAILABILITY",
            "10. HONEST CONVERGENCE",
        ):
            with self.subTest(section=section):
                self.assertIn(section, pr_review.PROMPT_DEEP)
        self.assertIn("static pull-request diff", pr_review.PROMPT_DEEP)
        self.assertIn("You cannot run code", pr_review.PROMPT_DEEP)

    def test_deep_prompt_declares_compact_output_contract(self) -> None:
        self.assertIn("Evaluate all ten questions below before answering", pr_review.PROMPT_DEEP)
        self.assertIn("internal review", pr_review.PROMPT_DEEP)
        self.assertIn("not ten required output sections", pr_review.PROMPT_DEEP)
        self.assertIn("Lead with `## Findings`", pr_review.PROMPT_DEEP)
        self.assertIn("exactly one compact `## Audit coverage` paragraph", pr_review.PROMPT_DEEP)
        self.assertIn("`NOT PROVEN:` clause", pr_review.PROMPT_DEEP)
        self.assertIn("Do not emit ten headings", pr_review.PROMPT_DEEP)
        self.assertIn("fewer than 1,200 words", pr_review.PROMPT_DEEP)
        self.assertIn("Never omit or merge independently material", pr_review.PROMPT_DEEP)
        self.assertIn("at most three sentences", pr_review.PROMPT_DEEP)
        self.assertIn("The `## Audit coverage` paragraph is still required", pr_review.PROMPT_DEEP)
        self.assertNotIn("Answer all ten sections", pr_review.PROMPT_DEEP)
        self.assertNotIn("even when a section has no finding", pr_review.PROMPT_DEEP)
        self.assertIn(
            "No material security or correctness issues found in the supplied static diff.",
            pr_review.PROMPT_DEEP,
        )

    def test_deep_mode_routes_to_adversarial_prompt_and_larger_diff(self) -> None:
        self.assertIs(pr_review.prompt_for_mode("deep"), pr_review.PROMPT_DEEP)
        self.assertIs(pr_review.prompt_for_mode("default"), pr_review.PROMPT_SECURITY)
        self.assertEqual(pr_review.diff_limit_for_mode("default"), 100_000)
        self.assertEqual(pr_review.diff_limit_for_mode("deep"), 200_000)

    def test_deep_review_uses_xhigh_reasoning(self) -> None:
        self.assertEqual(pr_review.DEEP_REASONING_EFFORT, "xhigh")

    def test_workflow_passes_documented_llm_credentials(self) -> None:
        workflow = WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("ref: ${{ github.event.repository.default_branch }}", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn("LITELLM_BASE_URL: ${{ secrets.LITELLM_BASE_URL }}", workflow)
        self.assertIn("LITELLM_API_KEY: ${{ secrets.LITELLM_API_KEY }}", workflow)
        self.assertIn("OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}", workflow)
        self.assertIn("group: pr-review-${{ github.repository }}-${{ github.event.issue.number }}", workflow)
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertIn("python -m unittest scripts/pr_review_test.py", workflow)


class ResponseParsingTest(unittest.TestCase):
    def test_nonobject_response_roots_fail_closed(self) -> None:
        for data in ([], "response", None, 1):
            with self.subTest(data=data):
                with self.assertRaisesRegex(
                    pr_review.LLMReviewError, "invalid response shape"
                ):
                    pr_review.extract_chat_content(data)

    def test_nonlist_choices_fail_closed(self) -> None:
        for choices in ({}, "invalid", None, 1):
            with self.subTest(choices=choices):
                with self.assertRaisesRegex(pr_review.LLMReviewError, "no choices"):
                    pr_review.extract_chat_content({"choices": choices})

    def test_shape_errors_are_generic_and_fail_closed(self) -> None:
        with self.assertRaises(pr_review.LLMReviewError) as ctx:
            pr_review.extract_chat_content(
                {"choices": [], "private": "provider detail"}
            )
        self.assertIn("no choices", str(ctx.exception))
        self.assertNotIn("provider detail", str(ctx.exception))

        with self.assertRaisesRegex(pr_review.LLMReviewError, "empty content"):
            pr_review.extract_chat_content({"choices": [None]})

    def test_extract_chat_content_accepts_string_content(self) -> None:
        data = {"choices": [{"message": {"content": "review body"}}]}
        self.assertEqual(pr_review.extract_chat_content(data), "review body")

    def test_extract_chat_content_accepts_content_parts(self) -> None:
        data = {
            "choices": [
                {
                    "message": {
                        "content": [
                            {"type": "text", "text": "review "},
                            {"type": "text", "text": "body"},
                        ]
                    }
                }
            ]
        }
        self.assertEqual(pr_review.extract_chat_content(data), "review body")

    def test_extract_chat_content_rejects_empty_reasoning_only_response(self) -> None:
        data = {
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {"content": ""},
                }
            ],
            "usage": {
                "prompt_tokens": 1000,
                "completion_tokens": 4096,
                "total_tokens": 5096,
                "completion_tokens_details": {"reasoning_tokens": 4096},
            },
        }
        with self.assertRaisesRegex(
            pr_review.LLMReviewError,
            "finish_reason=length.*reasoning=4096",
        ):
            pr_review.extract_chat_content(data)

    def test_extract_chat_content_warns_on_truncated_nonempty_response(self) -> None:
        data = {
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {"content": "partial review"},
                }
            ],
            "usage": {
                "prompt_tokens": 1000,
                "completion_tokens": 25000,
                "total_tokens": 26000,
                "completion_tokens_details": {"reasoning_tokens": 22000},
            },
        }
        content = pr_review.extract_chat_content(data)
        self.assertIn("partial review", content)
        self.assertIn("Warning", content)
        self.assertIn("reasoning=22000", content)


class CallLLMTest(unittest.TestCase):
    def test_call_llm_uses_fast_budget_effort_and_timeout_by_default(self) -> None:
        response = FakeResponse({"choices": [{"message": {"content": "review"}}]})
        with mock.patch.dict(
            pr_review.os.environ,
            {"OPENAI_API_KEY": "test-key", "PR_REVIEW_MODEL_FAST": "gpt-5.4-mini"},
            clear=True,
        ), mock.patch.object(pr_review.requests, "post", return_value=response) as post:
            self.assertEqual(pr_review.call_llm("diff", "default", "system"), "review")

        _, kwargs = post.call_args
        self.assertEqual(kwargs["timeout"], pr_review.DEFAULT_LLM_TIMEOUT_SECONDS)
        self.assertEqual(
            kwargs["json"]["max_completion_tokens"],
            pr_review.DEFAULT_MAX_COMPLETION_TOKENS,
        )
        self.assertEqual(
            kwargs["json"]["reasoning_effort"],
            pr_review.FAST_REASONING_EFFORT,
        )

    def test_call_llm_uses_deep_budget_effort_and_timeout_for_deep_mode(self) -> None:
        response = FakeResponse({"choices": [{"message": {"content": "review"}}]})
        with mock.patch.dict(
            pr_review.os.environ,
            {"OPENAI_API_KEY": "test-key", "PR_REVIEW_MODEL_DEEP": "gpt-5.5"},
            clear=True,
        ), mock.patch.object(pr_review.requests, "post", return_value=response) as post:
            self.assertEqual(pr_review.call_llm("diff", "deep", "system"), "review")

        _, kwargs = post.call_args
        self.assertEqual(kwargs["timeout"], pr_review.DEEP_LLM_TIMEOUT_SECONDS)
        self.assertEqual(
            kwargs["json"]["max_completion_tokens"],
            pr_review.DEEP_MAX_COMPLETION_TOKENS,
        )
        self.assertEqual(
            kwargs["json"]["reasoning_effort"],
            pr_review.DEEP_REASONING_EFFORT,
        )

    def test_call_llm_raises_on_non_200_response(self) -> None:
        response = FakeResponse({}, status_code=500, text="boom")
        with mock.patch.dict(
            pr_review.os.environ,
            {"OPENAI_API_KEY": "test-key", "PR_REVIEW_MODEL_FAST": "gpt-5.4-mini"},
            clear=True,
        ), mock.patch.object(pr_review.requests, "post", return_value=response):
            with self.assertRaises(pr_review.LLMReviewError) as ctx:
                pr_review.call_llm("diff", "default", "system")

        message = str(ctx.exception)
        self.assertIn("LLM API returned 500", message)
        self.assertIn("gpt-5.4-mini", message)
        self.assertNotIn("boom", message)

    def test_call_llm_raises_when_no_api_is_configured(self) -> None:
        with mock.patch.dict(pr_review.os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                pr_review.LLMReviewError,
                "No LLM API configured",
            ):
                pr_review.call_llm("diff", "default", "system")


class DeepReviewValidationTest(unittest.TestCase):
    valid_clean = (
        "## Findings\n\n"
        + pr_review.DEEP_REVIEW_CLEAN_FINDINGS
        + "\n\n## Audit coverage\n\nAll ten questions were checked."
    )

    def test_accepts_compact_clean_review(self) -> None:
        self.assertEqual(pr_review.validate_deep_review(self.valid_clean), [])

    def test_rejects_malformed_sections_and_finding_heading(self) -> None:
        malformed = (
            "## Audit coverage\n\nChecked.\n\n"
            "## Findings\n\n### Finding without severity\nDetails."
        )
        errors = pr_review.validate_deep_review(malformed)
        self.assertIn("response must start with ## Findings", errors)
        self.assertIn("## Audit coverage must follow ## Findings", errors)

    def test_rejects_material_finding_without_compact_fields(self) -> None:
        malformed = (
            "## Findings\n\n### 1. medium — script.py/main\nWhy: Risk.\n"
            "\n## Audit coverage\n\nChecked."
        )
        errors = pr_review.validate_deep_review(malformed)
        self.assertIn("each material finding must include a non-empty Check: line", errors)
        self.assertIn("each material finding must include a non-empty Fix: line", errors)

    def test_rejects_over_limit_review(self) -> None:
        review = self.valid_clean + "\n" + "word " * pr_review.DEEP_REVIEW_MAX_WORDS
        self.assertTrue(
            any("must be fewer than" in error for error in pr_review.validate_deep_review(review))
        )

    def test_invalid_deep_review_gets_one_correction_retry(self) -> None:
        with mock.patch.object(
            pr_review,
            "call_llm",
            side_effect=["invalid", self.valid_clean],
        ) as call_llm:
            review = pr_review.call_review("diff", "deep", pr_review.PROMPT_DEEP)

        self.assertEqual(review, self.valid_clean)
        self.assertEqual(call_llm.call_count, 2)
        self.assertIn("previous response was not published", call_llm.call_args.args[2])

    def test_second_invalid_deep_review_fails_closed(self) -> None:
        with mock.patch.object(
            pr_review,
            "call_llm",
            return_value="invalid",
        ) as call_llm, self.assertRaisesRegex(
            pr_review.LLMReviewError,
            "violated output contract after one correction retry",
        ):
            pr_review.call_review("diff", "deep", pr_review.PROMPT_DEEP)

        self.assertEqual(call_llm.call_count, 2)


class MainFlowTest(unittest.TestCase):
    def test_deep_comment_exposes_static_review_scope(self) -> None:
        review_result = DeepReviewValidationTest.valid_clean
        with mock.patch.dict(
            pr_review.os.environ,
            {
                "GITHUB_TOKEN": "test-token",
                "REPO": "owner/repo",
                "PR_NUMBER": "42",
                "REVIEW_MODE": "deep",
            },
            clear=True,
        ), mock.patch.object(
            pr_review, "get_pr_diff", return_value="diff --git a/a b/a"
        ), mock.patch.object(
            pr_review, "call_llm", return_value=review_result
        ) as call_llm, mock.patch.object(
            pr_review, "post_comment"
        ) as post_comment, mock.patch("builtins.print") as output:
            pr_review.main()

        call_llm.assert_called_once_with(
            "diff --git a/a b/a", "deep", pr_review.PROMPT_DEEP
        )
        post_comment.assert_called_once()
        repo, pr_number, token, body = post_comment.call_args.args
        self.assertEqual((repo, pr_number, token), ("owner/repo", "42", "test-token"))
        self.assertIn("**Scope:** Static diff review", body)
        self.assertIn("no tests or repository-wide search were executed", body)
        self.assertIn(pr_review.DEEP_REVIEW_CLEAN_FINDINGS, body)
        output.assert_any_call(f"Deep review output: {len(review_result.split())} words")


class StatsSafetyTest(unittest.TestCase):
    def test_stats_subprocess_env_allowlists_safe_runtime_variables(self) -> None:
        env = pr_review.env_without_runtime_secrets(
            {
                "AWS_SECRET_ACCESS_KEY": "secret",
                "CUSTOM_API_KEY": "secret",
                "CUSTOM_TOKEN": "secret",
                "DATABASE_URL": "postgres://secret",
                "GITHUB_TOKEN": "ghs_secret",
                "GOCACHE": "/tmp/go-cache",
                "OPENAI_API_KEY": "sk-secret",
                "PASSWORD": "secret",
                "PATH": "/usr/bin",
                "HOME": "/tmp/home",
            }
        )

        self.assertEqual(
            env,
            {
                "GOCACHE": "/tmp/go-cache",
                "PATH": "/usr/bin",
                "HOME": "/tmp/home",
            },
        )
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
        self.assertNotIn("CUSTOM_API_KEY", env)
        self.assertNotIn("CUSTOM_TOKEN", env)
        self.assertNotIn("DATABASE_URL", env)
        self.assertNotIn("GITHUB_TOKEN", env)
        self.assertNotIn("OPENAI_API_KEY", env)
        self.assertNotIn("PASSWORD", env)


if __name__ == "__main__":
    unittest.main()
