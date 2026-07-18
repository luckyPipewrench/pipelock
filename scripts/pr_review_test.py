#!/usr/bin/env python3
# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for scripts/pr-review.py."""

import importlib.util
import pathlib
import unittest
from unittest import mock


SCRIPT_PATH = pathlib.Path(__file__).with_name("pr-review.py")
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

    def test_gpt5_deep_payload_can_use_medium_reasoning_effort(self) -> None:
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


class ResponseParsingTest(unittest.TestCase):
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
        self.assertIn("boom", message)

    def test_call_llm_raises_when_no_api_is_configured(self) -> None:
        with mock.patch.dict(pr_review.os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                pr_review.LLMReviewError,
                "No LLM API configured",
            ):
                pr_review.call_llm("diff", "default", "system")


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
