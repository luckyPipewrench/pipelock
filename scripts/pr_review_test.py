#!/usr/bin/env python3
"""Unit tests for scripts/pr-review.py."""

import importlib.util
import pathlib
import unittest


SCRIPT_PATH = pathlib.Path(__file__).with_name("pr-review.py")
SPEC = importlib.util.spec_from_file_location("pr_review", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"failed to load {SCRIPT_PATH}")
pr_review = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pr_review)


class PayloadTest(unittest.TestCase):
    def test_gpt5_models_omit_temperature(self) -> None:
        payload = pr_review.build_llm_payload("gpt-5.5", "system", "diff")
        self.assertNotIn("temperature", payload)

    def test_prefixed_gpt5_models_omit_temperature(self) -> None:
        payload = pr_review.build_llm_payload("openai/gpt-5.5", "system", "diff")
        self.assertNotIn("temperature", payload)

    def test_legacy_chat_models_keep_low_temperature(self) -> None:
        payload = pr_review.build_llm_payload("gpt-4.1", "system", "diff")
        self.assertEqual(payload["temperature"], pr_review.DEFAULT_TEMPERATURE)


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
