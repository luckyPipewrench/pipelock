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


if __name__ == "__main__":
    unittest.main()
