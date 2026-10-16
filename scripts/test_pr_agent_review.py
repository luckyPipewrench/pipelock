# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Admission, spending, and failure contracts for the separate review command."""

from __future__ import annotations

import asyncio
import copy
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock

import yaml

from scripts import pr_agent_review as review

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = yaml.load((ROOT / ".github/workflows/agent-review.yaml").read_text(), Loader=yaml.BaseLoader)
HAIKU = "anthropic/claude-haiku-5-5"
OPENAI = "gpt-6-luna"


def admitted(gate, event):
    for term in gate.split("&&"):
        match = re.fullmatch(r"\s*(github\.[\w.]+)(?:\s*==\s*(?:'([^']*)'|(\d+)))?\s*", term)
        if not match:
            raise AssertionError("Unexpected admission expression")
        key, text, number = match.groups()
        actual = event.get(key)
        if text is not None and actual != text:
            return False
        if number is not None and actual != int(number):
            return False
        if text is None and number is None and not actual:
            return False
    return True


def billing(status=400, body=None):
    error = RuntimeError("provider detail must not be logged")
    error.status_code = status
    error.body = body if body is not None else {"error": {
        "type": "invalid_request_error", "message": "Your credit balance is too low to access the API."
    }}
    return error


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.gate = WORKFLOW["jobs"]["admit"]["if"]
        self.event = {
            "github.actor": "luckyPipewrench", "github.actor_id": "142104046",
            "github.run_attempt": "1", "github.triggering_actor": "luckyPipewrench",
            "github.event.comment.user.login": "luckyPipewrench",
            "github.event.comment.user.id": 142104046,
            "github.event.comment.user.type": "User",
            "github.event.comment.author_association": "MEMBER",
            "github.event.issue.pull_request": {"url": "https://api.github.com/repos/example/project/pulls/1"},
            "github.event.comment.body": "/agent-review",
        }

    def test_gate_accepts_only_exact_identity_and_command(self):
        self.assertTrue(admitted(self.gate, self.event))
        attacks = {
            "github.actor": "contributor", "github.actor_id": "123",
            "github.run_attempt": "2", "github.triggering_actor": "contributor",
            "github.event.comment.user.login": "contributor",
            "github.event.comment.user.id": 123,
            "github.event.comment.user.type": "Bot",
            "github.event.comment.author_association": "CONTRIBUTOR",
            "github.event.issue.pull_request": None,
        }
        for key, value in attacks.items():
            with self.subTest(key=key):
                event = dict(self.event, **{key: value})
                self.assertFalse(admitted(self.gate, event))
        for body in ("/review", "/review deep", "/agent-review deep", "/agent-review\n", " /agent-review", "/agent-review --config.model=other"):
            with self.subTest(body=body):
                self.assertFalse(admitted(self.gate, dict(self.event, **{"github.event.comment.body": body})))

    def test_gate_mutation_exposes_renamed_login_attack(self):
        event = dict(self.event, **{"github.event.comment.user.id": 123})
        broken = self.gate.replace("github.event.comment.user.id == 142104046 &&", "")
        self.assertFalse(admitted(self.gate, event))
        self.assertTrue(admitted(broken, event))

    def test_created_comments_only_and_secret_isolation(self):
        self.assertEqual({"issue_comment": {"types": ["created"]}}, WORKFLOW["on"])
        self.assertEqual({}, WORKFLOW["permissions"])
        admit = WORKFLOW["jobs"]["admit"]
        self.assertEqual({"pull-requests": "read"}, admit["permissions"])
        self.assertNotIn("secrets.", json.dumps(admit))
        job = WORKFLOW["jobs"]["review"]
        self.assertEqual("admit", job["needs"])
        self.assertEqual("needs.admit.outputs.admitted == 'true'", job["if"])
        self.assertRegex(job["container"]["image"], r"^pragent/pr-agent:0\.47\.0@sha256:[0-9a-f]{64}$")
        self.assertNotIn("env", job)
        checkout, run = job["steps"]
        self.assertEqual("${{ github.workflow_sha }}", checkout["with"]["ref"])
        self.assertEqual("false", checkout["with"]["persist-credentials"])
        self.assertNotIn("secrets.", json.dumps(checkout))
        self.assertEqual("python scripts/pr_agent_review.py", run["run"])
        self.assertNotIn("comment.body", json.dumps(run))

    def test_container_keeps_hardening_and_uses_hosted_runner_uid(self):
        job = WORKFLOW["jobs"]["review"]
        # Hosted Ubuntu's runner UID is documented by actions/runner-images#10936.
        self.assertEqual("ubuntu-latest", job["runs-on"])
        self.assertCountEqual([
            "--user", "1001:1001", "--cap-drop=ALL", "--security-opt=no-new-privileges",
        ], shlex.split(job["container"]["options"]))
        self.assertEqual({"contents": "read", "issues": "write", "pull-requests": "write"},
                         job["permissions"])

    @unittest.skipUnless(shutil.which("jq"), "jq required to run the admission step")
    def test_admission_step_outputs_only_valid_same_repository_commits(self):
        script = WORKFLOW["jobs"]["admit"]["steps"][0]["run"]
        pr = {"state": "open", "head": {"repo": {"fork": False, "full_name": "example/project"},
                                            "sha": "a" * 40},
              "base": {"repo": {"full_name": "example/project"}, "sha": "b" * 40}}
        cases = [(pr, True)]
        for section, key, value in (("head", "sha", "invalid"), ("base", "sha", None),
                                    ("head", "repo", None),
                                    ("base", "repo", {"full_name": "other/project"}),
                                    ("head", "repo", {"fork": True, "full_name": "example/project"})):
            invalid = copy.deepcopy(pr)
            invalid[section][key] = value
            cases.append((invalid, False))
        cases.append((dict(pr, state="closed"), False))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            gh = root / "gh"
            gh.write_text('#!/bin/sh\n[ "$1" = api ] && [ "$2" = repos/example/project/pulls/1 ] || exit 2\n'
                          'cat "$PR_FIXTURE"\nexit "${API_EXIT:-0}"\n')
            gh.chmod(0o700)
            fixture, output = root / "pr.json", root / "output"
            env = dict(os.environ, PATH=f"{root}:{os.environ['PATH']}", PR_FIXTURE=str(fixture),
                       GITHUB_REPOSITORY="example/project", PR_NUMBER="1", GITHUB_OUTPUT=str(output))
            for data, expected in cases:
                with self.subTest(pr=data):
                    fixture.write_text(json.dumps(data))
                    output.write_text("")
                    result = subprocess.run(["bash", "-c", script], env=env, capture_output=True,
                                            text=True, timeout=10, check=False)
                    wanted = f"admitted=true\nhead={'a' * 40}\nbase={'b' * 40}\n" if expected else ""
                    self.assertEqual(wanted, output.read_text(), result.stderr)
                    if expected:
                        self.assertEqual(0, result.returncode, result.stderr)
            fixture.write_text(json.dumps(pr))
            output.write_text("")
            result = subprocess.run(["bash", "-c", script], env=dict(env, API_EXIT="1"),
                                    capture_output=True, text=True, timeout=10, check=False)
            self.assertNotEqual(0, result.returncode)
            self.assertEqual("", output.read_text())

    @unittest.skipUnless(shutil.which("jq"), "jq required to exercise the workflow's actual fork predicate")
    def test_actual_jq_fork_predicate(self):
        script = WORKFLOW["jobs"]["admit"]["steps"][0]["run"]
        predicate = re.search(r"--arg repo .*? '(.*?)' <<<", script, re.S).group(1)
        pr = {"state": "open", "head": {"repo": {"fork": False, "full_name": "example/project"}},
              "base": {"repo": {"full_name": "example/project"}}}
        cases = [pr]
        for path, value in (("fork", True), ("full_name", "contributor/project")):
            attack = copy.deepcopy(pr)
            attack["head"]["repo"][path] = value
            cases.append(attack)
        cases.extend([dict(pr, state="closed"), dict(pr, head={"repo": None})])
        for i, case in enumerate(cases):
            result = subprocess.run(["jq", "-e", "--arg", "repo", "example/project", predicate],
                                    input=json.dumps(case), capture_output=True, text=True, check=False)
            self.assertEqual(i == 0, result.returncode == 0, result.stderr)


class CompletionTests(unittest.IsolatedAsyncioTestCase):
    async def test_absent_anthropic_skips_both_slots_without_spend(self):
        slots = review.credential_chain([HAIKU, OPENAI], {"OPENAI_API_KEY": "fixture", "ANTHROPIC_API_KEY_2": "unused"})
        self.assertEqual([(OPENAI, "OPENAI_API_KEY")], slots)
        complete = AsyncMock(return_value=("result", "stop"))
        router = review.CompletionChain(slots, complete, 2)
        await router.run("system", "untrusted diff", 0.2, None)
        complete.assert_awaited_once_with(OPENAI, "OPENAI_API_KEY", "system", "untrusted diff", 0.2, None)
        self.assertEqual([], review.credential_chain([HAIKU, OPENAI], {}))

    async def test_billing_rotates_two_slots_then_provider_and_retires_slots(self):
        complete = AsyncMock(side_effect=[billing(), billing(), ("result", "stop"), ("result", "stop")])
        chain = [(HAIKU, "one"), (HAIKU, "two"), (OPENAI, "fallback")]
        router = review.CompletionChain(chain, complete, 2)
        await router.run()
        await router.run()
        self.assertEqual(chain + [chain[-1]], [tuple(c.args) for c in complete.await_args_list])
        with self.assertRaises(review.ReviewAbort):
            await router.run()
        self.assertEqual(4, complete.await_count)

    async def test_timeout_rate_limit_auth_unknown_and_truncation_never_retry(self):
        for result in (TimeoutError(), billing(429, {"error": {"code": "rate_limit_exceeded"}}),
                       billing(401), RuntimeError("unknown"), ("partial", "length"), ("", "content_filter")):
            with self.subTest(result=result):
                complete = AsyncMock(side_effect=result) if isinstance(result, Exception) else AsyncMock(return_value=result)
                router = review.CompletionChain([(HAIKU, "one"), (OPENAI, "two")], complete, 2)
                with self.assertRaises(review.ReviewAbort):
                    await router.run()
                self.assertEqual(1, complete.await_count)

    async def test_concurrent_chunks_share_budget_and_slot_retirement(self):
        complete = AsyncMock(side_effect=[billing(), ("a", "stop"), ("b", "stop")])
        router = review.CompletionChain([(HAIKU, "one"), (OPENAI, "two")], complete, 2)
        self.assertEqual([("a", "stop"), ("b", "stop")], await asyncio.gather(router.run(), router.run()))
        self.assertEqual([HAIKU, OPENAI, OPENAI], [c.args[0] for c in complete.await_args_list])

    async def test_failure_stops_queued_chunks_before_another_request(self):
        complete = AsyncMock(side_effect=[("partial", "length"), ("b", "stop")])
        router = review.CompletionChain([(HAIKU, "one")], complete, 3)
        results = await asyncio.gather(router.run(), router.run(), return_exceptions=True)
        self.assertTrue(all(isinstance(r, review.ReviewAbort) for r in results))
        self.assertEqual(1, complete.await_count)

    async def test_exhaustion_is_failure(self):
        router = review.CompletionChain([(HAIKU, "one")], AsyncMock(side_effect=billing()), 2)
        with self.assertRaises(review.ReviewAbort):
            await router.run()


class ResultTests(unittest.TestCase):
    def test_only_structured_billing_errors_allow_fallback(self):
        self.assertTrue(review.billing_rejection(billing()))
        self.assertTrue(review.billing_rejection(billing(402, {"error": {"type": "billing_error", "message": "Spend limit reached"}})))
        self.assertTrue(review.billing_rejection(billing(429, {"error": {"code": "insufficient_quota"}})))
        for error in (TimeoutError("credit balance is too low"), billing(500), billing(400, "credit balance is too low"),
                      billing(400, {"error": {"type": "invalid_request_error", "message": "bad model"}})):
            self.assertFalse(review.billing_rejection(error))
        timeout = TimeoutError("ambiguous")
        timeout.__context__ = billing()
        self.assertFalse(review.billing_rejection(timeout))

    def test_stale_base_head_fork_and_closed_pr_block_publication(self):
        repo = "example/project"
        pr = NS(state="open", head=NS(repo=NS(full_name=repo, fork=False), sha="head"),
                base=NS(repo=NS(full_name=repo), sha="base"))
        review.check_pull_request(pr, repo, "head", "base")
        for section, field, value in (("head", "sha", "moved"), ("base", "sha", "moved"),
                                      ("head", "repo", NS(full_name=repo, fork=True))):
            broken = copy.deepcopy(pr)
            setattr(getattr(broken, section), field, value)
            with self.assertRaises(review.ReviewAbort):
                review.check_pull_request(broken, repo, "head", "base")
        pr.state = "closed"
        with self.assertRaises(review.ReviewAbort):
            review.check_pull_request(pr, repo, "head", "base")

    def test_empty_omitted_partial_and_swallowed_error_cannot_be_green(self):
        good = NS(prediction="result", review_failed_chunk_count=0, remaining_files_list=[])
        review.check_complete(good, 1, False)
        for field, value in (("prediction", None), ("review_failed_chunk_count", 1), ("remaining_files_list", ["omitted.go"])):
            broken = copy.deepcopy(good)
            setattr(broken, field, value)
            with self.assertRaises(review.ReviewAbort):
                review.check_complete(broken, 1, False)
        for calls, failed in ((0, False), (1, True)):
            with self.assertRaises(review.ReviewAbort):
                review.check_complete(good, calls, failed)

    def test_trusted_config_disables_untrusted_instructions_and_side_effects(self):
        config = tomllib.loads(review.CONFIG.read_text())
        self.assertFalse(config["config"]["use_repo_settings_file"])
        self.assertFalse(config["config"]["use_global_settings_file"])
        self.assertEqual([], config["config"]["repo_context_files"])
        self.assertTrue(config["pr_reviewer"]["inline_key_issues"])
        self.assertFalse(config["otel"]["is_enabled"])
        self.assertFalse(config["skills"]["enabled"])
        self.assertFalse(config["artifacts"]["enable"])


if __name__ == "__main__":
    unittest.main()
