# Copyright 2026 Pipelock contributors
# SPDX-License-Identifier: Apache-2.0

"""Trusted PR-Agent adapter: explicit review, bounded calls, billing-only fallback."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import tomllib
from pathlib import Path
from unittest.mock import patch

CONFIG = Path(__file__).resolve().parents[1] / ".github" / "pr-agent.toml"


class ReviewAbort(BaseException):
    """Bypass upstream's broad retry/partial-result handlers after an unsafe failure."""


def billing_rejection(error: Exception) -> bool:
    """Accept explicit provider billing signals, never a timeout or bare HTTP 429.

    Anthropic's SDK defines billing_error; PR-Agent recognizes the legacy credit
    message. OpenAI uses insufficient_quota. Never inspect formatted log strings.
    LiteLLM 1.103.0 drops Anthropic bodies during mapping, so inspect the original
    HTTP response in the exception chain (http_handler.MaskedHTTPStatusError).
    """
    seen, errors = set(), []
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        # A timeout remains ambiguous even if another exception is attached.
        if (isinstance(error, TimeoutError) or "timeout" in type(error).__name__.lower()
                or getattr(error, "status_code", None) in (408, 504)):
            return False
        errors.append(error)
        error = error.__cause__ or error.__context__
    for error in errors:
        response = getattr(error, "response", None)
        status = getattr(error, "status_code", getattr(response, "status_code", None))
        if status not in (400, 402, 429):
            continue
        body = getattr(error, "body", None)
        if not isinstance(body, dict) and response is not None:
            try:
                body = response.json()
            except (ValueError, RuntimeError):
                continue
        if not isinstance(body, dict):
            continue
        detail = body.get("error", body)
        if not isinstance(detail, dict):
            continue
        if detail.get("type") == "billing_error" or detail.get("code") == "insufficient_quota":
            return True
        if (detail.get("type") == "invalid_request_error"
                and "credit balance is too low" in str(detail.get("message", "")).lower()):
            return True
    return False


async def deny_transport_retry(*args, **kwargs):
    # LiteLLM's HTTP handler retries RemoteProtocolError/ConnectError independently
    # of num_retries. This pinned method is called only from those retry branches.
    raise ReviewAbort("Connection failed; ambiguous requests are never retried")


def credential_chain(models: list[str], credentials: dict[str, str]) -> list[tuple[str, str]]:
    """Skip absent providers before inference; slot two requires slot one rejection."""
    chain = []
    for model in models:
        if model.startswith("anthropic/"):
            if credentials.get("ANTHROPIC_API_KEY"):
                chain.append((model, "ANTHROPIC_API_KEY"))
                if credentials.get("ANTHROPIC_API_KEY_2"):
                    chain.append((model, "ANTHROPIC_API_KEY_2"))
        elif model.startswith(("gpt-", "openai/")):
            if credentials.get("OPENAI_API_KEY"):
                chain.append((model, "OPENAI_API_KEY"))
        else:
            raise ValueError("Configure an Anthropic or OpenAI model for this adapter")
    return list(dict.fromkeys(chain))


def check_pull_request(pr, repo, head, base):
    if (pr.state != "open" or pr.head.repo.full_name != repo or pr.head.repo.fork
            or pr.base.repo.full_name != repo or pr.head.sha != head or pr.base.sha != base):
        raise ReviewAbort("Pull request moved or became ineligible; post a new command")


def check_complete(reviewer, calls, failed):
    if (failed or not reviewer.prediction or not calls
            or reviewer.review_failed_chunk_count or reviewer.remaining_files_list):
        raise ReviewAbort("Review incomplete; inspect the coverage footer and workflow log")


class CompletionChain:
    def __init__(self, chain, complete, max_calls):
        self.chain = list(chain)
        self.complete = complete
        self.max_calls = max_calls
        self.calls = 0
        self.index = 0
        self.aborted = False
        self.lock = asyncio.Lock()

    async def run(self, *args):
        # Upstream chunks run concurrently. Serialize so rejected slots stay retired
        # and the aggregate call limit cannot race. Upstream gather does not cancel
        # sibling chunks, so the first failure must stop every queued request.
        async with self.lock:
            if self.aborted:
                raise ReviewAbort("Review already failed; no further provider requests")
            try:
                return await self._run_locked(*args)
            except BaseException:
                self.aborted = True
                raise

    async def _run_locked(self, *args):
        if self.calls >= self.max_calls:
            raise ReviewAbort("Completion budget exceeded")
        while self.index < len(self.chain):
            model, slot = self.chain[self.index]
            try:
                result = await self.complete(model, slot, *args)
            except Exception as error:
                if billing_rejection(error):
                    self.index += 1
                    continue
                raise ReviewAbort("Provider failed; ambiguous requests are never retried") from None
            if result[1] not in ("stop", "end_turn"):
                raise ReviewAbort("Provider returned an incomplete completion")
            self.calls += 1
            print(f"Completed review call {self.calls} with {model}")
            return result
        raise ReviewAbort("Configured provider credits exhausted")


def configure():
    # Set before importing LiteLLM: its default import can fetch mutable metadata.
    os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
    os.environ["OTEL_SDK_DISABLED"] = "true"
    import litellm
    from pr_agent.config_loader import get_settings
    from pr_agent.log import get_logger

    # Upstream exception logging may include request/response text. Emit only
    # our fixed status messages and allowlisted metadata, never upstream logs.
    get_logger().remove()
    settings = get_settings()
    data = tomllib.loads(CONFIG.read_text(encoding="utf-8"))
    for section, entries in data.items():
        for key, value in entries.items():
            settings.set(f"{section}.{key}", value)
    # Provider registration supplies routing metadata only. The operator's token
    # ceiling above controls budgeting; it is not the model's advertised context.
    litellm.register_model({"gpt-6-luna": {
        "litellm_provider": "openai", "mode": "chat",
        "supports_system_messages": True,
    }})
    litellm.telemetry = False
    litellm.suppress_debug_info = True
    litellm.redact_messages_in_exceptions = True
    return settings, litellm


def print_settings(settings, litellm):
    models = [settings.config.model, *settings.config.fallback_models]
    # Allowlisted non-secret fields only; never dump the full Dynaconf settings.
    print(json.dumps({
        "model": models[0], "fallback_models": models[1:],
        "routes": {m: litellm.get_llm_provider(m)[:2] for m in models},
        "inline_key_issues": settings.pr_reviewer.inline_key_issues,
        "persistent_comment": settings.pr_reviewer.persistent_comment,
        "security_review": settings.pr_reviewer.require_security_review,
        "max_findings": settings.pr_reviewer.num_max_findings,
        "max_model_tokens": settings.config.max_model_tokens,
        "max_output_tokens": settings.config.max_output_tokens,
        "max_calls": settings.pr_reviewer.max_number_of_calls,
        "repo_settings": settings.config.use_repo_settings_file,
        "telemetry": settings.otel.is_enabled,
    }, sort_keys=True))


async def review(settings):
    from pr_agent.algo.ai_handlers.litellm_ai_handler import LiteLLMAIHandler
    from pr_agent.algo.run_details import command_failed
    from pr_agent.tools.pr_reviewer import PRReviewer
    from tenacity import stop_after_attempt
    from litellm.llms.custom_httpx.http_handler import AsyncHTTPHandler

    credentials = {name: os.environ.pop(name, "") for name in (
        "ANTHROPIC_API_KEY", "ANTHROPIC_API_KEY_2", "OPENAI_API_KEY",
    )}
    models = [settings.config.model, *settings.config.fallback_models]
    chain = credential_chain(models, credentials)
    if not chain:
        raise ReviewAbort("No configured provider credential is available")
    settings.set("config.model", chain[0][0])
    # Preserve the configured order in our per-completion chain. Upstream's
    # fallback would also retry timeouts and may repeat already successful chunks.
    settings.set("config.fallback_models", [])
    settings.set("github.user_token", os.environ.pop("GITHUB_TOKEN"))
    settings.set("github.deployment_type", "user")
    repo = os.environ["GITHUB_REPOSITORY"]
    number = os.environ["PR_NUMBER"]
    head, base = os.environ["REVIEW_HEAD"], os.environ["REVIEW_BASE"]
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)
            or not re.fullmatch(r"[1-9][0-9]*", number)
            or not all(re.fullmatch(r"[0-9a-f]{40}", sha) for sha in (head, base))):
        raise ReviewAbort("Invalid admitted pull request identity")

    async def complete(model, slot, system, user, temperature, image):
        if image:
            raise ReviewAbort("Images are outside the static-diff review contract")
        settings.set("anthropic.key", credentials[slot] if slot.startswith("ANTHROPIC") else "")
        settings.set("openai.key", credentials[slot] if slot == "OPENAI_API_KEY" else "")
        handler = LiteLLMAIHandler()
        # Tenacity's supported retry_with API disables the upstream handler's
        # same-model retries; config.num_retries disables completion-client retries.
        once = handler._chat_completion_with_retry.retry_with(stop=stop_after_attempt(1))
        with patch.object(AsyncHTTPHandler, "single_connection_post_request", deny_transport_retry):
            return await once(handler, model, system, user, temperature, image,
                              configured_deployment_id=handler.deployment_id)

    router = CompletionChain(chain, complete, settings.pr_reviewer.max_number_of_calls)

    class Handler:
        main_pr_language = ""

        async def chat_completion(self, model, system, user, temperature=0.2, img_path=None):
            return await router.run(system, user, temperature, img_path)

    class Reviewer(PRReviewer):
        def check_binding(self, fresh=False):
            provider = self.git_provider
            pr = provider.github_client.get_repo(repo).get_pull(int(number)) if fresh else provider.pr
            check_pull_request(pr, repo, head, base)

        def _prepare_pr_review(self):
            self.check_binding(fresh=True)
            data = self.prediction_data if self.prediction_data is not None else self._load_review_yaml(self.prediction)
            if not self._validate_review_schema(data):
                raise ReviewAbort("Provider returned an invalid review schema")
            result = super()._prepare_pr_review()
            if not result:
                raise ReviewAbort("Provider returned an invalid review")
            return result + f"\n\nReviewed base `{base}` and head `{head}`."

    reviewer = Reviewer(f"https://github.com/{repo}/pull/{number}", ai_handler=Handler)
    reviewer.check_binding()
    try:
        await reviewer.run()
    except Exception as error:
        # Upstream raises generic exceptions, for example after an unparseable
        # prediction. Report only the class; the message can carry model output.
        raise ReviewAbort(f"PR-Agent review failed ({type(error).__name__})") from None
    check_complete(reviewer, router.calls, command_failed())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args()
    try:
        settings, litellm = configure()
        print_settings(settings, litellm)
        if not args.check_config:
            asyncio.run(review(settings))
    except (ReviewAbort, Exception) as error:
        # Provider exception messages can echo requests or credentials. Report a
        # fixed failure class; only our own ReviewAbort messages are safe to show.
        message = str(error) if isinstance(error, ReviewAbort) else type(error).__name__
        print(f"Review failed: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
