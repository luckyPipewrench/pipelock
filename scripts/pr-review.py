#!/usr/bin/env python3
"""AI-powered PR review for Pipelock.

Triggered by /review, /review fast, or /review deep comments on PRs.
Sends the PR diff to an LLM and posts the review as a single PR comment.

Requires environment variables:
  GITHUB_TOKEN       - GitHub token (provided by Actions)
  REPO               - owner/repo
  PR_NUMBER          - PR number
  REVIEW_MODE        - "fast" or "deep"

LLM configuration (one of):
  LITELLM_BASE_URL + LITELLM_API_KEY  - LiteLLM proxy
  OPENAI_API_KEY                       - Direct OpenAI API

Model selection:
  PR_REVIEW_MODEL_FAST  - Model for /review and /review fast (default: gpt-4.1-mini)
  PR_REVIEW_MODEL_DEEP  - Model for /review deep (default: gpt-4.1)
"""

import json
import os
import sys

import requests

# --- Constants ---

MAX_DIFF_CHARS = 100_000  # ~25k tokens, keeps costs reasonable
DEFAULT_MODEL_FAST = "gpt-5.4-nano"
DEFAULT_MODEL_DEEP = "gpt-5.4"

SYSTEM_PROMPT = """You are reviewing a pull request for Pipelock, an AI agent firewall and security boundary product. Pipelock is a network proxy that sits between AI agents and the internet, scanning HTTP/WebSocket/MCP traffic for secret exfiltration, prompt injection, SSRF, and tool poisoning.

Focus only on issues that materially affect security, correctness, enforcement integrity, privilege boundaries, auditability, or operational safety.

Flag:
- anything that weakens isolation or sandbox boundaries
- implicit trust of model output
- unsafe handling of tool inputs or tool outputs
- auth, policy, or permission bypass risk
- race conditions or ordering bugs in enforcement paths
- missing validation, escaping, or normalization where untrusted data crosses boundaries
- logging or audit gaps that would make incidents hard to investigate
- changes that make prompt injection or malicious content more likely to escape controls

Do not waste time on style nits or trivial suggestions.
Be direct and specific.
For each finding, include:
1. severity: high, medium, or low
2. file and function or section
3. why it matters
4. a concrete fix or safer pattern

If there are no material issues, say exactly: No material security or correctness issues found in this diff."""


def get_pr_diff(repo: str, pr_number: str, token: str) -> str:
    """Fetch the PR diff from GitHub."""
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3.diff",
    }
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.text


def truncate_diff(diff: str, max_chars: int = MAX_DIFF_CHARS) -> str:
    """Truncate diff to stay within token limits."""
    if len(diff) <= max_chars:
        return diff
    truncated = diff[:max_chars]
    return truncated + f"\n\n... (diff truncated at {max_chars} chars, {len(diff)} total)"


def call_llm(diff: str, mode: str) -> str:
    """Send the diff to the LLM and return the review."""
    litellm_url = os.environ.get("LITELLM_BASE_URL", "")
    litellm_key = os.environ.get("LITELLM_API_KEY", "")
    openai_key = os.environ.get("OPENAI_API_KEY", "")

    # Pick model based on mode.
    if mode == "deep":
        model = os.environ.get("PR_REVIEW_MODEL_DEEP", DEFAULT_MODEL_DEEP)
    else:
        model = os.environ.get("PR_REVIEW_MODEL_FAST", DEFAULT_MODEL_FAST)

    # Prefer LiteLLM if configured, fall back to OpenAI.
    if litellm_url and litellm_key:
        api_url = litellm_url.rstrip("/") + "/chat/completions"
        api_key = litellm_key
    elif openai_key:
        api_url = "https://api.openai.com/v1/chat/completions"
        api_key = openai_key
    else:
        return "**Error:** No LLM API configured. Set LITELLM_BASE_URL + LITELLM_API_KEY or OPENAI_API_KEY in repo secrets."

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"Review this pull request diff:\n\n```diff\n{diff}\n```",
            },
        ],
        "temperature": 0.2,
        "max_tokens": 4096,
    }

    resp = requests.post(api_url, headers=headers, json=payload, timeout=120)
    resp.raise_for_status()
    data = resp.json()
    choices = data.get("choices", [])
    if not choices:
        return "**Error:** LLM returned no choices. Raw response: " + json.dumps(data)[:500]
    message = choices[0].get("message", {})
    content = message.get("content", "")
    if not content:
        return "**Error:** LLM returned empty content."
    return content


def post_comment(repo: str, pr_number: str, token: str, body: str) -> None:
    """Post a comment on the PR."""
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
    }
    resp = requests.post(url, headers=headers, json={"body": body}, timeout=30)
    resp.raise_for_status()


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("REPO", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    mode = os.environ.get("REVIEW_MODE", "fast")

    if not all([token, repo, pr_number]):
        print("Missing required environment variables", file=sys.stderr)
        sys.exit(1)

    print(f"Reviewing PR #{pr_number} in {repo} (mode: {mode})")

    # Fetch diff.
    try:
        diff = get_pr_diff(repo, pr_number, token)
    except requests.RequestException as e:
        post_comment(repo, pr_number, token, f"**AI Review Error:** Failed to fetch PR diff: {e}")
        sys.exit(1)

    if not diff.strip():
        post_comment(repo, pr_number, token, "**AI Review:** No diff found for this PR.")
        return

    diff = truncate_diff(diff)
    print(f"Diff size: {len(diff)} chars")

    # Call LLM.
    try:
        review = call_llm(diff, mode)
    except requests.RequestException as e:
        post_comment(repo, pr_number, token, f"**AI Review Error:** LLM API call failed: {e}")
        sys.exit(1)

    # Post review.
    model_name = os.environ.get(
        "PR_REVIEW_MODEL_DEEP" if mode == "deep" else "PR_REVIEW_MODEL_FAST",
        DEFAULT_MODEL_DEEP if mode == "deep" else DEFAULT_MODEL_FAST,
    )
    header = f"## AI Security Review (`/review {mode}`)\n\n**Model:** `{model_name}`\n\n---\n\n"
    post_comment(repo, pr_number, token, header + review)
    print("Review posted.")


if __name__ == "__main__":
    main()
