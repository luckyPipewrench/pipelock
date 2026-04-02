#!/usr/bin/env python3
"""AI-powered PR review for Pipelock.

Triggered by /review comments on PRs. Supports multiple review modes:
  /review       - Security and correctness review (fast model)
  /review fast  - Same as /review
  /review deep  - Deeper review (large model)
  /review tests - Test coverage and boundary analysis
  /review docs  - Documentation accuracy check
  /review stats - Compare codebase stats against docs (no LLM)

Requires environment variables:
  GITHUB_TOKEN       - GitHub token (provided by Actions)
  REPO               - owner/repo
  PR_NUMBER          - PR number
  REVIEW_MODE        - "fast", "deep", "tests", "docs", or "stats"

LLM configuration (one of, not needed for /review stats):
  LITELLM_BASE_URL + LITELLM_API_KEY  - LiteLLM proxy
  OPENAI_API_KEY                       - Direct OpenAI API

Model selection:
  PR_REVIEW_MODEL_FAST  - Model for fast/tests/docs (default: gpt-5.4-mini)
  PR_REVIEW_MODEL_DEEP  - Model for /review deep (default: gpt-5.4)
"""

import json
import os
import re
import subprocess
import sys

import requests

# --- Constants ---

MAX_DIFF_CHARS = 100_000
DEFAULT_MODEL_FAST = "gpt-5.4-mini"
DEFAULT_MODEL_DEEP = "gpt-5.4"

PROMPT_SECURITY = """You are reviewing a pull request for Pipelock, an AI agent firewall and security boundary product. Pipelock is a network proxy that sits between AI agents and the internet, scanning HTTP/WebSocket/MCP traffic for secret exfiltration, prompt injection, SSRF, and tool poisoning.

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

PROMPT_TESTS = """You are reviewing the TEST COVERAGE of a pull request for Pipelock, an AI agent firewall.

For each code change in the diff, check:

1. **Boundary coverage**: If a range, threshold, or enum was added/changed, are both endpoints tested? Example: a Unicode range U+115F-U+1160 should have tests for both U+115F AND U+1160.
2. **Error paths**: If new error returns were added, do tests exercise them?
3. **Edge cases**: Empty input, nil/zero values, max-length input, Unicode edge cases.
4. **Negative tests**: If the code blocks/rejects something, is there a test proving it blocks?
5. **Transport parity**: If a scanning feature was added, is it tested on all applicable transports (fetch, forward, CONNECT, WebSocket, MCP)?
6. **Table-driven gaps**: If table-driven tests were extended, are the new entries sufficient?

Do NOT review code quality, style, or security. Focus exclusively on whether the tests adequately cover the code changes.

For each gap found:
1. severity: high (untested security path), medium (untested boundary), low (nice-to-have)
2. file and line
3. what specific test case is missing
4. a concrete test case to add (function name, input, expected output)

If test coverage is adequate, say exactly: Test coverage is adequate for this diff."""

PROMPT_DOCS = """You are reviewing a pull request for Pipelock for DOCUMENTATION ACCURACY.

Check every claim in the diff against the code:

1. **Stat accuracy**: Any number (pattern counts, test counts, dependency counts, metric counts, scenario counts) must match what the code actually produces. Flag mismatches.
2. **Feature claims**: If docs say "automatic" or "enforced", verify the code actually does it. Flag doc claims that only exist at the deployment layer.
3. **Config field names**: Verify field names in docs match the actual YAML config struct.
4. **Stale references**: Flag references to removed features, renamed fields, or old behavior.
5. **Internal consistency**: If the same stat appears in multiple places in the diff, flag if they disagree.

Do NOT review code quality or test coverage. Focus exclusively on whether documentation accurately reflects the code.

For each issue:
1. severity: high (wrong number/claim), medium (stale reference), low (unclear wording)
2. file and line
3. what it says vs what the code shows
4. the correct value with the source file

If documentation is accurate, say exactly: Documentation accurately reflects the codebase in this diff."""


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


def call_llm(diff: str, mode: str, system_prompt: str) -> str:
    """Send the diff to the LLM and return the review."""
    litellm_url = os.environ.get("LITELLM_BASE_URL", "")
    litellm_key = os.environ.get("LITELLM_API_KEY", "")
    openai_key = os.environ.get("OPENAI_API_KEY", "")

    if mode == "deep":
        model = os.environ.get("PR_REVIEW_MODEL_DEEP") or DEFAULT_MODEL_DEEP
    else:
        model = os.environ.get("PR_REVIEW_MODEL_FAST") or DEFAULT_MODEL_FAST

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
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": f"Review this pull request diff:\n\n```diff\n{diff}\n```",
            },
        ],
        "temperature": 0.2,
        "max_completion_tokens": 4096,
    }

    resp = requests.post(api_url, headers=headers, json=payload, timeout=120)
    if resp.status_code != 200:
        body = resp.text[:500]
        return f"**Error:** LLM API returned {resp.status_code}.\n\n**Model:** `{model}`\n\n**Response:**\n```\n{body}\n```"
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


# --- Stats checker (no LLM) ---

def run_stats_check() -> str:
    """Compare codebase stats against doc references. Returns markdown report."""
    findings = []

    # Get canonical counts from Go code.
    canonical = {}
    try:
        result = subprocess.run(
            ["go", "test", "-v", "-run", "TestGenerateStats", "./internal/config/"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                line = line.strip()
                if ":" in line and not line.startswith("#"):
                    key, _, val = line.partition(":")
                    val = val.strip()
                    if val.isdigit():
                        canonical[key.strip()] = int(val)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # If make stats didn't work, count manually.
    if "dlp_patterns" not in canonical:
        try:
            result = subprocess.run(
                ["grep", "-c", "Regex:", "internal/config/config.go"],
                capture_output=True, text=True, timeout=10,
            )
            canonical["dlp_patterns"] = int(result.stdout.strip())
        except (ValueError, subprocess.TimeoutExpired, FileNotFoundError):
            pass

    # Scan docs for stat claims.
    stat_patterns = [
        (r"(\d[\d,]*)\+?\s*(?:DLP|credential)\s*patterns?", "dlp_patterns"),
        (r"(\d[\d,]*)\+?\s*(?:response|injection)\s*patterns?", "response_patterns"),
        (r"(\d[\d,]*)\+?\s*Prometheus\s*metric", "prometheus_metrics"),
        (r"(\d[\d,]*)\+?\s*(?:direct\s*)?(?:Go\s*)?dep", "direct_deps"),
        (r"~?(\d+)\s*MB\b", "binary_size_mb"),
        (r"(\d[\d,]*)\+?\s*(?:built-in\s*)?(?:attack\s*)?scenarios?", "simulate_scenarios"),
        (r"(\d[\d,]*)\+?\s*(?:passing\s*)?tests?\b", "tests"),
        (r"(\d[\d,]*)\+?\s*(?:tool\s*)?policy\s*rules?", "tool_policy_rules"),
    ]

    doc_files = []
    for root, _, files in os.walk("."):
        if ".git" in root or "public" in root or "node_modules" in root:
            continue
        for f in files:
            if f.endswith((".md", ".html", ".yaml", ".yml")) and not f.startswith("."):
                doc_files.append(os.path.join(root, f))

    stat_refs = {}  # {(file, stat_name): claimed_value}
    for filepath in doc_files:
        try:
            with open(filepath, encoding="utf-8", errors="ignore") as fh:
                for i, line in enumerate(fh, 1):
                    for pattern, stat_name in stat_patterns:
                        for match in re.finditer(pattern, line, re.IGNORECASE):
                            raw = match.group(1).replace(",", "")
                            try:
                                val = int(raw)
                            except ValueError:
                                continue
                            key = (filepath, stat_name, i)
                            stat_refs[key] = val
        except OSError:
            continue

    # Fail closed: if we couldn't get any canonical stats, say so.
    if not canonical:
        findings.append(
            "- **Could not extract canonical stats from codebase.** "
            "`go test -run TestGenerateStats` and `grep` fallback both failed. "
            "Cross-reference check skipped."
        )

    # Compare canonical vs doc claims.
    for (filepath, stat_name, lineno), claimed in sorted(stat_refs.items()):
        if stat_name in canonical:
            actual = canonical[stat_name]
            if claimed != actual:
                findings.append(
                    f"- **{stat_name}**: `{filepath}:{lineno}` claims "
                    f"**{claimed}** but code has **{actual}**"
                )

    # Check for inconsistency across docs (same stat, different values).
    by_stat = {}
    for (filepath, stat_name, lineno), val in stat_refs.items():
        by_stat.setdefault(stat_name, []).append((val, filepath, lineno))

    for stat_name, refs in by_stat.items():
        values = set(v for v, _, _ in refs)
        if len(values) > 1:
            detail = ", ".join(f"`{f}:{ln}` = {v}" for v, f, ln in refs[:5])
            findings.append(
                f"- **{stat_name}** has inconsistent values across docs: {detail}"
            )

    if not findings:
        return "All stats are consistent across docs and match codebase values."

    return "### Stat Drift Found\n\n" + "\n".join(findings)


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("REPO", "")
    pr_number = os.environ.get("PR_NUMBER", "")
    mode = os.environ.get("REVIEW_MODE", "fast")

    if not all([token, repo, pr_number]):
        print("Missing required environment variables", file=sys.stderr)
        sys.exit(1)

    print(f"Reviewing PR #{pr_number} in {repo} (mode: {mode})")

    # Stats mode: no LLM, just scripting.
    if mode == "stats":
        report = run_stats_check()
        header = "## Stats Check (`/review stats`)\n\n---\n\n"
        post_comment(repo, pr_number, token, header + report)
        print("Stats check posted.")
        return

    # All other modes need the diff.
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

    # Select prompt.
    prompts = {
        "fast": PROMPT_SECURITY,
        "deep": PROMPT_SECURITY,
        "tests": PROMPT_TESTS,
        "docs": PROMPT_DOCS,
    }
    system_prompt = prompts.get(mode, PROMPT_SECURITY)

    try:
        review = call_llm(diff, mode, system_prompt)
    except requests.RequestException as e:
        post_comment(repo, pr_number, token, f"**AI Review Error:** LLM API call failed: {e}")
        sys.exit(1)

    model_name = (
        os.environ.get("PR_REVIEW_MODEL_DEEP" if mode == "deep" else "PR_REVIEW_MODEL_FAST")
        or (DEFAULT_MODEL_DEEP if mode == "deep" else DEFAULT_MODEL_FAST)
    )

    mode_labels = {
        "fast": "security",
        "deep": "security deep",
        "tests": "test coverage",
        "docs": "docs accuracy",
    }
    label = mode_labels.get(mode, mode)
    header = f"## AI Review: {label} (`/review {mode}`)\n\n**Model:** `{model_name}`\n\n---\n\n"
    post_comment(repo, pr_number, token, header + review)
    print("Review posted.")


if __name__ == "__main__":
    main()
