# AI PR Review

Manual-trigger AI security review for pull requests. Comment `/review` on any PR to get a focused security review.

## Trigger Commands

| Command | Model | Use When |
|---------|-------|----------|
| `/review` | Efficient (default: gpt-5.6-luna, low reasoning) | Quick check, most PRs |
| `/review deep` | Balanced (default: gpt-5.6-terra, medium reasoning) | Complex changes, security-sensitive code |

## What It Reviews

The reviewer is tuned for Pipelock's security model. It flags:

- Weakened isolation or sandbox boundaries
- Implicit trust of model output
- Unsafe tool input/output handling
- Auth, policy, or permission bypass risk
- Race conditions in enforcement paths
- Missing validation where untrusted data crosses boundaries
- Logging or audit gaps
- Prompt injection escape vectors

It ignores style nits and generic suggestions. If nothing is wrong, it says so explicitly.

## Setup

### Required GitHub Secrets

Set these in **Settings > Secrets and variables > Actions**:

| Secret | Required | Description |
|--------|----------|-------------|
| `LITELLM_BASE_URL` | If using LiteLLM | Your LiteLLM proxy URL (e.g., `https://litellm.example.com/v1`) |
| `LITELLM_API_KEY` | If using LiteLLM | API key for LiteLLM proxy |
| `OPENAI_API_KEY` | If not using LiteLLM | Direct OpenAI API key (fallback) |

`GITHUB_TOKEN` is provided automatically by GitHub Actions.

### Optional GitHub Variables

Set these in **Settings > Secrets and variables > Actions > Variables** only
when intentionally overriding the reviewed defaults:

| Variable | Default | Used By |
|----------|---------|---------|
| `PR_REVIEW_MODEL_FAST` | `gpt-5.6-luna` | `/review`, `/review tests`, `/review docs` |
| `PR_REVIEW_MODEL_DEEP` | `gpt-5.6-terra` | `/review deep` |

The defaults live in `scripts/pr-review.py`; the workflow passes optional
repository variables through without maintaining another copy.

### LiteLLM vs Direct OpenAI

**LiteLLM (preferred):** Set `LITELLM_BASE_URL` and `LITELLM_API_KEY`. Point at whatever upstream model you want (OpenAI, Anthropic, local). The script sends OpenAI-compatible requests to your LiteLLM proxy.

**Direct OpenAI (fallback):** Set only `OPENAI_API_KEY`. The script calls `api.openai.com` directly.

If both are set, LiteLLM takes priority.

### Switching Models

Override the model via repository variables:

```text
PR_REVIEW_MODEL_FAST=gpt-5.6-luna
PR_REVIEW_MODEL_DEEP=gpt-5.6-terra
```

With LiteLLM, use any model your proxy supports:

```
PR_REVIEW_MODEL_DEEP=anthropic/claude-sonnet-4-20250514
PR_REVIEW_MODEL_FAST=groq/llama-3.3-70b-versatile
```

## Cost Control

- Only runs when manually triggered (no auto-review on push)
- Diff is truncated to ~100k chars (~25k tokens) to cap costs
- `/review` uses the efficient model by default
- `/review deep` is opt-in for thorough analysis

## Files

| File | What |
|------|------|
| `.github/workflows/pr-review.yaml` | GitHub Actions workflow |
| `scripts/pr-review.py` | Review script (fetches diff, calls LLM, posts comment) |
