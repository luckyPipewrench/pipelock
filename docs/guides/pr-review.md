# AI PR Review

Manual-trigger AI security review for pull requests. Comment `/review` on any PR to get a focused security review.

## Trigger Commands

| Command | Model | Use When |
|---------|-------|----------|
| `/review` | Efficient (default: gpt-5.6-luna, low reasoning) | Quick check, most PRs |
| `/review deep` | Balanced (default: gpt-5.6-terra, xhigh reasoning) | Adversarial static-diff review (findings-first) |

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

It ignores style nits and generic suggestions. `/review deep` adds the
adversarial rubric for state transitions, failure direction, blast radius, test
vacuity, self-produced artifacts, and availability. The core security and
correctness rubric always runs, including for test-heavy or documentation-heavy
diffs.

The runner binds the review to the PR's captured base and head SHAs, reviewer
source SHA, and rubric version. It fetches the comparison by those exact commits
and marks the result `superseded` if the head changes before finalization. It
uses deterministic token budgeting instead of character slicing: Go source and
additions rank above tests, configuration, and documentation. The final comment
contains an omission manifest and never reports `clean` when a unit was omitted,
collapsed, unparseable, or left without a valid structured result.

Each run creates one bot-owned status comment and edits it in place. The runner
uses strict JSON output, a cross-file synthesis pass, and a second actual-code
judge pass before publishing findings. It strips mentions and command-shaped
text from model-supplied fields.

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
| `PR_REVIEW_MODEL_FAST` | `gpt-5.6-luna` | `/review` |
| `PR_REVIEW_MODEL_DEEP` | `gpt-5.6-terra` | `/review deep` |

The defaults live in `.github/actions/pr-review/pr_review.py`; the composite
action passes optional repository variables through without maintaining another
copy.

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
- Never retries an ambiguous provider timeout, which could double-spend
- Splits by complete hunks and explicit token budgets, never a character slice
- `/review` uses the efficient model by default
- `/review deep` is opt-in for the xhigh adversarial pass

## Reusing the reviewer in another repository

Copy this workflow stub and replace both occurrences of
`PINNED_PIPELOCK_REVIEW_COMMIT_SHA` with the same full, immutable Pipelock
commit SHA. Do not use a branch or tag. Personal-account repositories must map
each named secret explicitly; `secrets: inherit` is not available here.

```yaml
name: AI PR Review

on:
  issue_comment:
    types: [created]

permissions:
  contents: read
  issues: write
  pull-requests: write

jobs:
  review:
    if: >-
      github.event.comment.user.login == 'luckyPipewrench' &&
      github.event.comment.author_association == 'OWNER' &&
      github.event.issue.pull_request &&
      (github.event.comment.body == '/review' ||
       github.event.comment.body == '/review deep')
    uses: luckyPipewrench/pipelock/.github/workflows/pr-review-reusable.yaml@PINNED_PIPELOCK_REVIEW_COMMIT_SHA
    with:
      pr_number: ${{ github.event.issue.number }}
      review_mode: ${{ github.event.comment.body == '/review deep' && 'deep' || 'default' }}
      reviewer_sha: PINNED_PIPELOCK_REVIEW_COMMIT_SHA
    secrets:
      review_token: ${{ secrets.GITHUB_TOKEN }}
      litellm_base_url: ${{ secrets.LITELLM_BASE_URL }}
      litellm_api_key: ${{ secrets.LITELLM_API_KEY }}
      openai_api_key: ${{ secrets.OPENAI_API_KEY }}
```

## Files

| File | What |
|------|------|
| `.github/workflows/pr-review.yaml` | Thin Pipelock caller for the reusable workflow |
| `.github/workflows/pr-review-reusable.yaml` | Shared job control plane, permissions, and concurrency |
| `.github/actions/pr-review/` | Composite action, runner, and pinned Python requirements |
