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
unparseable, or left without a valid structured result. Default-mode deletion
compression is disclosed separately; deep mode reads deletions in full.

Each run creates one bot-owned status comment and edits it in place. The runner
uses strict JSON output, a cross-file synthesis pass, and a second actual-code
judge pass before publishing findings. It strips mentions and command-shaped
text from model-supplied fields.

## Setup

### Required GitHub Secret

Set these in **Settings > Secrets and variables > Actions**:

| Secret | Required | Description |
|--------|----------|-------------|
| `OPENAI_API_KEY` | Yes | Direct OpenAI API key for the reviewer |

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

### Provider

Set `OPENAI_API_KEY`. The reviewer calls `api.openai.com` directly.

### Switching Models

Override the model via repository variables:

```text
PR_REVIEW_MODEL_FAST=gpt-5.6-luna
PR_REVIEW_MODEL_DEEP=gpt-5.6-terra
```

Values must name models available through the direct OpenAI API.

## Cost Control

- Only runs when manually triggered (no auto-review on push)
- Never retries an ambiguous provider timeout, which could double-spend
- Uses explicit token budgets; deep mode splits an oversized hunk into complete
  contiguous review units rather than summarizing or dropping its deletion lines
- `/review` uses the efficient model by default
- `/review deep` is opt-in for the xhigh adversarial pass
- Re-running a command against an unchanged head does not review again; it
  links the review that already covered it

## Repeat reviews

Reviewing the same pull request twice is normal, and the two cases behave
differently.

**Nothing changed since the last review.** The command links the existing review
and stops. A finished review of the same base, head, reviewer commit, rubric,
and selected model cannot reach a different answer, so running it again would
spend a full review,
twenty minutes on a large diff, to reproduce what is already posted. Depth is
part of that comparison, so `/review deep` still runs after `/review`. Only a
review that covered the whole diff counts; a `partial` or `failed` one is worth
retrying because it may have been short for a transient reason. To review an
unchanged head anyway, run the workflow manually from Actions.

**You pushed a fix and want another look.** The head changed, so this is a
different review and it reads the whole diff again. That is deliberate rather
than a cost oversight: reviewing only the newest commits assumes findings
compose, and they do not. A commit that is fine alone can break code reviewed
earlier, and a fix for a finding can itself be wrong. What the review does
instead is mark any finding it has already reported on this pull request with
`(reported before)`, so the new work is visible without re-triaging the list.
Every finding is still published; the label never hides one.

## Reusing the reviewer in another repository

The stub below carries nothing specific to any one repository, so every adopting
repository holds the same file. Make two replacements. Replace both occurrences
of `PINNED_PIPELOCK_REVIEW_COMMIT_SHA` with the same full, immutable Pipelock
commit SHA; do not use a branch or tag, because either can move the reviewer
code under the pin. Replace `YOUR_GITHUB_LOGIN` with the login allowed to
trigger a review, or drop those clauses and rely on `author_association ==
'OWNER'` alone.

Grant both `issues: write` and `pull-requests: write`. A called workflow cannot
hold a permission its caller withheld, so dropping either one silently strips it
from the reviewer rather than failing at load, and the review then ends on a
permission error when it tries to post.

Personal-account repositories must map each named secret explicitly, because
`secrets: inherit` is not available to them.

Keep the manual dispatch. A comment-triggered workflow only ever executes the
copy on the default branch, so a change to this file cannot run on the pull
request that introduces it, and the dispatch is the only way to exercise a
change here before it lands.

```yaml
name: AI PR Review

on:
  issue_comment:
    types: [created]
  workflow_dispatch:
    inputs:
      pr_number:
        description: Pull request to review with the workflow on this branch.
        required: true
        type: string
      review_mode:
        description: default or deep.
        required: true
        default: default
        type: choice
        options: [default, deep]

permissions:
  contents: read
  issues: write
  pull-requests: write

jobs:
  review:
    if: >-
      github.actor == 'YOUR_GITHUB_LOGIN' &&
      github.triggering_actor == 'YOUR_GITHUB_LOGIN' &&
      ((github.event_name == 'issue_comment' &&
        github.event.comment.user.login == 'YOUR_GITHUB_LOGIN' &&
        github.event.comment.author_association == 'OWNER' &&
        github.event.issue.pull_request &&
        (github.event.comment.body == '/review' ||
         github.event.comment.body == '/review deep')) ||
       github.event_name == 'workflow_dispatch')
    uses: luckyPipewrench/pipelock/.github/workflows/pr-review-reusable.yaml@PINNED_PIPELOCK_REVIEW_COMMIT_SHA
    with:
      pr_number: >-
        ${{ github.event_name == 'issue_comment' &&
        github.event.issue.number || inputs.pr_number }}
      review_mode: >-
        ${{ github.event_name == 'issue_comment' &&
        (github.event.comment.body == '/review deep' && 'deep' ||
         'default') ||
        inputs.review_mode }}
      reviewer_sha: PINNED_PIPELOCK_REVIEW_COMMIT_SHA
    secrets:
      review_token: ${{ secrets.GITHUB_TOKEN }}
      openai_api_key: ${{ secrets.OPENAI_API_KEY }}
```

`github.triggering_actor` names the account that started the current attempt,
which differs from `github.actor` when someone re-runs an existing workflow.
Requiring both means a re-run cannot widen who is able to start a review.

## Files

| File | What |
|------|------|
| `.github/workflows/pr-review.yaml` | Thin Pipelock caller for the reusable workflow |
| `.github/workflows/pr-review-reusable.yaml` | Shared job control plane, permissions, and concurrency |
| `.github/actions/pr-review/` | Composite action, runner, and pinned Python requirements |
