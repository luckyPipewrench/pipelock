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
also checks out the captured head for the judge, then searches that checkout for
the consumers and tests related to each candidate. A same-file hunk isn't enough
to verify a cross-file claim.

The runner uses deterministic token budgeting instead of character slicing: Go
source and additions rank above tests, configuration, and documentation. The
final comment contains an omission manifest and never reports `clean` when a
unit was omitted, unparseable, or left without a valid structured result. A
candidate the judge can't settle stays unpublished and makes the review partial.
That unpublished candidate is not an actionable finding. A finding the judge
does keep can still show `(needs verification)` when the reviewer marked it.
Default-mode deletion compression is disclosed separately; deep mode reads
deletions in full.

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

- Only runs from an authorized `/review` comment (no auto-review on push)
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
retrying because it may have been short for a transient reason. There is no way
to force a second review of an unchanged head in the same mode. The manual
dispatch that once did that was removed, because a manual run chooses the branch
that supplies the reviewer code. Run the other mode, or push a change.

**You pushed a fix and want another look.** The head changed, so this is a
different review. When the PR base is unchanged, the reviewer reads the new
delta and rechecks every open finding against the current head. When a merge or
rebase advances the PR base, it reads the effective `current-base..head` pull
request whole. It doesn't spend its budget reviewing upstream commits that are
already on the base branch.

The review marks any finding also reported by a completed review on this pull
request with `(re-raised at this head)`. The current-head judge found it again,
so the prior fix didn't close it or introduced the same failure elsewhere.

A finding that simply does not appear in a later review is NOT reported as
fixed. Its absence is not evidence: the model may not have surfaced it this
time. Nothing here claims a finding was resolved.

## Changing the reviewer

Read this before editing anything under `.github/actions/pr-review/` or either
review workflow.

**A change here cannot be tested by the pull request that makes it.** A workflow
triggered by `issue_comment` only ever executes the copy already on the default
branch. Comment `/review` on your own pull request and you exercise the old
reviewer, not your change, and it reports success while proving nothing about
what you wrote. That is how the trigger works, not a quirk to route around.

**There is deliberately no manual dispatch to test with.** A `workflow_dispatch`
on this caller lets whoever starts the run pick the branch, and that branch then
picks the workflow code that receives the review credential and the provider
key. Closing that is the whole reason the trigger set is one event, so do not
add a dispatch back to get a pre-merge test.

Test a reviewer change these three ways instead, in this order.

**Locally, with the unit tests below.** They parse both workflows and drive the
action's state machine directly, so they are the only thing that exercises your
version of the reviewer before it merges. That is why a change here is expected
to arrive with tests rather than with a screenshot of a successful run.

**In a scratch repository you own.** Copy the stub from "Reusing the reviewer in
another repository" into a throwaway repository, set both pins to your branch's
head commit, which is a full immutable SHA like any other, and give it a
disposable provider key. Branch-selected code only matters where it can reach a
credential worth stealing, so a repository holding nothing is a safe place to
run one, and it exercises the real caller against a real pull request.

**On the default branch, after it merges.** The first `/review` on the next pull
request is the first run of your change in this repository. Treat it as a
smoke test of something already reviewed, not as the test that finds the bug.

The local suite is fast:

```bash
pip install --require-hashes -r .github/actions/pr-review/requirements.txt
pip install --require-hashes -r .github/requirements-pr-review-test.txt
python -m unittest scripts.pr_review_test
```

The `pr-review-tests` job in `ci.yaml` runs the same command. A suite that runs
only inside a review cannot gate a change to the reviewer, because a review runs
the default-branch copy.

**Two signals, and they mean different things.** The `review` job reports
whether the runner published a verdict, so a published `partial` is a successful
run. The `completeness` job reports whether the review covered the whole pull
request, and fails when it did not. Do not make a red `completeness` green; read
the review comment, which names what was not covered. One signal cannot carry
both without either making a working review look crashed or showing a green
check on a review that read part of the diff.

**Deletions are a security change.** Removing a guard reads as a deletion hunk.
Deep mode reads deletion hunks in full and splits an oversized one into bounded
pieces rather than summarizing or dropping it. Default mode compresses large
deletion runs and discloses that it did. Do not make deep mode compress them.

**A disclosed compression is not a coverage gap.** `coverage_gaps()` names only
what the review should have read and did not: omitted units, parse errors, a
truncated compare, a timeout, a moved head, a failed fetch. Counting a
compression there makes the completeness check fail on reviews that covered
everything, and a check that is red on complete work is one an operator learns
to ignore.

**Structural assertions parse; they do not match text.** A guard that greps a
workflow can be satisfied by a comment naming the thing it guards, by a quoted
value, by a flow mapping, or by whitespace before a colon. Assert against parsed
YAML. When you add a guard, break the thing it guards and watch that test fail
before you trust it.

## Propagating a change to the other repositories

The reviewer lives in this repository only. Other repositories hold a caller of
about forty lines with no logic in it, pinned to a Pipelock commit, so a fix
here reaches them when their pin advances and not before.

Confirm the current adopters live rather than trusting a list that rots:

```bash
gh search code --owner luckyPipewrench 'pr-review-reusable.yaml' --limit 20
```

Two rules for a pin bump:

- **Advance both occurrences together.** `uses:` and `reviewer_sha:` must name
  the same commit. They select the workflow and the reviewer source separately,
  and a mismatch runs one version's workflow against another version's code.
- **Carry any stub change in the same commit as the bump.** The caller's inputs
  and secrets are a contract with the reusable workflow at the pinned commit. If
  a bump removes or renames a secret, a caller still passing the old one fails
  at workflow load. Because the pin is immutable, the old caller keeps working
  against the old commit until both move, so this only breaks if they are split.

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

Do not add `workflow_dispatch` to this caller. A manual run may select a branch,
which would let that branch choose the workflow code that receives the review
credential. Test caller changes after they merge to the default branch.

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
      github.actor == 'YOUR_GITHUB_LOGIN' &&
      github.triggering_actor == 'YOUR_GITHUB_LOGIN' &&
      github.event.comment.user.login == 'YOUR_GITHUB_LOGIN' &&
      github.event.comment.author_association == 'OWNER' &&
      github.event.issue.pull_request &&
      (github.event.comment.body == '/review' ||
       github.event.comment.body == '/review deep')
    uses: luckyPipewrench/pipelock/.github/workflows/pr-review-reusable.yaml@PINNED_PIPELOCK_REVIEW_COMMIT_SHA
    with:
      pr_number: ${{ github.event.issue.number }}
      review_mode: >-
        ${{ github.event.comment.body == '/review deep' && 'deep' ||
        'default' }}
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
| `.github/actions/pr-review/action.yml` | Composite action: runner inputs, outputs, and setup |
| `.github/actions/pr-review/pr_review.py` | The reviewer: diff parsing, budgets, provider calls, state |
| `.github/actions/pr-review/requirements.txt` | Pinned runtime dependencies, installed by the action |
| `.github/requirements-pr-review-test.txt` | Pinned test-only dependency, installed by CI |
| `scripts/pr_review_test.py` | The test suite, including the structural workflow guards |
| `.github/workflows/ci.yaml` | The `pr-review-tests` job, which runs that suite on pull requests |

Every other repository holds only its own `.github/workflows/pr-review.yaml`
caller. Nothing in this table is duplicated into them.
