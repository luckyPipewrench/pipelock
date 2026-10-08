# AI PR Review

Manual-trigger AI security review for pull requests. Comment `/review` on any PR to get a focused security review.

## Trigger Commands

| Command | Model | Use When |
|---------|-------|----------|
| `/review` | GPT-6 Luna at high reasoning for discovery; GPT-6 Sol at low reasoning judges candidates | Quick check, most PRs |
| `/review deep` | GPT-6 Sol at low reasoning | Adversarial static-diff review (findings-first) |

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

The result shows the review profile, model, and reasoning level next to the
verdict. A later default review can't look like another deep pass unless a
reader ignores that visible profile.

The stronger default-mode judge runs only when discovery produces candidates.
Provider token usage is recorded by phase in the workflow log so the extra
cost remains visible without publishing billing details in the review comment.

The runner binds the review to the PR's captured base and head SHAs, reviewer
source SHA, and rubric version. It fetches the comparison by those exact commits
and marks the result `superseded` if the head changes before finalization. It
also checks out the captured head for the judge, then searches that checkout for
the consumers and tests related to each candidate. A same-file hunk isn't enough
to verify a cross-file claim.

Search hits carry surrounding source lines. Nearby hits in the same file share
a window that includes each hit's context; definition hits also include the body,
up to 60 lines from the definition. An identifier also gets one search for the
line that defines it, from the same search budget, because the literal search keeps
only the first three hits per file. Literal searches requested by the judge use
the same windows. The existing search, window, token, request, and time limits
still apply. A file too large to read still contributes its matching lines. Omitted code and failed reads are marked so the judge leaves a
premise unresolved when the supplied evidence cannot decide it.

The reusable workflow builds the comparison from shallow checkouts of the exact
head and GitHub-reported merge base. This avoids both the compare API's 300-file
ceiling and an unbounded full-history fetch. If it can't produce the exact diff,
or the diff exceeds the runner's bounded size, the review fails instead of
inspecting a subset.

The runner uses deterministic token budgeting instead of character slicing. Go
source and additions rank above tests, configuration, and documentation. The
planner keeps that priority order while using spare chunk space for smaller
units after a larger one doesn't fit. It never removes already-admitted work to
make that space. Python `test_*.py` files and `test`, `tests`, and `testdata` path
components are classified as tests; signed fixtures remain reviewable units.
The final comment includes an omission manifest, including chunks that failed
or never started. A planned unit is counted as reviewed only after a valid
provider result is received. If the reviewer omits a unit, can't
parse it, or gets unusable provider output, it reports `partial` instead of
`clean`.

The judge gets one bounded follow-up with only the candidates it didn't settle. The first pass can request a specific repository path or literal search; the runner fetches that evidence from the immutable reviewed checkout before the follow-up. The review job never executes pull-request code to settle a candidate.
When a candidate depends on external evidence or evidence the run couldn't
include, the comment reports `inconclusive` and keeps the candidate in a
collapsed unverified-candidates section. The candidate doesn't count as an actionable
finding, and the action's `complete` output stays false until the review reaches
`clean` or `findings` with coverage of the current pull request base.
A finding the judge does keep can still show `(needs verification)` when the
reviewer marked it.
Default-mode deletion compression is disclosed separately; deep mode reads
deletions in full.

Each run creates one bot-owned status comment and edits it in place. The runner
uses strict JSON output, a cross-file synthesis pass, and a second actual-code
judge pass before publishing findings. It strips mentions and command-shaped
text from model-supplied fields.

The final comment names the captured base and head. If either moves during the
review, the result cannot claim complete coverage of the current pull request.
Verdicts are informational. A `partial`, `inconclusive`, or `failed` verdict
appears in the comment and the job stays green, even if the step outputs cannot
be written afterward. The job fails only when no verdict could be published,
such as on a setup failure or a local interrupt that stops the run before its
`failed` verdict is posted; a job cancelled on GitHub shows as cancelled. A review that stops on an unexpected
error publishes `failed` (`superseded` if the run had already seen the head
move) naming the error's type, not a verdict it never reached, and lists any
candidates the judge had not ruled on as unverified. Before it starts, the
command checks for a review already running; if that check fails it publishes
`failed` and does not start one. An earlier check for a finished review of the
same head does not stop the command when it fails: the command reviews anyway.
A command declined with a notice (already reviewed, or already running) also
stays green when its outputs cannot be written, and a run whose verdict or notice
is posted stays green if a local interrupt arrives while it writes those outputs.
When GitHub's reply to the final
comment update is lost to a timeout or a server error, the reviewer reads the
comment back once and stays green only if it shows this run's verdict. Read the
signed comment marker to decide coverage; the reviewer does not publish commit
statuses or CI checks.

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
| `PR_REVIEW_MODEL_FAST` | `gpt-6-luna` | `/review` |
| `PR_REVIEW_MODEL_DEEP` | `gpt-6.1-sol` | `/review deep` and candidate judging |

The defaults live in `.github/actions/pr-review/pr_review.py`; the composite
action passes optional repository variables through without maintaining another
copy.

### Provider

Set `OPENAI_API_KEY`. The reviewer calls `api.openai.com` directly.

### Switching Models

Override the model via repository variables:

```text
PR_REVIEW_MODEL_FAST=gpt-6-luna
PR_REVIEW_MODEL_DEEP=gpt-6.1-sol
```

Values must name models available through the direct OpenAI API.

## Cost Control

- Only runs from an authorized `/review` comment (no auto-review on push)
- Never retries an ambiguous provider timeout, which could double-spend
- Sizes each provider call's timeout from its output allowance at the observed
  generation rate, and holds the whole review under a wall clock the job
  timeout exceeds, so a slow provider yields a `partial` verdict rather than a
  stranded status comment. Each completed call logs its elapsed seconds beside
  its token usage so the next resize is measured, not guessed.
- Uses explicit token budgets; deep mode splits an oversized hunk into complete
  contiguous review units rather than summarizing or dropping its deletion lines
- `/review` uses the efficient model by default
- `/review deep` is opt-in for GPT-6 Sol at low reasoning
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
review that covered the whole diff and settled its candidates counts. Retry a
`partial` or `failed` review after a transient failure, because the run may have
stopped short. A deterministic budget omission will recur on the same input;
repeating the command does not continue from the units the prior run reviewed.
Retry an
`inconclusive` review after supplying the missing evidence or making the human
decision it names. There is no way
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

## Handling an incomplete review

- Read the bound head, coverage count, omission reasons, and unverified
  candidates before deciding what remains. A successful workflow is not a
  clean review.
- `priority-token-budget` means the unit did not fit the configured chunk or
  unit limits. `hunk-exceeds-token-budget` means one whole unit was too large.
  Ordinary mode allows six chunks of up to 30 units and 12,000 estimated input
  tokens each; deep mode allows eight chunks of up to 60 units and 48,000
  estimated tokens each. The planner also accounts for serialized prompt
  structure and escaping. Wall-clock limits still apply. Better packing can't
  make an arbitrarily large diff fit.
- Review deterministic omissions independently, or deliberately choose
  `/review deep` when its larger budget is appropriate. Neither an unchanged
  ordinary rerun nor a deep run promises complete coverage. Fixtures and
  security-sensitive tests are not exempt from this accounting.
- Provider timeouts, exhausted connection retries, rate limits, and invalid or
  truncated responses remain unreviewed in the manifest. A manual retry starts
  a new bounded review; ambiguous timed-out provider calls are never retried
  automatically.
- `not-attempted` units were planned but never sent, for example because the
  wall clock expired or the head moved. An unchanged-head rerun starts over;
  partial results are never accepted as complete delta baselines.
- Full diff coverage with unresolved candidates is still `inconclusive`.
  Verify the named evidence rather than treating the lack of verified findings
  as evidence of no defects.
- Full diff coverage can also be `partial` when a judge response is unusable.
  The validation section and workflow logs identify the phase and safe rejection
  categories, such as `reason-too-long`, `invalid-index`, or `missing-decision`.
  These are counts of validation events, including events corrected by repair;
  they are not findings or raw provider responses. HTTP 200 alone does not prove
  a usable decision.
- Both judge prompts state the existing 300-character reason limit and index
  and evidence-request rules. The single bounded repair receives validation
  categories for its own candidate indices. It still must decide the candidate;
  diagnostics do not relax validation, add calls, or make an incomplete result
  clean. A malformed primary response can use that same repair slot. The limit
  remains two judge calls, with a 4,096-token output cap for repair.

Each candidate has a stable ID and its own evidence window, even if several candidates name the same file. The runner prefers a valid head line, then a named definition or relevant changed hunk. File-start and changed-hunk fallbacks are labelled. Deleted paths use the bound diff and available base content. Content reads are cached by immutable commit and path. Searches can find more code in the same file outside the supplied ranges. Failed reads and searches affect the candidate that needs them; they don't cancel judgment of its siblings.

The comment retains each unsettled candidate's sanitized reason, evidence source and retrieval outcome. Missing evidence can't dismiss a candidate. Truncated surrounding evidence can still contain the fact that decides a premise. The repair uses the remaining prompt allowance for unresolved candidates, invalid decisions and overflow candidates that fit. Candidates that still don't fit remain visibly incomplete. Prompt accounting includes labels, escaped strings, summaries and truncation notices without shortening candidate claims.

Oversized hunks split in both modes with accurate line coordinates and attached no-newline markers. Default deletion compression remains disclosed. Pure renames and file-mode changes are review units; binary content remains a coverage gap. The runner computes both capacity plans before provider work. It recommends deep only if that plan removes the representable-unit capacity gap. Deep doesn't promise to resolve binary or evidence gaps.

Discovery admission holds a rolling reserve for remaining synthesis, judgment, possible repair and publication. It reserves the next discovery call rather than every future call's worst-case duration. Unnecessary phases release their reserve. A slow response can still exhaust the budget; unfinished units remain in the manifest and publication has separate headroom. Valid candidates in a malformed discovery response survive, but its unit stays incomplete unless a full response validates. Schema repair can use only a spare call within the mode's existing six- or eight-call discovery limit. Authentication failures and ambiguous transport failures don't receive paid repair retries. Logs distinguish transport from schema failures and record bounded finish-reason and usage counts. This repair doesn't add persistent checkpoints or automatic paid reruns.

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

**The signed comment is the review signal.** Verdicts are informational:
`partial`, `inconclusive`, and `failed` appear in the comment and leave the
`review` job green, including when the step outputs cannot be written after the
verdict is posted; no job reads them. It fails only when no verdict could be
published, including when a local interrupt stops the run before it posts `failed`.
Automation reads the signed marker in the comment to decide
whether the reviewer settled the whole pull request; review verdicts do not
publish commit statuses or CI checks.

**Deletions are a security change.** Removing a guard reads as a deletion hunk.
Deep mode reads deletion hunks in full and splits an oversized one into bounded
pieces rather than summarizing or dropping it. Default mode compresses large
deletion runs and discloses that it did. Do not make deep mode compress them.

**A disclosed compression is not a coverage gap.** `coverage_gaps()` names only
what the review should have read and did not: omitted units, parse errors, a
truncated compare, a timeout, a moved head, a failed fetch. Counting a
compression there makes reviews that covered everything read `partial`, and an
incomplete label on complete work is one an operator learns to ignore.

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
  the same commit. The source helper checks an explicit `reviewer_sha` against
  the loaded workflow commit and rejects a mismatch before admission.
- **Carry any stub change in the same commit as the bump.** The caller's inputs
  and secrets are a contract with the reusable workflow at the pinned commit. If
  a bump removes or renames a secret, a caller still passing the old one fails
  at workflow load. Because the pin is immutable, the old caller keeps working
  against the old commit until both move, so this only breaks if they are split.

### Workflow source binding

The reusable workflow calls `.github/workflows/pr-review-source.yaml` locally, so GitHub loads the helper from the same revision as the reusable workflow. The helper has `permissions: {}`, receives no secrets, and runs no checkout or action. It validates `job.workflow_sha` as a full lowercase commit SHA, requires `job.workflow_repository` to be `luckyPipewrench/pipelock`, and requires `job.workflow_file_path` to identify the helper. Missing or mismatching identity fails before admission can claim a comment or use a credential. Every trusted checkout and review action consumes the validated SHA.

`reviewer_sha` is optional for callers using this workflow contract. When omitted or empty, the source helper uses the loaded workflow SHA. An explicit value must equal that SHA. The local Pipelock caller omits it. External callers should keep the paired pins in the example below until a credential-free cross-repository run proves GitHub supplies the callee identity through both reusable calls. Callers pinned to older workflow contracts still require both pins.

CI calls the same helper with no permissions or secrets to exercise GitHub's actual runtime fields. A pull request can select that helper's code, so this CI job must never receive review credentials or execute the privileged review workflow. Local shell tests prove validation and output linkage with supplied values; they don't prove GitHub's runtime semantics. A successful local CI helper call also doesn't prove the cross-repository nested-call behavior. Record the actual helper SHA, repository, path, and output from that cross-repository run before adopting a caller with only the `uses:` pin. GitHub documents the fields in the [job context](https://docs.github.com/en/actions/reference/workflows-and-actions/contexts#job-context).

### Recovering a failed finalizer

If `finalize` fails while the comment still reads `running`, retry only that job after the GitHub API problem clears. Re-running the entire workflow or all failed jobs can repeat review work. The finalizer uses the original claim's comment ID and identity, closes only its own `running` marker, and leaves a terminal verdict unchanged. A lost edit reply is checked by reading the marker back. Once the claim is closed as `failed`, a new `/review` can start normally. If finalization still can't close it, a new command remains blocked until the claim is 105 minutes old; it doesn't resume the old review.

## Reusing the reviewer in another repository

The stub below carries nothing specific to any one repository, so every adopting
repository holds the same file. Make two replacements. Replace both occurrences
of `PINNED_PIPELOCK_REVIEW_COMMIT_SHA` with the same full, immutable Pipelock
commit SHA; do not use a branch or tag, because either can move the reviewer
code under the pin. Replace `YOUR_GITHUB_LOGIN` with the login allowed to
trigger a review, or drop those clauses and rely on `author_association ==
'OWNER'` alone.

Grant `issues: write` and `pull-requests: write`. A called workflow cannot hold
a permission its caller withheld, so dropping either one silently strips it
from the reviewer rather than failing at load, and the review then ends on a
permission error when it tries to update its pull-request comment. Review
verdicts are informational and do not publish commit statuses or CI checks;
automation must read the signed review marker in the comment.

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
| `.github/workflows/pr-review-source.yaml` | Credential-free loaded workflow identity validation |
| `.github/actions/pr-review/action.yml` | Composite action: runner inputs, outputs, and setup |
| `.github/actions/pr-review/pr_review.py` | The reviewer: diff parsing, budgets, provider calls, state |
| `.github/actions/pr-review/requirements.txt` | Pinned runtime dependencies, installed by the action |
| `.github/requirements-pr-review-test.txt` | Pinned test-only dependency, installed by CI |
| `scripts/pr_review_test.py` | The test suite, including the structural workflow guards |
| `.github/workflows/ci.yaml` | Reviewer tests and the credential-free runtime source helper call |

Every other repository holds only its own `.github/workflows/pr-review.yaml`
caller. Nothing in this table is duplicated into them.
