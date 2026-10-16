# PR-Agent diff review

Comment exactly `/agent-review` on an open pull request from this repository. The command runs only for the designated maintainer's original comment. Edited comments, workflow reruns, other accounts, bots, plain issues, and fork pull requests cannot start provider work. The workflow must already be on the default branch; commenting on the pull request that adds it does not test that new workflow.

The reviewer posts findings on changed lines as resolvable review threads. A persistent summary is updated across runs. Findings that cannot be anchored safely stay in the summary. Security analysis is enabled; scores, effort estimates, labels, and update notices are disabled. The review requests up to ten material findings and ignores style nits. It uses the security contracts in `AGENTS.md` and the existing reviewer's security and correctness rubric.

This is a separate comparison command alongside [`/review`](pr-review.md). It does not replace or invoke that reviewer. It reviews a bounded static diff, with nearby code context, rather than exploring or executing the repository. There is no `/agent-review deep` command and no automatic `/improve` pass. Suggested repairs are described in findings; the command cannot commit them.

## Models and credentials

The trusted configuration is [`.github/pr-agent.toml`](../../.github/pr-agent.toml). `config.model` defaults to `anthropic/claude-sonnet-5-5`; `config.fallback_models` contains `gpt-6-luna`. Set `config.model` to `anthropic/claude-haiku-5-5` to compare a cheaper Anthropic model, or to `gpt-6-luna` to use OpenAI directly. Model selection is a repository configuration change, never a comment argument. The adapter registers routing metadata for `gpt-6-luna`, which the pinned LiteLLM registry doesn't list. OpenAI uses medium reasoning with temperature omitted through PR-Agent's supported model overrides. Haiku 5.5 is also listed as a no-temperature model because it rejects non-default sampling values. `custom_model_max_tokens` is an operator budget, not a statement of model capacity.

The workflow uses `ANTHROPIC_API_KEY`, optional `ANTHROPIC_API_KEY_2`, and `OPENAI_API_KEY`. Configure secrets through the repository or organization settings; never put keys in the configuration file. If the first Anthropic key is absent, the command goes directly to OpenAI. The second Anthropic slot is used only after an explicit credit-exhausted response from the first slot. An orphaned second key is ignored. If both Anthropic slots are depleted, the configured OpenAI fallback runs. Providers without a configured credential are skipped before inference.

Fallback requires a structured rejection with HTTP status 400, 402, or 429. Anthropic qualifies with `error.type = "billing_error"`, or with `error.type = "invalid_request_error"` and a message containing `credit balance is too low`. OpenAI qualifies with `error.code = "insufficient_quota"`. Anthropic's [shared SDK schema](https://github.com/anthropics/anthropic-sdk-python/blob/v1.15.0/src/anthropic/types/shared/billing_error.py#L11) defines the billing type; its [billing-error description](https://github.com/anthropics/anthropic-sdk-python/blob/v1.15.0/src/anthropic/types/beta/sessions/beta_managed_agents_billing_error.py#L23) covers exhausted credits and spend limits. The legacy message is also recognized by [the pinned reviewer](https://github.com/the-pr-agent/pr-agent/blob/8e5a9295973b24af4b70cafd0b660a230811ef9e/pr_agent/tools/pr_reviewer.py#L83). Other message text alone never authorizes fallback.

Unknown billing formats fail visibly. Timeouts, dropped connections, rate limiting, authentication errors, malformed output, and truncated completions fail the run without another paid request. The wrapper disables PR-Agent's same-model retries, LiteLLM's client retries, and the pinned HTTP handler's separate connection retry. It reads structured error bodies from the original HTTP exception chain because LiteLLM's Anthropic mapping drops them from the final exception. Rejected slots stay retired for the rest of that review. Credential fallback happens before review findings are published.

## Budget and expected cost

Each review allows at most three successful completion calls, each with a 90,000-token input/context ceiling and a 16,000-token output cap that covers adaptive thinking and the review. Claude models think adaptively at medium effort; OpenAI uses medium reasoning. A typical review diff fits in one call. PR-Agent splits large diffs into bounded chunks. Generated protobufs, vendored dependencies, `testdata`, and selected lock files are excluded. An oversized PR may still exceed the budget: the summary lists omitted files and the workflow fails, so partial coverage cannot look complete. Check the coverage footer before relying on a review. Split the change or deliberately raise the trusted budget for a larger review.

The following estimates assume 65,000 to 78,000 input tokens and 1,000 output tokens per review, without caching or batch discounts. They use illustrative rates of $0.10/$0.50 per million input/output tokens for Haiku, $2/$10 for Sonnet, and $4/$20 for Opus. Confirm current [Anthropic pricing](https://platform.claude.com/docs/en/about-claude/pricing) before budgeting; rates and actual token usage can change.

| Model | Estimated cost per review | At 500 reviews per month |
| --- | --- | --- |
| Haiku 5.5 | $0.0070 to $0.0083 | $3.50 to $4.15 |
| Sonnet 5.5 | $0.140 to $0.166 | $70 to $83 |
| Opus 5.5, comparison only | $0.280 to $0.332 | $140 to $166 |

Thinking adds output tokens beyond the 1,000 assumed above, so expect somewhat higher real costs. The ceiling, three full Sonnet calls, would cost about $1.02 at those rates, but only an unusually large pull request approaches it. The expected $70 to $83 monthly cost makes Sonnet a reasonable starting point for evaluating review quality. OpenAI fallback cost depends on the current [`gpt-6-luna` price](https://openai.com/api/pricing/) and its token usage; the workflow doesn't assume the providers charge the same rate. Model quality and actual cost need comparison on real pull requests before changing the daily reviewer.

## Trust and maintenance

Admission runs without model credentials. The review job checks out the immutable revision that supplied the default-branch workflow, with checkout credentials disabled. It never checks out or executes PR head code. PR-Agent reads the captured head through the GitHub API as untrusted input. A changed head or base fails before findings are published. The model has no tools, environment access, or control over the target repository or pull request. Prompt instructions in a diff cannot select a credential, run a command, or change the publishing target. A model can still produce incorrect or misleading text, so treat findings as review advice.

The adapter bypasses PR-Agent's webhook/comment parser and invokes only its review implementation. Remote repository settings, global settings, skills, artifacts, related-ticket analysis, callbacks, and telemetry are disabled. Credentials are attached only to the review step. Logs contain selected model names, call counts, and fixed failure messages, rather than prompts, keys, or provider exception bodies.

The upstream CLI image is pinned by version and image digest in [the workflow](../../.github/workflows/agent-review.yaml). The digest freezes its entire dependency tree, and Renovate's GitHub Actions image updater can propose updates. Review the image source and run the adapter checks when updating it. The wrapper depends on the pinned handler's Tenacity `retry_with` interface, exception chaining, and HTTP retry method. The adapter has no server or hosted-review subscription dependency.

The container runs as UID 1001, matching the [hosted Ubuntu runner](https://github.com/actions/runner-images/issues/10936), with all Linux capabilities dropped and privilege escalation disabled. This lets checkout write the runner-owned workspace and file-command mounts through ordinary ownership permissions. Group 1001 is deliberate: it leaves out the runner's `docker` group, so the job can't reach the mounted Docker socket. GitHub supplies the writable home at `/github/home`. A runner or image change needs the same checkout, cache-write, and adapter checks as an image update; restoring filesystem-bypass capabilities isn't required. See [GitHub's container job options](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container) and [Docker's user and capability controls](https://docs.docker.com/engine/containers/run/).

Run the fast checks with the repository's pinned test dependencies installed:

```bash
python -m unittest scripts.test_pr_agent_review
python -m unittest scripts.pr_review_test
```

With `pr-agent==0.47.0` installed in a disposable environment, run `python scripts/pr_agent_review.py --check-config` to print only non-secret effective settings. This does not call a model or require provider credentials.

Before running the offline integration tests, prepare the tokenizer data once in that disposable environment, without credentials:

```bash
python -c "import tiktoken; tiktoken.get_encoding('o200k_base')"
```

This downloads the data verified by tiktoken's bundled hash. Keep the cache directory when disabling networking; set `TIKTOKEN_CACHE_DIR` to a writable directory to choose its location. A fresh image doesn't include this cache.

Run `python -m unittest scripts.test_pr_agent_runtime` in that same environment to exercise the real pinned handler, parser, GitHub diff reads, and comment publication with fixture credentials and network connections blocked. The GitHub fixture rejects unexpected API operations and verifies persistent summary reuse with the workflow bot identity. These optional integration tests skip in environments without PR-Agent; admission and failure-contract tests always run through the existing CI test discovery.

For the first live smoke test after merging and configuring credentials, comment `/agent-review` on a small same-repository pull request with a known, harmless correctness defect on an added line. Verify the job succeeds, logs the configured Anthropic model when its primary key is available, posts a resolvable inline thread, and names the captured commits in the summary. Repeat the command to check summary reuse and inline deduplication. Local fixtures cover OpenAI-only operation and credit/spend-limit rollover without deliberately spending an account down. Real API model acceptance, account access, actual billing-response formats, and GitHub publication permissions require live verification.
