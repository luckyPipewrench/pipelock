# Agent review

The `/agent-review` pull request command runs from the shared [pipelab-org/agent-review](https://github.com/pipelab-org/agent-review) repository. Its README and guide cover admission, the trust model, credentials, spending limits, and failure reporting.

This repository keeps only two files for it. [The caller](../../.github/workflows/agent-review.yaml) pins the shared reusable workflow to a full commit SHA and must match the template that the shared validator accepts. [The profile](../../.github/agent-review.toml) adds Pipelock's review instructions and path exclusions. Changing either file takes effect only after it reaches the default branch. Every pull request runs the `agent-review-contract` CI job, which checks out the pinned engine commit, refuses a pin that isn't on its `main` branch, and runs that commit's validator against both files. The required `build` check fails if the job does.

To adopt a newer engine, update the caller's SHA to a merged `pipelab-org/agent-review` commit that has passed its CI and a smoke review.
