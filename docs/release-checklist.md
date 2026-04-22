# Release Checklist

This checklist is the public, repo-local release gate for Pipelock. It exists
to catch policy drift, hot-reload regressions, and CI workflow footguns before
tagging a release.

## Security Model

- PR workflows must use `pull_request`, not `pull_request_target`.
- PR workflows must not use custom secrets.
- External GitHub Actions must be pinned to full commit SHAs.
- PR and CI checkouts must use `persist-credentials: false`.
- Comment-triggered workflows that use secrets must gate on
  `author_association` and must check out the PR merge ref, not the head ref.
- Runtime policy changes must be resolved through config-level clone-and-resolve
  logic, not by mutating loaded config inside runtime packages.

### A note on the runtime policy audit

`make runtime-policy-audit` is a coarse regex tripwire: it scans
`internal/cli/runtime`, `internal/mcp`, and `internal/proxy` for direct
assignment of a fixed set of policy-relevant config fields outside of test
files. It catches the common regression class (copy-paste of the pre-refactor
in-place mutation pattern) but it is not a complete control. Mutation routed
through a helper, a different field name, or an adjacent package can slip
past it. Treat its green output as "no obvious regression", not "the
invariant is proven".

The load-bearing invariants are enforced by Go tests in
`internal/config/runtime_test.go`: `ResolveRuntime` never mutates its
receiver, the clone's raw `Hash()` equals the receiver's `Hash()` while
`CanonicalPolicyHash()` may diverge, deep-clone prevents slice aliasing,
and the MCP proxy response-scanning fallback runs before the bundle merge.
A future tightening is an AST analyzer that walks runtime packages and
asserts every consumer of the loaded config flows through
`config.ResolveRuntime`; tracked as a follow-up.

## Required Automated Checks

Run these before tagging locally, and keep the matching GitHub Actions checks
required on `main`:

```bash
make release-audit
make test-runtime-critical
make runtime-policy-audit
go test -race -count=1 ./...
golangci-lint run ./...
```

For a one-shot local gate:

```bash
make release-check
```

For debt trending that should be reviewed before release even when it does not
yet block PRs:

```bash
make debt-check
```

## Human Sign-Off

- Confirm the release branch is based on the intended commit and that no
  release-critical PR is waiting to merge.
- Confirm `Hardening / workflow-audit` and `Hardening / runtime-critical` are
  green on the candidate commit.
- Review the `Hardening / hardening-report` summary for policy-drift or debt
  warnings.
- Confirm no runtime package is directly mutating policy-relevant config.
- Confirm receipt and envelope hash call sites still match their intended
  contracts.
- Confirm strict-mode hot reload still rejects real downgrades but allows safe
  operational changes.
- Confirm degraded rule-bundle behavior is visible in logs and still fail-closed
  on enforcement paths.

## Repo Settings To Pair With This

These are not enforceable from the repo alone, but they should be configured in
GitHub:

- Require review before merging changes to `.github/workflows/**`,
  `scripts/**`, and `Makefile`.
- Require the `CI` and `Hardening` status checks on `main`.
- Keep GitHub Actions secrets unavailable to fork PRs.
- Prefer rulesets or branch protection over manual convention.
