# PR C — Conductor observability + audit (fleet status / followers + audit query)

## What this PR adds

Three operator-side read CLIs under `enterprise/cli/conductor/`, plus ONE new
server-side read endpoint that did not exist before.

### CLI commands (client-only)
- `conductor audit query` — list/get accepted audit-batch **metadata** from a
  Conductor (auditor or admin bearer, audience-scoped). Pure client against the
  pre-existing `controlplane.AuditBatchesPath` GET handlers
  (`handleListAuditBatches` / `handleGetAuditBatch`).
- `conductor fleet status` and `conductor followers` (alias) — list enrolled
  followers (auditor or admin bearer, audience-scoped).

All three share `client.go`: an mTLS-client + bearer-token, GET-only,
size-capped HTTP client. They fail closed on the `fleet` license entitlement
(`license.VerifyFleet`) before any connection, matching `serve` / `bootstrap`.

### NEW SERVER ENDPOINT (flag this in review)
There was **no follower-list read endpoint** before this PR. This PR adds one,
isolated to this PR per the coordination doc:

- **Route:** `GET /api/v1/conductor/followers` (`controlplane.FollowersPath`).
- **Handler:** `handleListFollowers` in `enterprise/conductor/controlplane/followers.go`.
- **Store method:** `EnrollmentStore.ListEnrolledFollowers(ctx, FollowerListQuery)`
  + the `FileEnrollmentStore` implementation in `enrollment.go`.
- **Authorizer:** `ScopedBearerFollowerListAuthorizer` in `auth.go` (admits
  admin + auditor roles, enforces credential org/fleet scope against the query —
  identical semantics to `ScopedBearerAuditQueryAuthorizer`).
- **Wiring:** `HandlerOptions.AuthorizeFollowers` + the serve command
  (`buildServeHandler`) reuses the existing auditor/admin token files.

### Security properties (tested)
- **Mandatory org scoping.** The handler rejects a missing `org_id` with 400
  before any auth or store access, so the roster read is never globally
  unscoped.
- **Audience isolation.** An org-A-scoped auditor reading `org_id=org-B` gets
  403 — the authorizer binds credential scope to the requested org BEFORE the
  store is touched, so no org-B roster ever leaves the process
  (`TestHandlerListFollowersDeniesCrossOrgRead`).
- **Fail-closed default.** An unconfigured `AuthorizeFollowers` denies every
  read (`ErrFollowerListForbidden`).
- **Bounded list (anti-DoS).** Server clamps the result to `[1, 1000]`
  (default 100) via `normalizeFollowerListLimit`; the client `--limit` is
  validated non-negative.
- **Strict query parsing.** Allowlisted params only; unknown/duplicate params,
  invalid identifiers, and bad limits → 400.
- **Metadata-only.** `FollowerSummary` omits the audit public-key bytes; only
  identity, audit_key_id, enrolled_at, active state are returned.

## Honest scope limitation (applied-version / last-seen)
The kickoff asked fleet status to show "applied bundle version" and "last-seen".
**The Conductor enrollment store does not track either today** — there is no
per-follower last-contact timestamp or applied-version record anywhere in
`enterprise/conductor/` (confirmed by grep: no `last_seen`/`applied_version`
fields exist). Rather than invent fields the server cannot populate, this PR
reports only what the store actually holds (enrollment state). Adding
applied-version/last-seen is a follower-contact-tracking feature (the bundle
store / poller would have to record per-follower `Latest()` hits) and is a
separate change. **Flagged as a deferred follow-up, not silently dropped.**

## fleet-sink: studied, live proof DEFERRED
The audit sink path is the existing `SQLiteAuditStore` (an `AuditBatchSink` that
also implements `AuditBatchQuerier`). `conductor audit query` reads exactly the
batches that path accepts. The end-to-end live proof is deferred per the
worktree guardrails (no cluster deploy in this run; #736 keygen not on this
branch). Unit coverage proves the client/endpoint contract; the live proof is
documented below.

## Deferred live-proof commands (run after merge, on the dogfood fleet)

Fleet material lives at `~/.local/share/v27-prod-fleet/` (CA, roster, control
keys, operator tokens); fedora-host follower at `~/.local/share/v27-fedora-follower/`.
Substitute the real org/fleet/instance and the operator token + cert paths.

1. **Fleet status — list both enrolled followers:**
   ```
   pipelock conductor fleet status \
     --server https://<conductor-host>:8895 \
     --ca-file ~/.local/share/v27-prod-fleet/ca.pem \
     --client-cert ~/.local/share/v27-prod-fleet/operator-client.pem \
     --client-key ~/.local/share/v27-prod-fleet/operator-client.key \
     --token-file ~/.local/share/v27-prod-fleet/admin-token \
     --org-id <org> --fleet-id <fleet>
   ```
   Expect: a table with both followers, ACTIVE=true, their audit_key_id and
   enrolled_at. (Applied-version/last-seen intentionally absent — see above.)

2. **Generate audit traffic, then query the batches:**
   Drive follower audit emission (normal agent traffic through the follower),
   then:
   ```
   pipelock conductor audit query \
     --server https://<conductor-host>:8895 \
     --ca-file ... --client-cert ... --client-key ... \
     --token-file ~/.local/share/v27-prod-fleet/auditor-token \
     --org-id <org> --fleet-id <fleet>
   ```
   Expect: JSON `{"batches":[...],"count":N}` including the freshly-emitted
   batch ids.

3. **Fetch one batch by id, then verify it OFFLINE:**
   ```
   pipelock conductor audit query ... --org-id <org> --fleet-id <fleet> \
     --instance-id <instance> --batch-id <batch-id>
   ```
   Then verify the signed batch offline with the existing batch verifier
   (the path `conductor bootstrap` already exercises via `audit-batch.json`).

4. **fleet-sink end-to-end:** deploy the audit sink in-cluster and demonstrate
   `follower → conductor → sink → conductor audit query → offline-verify`. The
   `conductor bootstrap` command already proves this loop in-process; the
   in-cluster deploy + proof is the deferred operator-workflow step.

## cmd.go shared-file note
This PR appends `auditCmd()`, `fleetCmd()`, `followersCmd()` to
`enterprise/cli/conductor/cmd.go` `Cmd()` (the one shared Go file across the
A/B/C/D conductor PRs). Whoever merges later re-adds their `AddCommand` line per
the coordination doc.

## Validation run locally (this worktree)
- `go build -tags enterprise ./...` — green.
- `go test -tags enterprise -race -count=1` on
  `./enterprise/conductor/controlplane/`, `./enterprise/cli/conductor/`, and
  `./enterprise/conductor/bootstrap/` — green.
- `golangci-lint run --new-from-rev=HEAD --build-tags enterprise` on both
  touched packages — 0 issues.
- New-symbol coverage: authorizer 90.9%, store list 94.7%, handler 85%,
  parse 92.9%, license-gate paths covered.
