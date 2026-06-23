# Conductor Operator Recovery Commands

This page documents the Conductor recovery and operator-convenience commands
added for day-2 fleet management. All are Enterprise-tier and require a license
with the `fleet` feature.

## `publish --previous-bundle-hash auto`

After a rollback, the operator must publish a new policy bundle version above the
stream's max-ever version. The `--previous-bundle-hash` flag chains the new
bundle to the current stream head. Normally the operator must copy this hash from
a prior publish output or a `conductor stream status` query.

`--previous-bundle-hash auto` resolves the hash automatically by querying the
Conductor's stream-status endpoint before building the bundle:

```sh
pipelock conductor publish \
  --conductor-url https://conductor.example:8895 \
  --config policy.yaml \
  --org acme --fleet prod --env prod \
  --audience '*' \
  --version 10 \
  --previous-bundle-hash auto \
  --signing-key /etc/pipelock/keys/policy-signing.json \
  --publisher-token-file /etc/pipelock/publisher.token \
  --tls-cert client.crt --tls-key client.key --server-ca ca.pem
```

The resolved hash is printed before the publish proceeds. For the first bundle
in a stream (no existing head), `auto` resolves to an empty string and the
publish proceeds without a previous hash.

## `publish` with stream-switch authorization

When moving a follower from one policy stream to another, for example from the
fleet wildcard audience (`*`) to a specific instance audience, the new target
bundle must carry a signed stream-switch authorization. The authorization is
signed with the `policy-bundle-rollback` threshold keys and binds the exact
source bundle hash to the exact target bundle hash before the authorization is
embedded.

```sh
pipelock conductor publish \
  --conductor-url https://conductor.example:8895 \
  --config policy-instance.yaml \
  --org acme --fleet prod --env prod \
  --audience edge-01 \
  --version 11 \
  --signing-key /etc/pipelock/keys/policy-signing.json \
  --stream-switch-from-audience '*' \
  --stream-switch-from-bundle-id prod-wildcard-v10 \
  --stream-switch-from-version 10 \
  --stream-switch-from-hash 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --stream-switch-reason "retarget edge-01 to canary policy" \
  --stream-switch-signing-key /etc/pipelock/keys/rollback-approver-1.json \
  --stream-switch-signing-key /etc/pipelock/keys/rollback-approver-2.json \
  --publisher-token-file /etc/pipelock/publisher.token \
  --tls-cert client.crt --tls-key client.key --server-ca ca.pem
```

Followers reject a cross-stream bundle without this authorization, with an
expired authorization, or when the authorization names a different source hash,
target bundle, or audience. Same-stream forward publishes still use
`--previous-bundle-hash` continuity.

## `follower reset-bundle-state`

`follower reset-bundle-state` is an offline follower-side recovery command for a
wedged local policy-bundle apply cache. It removes only the follower's active
policy-bundle pointer and cached bundle/config records under
`conductor.bundle_cache_dir`. It does **not** modify the remote-kill replay
state.

Dry run:

```sh
pipelock conductor follower reset-bundle-state \
  --state-dir /var/lib/pipelock/bundles
```

Apply:

```sh
pipelock conductor follower reset-bundle-state \
  --state-dir /var/lib/pipelock/bundles \
  --confirm
```

After a confirmed reset, restart the follower if it is wedged. On the next poll
it re-fetches and verifies the authoritative bundle for its current audience.

## `follower reset-replay-state`

`follower reset-replay-state` is an offline follower-side recovery command for a
wedged remote-kill replay state. Use it when the follower reports:

> conductor remote kill replay state missing while follower context is present; run: pipelock conductor follower reset-replay-state --state-dir <conductor.bundle_cache_dir> --confirm

This happens when the follower's enrollment context exists but the corresponding
replay-state file is missing or corrupt (e.g., after a partial disk recovery or
an interrupted enrollment).

The command rewrites the follower's local remote-kill replay state to a clean
baseline. On the next poll the follower re-syncs the authoritative kill state
from the Conductor.

Dry run (default):

```sh
pipelock conductor follower reset-replay-state \
  --state-dir /var/lib/pipelock/bundles
```

Apply:

```sh
pipelock conductor follower reset-replay-state \
  --state-dir /var/lib/pipelock/bundles \
  --confirm
```

`--state-dir` is the same directory as `conductor.bundle_cache_dir` in the
follower config. Without `--confirm`, the command prints what it would do and
exits without modifying state (fail-closed dry run).

## `rollback clear`

Clear a single active rollback authorization by its `authorization_id`. This is
an admin-only operation that lets the operator unblock forward publishes without
waiting for the rollback TTL to expire.

```sh
pipelock conductor rollback clear \
  --authorization-id rollback-42-to-41-100 \
  --confirm \
  --server https://conductor.example:8895 \
  --token-file admin.token \
  --client-cert client.crt --client-key client.key --ca-file ca.pem
```

The `--confirm` flag is mandatory. Without it, the command refuses to run (fail
closed).

## `kill status`

A read-only alias that surfaces active remote-kill messages from the Conductor's
stream-status endpoint. No new server endpoint is needed; this is a CLI
convenience that filters the existing stream-status response to just the kill
state.

```sh
pipelock conductor kill status \
  --org-id acme --fleet-id prod \
  --server https://conductor.example:8895 \
  --token-file admin.token \
  --client-cert client.crt --client-key client.key --ca-file ca.pem
```

Use `--json` for the raw JSON response.

## `store dump`

A read-only dump of the Conductor's stream overview (streams, bundle chains,
emergency controls) as pretty-printed JSON for support and debugging. No state
is modified.

```sh
pipelock conductor store dump \
  --org-id acme --fleet-id prod \
  --server https://conductor.example:8895 \
  --token-file admin.token \
  --client-cert client.crt --client-key client.key --ca-file ca.pem
```

## `store inspect-offline` and `store repair` (offline recovery)

`store dump`, `stream inspect`, `stream status`, and `stream reset` are all
client-side: they require a live Conductor reachable over mTLS. If a corrupt
bundle store crashes the Conductor at startup, none of those live-server commands
can run, so recovery needs an offline path.

`store inspect-offline` and `store repair` operate directly on `--storage-dir`
with **no running server**. `--storage-dir` is the same directory passed to
`conductor serve`; the policy-bundle store lives under its `policy-bundles/`
subdirectory.

### `store inspect-offline`

Read-only analysis of the on-disk bundle store. Reports each stream's head and
chain, any record files that could not be parsed, and any provably-orphaned
records that would fail startup validation. Always exits without modifying state.

```sh
pipelock conductor store inspect-offline --storage-dir /var/lib/pipelock/conductor
```

An *orphaned* record is one that is NOT reachable from its stream's head, NOT
covered by a durable rollback marker, and NOT a tolerated historical fork sibling
(a branch abandoned by an authorized rollback-then-publish cycle, which the store
loads as audit history). Add `--json` for machine-readable output.

### `store repair`

Removes provably-orphaned records to unbrick startup. It mirrors the safety
posture of `stream reset`:

- **Without `--confirm` it is a dry run**: it lists what it would remove and
  changes nothing.

```sh
pipelock conductor store repair --storage-dir /var/lib/pipelock/conductor
```

- **With `--confirm` it removes the orphans**, copying each removed record to a
  backup directory first (default
  `<storage-dir>/policy-bundles/offline-repair-backup/<timestamp>`; override with
  `--backup-dir`).

```sh
pipelock conductor store repair --storage-dir /var/lib/pipelock/conductor --confirm
```

`store repair` NEVER removes a record reachable from a head, a rollback-covered
record, a tolerated historical fork sibling, an unreadable record, an off-chain
record whose own ancestry chain is corrupt (flagged for manual review), the
stream-head markers, or the audit store. Records flagged for manual review are
reported but left in place for the operator to investigate.

## Rollback authorization TTL enforcement

The rollback authorization's `expires_at` field (set via `--ttl` at publish time,
default 1 hour) is enforced at every read/apply path:

- **Server-side emergency store reads** (`LatestRollbackAuthorization`,
  `ActiveRollbackForFollower`) call `ValidateAtTime(now)` and skip expired
  records.
- **Server-side stream-status display** calls `ValidateAtTime(now)` and omits
  expired authorizations from the active list.
- **Follower-side applycache** calls `ValidateAtTime(now)` and rejects expired
  rollback authorizations before applying them.

An expired rollback authorization stops affecting followers without operator
intervention. Use `rollback clear` to remove an authorization before its TTL
expires.

## See also

- [`pipelock conductor stream`](conductor-stream.md) -- stream observability.
- [Conductor operator runbook](../guides/conductor-operator-runbook.md) --
  publish, kill, rollback, and bootstrap workflows.
