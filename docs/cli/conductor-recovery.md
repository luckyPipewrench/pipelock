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
