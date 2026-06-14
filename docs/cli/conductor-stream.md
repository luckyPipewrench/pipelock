# `pipelock conductor stream`

`pipelock conductor stream` inspects the Conductor's publication-stream state for
an org (and optional fleet): each stream's effective head, the monotonicity gate
(max-ever published version), the ordered bundle chain, and the active emergency
controls (remote kills and rollback authorizations) currently in scope.

It is a read-only operator overview. It reports **stream topology only**. See the
[honesty note](#honesty-what-this-does-not-report) below for what it deliberately
does not claim.

These are Enterprise commands and require a license with the `fleet` feature.

```sh
pipelock conductor stream status  --org-id acme
pipelock conductor stream status  --org-id acme --fleet-id prod
pipelock conductor stream inspect --org-id acme --fleet-id prod
```

## Subcommands

| Subcommand | Output |
|---|---|
| `status` | A human-readable table of streams plus active emergency controls. Add `--json` for the raw response. |
| `inspect` | Always emits the raw JSON response, including every stream's complete bundle chain (`bundle_id`, `version`, `bundle_hash`, `previous_bundle_hash`, `created_at`, `min_pipelock_version`, `published_at`). Identical authorization and scope to `status`. |
| `reset` | Clear all active rollback authorizations for an org/fleet scope. Requires `--confirm` (refuses without it). See [Stream reset](#stream-reset). |

## Authorization and scope

`status` and `inspect` call the same control-plane endpoint and enforce the same
scope. The request must carry a bearer token bound to a Conductor **admin** or
**auditor** role whose org (and fleet, when the token is fleet-scoped) matches the
query. The authorizer binds the caller's credential scope to the requested
org/fleet **before** any store is touched, and fails closed: an unconfigured
authorizer, a missing token, or a cross-org/cross-fleet request is denied with
`403 Forbidden`.

`--org-id` is required: the read is never globally unscoped. `--fleet-id` is
optional; when supplied, results are narrowed to that fleet (and identifiers are
validated before the store is read).

## The endpoint

Both subcommands issue a single request:

```http
GET /api/v1/conductor/stream?org_id=<org>&fleet_id=<fleet>
```

`fleet_id` is omitted from the query string when no `--fleet-id` is given. Only
`org_id` and `fleet_id` are accepted; any other query parameter, or a duplicated
parameter, is rejected with `400 Bad Request`. The method must be `GET`.

## Response fields

The endpoint returns a JSON object:

| Field | Meaning |
|---|---|
| `org_id` | The org the read was scoped to. |
| `fleet_id` | The fleet the read was scoped to (omitted when the query was org-wide). |
| `stream_count` | Number of publication streams matching the scope. |
| `streams` | Array of per-stream summaries (below). |
| `active_remote_kills` | Currently-valid remote kills in scope whose state is `active` (below). Always present, possibly empty. |
| `active_rollback_authorizations` | Currently-valid rollback authorizations in scope (below). Always present, possibly empty. |
| `emergency_controls_read` | Whether the configured emergency store could be enumerated. See [Fail-loud emergency controls](#fail-loud-emergency-controls). |

### `streams[]`

| Field | Meaning |
|---|---|
| `stream_key` | Internal key identifying the stream. |
| `org_id` / `fleet_id` / `environment` | The stream's scope. |
| `audience` | The audience selector (instance IDs) the stream publishes to. |
| `head_version` | The effective head version (capped below `max_version` when an active rollback applies). |
| `head_bundle_id` / `head_bundle_hash` | Identity and content hash of the effective head bundle. In the table the hash is truncated; the full hash is in `inspect` / `--json`. |
| `max_version` | The max-ever published version — the monotonicity gate. A new publish must exceed this. |
| `rolled_back` | `true` when an active rollback marker currently caps the effective head below `max_version`. |
| `bundle_chain` | Ordered (ascending by version) list of every stored bundle record for the stream, including records superseded by a durable rollback marker (they remain on disk as audit history). |

### `active_remote_kills[]`

| Field | Meaning |
|---|---|
| `message_id` / `message_hash` | Identity and content hash of the kill message. |
| `org_id` / `fleet_id` / `audience` | The kill's scope. |
| `state` | The kill-switch state the message asserts. This list only includes `active` messages; fresh `inactive` resume messages are not reported as active kills. |
| `counter` | Replay counter. |
| `reason` | Operator-supplied reason. |
| `not_before` / `expires_at` | The validity window. Only kills valid at the current time are listed. |
| `published_at` | When the control plane stored the kill. |

### `active_rollback_authorizations[]`

| Field | Meaning |
|---|---|
| `authorization_id` / `authorization_hash` | Identity and content hash of the authorization. |
| `org_id` / `fleet_id` / `audience` | The authorization's scope. |
| `current_bundle_id` / `current_version` | The version the authorization rolls back **from**. |
| `target_bundle_id` / `target_version` | The version the authorization rolls back **to**. |
| `counter` | Replay counter. |
| `reason` | Operator-supplied reason. |
| `created_at` / `expires_at` | The validity-window start and end. Only authorizations valid at the current time are listed; `created_at` lets an operator see when the window opened and compute its duration. |
| `published_at` | When the control plane stored the authorization. |

## Fail-loud emergency controls

`emergency_controls_read` reports whether the configured emergency store could be
enumerated. The `status` table surfaces it explicitly so an empty kill/rollback
list is never mistaken for "nothing active":

- When the store could **not** be read, the table prints
  `emergency controls: NOT AVAILABLE (kill/rollback list may be incomplete)`.
- When the store was read and there are no active kills or rollbacks, the table
  prints `emergency controls: none active`.

An unreadable store is not an empty store: the warning replaces — never coexists
with — the "none active" line. `--json` always carries the
`emergency_controls_read` boolean directly.

## Honesty: what this does NOT report

This overview reports stream topology only. It does **not** report **per-follower
applied bundle version** or **drift**, because the Conductor does not track which
version each enrolled follower has actually applied — reporting it would be a
fabrication. The follower-derived figure the Conductor does track is the enrolled
roster, which is reported by a separate command:

```sh
pipelock conductor fleet status --org-id acme
```

Use `conductor fleet status` for the enrolled-follower roster; use `conductor
stream status` for the publication-stream head, monotonicity gate, bundle chain,
and active emergency controls.

## Flags

| Flag | Default | Purpose |
|---|---|---|
| `--org-id` | (required) | Org to query. |
| `--fleet-id` | (org-wide) | Narrow the query to a single fleet. |
| `--json` | `false` (always `true` for `inspect`) | Emit the raw JSON response instead of a table. |

Connection flags (control-plane address, token file, CA, license CRL) are shared
with the other `conductor` subcommands; run `pipelock conductor stream status
--help` for the full list.

## Stream reset

`pipelock conductor stream reset` is a guarded, destructive admin operation that
clears all active (non-expired) rollback authorizations for the given org/fleet
scope. It fetches the stream status to discover active rollback authorizations,
then deletes each one via the Conductor's DELETE endpoint.

```sh
pipelock conductor stream reset --org-id acme --fleet-id prod --confirm
```

The `--confirm` flag is mandatory; the command refuses to run without it. Prefer
`pipelock conductor rollback clear --authorization-id <id>` to remove a single
rollback authorization rather than clearing all of them.

The command also fails closed if stream status cannot read emergency controls.
In that case it aborts before deleting any rollback authorization, so operators
do not get a partial reset from incomplete control-plane state.

## See also

- [`pipelock conductor fleet status`](../guides/conductor.md) — the enrolled-follower roster.
- [Conductor operator runbook](../guides/conductor-operator-runbook.md) — publish, kill, and rollback workflows.
