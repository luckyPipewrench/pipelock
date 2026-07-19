# pipelock session — operator CLI for airlock recovery

The `pipelock session` command group is the operator-facing surface on
top of pipelock's per-session airlock. Use it to inspect sessions that
adaptive enforcement has quarantined, explain why they are in their
current tier, and either release them back to normal or terminate them
entirely.

Every subcommand talks to the running pipelock instance's session admin
API. The admin API is gated by the `kill_switch.api_token` setting — if
you have not set that token, the CLI will refuse to connect. See
[configuration.md](../configuration.md) for the admin API options.

## Quick reference

| Command | Purpose |
|---|---|
| `pipelock session list [--tier hard] [--json]` | Enumerate sessions, optionally filtered by airlock tier |
| `pipelock session inspect <key> [--json]` | Full detail snapshot: tier, entry time, in-flight, recent events |
| `pipelock session risk [<key>] [--json]` | Compact adaptive risk view: score, level, block-all state, and auto-recover ETA |
| `pipelock session explain <key> [--json]` | Why the session is where it is: trigger, evidence, next auto-recovery time |
| `pipelock session release <key> [--to none\|soft]` | Move an airlocked session down to a lower tier |
| `pipelock session terminate <key>` | Destructive: reset enforcement state, cut in-flight connections, clear CEE state |
| `pipelock session recover <key> [--choice ...]` | Interactive workflow: inspect → explain → pick an action |
| `pipelock session deferred list [--json]` | Enumerate held (deferred) MCP actions awaiting an operator decision |
| `pipelock session deferred approve <defer-id>` | Approve a held action (opens it only if its rule permits) |
| `pipelock session deferred deny <defer-id>` | Deny a held action, resolving it closed (blocked) |

## What the tiers mean

Airlock has four tiers. The state machine moves sessions upward in
response to adaptive-enforcement escalations and downward in response
to configured timers or explicit operator action.

| Tier | Who can egress | Typical reason |
|---|---|---|
| `none` | Everyone | Normal steady state |
| `soft` | Everyone (observe-only) | Session crossed a `high` escalation threshold; logging and metrics record all traffic but no enforcement change |
| `hard` | Read methods only (GET/HEAD/OPTIONS) and fetch proxy | Session crossed `critical`; writes are blocked and long-lived connections are torn down |
| `drain` | No one | Operator requested a graceful shutdown or the session hit a drain trigger; in-flight requests complete then the session terminates |

Upward transitions happen automatically when adaptive enforcement
crosses a trigger threshold. Downward transitions happen automatically
when the tier timer expires — for example, `hard_minutes: 15` drops a
hard-tier session back to soft after 15 minutes without further
escalation. Operator commands override both.

## Typical airlock recovery workflow

```sh
# 1. Find quarantined sessions.
pipelock session list --tier hard

# 2. Figure out why one of them is quarantined.
pipelock session explain "agent|10.0.0.1"

# 3. Confirm the threat is resolved before releasing.
pipelock session inspect "agent|10.0.0.1"

# 4. Check adaptive risk and the auto-recover ETA.
pipelock session risk "agent|10.0.0.1"

# 5. Release the session back to normal.
pipelock session release "agent|10.0.0.1" --to none

# Or, if the session cannot be trusted, terminate it.
pipelock session terminate "agent|10.0.0.1"
```

The interactive `pipelock session recover <key>` command runs the
inspect → explain → action portion of this workflow for the supplied
key (it does not perform the discovery/list step above). Use
`--choice release-none|release-soft|terminate|leave` to script the
workflow non-interactively.

## Resolving the admin API endpoint

Every subcommand needs two pieces of config: the admin API URL and the
bearer token. They are resolved in this order:

1. Explicit flags: `--api-url`, `--api-token`
2. Environment variables: `PIPELOCK_API_URL`, `PIPELOCK_KILLSWITCH_API_TOKEN`
3. A pipelock config file, resolved via:
   - `--config` flag
   - `PIPELOCK_CONFIG` environment variable
   - `~/.config/pipelock/pipelock.yaml`
   - `/etc/pipelock/pipelock.yaml`

When the config file is used as the token source, the CLI refuses to
read world- or group-readable files — restrict your token file to
`0600` permissions before running any session command.

## session list

```sh
pipelock session list [--tier none|soft|hard|drain|normal] [--json]
```

Enumerates every session the proxy currently tracks. Default output is
a human-readable table; `--json` returns the raw admin API response.

The `--tier` filter is validated both locally and on the server.
`normal` is accepted as an alias for `none`. Omitting `--tier` returns
all sessions regardless of tier.

## session inspect

```sh
pipelock session inspect <key> [--json]
```

Returns the full `SessionDetail` structure for the session, including
the tier entry time, adaptive escalation level, threat score,
auto-recover ETA, the in-flight request count, and the most recent 20
notable events (blocks, anomalies, and airlock transitions).

## session risk

```sh
pipelock session risk [<key>] [--json]
```

Shows the compact adaptive-enforcement state for one session: threat
score, escalation level, block-all state, auto-recover ETA, and the
operator recovery hint. When `<key>` is omitted, the command calls the
`adaptive whoami` endpoint and reports the risk state for the caller's
own identity session.

The auto-recover ETA is the earliest time the session becomes eligible
to drop one level. The background sweep applies it, so the actual
de-escalation can lag by up to `deescalation_check_seconds`.

## session explain

```sh
pipelock session explain <key> [--json]
```

Walks the operator through the state of the session:

- **tier** / **reason** — where the session sits and why
- **trigger** / **trigger_source** — which configured trigger fired
- **evidence** — the most recent event kind/target/detail that drove
  escalation
- **next_deescalation_tier** / **next_deescalation_at** — when the
  configured timer will automatically drop the tier

Sessions at the `none` tier return a `200` response with the reason
"session not quarantined" plus the most recent event (if any). That
makes it safe to call explain on any session as part of scripted
healthchecks.

## session release

```sh
pipelock session release <key> --to none|soft
```

Moves the session back to a lower tier via the admin API's airlock
endpoint. The `--to` flag accepts `none` (default, fully release),
`normal` (alias for `none`), and `soft` (observe-only). Upward
transitions are not allowed through this command — use the airlock
endpoint directly for upward admin overrides.

## session terminate

```sh
pipelock session terminate <key>
```

Destructive. Resets the session's enforcement state (threat score,
escalation level, airlock tier, block-all flag), fires all registered
cancel funcs so in-flight long-lived connections are torn down,
clears the cross-request entropy tracker and fragment buffer for the
session's agent/IP pair.

Terminate rejects invocation sessions (ephemeral MCP transport keys
like `mcp-stdio-42`) with a `400` error — those contexts are not
safely mutable through the admin API.

## session recover

```sh
pipelock session recover <key> [--choice release-none|release-soft|terminate|leave]
```

Interactive recovery helper. Runs `inspect`, then `explain`, then
prompts for an action. Use `--choice` to skip the prompt in scripts.
The four actions map to:

- `release-none` — `session release --to none`
- `release-soft` — `session release --to soft`
- `terminate` — `session terminate`
- `leave` — no-op confirmation that the session is unchanged

## session deferred

```sh
pipelock session deferred list [--json]
pipelock session deferred approve <defer-id>
pipelock session deferred deny <defer-id>
```

Operate the deferred ("held") action surface. When a tool policy rule uses
`action: defer`, a matching MCP call is held pending an operator decision
instead of being allowed or blocked immediately. These commands list the
pending holds and resolve each one by its defer id.

This surface is only served by a `pipelock mcp proxy` running a defer-capable
transport (MCP stdio or `--upstream` streamable HTTP) **and** configured with a
dedicated operator port via `kill_switch.api_listen` + `kill_switch.api_token`.
Point `--api-url` at that operator port. The deferred routes are never mounted
on the agent-facing/MCP-data port, so a proxied agent can never approve its own
held actions.

- **`list`** returns each hold's identifying fields (defer id, surface, method,
  target, session, cascade depth, reason). It deliberately omits the raw held
  request payload and argument digest — an operator sees *what* is held, not the
  request bytes.
- **`approve`** sends an affirmative decision. It opens the hold **only if the
  matched rule permits approval** (`resolution_policy.allow_on.approval: true`);
  otherwise the hold resolves closed (blocked). The command prints the decision
  actually applied (`approve <id> -> block` when the rule forbids approval), so
  an approve is never a misleading success.
- **`deny`** resolves the hold closed (blocked). Denying a parent hold cascades:
  every held descendant of that action is blocked too.

Resolution is fail-closed: an unknown defer id returns `404` (exit `1`), and a
hold that a concurrent timeout, cascade, or other operator already resolved
returns `409` (exit `1`) rather than reporting a false success.

## Exit codes

The session commands use the standard pipelock exit codes:

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Operational failure (HTTP 404, 429, 500, network error) |
| `2` | Configuration or auth failure (HTTP 401, 400, missing token, bad flags) |

Scripts should retry `1` with back-off and treat `2` as a fix-your-setup
signal that should be surfaced to a human.
