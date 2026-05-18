# pipelock adaptive — operator CLI for adaptive enforcement

The `pipelock adaptive` command group exposes fleet-level adaptive-enforcement
state from the running proxy. Use it when a session escalation looks systemic,
when a cooperative tool burst needs inspection, or when an operator needs to
clear adaptive state without reloading config.

Every subcommand talks to the authenticated admin API. The API URL and bearer
token resolve the same way as `pipelock session`: explicit flags, environment
variables, then the configured `kill_switch.api_listen` and
`kill_switch.api_token`.

## Quick reference

| Command | Purpose |
|---|---|
| `pipelock adaptive status [--json]` | Summarize adaptive state, escalation counts, recent event counts, and top anomalies |
| `pipelock adaptive flush [--json]` | Reset identity-session adaptive state and clear shared IP-domain burst tracking |
| `pipelock adaptive whoami [--json]` | Show how the running proxy classifies the calling client |

## adaptive status

```sh
pipelock adaptive status [--json]
```

Returns whether adaptive enforcement is enabled, how many sessions are tracked,
the highest current escalation level, the active airlock TTL, recent event
counts, and the top recent session anomalies.

## adaptive flush

```sh
pipelock adaptive flush [--json]
```

Resets all identity-session adaptive state: threat scores, escalation levels,
`block_all`, and shared IP-domain burst tracking. Invocation sessions used for
ephemeral MCP transports are skipped.

## adaptive whoami

```sh
pipelock adaptive whoami [--json]
```

Shows the client IP and session key the admin API assigns to the caller. Use it
to confirm which identity a proxy-side operator command will affect.
