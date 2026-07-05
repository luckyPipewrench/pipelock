# pipelock baseline — operator CLI for behavioral baselines

The `pipelock baseline` command group inspects and ratifies learned behavioral-baseline profiles on a running Pipelock instance.

Every subcommand talks to the authenticated admin API. Configure `kill_switch.api_token` and `kill_switch.api_listen`; the baseline admin endpoints (list, show, ratify, forget) are only registered on the dedicated admin API listener, never on the agent-facing proxy port.

| Command | Purpose |
|---------|---------|
| `pipelock baseline list [--json]` | List tracked baseline profiles and lifecycle states |
| `pipelock baseline show <agent> [--json]` | Show learned ranges, retained/observed/trimmed sessions, and ratification state |
| `pipelock baseline ratify <agent> [--json]` | Lock a pending profile so it enforces immediately |
| `pipelock baseline forget <agent> [--json]` | Remove a profile and return the agent to observe/relearn state |

## Resolving the Admin API Endpoint

The baseline commands use the same endpoint resolution as `pipelock session` and `pipelock adaptive`:

1. `--api-url` and `--api-token`
2. `PIPELOCK_API_URL` and `PIPELOCK_KILLSWITCH_API_TOKEN`
3. `--config`, `PIPELOCK_CONFIG`, or the default config search path, reading `kill_switch.api_listen` and `kill_switch.api_token`

Config files used as an admin-token source must be restricted to `0o600`.

## baseline list

```bash
pipelock baseline list
pipelock baseline list --json
```

Lists every tracked baseline profile. The table shows the agent key, lifecycle state, retained training sessions, observed sessions, trimmed sessions, ratification flag, and learned timestamp.

Profiles in `ratify` are ready for operator review. Profiles in `locked` are enforcing. Profiles in `observe` or `learn` are not enforcing yet.

## baseline show

```bash
pipelock baseline show agent-a
pipelock baseline show agent-a --json
```

Shows the approval-grade profile for one agent:

- lifecycle state and ratification timestamp
- retained, observed, and trimmed session counts
- learned min/max/mean/stddev ranges for tool calls, unique tools, domains, bytes, duration, and requests

Use this before ratifying so the operator can see what will become the locked definition of normal behavior.

## baseline ratify

```bash
pipelock baseline ratify agent-a
```

Transitions a profile from `ratify` to `locked`. The running proxy starts enforcing the profile immediately because the command calls the live manager through the admin API.

Ratify fails closed for unknown agents and rejects profiles that are not currently in `ratify`.

## baseline forget

```bash
pipelock baseline forget agent-a
```

Removes the learned profile, deletes its persisted profile JSON, and returns the agent to `observe` so it can relearn. Use this when a profile was ratified by mistake, grew stale, or was learned from suspect traffic.

## Full profile wipe

Use `pipelock baseline forget <agent>` for normal relearning. For an intentional full wipe outside the API, remove the profile directory only if you also clear the trusted integrity key and generation high-water beside it. With the default paths, that means deleting `profile_dir`, `profile_dir.integrity.key`, and `profile_dir.integrity.key.generation` together.

The generation high-water is bound to the accepted manifest identity. Replaying a different signed manifest at the same generation, or restoring a manifest below the accepted generation, fails closed.

If the profile directory is wiped but the trusted integrity state remains, startup fails closed because the signed manifest/high-water still proves Pipelock used to have integrity-bound profiles. That failure is expected; either restore the profiles or complete the wipe by clearing the key-side integrity state.

## Upgrade note: pending ratification profiles

`ratify` profiles are integrity-bound the same way `locked` profiles are. After upgrading from a version that only manifested locked profiles, an old unmanifested pending `ratify` profile under an enforcing `deviation_action` fails startup closed instead of being trusted silently.

Recover by restoring the matching integrity manifest/key/high-water set, or by performing a deliberate full wipe of the profile directory plus the key-side integrity state and letting the agent relearn. Do not copy or hand-edit a pending profile into place without signing it through the normal manager path.

## Exit Codes

The baseline commands use the standard Pipelock admin CLI exit codes:

| Code | Meaning |
|------|---------|
| `0` | Success |
| `1` | Operational failure such as missing profile, rate limit, server error, or network failure |
| `2` | Auth, config, usage, or bad-request failure |
