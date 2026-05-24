# Pipelock plugin for Hermes Agent

Installed by `pipelock hermes install`. Registers five hooks:

| Hook | Purpose |
|------|---------|
| `pre_tool_call` | DLP + prompt-injection scan on tool arguments; can block |
| `transform_tool_result` | DLP + response-injection scan on tool output; can redact |
| `pre_gateway_dispatch` | DLP + injection scan on inbound messaging-gateway text |
| `on_session_start` | Observer — surfaces session start to the pipelock audit channel |
| `on_session_end` | Observer — surfaces session end + completion flags |

## Wire protocol

Each hook subprocess-execs `pipelock-hermes-hook` with the same JSON-over-
stdin/stdout schema Hermes uses for its native shell hooks. The binary loads
pipelock's scanner configuration, runs the relevant scan pipeline, and emits
`{"decision": "block", "reason": "..."}` or `{}` on stdout.

Fail-closed: timeout, missing binary, malformed response, empty stdout,
non-zero exit, or stdin larger than the binary's 4 MiB payload cap all become
block decisions. This matches pipelock's invariant that ambiguity must not
unblock the agent.

## Environment overrides

- `PIPELOCK_HERMES_HOOK_BIN` — full path to the `pipelock-hermes-hook` binary.
  Required if the binary is not on `PATH`.
- `PIPELOCK_HERMES_HOOK_CONFIG` — pipelock config file path. Passed as
  `--config` to every binary invocation. If unset, the binary uses pipelock's
  built-in defaults.

## Reinstalling

Re-run `pipelock hermes install`. The installer is idempotent: existing files
are rotated to `.bak` before being overwritten.
