# Route T3 Code MCP tools through Pipelock

T3 Code can launch an operator-selected stdio wrapper for its built-in MCP
server. Pipelock can be that wrapper: it scans tool arguments, tool definitions,
and responses between a provider and T3's MCP endpoint.

This is an opt-in, prerelease integration. It requires the implementation in
[T3 Code PR #15273](https://github.com/pingdotgg/t3code/pull/15273). The T3 setting
is vendor-neutral and does not require Pipelock.

## Requirements and tested scope

Use a Pipelock build containing the T3 compatibility fixes in
[#1778](https://github.com/luckyPipewrench/pipelock/pull/1778),
[#1780](https://github.com/luckyPipewrench/pipelock/pull/1780),
[#1787](https://github.com/luckyPipewrench/pipelock/pull/1787), and
[#1792](https://github.com/luckyPipewrench/pipelock/pull/1792).
These fixes are absent from v3.6.0. Do not assume that installing v3.6.0 is
equivalent to this setup.

The Linux setup below was exercised with T3 revision `3fb5ae602c` and a Pipelock
development binary reporting revision `eb1ed809f`. Claude and Codex both
completed a T3-owned child task, received its completion, and passed T3's live
verifier restart check. A separate protocol probe retrieved 80 tools, completed
a normal capabilities call, and received a Pipelock `dlp_match` refusal for a
synthetic credential in tool arguments. This is integration evidence, not a
release-candidate certification.

The shell instructions require a Unix host with `pipelock` on the T3 server's
`PATH`. Windows installation and provider-version combinations beyond these
live checks need separate verification.

## Install the wrapper

Create a private wrapper directory:

```sh
install -d -m 700 "$HOME/.local/libexec"
```

Save the following as `$HOME/.local/libexec/t3-pipelock`:

```sh
#!/bin/sh
set -eu
umask 077

: "${T3_MCP_URL:?T3 must supply its MCP endpoint}"
: "${T3_MCP_AUTHORIZATION:?T3 must supply its session authorization}"

headers=$(mktemp)
proxy_pid=
cleanup() {
  trap '' HUP INT TERM
  if [ -n "$proxy_pid" ]; then
    kill -TERM "$proxy_pid" 2>/dev/null || :
    wait "$proxy_pid" 2>/dev/null || :
  fi
  rm -f -- "$headers"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
printf 'Authorization: %s\n' "$T3_MCP_AUTHORIZATION" > "$headers"

pipelock mcp proxy \
  --upstream "$T3_MCP_URL" \
  --header-file "$headers" \
  --header 'MCP-Protocol-Version: 2025-06-18' \
  --server-name t3-code <&0 &
proxy_pid=$!
wait "$proxy_pid"
```

Then make it executable and configure the environment of the process that
starts the T3 server:

```sh
chmod 700 "$HOME/.local/libexec/t3-pipelock"
export T3_MCP_STDIO_WRAPPER="$HOME/.local/libexec/t3-pipelock"
```

Restart T3 from that environment. Setting the variable in an agent's terminal
after T3 has started does not configure the server. For a service-managed T3
installation, put the absolute wrapper path in the service's environment.

T3 supplies the endpoint and bearer value separately for each provider session.
The wrapper puts the authorization header in an owner-only temporary file,
keeping the credential out of process arguments. It removes the file on normal
exit and handled signals, stopping and waiting for the proxy child first.
The explicit stdin redirection keeps MCP input connected to the background
child. Configure the service supervisor to stop the whole process group too;
shell traps cannot guarantee cleanup during every launch-time race or if the
child does not terminate. A forced kill or host crash can leave the temporary
file behind; treat the temporary directory as credential-bearing storage.
Do not enable shell tracing or copy these values into logs.

The explicit protocol header matters. The tested T3 endpoint negotiates
`2025-06-18` and rejects subsequent requests without that header. Recheck this
value when upgrading T3. Do not assume Pipelock automatically propagates the
negotiated protocol version in this configuration.

`--header-carrier` is intended for Pipelock's VS Code carrier namespace; it does
not accept `T3_MCP_AUTHORIZATION` directly. Use the header file above.

## Verify the path

Start a fresh Claude or Codex session and request a harmless T3 operation such
as listing the available orchestration capabilities. Confirm that a Pipelock
MCP proxy process starts and the provider invokes the T3 MCP tool. A successful
answer alone is insufficient: a provider can use native tools or the direct
HTTP endpoint instead.

For a source checkout of the tested T3 revision, the existing
`apps/server/scripts/verify-background-live.ts` verifier exercises app-owned
delegation and completion with disposable T3 state. Run its `idle` scenario
with the wrapper environment configured, using an installed, authenticated
provider and a model available to that provider. It rejects native delegation
as the wrong path. Preserve its verdict and exact binary/revision identities.

Pipelock auto-enables MCP input, tool-definition, and tool-policy scanning when
no explicit configuration overrides them. The effective no-config actions are
input `block`, response `warn`, tool definitions `warn`, and tool policy
`warn`. The routing checks above do not establish each scanner's behavior.
Send scanner-specific MCP probes through the wrapper and check the results:

- An ordinary capabilities call succeeds.
- A tool argument containing a synthetic credential is refused by input DLP
  with `dlp_match`, before the upstream tool executes.
- A tool definition matching a tool-scanning rule produces the expected warning.
- A call matching a tool-policy rule produces the configured policy decision.
- Under the no-config defaults, a tool response matching a response-scanning
  rule produces a warning and is forwarded.
- To test response blocking, explicitly set `response_scanning.action: block`
  in the configuration passed to the wrapper with `--config`. Repeat the probe
  and confirm the matching response content does not reach the provider.

Use synthetic fixtures, never real credentials. Exercise tool-definition,
tool-policy, and response probes against a disposable test MCP server through
the same wrapper and configuration; do not alter a live T3 tool or execute a
dangerous operation to trigger a rule. A warning is not a block. Preserve the
matched rule, configured action, and observed result for each check.

If you add `--config` to the wrapper, validate that configuration and repeat
these probes against its expected actions. Do not silently disable scanning
to fix a tool discovery failure. See [false-positive tuning](false-positive-tuning.md).

## Troubleshooting

| Symptom | Check |
|---|---|
| T3 refuses startup | The wrapper path must be absolute, executable, and correctly quoted. |
| Provider reports a closed MCP connection | Run the wrapper with synthetic endpoint/authorization values and inspect stderr; keep stdout reserved for MCP messages. |
| Upstream HTTP 400 after initialization | Check the explicit `MCP-Protocol-Version` header against T3's negotiated version. |
| Warning about `request_secret` tool text | Inspect the reported rule and configured action; the tested default tool-definition action warns. A warning is not proof that the tool was blocked. |
| Pi refuses the session | The tested Pi adapter does not support this stdio path. |
| External OpenCode refuses the session | A remote OpenCode server cannot launch the wrapper on the T3 server's machine. Use a supported local provider. |

## Security boundary

This setup mediates the T3 MCP traffic that providers send through the wrapper.
It does not cover all provider network traffic, shell commands, other MCP
servers, or browser traffic. It does not make credentials inaccessible to the
provider. The selected wrapper receives an existing session credential and
must be trusted with that credential and the tool traffic.

An agent with access to the endpoint credential can connect directly. Mandatory
mediation needs operating-system or network isolation and restrictions on
direct endpoint access. Credential isolation is a separate design problem.
Do not describe this setting as a sandbox or as guaranteed exfiltration
prevention.
