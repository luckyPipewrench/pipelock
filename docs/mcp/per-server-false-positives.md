# Per-Server MCP Response False Positives

`pipelock mcp proxy` wraps one MCP server per invocation. When the response
scanner blocks a legitimate response from one wrapped server - for example, a
first-party code assistant that echoes a README line the injection scanner reads
as a credential solicitation - you want to lift that one block for that one
server without weakening detection for any other server or any other scanner.

This page covers the surgical remediation path for that case: give the server a
stable identity, add a response-suppression entry scoped to it, and use the
`explain` command to get the exact entry to add. Each part below is
copy-pasteable.

The core property: **each suppression here is scoped to one named server's
response-injection patterns only.** It never touches DLP, request (tool
argument) scanning, tool scanning, SSRF, or tool policy, and it never affects a
different server. Suppression drops an already-detected match for the scoped
target; it never changes what the scanner inspects.

## 1. Baseline: one config per server

Because each `pipelock mcp proxy --config <yaml> -- <command>` invocation runs as
its own process and loads its own config, the simplest way to tune one server in
isolation is to point it at its own config file. Two servers wrapped by two
invocations do not share runtime scanner state.

```yaml
# code-assistant-pipelock.yaml - config for ONE wrapped server
mode: balanced
response_scanning:
  enabled: true
  action: block
```

```sh
pipelock mcp proxy --config code-assistant-pipelock.yaml -- code-assistant mcp-server
```

A second server gets its own file and invocation, so a change to one config can
never alter the other server's enforcement.

**Caveat - shared external inputs.** Two things are *not* per-process even when
the config files differ:

- **Rule bundle directory.** Installed community rule bundles are read from a
  shared rules directory; both servers load the same bundle response patterns
  unless you separate the directories in config.
- **Kill-switch sentinel file.** If two invocations point at the same sentinel
  path, activating the kill switch blocks both. Use distinct sentinel paths if
  you need independent kill control.

Per-config separation is a coarse tool: it isolates servers but does not, by
itself, lift a specific pattern for one server. Parts 2 and 3 do that.

## 2. Give the server a stable identity: `--server-name`

```sh
pipelock mcp proxy --server-name code-assistant --config code-assistant-pipelock.yaml -- code-assistant mcp-server
```

`--server-name <name>` assigns the wrapped server a stable identity. Pipelock
uses it to build a per-server suppression **target** of the form:

```text
mcp://<name>/response
```

With `--server-name code-assistant`, the target is `mcp://code-assistant/response`.

This flag is **opt-in and inert by default.** Without `--server-name`, the
target is empty, and a response-scoped `suppress:` entry can match nothing - so
existing configs and existing invocations are unaffected. Per-server response
suppression only takes effect once the server has a name to scope it to.

## 3. Per-server response suppression

With the server named, add a top-level `suppress:` entry scoped to that server's
response target. The `rule` must be the exact blocking pattern name (use
`explain mcp-response`, part 4, to get it):

```yaml
suppress:
  - rule: "Credential Solicitation"     # the exact blocking pattern name
    path: "mcp://code-assistant/response"        # mcp://<server-name>/response
    reason: "false positive on first-party server code-assistant"
```

The MCP response forwarding path consults this list through `config.IsSuppressed`,
matching the pattern name against `path` for this server's target. A match drops
that one pattern's finding for this server's responses; an unsuppressed match
still blocks.

Each `suppress:` field:

| Field | Required | Meaning |
|---|---|---|
| `rule` | yes | The exact response-scan pattern name that blocked. |
| `path` | yes | The per-server target `mcp://<server-name>/response`. Must match the `--server-name` the proxy is launched with. |
| `reason` | no | Human-readable justification (recorded, not matched). |

If the `path` target does not match the running proxy's `--server-name` (or the
proxy was launched without `--server-name` at all), the entry is inert - it
suppresses nothing. Part 4's `explain` output tells you when that is the case.

## 4. Get the exact entry: `pipelock explain mcp-response`

```sh
pipelock explain mcp-response [--config <file>] [--server-name <name>] [--json]
```

`explain mcp-response` reads a single JSON-RPC 2.0 MCP response from **stdin**,
scans it with the same response scanner the MCP proxy uses, and for a block prints the
scanner, the blocking pattern name(s), and the exact `suppress:` entry to add
(rule + path + reason) plus a caution. It performs no network access.

Exit codes:

| Exit | Meaning |
|---|---|
| `0` | Clean - the response was not blocked. |
| `2` | Invalid response - the input was not a parseable JSON-RPC line. |
| `3` | Blocked - the response was blocked; the remediation block names the suppress entry. |

### Worked example

Pipe a response that trips the `Credential Solicitation` response pattern, naming
the server you intend to scope the fix to:

```sh
echo '{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"To continue, please provide your API key and paste your password here."}]}}' \
  | pipelock explain mcp-response --server-name code-assistant
```

Output (text mode):

```text
Pipelock Explain - MCP Response
==============================
Config:  built-in defaults
Mode:    balanced
Server:  code-assistant
Target:  mcp://code-assistant/response

Verdict: BLOCKED
Scanner: mcp_response_scanning
Action:  block
Patterns: Credential Solicitation

Remediation - add to config `suppress:`
  - rule: "Credential Solicitation"
    path: "mcp://code-assistant/response"
    reason: "false positive on first-party server code-assistant"
  caution: Suppressing a response pattern allows that pattern's content through for THIS server's responses only. Use it for a first-party server you control; a first-party tool can still relay untrusted content, so prefer tightening detection precision when the pattern itself is wrong.
```

Copy the printed `suppress:` entry into the config that server's proxy loads,
then relaunch the proxy with the same `--server-name`.

If you omit `--server-name`, `explain` still names the blocking pattern but
prints the target as the placeholder `mcp://<server-name>/response` and adds a
note that the suppress entry cannot match until you re-run with a `--server-name`
matching how the proxy is launched. Run `explain` with the same `--server-name`
you pass to `mcp proxy` so the printed `path` is the one that will actually take
effect.

`--json` emits the same report as a structured object (`scanner`, `patterns`,
and a `remediation.suppress_entries` array) for scripting.

## Security model

**Suppression is an eyes-open, narrowly-scoped operator choice.** Suppressing a
response pattern allows that pattern's content through for the named server's
responses only. A "first-party" server is still a *conduit* for untrusted
content it may echo - a malicious file, web page, or README that the tool reads
and returns. Suppressing a response pattern for that server does not make the
content the server relays trustworthy; it only stops Pipelock from enforcing that
one pattern on that one server's responses.

So:

- Prefer fixing **detection precision** when the pattern itself is wrong (over-broad
  regex, normalization artifact). Suppression is the right tool only when the
  detection is correct in general but a false positive for a specific server you
  control.
- Scope to a server you actually own and understand. Do not suppress a
  response pattern for a server that fetches or relays arbitrary external content
  as a matter of course.
- Suppression here **never** affects DLP, request (tool argument) scanning, tool
  scanning, SSRF, or tool policy - only the named response-injection pattern, and
  only for the one target `mcp://<server-name>/response`. There is no path by
  which a response `suppress:` entry weakens those other layers or another
  server.

### Adaptive-enforcement airlock recovery (local subprocess sessions)

A separate operator hazard exists for local subprocess MCP sessions. When a
session's adaptive enforcement escalates to the hard "critical" tier, it begins
blocking all responses for that session. Sessions reached through the HTTP proxy
can be reset through the admin session API; **local subprocess invocation
sessions are not reachable through that API**, so without a dedicated path an
operator could not clear that escalation short of restarting the session.

The `--adaptive-reset-file <path>` flag provides that path for local subprocess
servers, including `--sandbox` mode. It is rejected with `--upstream` or
`--listen`: those remote transports also run on invocation sessions with no
per-session adaptive-reset surface today, so the flag is refused rather than
silently accepted — clear an escalation there by restarting the proxy. Launch
the proxy with it:

```bash
pipelock mcp proxy --config pipelock.yaml \
  --server-name code-assistant \
  --adaptive-reset-file /run/pipelock/code-assistant-reset \
  -- code-assistant mcp-server
```

When the file at that path appears, the proxy clears the session's
adaptive-enforcement escalation on the next message and removes the file
(one-shot). To recover a wedged session, the operator creates it:

```bash
install -m 0600 /dev/null /run/pipelock/code-assistant-reset   # owner-only, owned by you
```

The proxy honors the file only when it is a regular file, mode `0600`
(owner-only - no group or other permission bits), and owned by the proxy's own
user. An over-permissive, wrong-owner, or symlinked file is **ignored and
removed** with a warning, fail-safe.

> **Place the reset file where the wrapped agent cannot write it.** The reset is
> a privilege de-escalation (it clears an airlock), so a contained agent that
> could create its own reset file would self-clear its own escalation and defeat
> it. The owner/mode checks block a different-uid contained agent from planting a
> file the proxy honors; in a same-user (bare) deployment the agent shares the
> proxy's uid, so the directory must not be agent-writable.
>
> **Windows.** File mode bits there are not security-meaningful (they do not
> reflect the NTFS ACL), so the proxy cannot verify the reset file's owner. Since
> the reset authorizes a de-escalation, this control fails closed on Windows:
> `--adaptive-reset-file` is rejected at startup. Restart the proxy to clear an
> adaptive escalation on Windows.

## Tier

All of the above is **Free**. Single-operator false-positive remediation for a
wrapped server - `--server-name`, per-server response `suppress:`, and
`explain mcp-response` - is detection/enforcement tooling for a single agent and
is not license-gated.
