# Using Pipelock with VS Code

Unlike Cursor and Claude Code, which use a hook, VS Code integration wraps MCP servers through Pipelock's MCP proxy the same way Cline and Continue do. Every tool call, response, and description is scanned bidirectionally.

## Quick start

```bash
pipelock generate config --preset balanced -o pipelock.yaml
pipelock vscode install --config "$PWD/pipelock.yaml" --dry-run
pipelock vscode install --config "$PWD/pipelock.yaml"
```

By default this rewrites `.vscode/mcp.json` in the current directory (project-level). Pass `--global` to target the VS Code user-level `mcp.json` instead. If `mcp.json` already exists, servers are wrapped in place; an already-wrapped server is skipped (install is idempotent), and a `.bak` backup is written before any change. Non-server fields such as `inputs` and `sandbox` are preserved. Re-running after upgrading Pipelock also recovers and re-wraps an older Pipelock-authored entry using the current binary's invocation shape; an entry it cannot safely normalize is refused with a message identifying the file and entry, and nothing is changed.

Stdio servers get their `command` and `args` rewritten to launch through `pipelock mcp proxy`. HTTP and SSE servers are converted to a stdio entry that launches the proxy with `--upstream` pointed at the original URL.

## Environment variables

VS Code resolves `${input:...}` and `${env:...}` substitutions in a server's `env` block at launch, so the installer leaves that resolution to VS Code. Each `env` entry moves into the wrapped entry's own `env` block under a generated `PIPELOCK_VSCODE_ENV_<hash>` name, and the proxy's arguments map it back with `--env-carrier <KEY>=<CARRIER>`. An entry set to `null` becomes `--env-unset <KEY>`, and an `envFile` path is carried the same way with `--env-file-carrier`, so `pipelock mcp proxy` reads that file at launch. The proxy still starts the child from a stripped environment plus these carried values.

The proxy refuses code-loading and other blocked target names at startup, including entries in `envFile`. Generated carriers preserve VS Code substitution but don't exempt those names. See [child environment restrictions](sandbox.md#child-environment-restrictions) for supported credential passing and startup refusal.

## Remote servers with headers

An HTTP or SSE server's `headers` map is validated at install time, not at launch: an empty or non-string header value, a header name with invalid characters, or a value with invalid characters (control characters other than tab) fails the install with an error naming the header, rather than surfacing only after the agent starts. Headers that VS Code's own HTTP/SSE transport manages (`Content-Type`, `Accept`, `Mcp-Session-Id`, `Content-Length`, `Transfer-Encoding`, `Host`) are refused, because they cannot be passed through.

A header value that contains a VS Code substitution (`${...}`) is carried the same way as `env`, with `--header-carrier <Header>=<CARRIER>`, so VS Code still resolves it at launch. Every other valid header is written to an operator-private (`0700`) sidecar file, one `Key: Value` line per header, and the wrapped server's launch args add `--header-file` pointing at it. The original `url` and `headers` are preserved in the `_pipelock` metadata so `remove` can restore them.

## Previewing and removing

```bash
pipelock vscode install --config "$PWD/pipelock.yaml" --dry-run
pipelock vscode remove --dry-run
pipelock vscode remove
```

`remove` takes the same `--global`/`--project` scoping as install. It restores each wrapped server from its `_pipelock` metadata field and deletes any header sidecar file for that server only after the restored config has been written successfully, so a later failure cannot leave a still-wrapped config on disk with its credential carrier already gone. Non-wrapped servers are left unchanged.

## What gets scanned

| Direction | Content |
|---|---|
| VS Code → MCP server | Tool-call arguments, DLP and policy checks |
| MCP server → VS Code | Tool results and response-injection checks |
| MCP definitions | Poisoned descriptions and schema changes |

## See also

- [Claude Code guide](claude-code.md)
- [Cursor guide](cursor.md)
- [Cline guide](cline.md)
