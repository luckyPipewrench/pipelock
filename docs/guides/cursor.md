# Using Pipelock with Cursor

Cursor does not route MCP traffic through a proxy the way Claude Code, Cline, or VS Code do. Instead it calls out to an external hook before shell commands, MCP tool calls, and file reads. `pipelock cursor install` registers Pipelock as that hook.

## Quick start

```bash
pipelock generate config --preset balanced -o pipelock.yaml
pipelock cursor install --config "$PWD/pipelock.yaml" --dry-run
pipelock cursor install --config "$PWD/pipelock.yaml"
```

By default this writes to `~/.cursor/hooks.json` (user-level). Pass `--project` to write to `.cursor/hooks.json` in the current directory instead; `--global` and `--project` are mutually exclusive. If `hooks.json` already exists, Pipelock's entries are merged in without disturbing other hooks, and a `.bak` backup is written first. Running install twice is idempotent.

Without `--config`, the hook command uses a security-focused default profile (tool policy enabled with several default rules, plus MCP input scanning) that differs from Pipelock's own base defaults, which ship with tool policy disabled. With `--config`, the hook respects every setting in the file, including an explicit `enabled: false` on any feature.

## What gets scanned

| Cursor hook event | What Pipelock evaluates |
|---|---|
| `beforeShellExecution` | The shell command and working directory against tool policy |
| `beforeMCPExecution` | The MCP server name, tool name, and tool input against tool policy and MCP input scanning |
| `beforeReadFile` | The file path and content from the JSON event on stdin |

For `beforeReadFile`, Pipelock reads `hook_event_name`, `file_path`, and `content` from Cursor's JSON event on stdin. The event can also include `conversation_id` and `generation_id`, which Pipelock reads but does not use for the file decision. For example:

```json
{
  "hook_event_name": "beforeReadFile",
  "conversation_id": "conversation-id",
  "generation_id": "generation-id",
  "file_path": "/workspace/notes.txt",
  "content": "Text Cursor is about to read."
}
```

The hook always exits `0`; the `permission` field in its JSON response on stdout is the authoritative allow/deny decision, and diagnostics go to stderr only.

## Bundle load diagnostics

If the loaded config pulls in a rule bundle, `cursor install` reports any bundle load errors or warnings on stderr the same way `pipelock claude setup` does, before writing `hooks.json`.

## Removing

```bash
pipelock cursor remove --dry-run
pipelock cursor remove
```

Removal takes the same `--global`/`--project` scoping as install and only removes Pipelock-managed hook entries; other hooks in the file are left intact.

## Alternative: MCP proxy wrapping

`configs/cursor.yaml` also works with the same manual MCP-proxy wrapping pattern used by [Claude Code](claude-code.md), for operators who would rather route MCP traffic through the proxy directly than rely on the hook.

## See also

- [Claude Code guide](claude-code.md)
- [VS Code guide](vscode.md)
