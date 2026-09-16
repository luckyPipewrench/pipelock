# Using Pipelock with Continue.dev

Continue.dev loads MCP servers from `~/.continue/config.yaml` and standalone YAML blocks in `~/.continue/mcpServers/`. Pipelock rewrites those entries so calls and responses pass through `pipelock mcp proxy`.

## Quick start

```bash
pipelock generate config --preset balanced -o pipelock.yaml
pipelock continue install --config "$PWD/pipelock.yaml" --dry-run
pipelock continue install --config "$PWD/pipelock.yaml"
```

Restart Continue after installation and run a harmless tool action to confirm the server connects. The installer wraps local `command`/`args` servers and remote `url` servers without custom headers, and it is idempotent.

## Remote servers with headers

The Continue installer refuses remote entries with nonempty `headers` because its generated launch doesn't forward those headers. The error identifies the file and server entry. Installation and dry runs stop before changing any configuration or backup, including when the entry is in a standalone YAML block. Empty or null header mappings don't affect wrapping.

Use a manual `pipelock mcp proxy` wrapper for a remote server that needs authentication headers. Store one `Header-Name: value` per line in a private file with `0o600` permissions. In the Continue entry, set `type` to `stdio` and `command` to Pipelock's absolute executable path. Set `args` to `mcp`, `proxy`, `--header-file`, the header file's absolute path, `--upstream`, and the server URL. Include `--config` and its path when using a custom Pipelock configuration. The manual stdio entry replaces the remote `url` and `headers` fields; header values belong only in the private file.

An older installer may have left a `headers` field beside an already-wrapped remote command. Installing again refuses that entry without nesting another proxy or removing its headers, even when the executable path hasn't changed. Preserve the original configuration or backup while converting it to a manual wrapper.

## Configuration files

By default the installer reads the global YAML configuration and every `.yaml` or `.yml` file in the global MCP block directory. Use `--path` for another `config.yaml` and `--mcp-dir` for another block directory.

Continue's legacy `~/.continue/config.json` is deprecated. When `config.yaml` is present, Continue loads it instead, so the installer wraps YAML and notes that the JSON file is ignored. When only the legacy file exists, the installer refuses: rename or remove it before creating `config.yaml`, because wrapping JSON would be inert.

The installer preserves sibling top-level keys, their order, and comments outside the rewritten MCP server entries. Formatting or comments inside an entry it rewrites may shift. Unknown YAML fields on the document and server entries are preserved.

## Previewing and removing

```bash
pipelock continue install --config "$PWD/pipelock.yaml" --dry-run
pipelock continue remove --dry-run
pipelock continue remove
```

Each changed file receives a `0o600` `.bak` backup. Removal restores only entries carrying valid Pipelock metadata; unrelated servers stay intact.

## What gets scanned

| Direction | Content |
|---|---|
| Continue → MCP server | Tool-call arguments, DLP and policy checks |
| MCP server → Continue | Tool results and response-injection checks |
| MCP definitions | Poisoned descriptions and schema changes |

For remote examples, use neutral endpoints such as `https://api.vendor.example/mcp`.

## See also

- [Cline guide](cline.md)
- [OpenCode guide](opencode.md)
- [Receipt verification](receipt-verification.md)
