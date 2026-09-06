# Using Pipelock with Continue.dev

Continue.dev loads MCP servers from `~/.continue/config.yaml` and standalone YAML blocks in `~/.continue/mcpServers/`. Pipelock rewrites those entries so calls and responses pass through `pipelock mcp proxy`.

## Quick start

```bash
pipelock generate config --preset balanced -o pipelock.yaml
pipelock continue install --config "$PWD/pipelock.yaml" --dry-run
pipelock continue install --config "$PWD/pipelock.yaml"
```

Restart Continue after installation and run a harmless tool action to confirm the server connects. The installer wraps local `command`/`args` servers and remote `url` servers, and it is idempotent.

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
