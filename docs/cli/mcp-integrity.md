# MCP Integrity Manifest Tooling

`pipelock mcp integrity manifest` generates and verifies the JSON manifest used
by `mcp_binary_integrity`.

## Generate

Pin one MCP server command before enabling enforcement:

```sh
pipelock mcp integrity manifest generate \
  --output /etc/pipelock/binary-manifest.json \
  -- node /opt/mcp/server.js
```

For interpreter commands, Pipelock pins both the resolved interpreter and the
resolved script path. To add another command to an existing manifest, use
`--merge`:

```sh
pipelock mcp integrity manifest generate \
  --output /etc/pipelock/binary-manifest.json \
  --merge \
  -- python3 /opt/mcp/weather.py
```

Use `--workdir` when relative script arguments must be resolved from the MCP
server's launch directory:

```sh
pipelock mcp integrity manifest generate \
  --output ./binary-manifest.json \
  --workdir /opt/mcp \
  -- python3 server.py
```

## Verify

Verify the manifest before wiring it into `pipelock mcp proxy`:

```sh
pipelock mcp integrity manifest verify \
  --manifest /etc/pipelock/binary-manifest.json \
  -- node /opt/mcp/server.js
```

The command exits non-zero if any resolved binary or script hash is missing or
mismatched. Use `--json` for automation.

## Operator notes

- **Prefer absolute script paths in your MCP launcher.** If a command uses a
  relative script argument, generate the manifest with the same working
  directory that production will use. Unsandboxed `pipelock mcp proxy` inherits
  the proxy process cwd; sandboxed mode resolves relative scripts against the
  sandbox `--workspace`. Absolute paths (for example,
  `python3 /opt/mcp/server.py`) avoid cwd drift entirely.
- **Manifest file ownership.** The generate command writes the file with
  mode `0o600` owned by whoever runs the CLI. If you generate as your
  operator user and Pipelock runs as a service user (e.g.
  `pipelock-proxy`), you must `chown` the manifest to the service user
  (or place it in a group Pipelock can read) before enabling enforcement.
  Otherwise the proxy will fail to load the manifest and fall back per the
  configured `action`.
- **`--merge` adds and updates entries; it never prunes.** Old entries for
  paths you no longer use stay in the manifest. They are harmless unless
  the binary at that path exists with content that matches an older pin
  by coincidence (vanishingly unlikely). For routine maintenance, prefer
  regenerating from scratch (omit `--merge`) when the set of MCP servers
  changes.
- **Package runners cannot be hashed.** Commands like `npx`, `bunx`, `uvx`,
  and `pipx` resolve executables dynamically at runtime. Generating against
  one of these pins only the runner itself, not the script it ultimately
  invokes. Where strict integrity matters, replace the runner with a direct
  interpreter + absolute script path.
- **TOCTOU is partial, not full.** The manifest hashes the resolved binary
  and any pinned script, then resolves symlinks again at exec time. Content
  replacement of an already-opened path between hash and exec is not
  detected (Go's `os/exec` cannot bind via `fexecve`). Pair the manifest
  with deployment-layer controls such as read-only mounts, signed package
  delivery, or container image immutability for the hash-to-exec window.
