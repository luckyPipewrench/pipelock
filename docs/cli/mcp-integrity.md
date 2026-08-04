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

## Sign and Trust

Sign the manifest after generating or merging entries:

```sh
pipelock mcp integrity manifest sign \
  --manifest /etc/pipelock/binary-manifest.json \
  --signer release
```

This writes `/etc/pipelock/binary-manifest.json.sig` by default. Verify that
signature before using the manifest:

```sh
pipelock mcp integrity manifest verify-signature \
  --manifest /etc/pipelock/binary-manifest.json \
  --signer release
```

The signer is resolved from the Pipelock keystore. For a signer public key
managed outside the local keystore, trust it first:

```sh
pipelock trust release /path/to/release.pub
```

To require a trusted manifest signature at runtime:

```yaml
mcp_binary_integrity:
  enabled: true
  manifest_path: /etc/pipelock/binary-manifest.json
  action: block
  require_signature: true
  trusted_signer: release
```

`signature_path` defaults to `<manifest_path>.sig`. Set `keystore` only when
the runtime should use a non-default Pipelock keystore.

`require_signature: true` is fail-closed regardless of `action`. Once you
assert manifest trust, an unverified, unsigned, or wrong-signer manifest
blocks subprocess spawn even when `action: warn` is set. The `action` knob
still governs the response to entry-hash mismatches for trusted manifests;
it does not relax trust establishment itself. Runtime reads the manifest
bytes once and verifies the signature against those exact bytes — no
TOCTOU window between trust check and parse.

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
- **Package runners are rejected under enforcement.** Commands like `npx`,
  `bunx`, `uvx`, and `pipx` resolve another executable dynamically at runtime.
  A manifest can describe the runner itself, but `action: block` rejects the
  launch because the downstream server cannot be descriptor-bound. Use the
  final native server executable directly.
- **Descriptor-bound launch is Linux-only.** On Linux, runtime verification
  opens each pinned executable once, hashes through that descriptor, and
  executes through the same descriptor. Replacing a
  symlink or directory entry after verification cannot redirect the launch.
  `action: block` fails closed when descriptor launch is unavailable, including
  when `/proc/self/exe` is unavailable. Other platforms reject enforcing
  launches instead of silently returning to path-based execution. `action:
  warn` remains intentionally non-enforcing and logs before using an unpinned
  platform launch.
- **Interpreter and wrapper limits are explicit.** Interpreter+script commands,
  shebang commands, package runners, and `/usr/bin/env` wrappers require a later
  pathname open or an inherited script descriptor. Pipelock rejects all of them
  under `action: block` rather than reintroducing a race or leaking a descriptor
  into the MCP server. Enforcing integrity currently requires the final native
  server executable as the MCP command.
- **An open descriptor pins identity, not mutable contents.** Atomic file or
  symlink replacement cannot change the opened inode. A process that can write
  in place to that same inode can still alter bytes after hashing; retain
  read-only mounts, signed package delivery, or container image immutability to
  prevent in-place mutation.
