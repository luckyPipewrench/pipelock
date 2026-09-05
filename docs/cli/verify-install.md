# `pipelock verify-install`

`pipelock verify-install` runs deterministic smoke checks against the local Pipelock binary and configuration. It proves the scanner surfaces are wired. Its direct-egress probes report a successful direct connection as exposure, while an unsuccessful connection without boundary attribution is inconclusive.

It complements `pipelock doctor`:

- `doctor` explains configured-vs-enforceable deployment posture and next steps.
- `verify-install` executes concrete probes and exits non-zero if a required check fails.

## Usage

```bash
pipelock verify-install --no-color
```

Useful flags:

| Flag | Purpose |
|---|---|
| `--config <path>` | Verify the supplied config as-is. Disabled protections are reported as failures. |
| `--json` | Emit a machine-readable report. |
| `--output <path>` | Write the JSON report to a file. |
| `--sign <key>` | Sign the report with an Ed25519 private key. |
| `--no-color` | Disable terminal color. |

Without `--config`, the verifier uses built-in defaults and enables the full proof set so a fresh binary can self-check out of the box.

## Checks

Scanning and local enforcement checks:

| Check | What it proves |
|---|---|
| `config_valid` | Config loads and validates. |
| `proxy_health` | The local proxy health endpoint responds. |
| `fetch_dlp` | Fetch-path DLP blocks a secret-shaped payload. |
| `forward_blocked` | Forward-proxy CONNECT blocklist enforcement works. |
| `scanning_dlp` | MCP input scanning catches secret-shaped tool input. |
| `scanning_injection` | Prompt-injection scanning fires on a hostile input. |
| `scanning_policy` | MCP tool policy denies a blocked command. |
| `scanning_websocket` | WebSocket frame scanning catches a hostile text frame. |
| `browser_shield` | Browser Shield rewrites shieldable browser content. |
| `file_sentry` | file_sentry detects a secret written to a watched workspace. |
| `mcp_binary_integrity_smoke` | MCP binary-integrity manifest loading and hash verification work against the current Pipelock executable. It uses that executable's configured entry when present, otherwise an ephemeral self-test entry. This does not verify configured MCP server binaries. |
| `mcp_tool_provenance_smoke` | MCP tool-provenance signing and verification work offline using a synthetic tool and ephemeral key. This does not verify upstream tools. |

Containment checks:

| Check | What it proves |
|---|---|
| `no_direct_http` | Whether a direct HTTP connection succeeded. A failed connection without containment-boundary evidence is inconclusive. |
| `no_direct_dns` | Whether a direct DNS exchange succeeded. A failed exchange without containment-boundary evidence is inconclusive. |
| `no_direct_https` | Whether a direct HTTPS connection succeeded. A failed connection without containment-boundary evidence is inconclusive. |

The containment probes are only meaningful inside a container, pod, or similar network boundary. On a normal host they are reported as not applicable, because the operator account is expected to retain direct network access. A blocked or unavailable public endpoint does not identify the local containment boundary, so it is reported as unknown and exits non-zero. Use `pipelock contain verify` for managed Linux host containment. Container and pod deployments need evidence from their own network-policy boundary.

## Exit Codes

The current container and pod probes cannot affirm containment. When all direct connections fail, the result is `unknown` with exit code `2`, even when network policy is correctly enforcing containment. This command does not ingest external policy evidence to turn that result into a pass.

| Code | Meaning |
|---|---|
| `0` | All required checks passed. Host-mode, not-applicable containment checks count as pass. |
| `1` | One or more checks failed. |
| `2` | Config or setup error, or an inconclusive containment probe. |

## Scope

The Browser Shield, file_sentry, MCP binary-integrity, and MCP tool-provenance checks are smoke tests. They prove the code paths work with controlled fixtures; they do not prove that every deployed client has been wired through Pipelock. Pair them with `pipelock doctor`, `pipelock contain verify`, and deployment-specific wrapper or sidecar smoke tests before claiming production enforcement.
