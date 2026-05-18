# `pipelock verify-install`

`pipelock verify-install` runs deterministic smoke checks against the local Pipelock binary and configuration. It is a quick proof that the scanner surfaces are wired and, when run inside a contained environment, that direct egress is blocked.

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
| `browser_shield` | Browser Shield rewrites shieldable browser content. |
| `file_sentry` | file_sentry detects a secret written to a watched workspace. |
| `mcp_binary_integrity_smoke` | MCP binary-integrity manifest loading and hash verification work. |
| `mcp_tool_provenance_smoke` | MCP tool-provenance signing and verification work offline. |

Containment checks:

| Check | What it proves |
|---|---|
| `no_direct_http` | The current environment blocks direct HTTP egress. |
| `no_direct_dns` | The current environment blocks direct DNS egress. |
| `no_direct_https` | The current environment blocks direct HTTPS egress. |

The containment probes are only meaningful inside a container, pod, or similar network boundary. On a normal host they are reported as not applicable, because the operator account is expected to retain direct network access.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | All required checks passed. Not-applicable containment checks count as pass. |
| `1` | One or more checks failed. |
| `2` | Config or setup error. |

## Scope

The Browser Shield, file_sentry, MCP binary-integrity, and MCP tool-provenance checks are smoke tests. They prove the code paths work with controlled fixtures; they do not prove that every deployed client has been wired through Pipelock. Pair them with `pipelock doctor`, `pipelock contain verify`, and deployment-specific wrapper or sidecar smoke tests before claiming production enforcement.
