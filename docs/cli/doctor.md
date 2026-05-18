# `pipelock doctor`

`pipelock doctor` reports whether configured protections are actually enforceable in the current local topology. It is a claim-audit command: it distinguishes "enabled in YAML" from "reachable by the running Pipelock process" and from "blocking enforcement."

```sh
pipelock doctor --config /etc/pipelock/pipelock.yaml
pipelock doctor --config /etc/pipelock/pipelock.yaml --json
```

The command does not make network requests. It checks local config, file readability, selected environment variables, and deployment prerequisites that can be inferred from the current process.

## What It Checks

| Check | Surface | What it reports |
|---|---|---|
| `http_proxy` | HTTP | Whether at least one fetch, forward, WebSocket, or reverse-proxy listener is configured and whether global `enforce` is blocking. |
| `tls_interception` | HTTP | Whether TLS interception is enabled and the configured CA certificate/key are readable. |
| `request_body_scanning` | HTTP | Whether request-body scanning is enabled with blocking action. |
| `browser_shield` | HTTP | Whether Browser Shield is enabled and whether HTTPS body visibility depends on TLS interception. |
| `mcp_wrapper_scanning` | MCP | Which wrapper-dependent MCP features are configured and need proof that the agent launches through `pipelock mcp proxy` or a Pipelock MCP listener. |
| `mcp_binary_integrity` | MCP | Whether binary integrity is enabled, has a manifest path, and the manifest is readable. |
| `mcp_tool_provenance` | MCP | Whether tool-provenance enforcement is configured and still depends on live `tools/list` traffic through the MCP wrapper/listener path. |
| `file_sentry` | MCP | Whether file_sentry is enabled and its watch paths are readable by the process arming the watcher. |
| `sentry` | Host | Whether Sentry telemetry is enabled and a DSN is present without printing the DSN value. |
| `direct_egress_boundary` | Host | Reminder that proxy env vars are not a wall; direct egress requires `pipelock contain`, sandboxing, NetworkPolicy, firewalling, or equivalent controls. |

## Exit Codes

| Exit code | Meaning |
|---|---|
| 0 | No failures or warnings. |
| 1 | At least one warning. The deployment may be usable, but the report found a claim that needs proof or tightening. |
| 2 | Config load failed or at least one check failed. |

## Operator Notes

- Run without `sudo` when checking service-user file readability. When run as root, DAC checks reflect root's view and may make unreadable service files look reachable.
- `doctor` does not prove that an agent launcher has consumed `PIPELOCK_MCP_PROXY_URL` or `PIPELOCK_MCP_CONFIG`; it tells you that MCP wrapper-dependent protections require that proof.
- `doctor` does not prove Kubernetes NetworkPolicy enforcement. Pair it with cluster smoke tests for direct-egress fail-closed behavior.
- Use `--json` for CI gates and dashboards. The JSON report includes per-check `configured`, `reachable`, `enforcing`, `detail`, and `next` fields.
