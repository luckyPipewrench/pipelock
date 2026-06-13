# `pipelock doctor`

`pipelock doctor` reports whether configured protections are actually enforceable in the current local topology. It is a claim-audit command: it distinguishes "enabled in YAML" from "reachable by the running Pipelock process" and from "blocking enforcement."

```sh
pipelock doctor --config /etc/pipelock/pipelock.yaml
pipelock doctor --config /etc/pipelock/pipelock.yaml --json
pipelock doctor --config /etc/pipelock/pipelock.yaml --check-ports
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
| `config_suppress_semantics` | Config | Whether each `suppress:` entry can actually affect an enabled scanner, or is inert (unknown pattern name, response-only pattern with response scanning off, or DLP pattern with no suppress-consulting scanner enabled). |
| `config_exemption_semantics` | Config | Whether `response_scanning.exempt_domains` / `adaptive_enforcement.exempt_domains` is set on a scanner that is disabled, making the exemption inert. |
| `sentry` | Host | Whether Sentry telemetry is enabled and a DSN is present without printing the DSN value. |
| `direct_egress_boundary` | Host | Reminder that proxy env vars are not a wall; direct egress requires `pipelock contain`, sandboxing, NetworkPolicy, firewalling, or equivalent controls. |
| `port_collisions:*` | Host | With `--check-ports`, whether configured listener ports are already held by another process. On Linux, this uses `/proc/net/tcp*` plus `/proc/<pid>/fd`; run as root when cross-user process ownership hides PID details. Non-Linux hosts report the check as unavailable. |

## Semantic Config Validation (Inert Exemptions)

Pipelock has several exemption knobs, and the same word (`exempt_domains`, `suppress`) means different things to different scanners. An exemption that parses cleanly but no enabled scanner consults is *inert*: the block silently persists, which is worse than no exemption because it trains an operator to believe a false positive is fixed when it is not.

`doctor` validates this from the loaded config and warns when a remediation cannot work:

- **Unknown proxy pattern name.** A `suppress:` entry whose `rule` matches no active DLP pattern (`dlp.patterns` plus defaults) and no `response_scanning.patterns` name is inert for the proxy enforcement path. It may still match `pipelock audit` / `pipelock git` project findings if those commands emit the same rule name. **Fix:** correct the rule name to match a real proxy pattern, keep audit/git-only suppressions in the config used for those commands, or remove the entry.
- **Suppress on a disabled response scanner.** A `suppress:` entry naming a response-scanning pattern while `response_scanning.enabled: false`. The only scanners that match that pattern are off, so the suppress is inert. **Fix:** enable `response_scanning`, or remove the entry.
- **Suppress on a DLP pattern with no suppress-consulting DLP scanner.** A `suppress:` entry naming a DLP pattern while neither `request_body_scanning` nor `response_scanning.sse_streaming` is enabled. Plain `response_scanning.enabled` does not make DLP-pattern suppressions effective because response scanning uses `response_scanning.patterns`, a separate namespace. URL-query DLP would still match the pattern, but **URL-query DLP does not consult `suppress:`** — it only honors per-pattern `dlp.patterns[].exempt_domains`. **Fix:** to exempt a URL-query match, set `dlp.patterns[].exempt_domains` on the pattern. (`suppress:` is also consulted by the `pipelock audit` and `pipelock git` project/secret scanners, so the entry is not universally dead — this warning is scoped to the proxy enforcement path `doctor` reports on.)
- **Exemption on a disabled scanner.** `response_scanning.exempt_domains` set while `response_scanning.enabled: false`, or `adaptive_enforcement.exempt_domains` set while `adaptive_enforcement.enabled: false`. **Fix:** enable the scanner, or remove the exemption list.

These checks are deliberately conservative: a warning is emitted only when inertness is provable from the loaded config model. Ambiguous cases are not flagged.

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
