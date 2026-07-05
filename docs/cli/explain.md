# `pipelock explain`

`pipelock explain <url>` runs a URL through the scanner pipeline using the loaded config and explains the verdict so that a block is **remediable**. For a blocked URL it prints the scanner/layer that produced the verdict, the matching pattern (for DLP and blocklist), which part of the URL was inspected, the destination host, the effective config path, and — most importantly — the **exact remediation knob that scanner consults**, plus any broader option and its tradeoff.

```sh
pipelock explain https://example.com/path
pipelock explain --config /etc/pipelock/pipelock.yaml "https://example.com/download?id=42"
pipelock explain --json https://10.0.0.1/internal
```

The remediation guidance is the point of the command: a hint must name a knob the blocking scanner *actually* consults. Pointing an operator at a knob the scanner ignores (for example, suggesting top-level `suppress:` for a URL-DLP block, which URL DLP never reads) trains them to believe they changed policy when they changed nothing. `explain` is built so every block names the correct, narrowest knob.

## No network access

`explain` does not resolve DNS or fetch anything. It runs the layers that fire **before** DNS resolution: scheme, CRLF injection, path traversal, allowlist, blocklist, the immutable core SSRF literal check, core and URL DLP, and path/subdomain entropy. The hostname-based SSRF layer (layer 8) resolves DNS at runtime, so `explain` reports when a verdict would *additionally* depend on resolution rather than reaching out itself. IP literals that fall in private/loopback/link-local ranges are still caught here by the immutable core SSRF literal check, which needs no resolution.

## Per-scanner remediation mapping

| Scanner / layer | Why it blocked | Correct (narrowest) knob | Broader option + tradeoff |
|---|---|---|---|
| `dlp` (URL DLP) | A configurable DLP pattern matched the URL | `dlp.patterns[].exempt_domains` for that pattern. **The top-level `suppress:` list does NOT apply to URL DLP** — it is body-DLP and response-scanning only. If a long token in the query also trips entropy, you may *additionally* need `fetch_proxy.monitoring.query_entropy_param_exclusions` for an exact endpoint+parameter, or `fetch_proxy.monitoring.query_entropy_exclusions` as the broader host-wide fallback (a separate gate). | `tls_interception.passthrough_domains` exempts the host in one line but blinds Pipelock to all inner TLS (method, path, body, response). Only for can't-scan-by-construction hosts. |
| `core_dlp` | An immutable critical-credential pattern matched | None — core DLP is a safety floor and cannot be exempted by config. A genuine false positive must be fixed by tightening the pattern in a release. | — |
| `entropy` (query entropy) | A high-entropy query key/value crossed the threshold | `fetch_proxy.monitoring.query_entropy_param_exclusions` for an exact HTTPS endpoint+parameter when host, path, and param are known; otherwise `fetch_proxy.monitoring.query_entropy_exclusions` is the broader host-wide fallback. **Separate gate from DLP** — exempting a DLP pattern does not lift an entropy block. | Raising `fetch_proxy.monitoring.entropy_threshold` lowers sensitivity for every destination. |
| `entropy` (path entropy) | A high-entropy path segment crossed the threshold | `fetch_proxy.monitoring.subdomain_entropy_exclusions` for host-wide path entropy false positives, or an enforced `request_policy` route for an exact host+path exemption. `query_entropy_exclusions` does **not** lift path entropy blocks. | Raising `fetch_proxy.monitoring.entropy_threshold` lowers sensitivity for every destination. |
| `subdomain_entropy` | A high-entropy DNS label was detected | `fetch_proxy.monitoring.subdomain_entropy_exclusions`. | Raising `fetch_proxy.monitoring.subdomain_entropy_threshold` globally. |
| `blocklist` | The host is on the domain blocklist | Remove or narrow the entry in `fetch_proxy.monitoring.blocklist`. | — |
| `allowlist` | Strict mode and the host is not allowlisted | Add the host to `api_allowlist`. | Switching `mode` from `strict` to `balanced` permits monitored browsing for all destinations. |
| `ssrf` / `ssrf_metadata` | The host resolves (at runtime) to a private/metadata IP | Top-level `trusted_domains` (hostname) or `ssrf.ip_allowlist` (IP range). This verdict depends on DNS resolution. | Disabling SSRF (`internal: []`) removes private-range protection for all destinations. |
| `core_ssrf` | A private/loopback/link-local IP literal | `ssrf.ip_allowlist` is the only override (honored even by the core check). The floor cannot be disabled wholesale. | — |
| `ratelimit` | Per-domain request ceiling reached | `fetch_proxy.monitoring.max_requests_per_minute`, or retry after the window. | — |
| `length` | URL exceeds the max length | `fetch_proxy.monitoring.max_url_length`, or inspect for query-param data stuffing. | — |
| `databudget` | Per-domain data ceiling reached | Adjust the session data-budget configuration. | — |
| `crlf_injection` / `path_traversal` | A header-injection or directory-escape sequence | None — never legitimate in a normal URL. Correct the URL at its source. | — |
| `scheme` | A non-http/https scheme | None — use an `http`/`https` URL. | — |

## Flags

| Flag | Default | Purpose |
|---|---|---|
| `--config`, `-c` | built-in defaults | Config file to load. Without it, the built-in default config is used. |
| `--json` | `false` | Emit a structured report instead of human-readable text. |

## Exit codes

| Exit code | Meaning |
|---|---|
| 0 | The URL is allowed under the loaded config. |
| 2 | Config load failed, or the URL was empty/unparseable. |
| 3 | The URL is blocked. The report names the scanner and the remediation. |

The non-zero exit on a block lets scripts branch on the verdict without parsing output.

## JSON report fields

`--json` emits a stable report shape: `url`, `config_file`, `mode`, `version`, `allowed`, `scanner`, `layer`, `target_view` (`url_query` / `host` / `path` / `scheme` / `url`), `host`, `pattern_name` (for DLP/blocklist), `reason`, `score`, `dns_dependent`, `notes`, `warn_matches`, and a `remediation` object with `knob`, `broader`, and `immutable`.

## See also

- [`pipelock doctor`](doctor.md) — audits whether configured protections are actually enforceable.
- [`pipelock check`](../../README.md) — validate a config and scan a single URL for an allow/block verdict.
- [False-positive tuning](../false-positive-tuning.md) — the knob-selection guide this command's remediation mapping is built from.
