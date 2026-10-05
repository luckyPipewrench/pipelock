# False Positive Tuning

When pipelock blocks or warns on legitimate traffic, this guide walks you through identifying the source, suppressing known-good findings, and tuning thresholds so the scanner stays useful without getting in the way.

**Start with the explanation and the active config.** Keep the config path printed by `pipelock init` (prefer an absolute path when changing directories). For a URL finding:

```bash
pipelock explain --config "/absolute/path/pipelock.yaml" "https://api.vendor.example/resource"
pipelock check --config "/absolute/path/pipelock.yaml" --url "https://api.vendor.example/resource"
```

[`explain`](cli/explain.md) names the scanner, matching rule, and narrowest applicable correction without DNS or fetching. Confirm that the traffic is legitimate, change only that rule or scoped exception in the active config, then repeat the same check. URL DLP uses `dlp.patterns[].exempt_domains`, not the top-level `suppress:` list. Core floors have their own restrictions; a broad allowlist or suppression is not a universal override.

For response or MCP findings, use the corresponding explanation command and recheck that surface through the actual client integration. A successful local URL check or `verify-install --config` synthetic test does not establish client routing. Use redacted logs to confirm which config and scanner handled the real request; do not publish credentials or raw payloads.

## Identifying Which Scanner Triggered

Every pipelock log entry includes a `scanner` field and a `rule` field. These tell you exactly which layer flagged the request and which pattern matched.

Scanner types:

| Scanner | What it checks |
|---------|---------------|
| `dlp` | Secret patterns (API keys, tokens, credentials, crypto keys) |
| `response_scan` | Injection patterns in content returned to the agent |
| `entropy` | Path and query entropy (high-randomness URL segments); header reason `path_entropy` or `query_entropy`. Subdomain entropy reports separately as `subdomain_entropy`. |
| `ssrf` | Private IPs, cloud metadata endpoints, DNS rebinding |
| `tool_policy` | MCP tool call rules (destructive ops, credential access) |
| `tool_chain` | Sequences of MCP tool calls matching attack patterns |
| `blocklist` | Domain blocklist matches |

Check recent findings:

```bash
pipelock logs --file pipelock-audit.log --last 50
pipelock logs --file pipelock-audit.log --filter blocked
```

Each finding includes an `event` field and the `scanner` that triggered. For DLP findings, the `reason` field names the matched pattern (e.g., "AWS Access ID", "GitHub Token"). For response scanning, the `patterns` field lists which patterns matched. Non-core names can be used in suppressions; core floor names require a pattern precision fix, or, for a core response finding on one host, a `response_scanning.core_observe_exceptions` entry.

## Seeing What Matched

Pipelock does not have a raw "dump the secret back to me" verbose mode. That would leak the same data the scanner is trying to protect.

Use these instead:

- Normal logs to see the `scanner`, `rule`/`pattern`, request ID, and verdict.
- The flight recorder to preserve a tamper-evident decision trail with redacted detail.

For example, enable the recorder:

```yaml
flight_recorder:
  enabled: true
  dir: /var/lib/pipelock/evidence
  signing_key_path: /etc/pipelock/keys/flight-recorder-signing.key   # `pipelock init` writes this next to your config
```

The recorder keeps receipt and decision context, but sensitive content is redacted before it is written unless you explicitly configure raw escrow. Expect pattern names and redacted evidence, not plaintext secrets.

## Suppressing Specific Findings

Add suppressions to your config when you know a non-core finding is safe. Each entry takes a `rule` (pattern name), `path` (URL or glob pattern), and optional `reason` for the audit trail. Core DLP and core response floor names fail validation at startup and reload.

```yaml
suppress:
  - rule: "Internal Provider API Key"
    path: "api.example.com/v2/*"
    reason: "Provider-bound credential on its first-party endpoint"
  - rule: "Jailbreak Attempt"
    path: "internal-testing.example.com/*"
    reason: "Test environment contains a known non-core fixture"
```

Suppressed findings still appear in logs with `suppressed: true`, so you can review them later.

For inline suppression in git-scanned files, put a `pipelock:ignore` comment at the end of the flagged line itself. A comment on the line above does nothing. Any text after `pipelock:ignore` is read as the rule name to suppress, so leave it empty to suppress every rule on that line, or name the rule exactly:

```python
TEST_KEY = "AKIA..."  # pipelock:ignore AWS Access ID
```

See [docs/guides/suppression.md](guides/suppression.md) for the full suppression reference.

## Tuning DLP Patterns

### Using only your own patterns

By default, pipelock merges your custom patterns with the 65 configurable built-in defaults. Set `include_defaults: false` to keep only your own patterns in that list. The independent immutable core DLP floor still detects core credentials, even with an empty configurable list. See the [DLP configuration reference](configuration.md#dlp-data-loss-prevention) for pattern merging and core restrictions.

```yaml
dlp:
  include_defaults: false
  patterns:
    - name: "internal_api_key"
      regex: "INTERNAL-[A-Z0-9]{32}"
      severity: "high"
```

There is no top-level `dlp.action`. Prefer a correction scoped to the matched pattern and destination. If you want transport-level redaction, configure the specific surface that supports it, such as `request_body_scanning.action`.

### Per-pattern domain exemptions

Each configurable DLP pattern supports an `exempt_domains` field, subject to the core and compiled-audience restrictions below. To exempt a domain for a custom pattern, add the exemption to that pattern entry. With `include_defaults: true`, a custom pattern with the same name replaces the configurable default; it doesn't replace the independent core detector. Reusing a built-in name alone doesn't grant its compiled credential audience. An `exempt_domains` entry on a built-in provider-key pattern with a compiled audience is refused unless it names only hosts already inside that audience, in which case it loads with a warning and is ignored:

```yaml
dlp:
  include_defaults: true
  patterns:
    - name: "Internal Service Token"
      regex: 'ist_[0-9A-Za-z]{32}\b'
      severity: "high"
      exempt_domains:
        - "internal-testing.example.com"
```

This keeps the configurable pattern active everywhere else while skipping it for the specified domain. Core safety-floor names (`AWS Access ID`, `AWS Secret Key`, `GitHub Token`, `GitHub Fine-Grained PAT`, `GitLab PAT`, `Slack Token`, `Private Key Header`, `GCP Service Account Key`) cannot carry `exempt_domains`: the compiled core URL floor never consults operator exemptions, so a config that tries is rejected at startup and reload instead of shipping an exemption that does nothing.

### Suppressing specific findings

For non-core body and header findings, use `suppress` entries at the top level of your config. URL DLP does not consult this list. See the [Suppressing Specific Findings](#suppressing-specific-findings) section above.

For a custom provider API key that you own, use both controls together: add `exempt_domains` on the DLP pattern for URL scans to the provider's own host, and add a matching `suppress` entry for body/header findings on that provider URL. Built-in provider-key patterns and the messaging-platform token patterns (Discord and Slack) instead have an immutable compiled audience host set: a match is allowed only at that set, logged as `dlp_credential_audience_allow`, and blocked everywhere else. This includes `Slack Token`, a core-floor pattern whose exact encrypted Slack API authorities include both the Web API and hosted MCP server, yet which still refuses every operator control (a URL-carried Slack Token is also blocked, because the core URL floor runs first). YAML cannot extend or clear that audience, and MCP input stays blocked because it has no verified upstream authority.

## Tuning Entropy Thresholds

Path entropy and subdomain entropy are the most common false positive sources. APIs that use UUIDs, base64-encoded IDs, or hash-based URLs in their paths trigger entropy checks. Defaults already exempt common package/object hosts with hash-based routing paths: `files.pythonhosted.org`, `pypi.org`, and `objects.githubusercontent.com`.

The default threshold is `4.5` (balanced preset). Raising it reduces sensitivity:

```yaml
fetch_proxy:
  monitoring:
    entropy_threshold: 5.0
```

To exempt specific domains instead of raising the global threshold:

```yaml
fetch_proxy:
  monitoring:
    subdomain_entropy_exclusions:
      - "api.example.com"
      - "cdn.example.com"
```

**Guideline:** If the domain is trusted and uses high-entropy URLs by design (CDNs, object storage, API gateways), exempt it. If the domain is untrusted, keep the threshold and investigate the findings.

Entropy-only URL, body, WebSocket, A2A/MCP content, and cross-request budget findings remain visible but do not raise the adaptive score or get upgraded by an elevated session. A configured `warn` still forwards opaque data, so it cannot prevent opaque exfiltration; choose `block` for an entropy detector that must deny it. Concrete DLP, injection, SSRF, policy, and structural hostname findings still score and upgrade. A session already at `block_all` denies every request.

### Structural hostname-exfiltration signals

Subdomain scanning also flags two structural patterns that the entropy threshold cannot catch, because encoded data sits *at or below* the entropy ceiling (hex tops out at 4.0 bits/char):

- A single subdomain label that is a long (14+ char) pure-hex or base32 token.
- A DNS-tunneling shape with either three or more encoded chunks, or two or more encoded chunks in a four-plus-label subdomain. An encoded chunk is a hex/base32-looking label of 8+ chars.

Both report `subdomain_entropy` and are independent of `subdomain_entropy_threshold`: **raising the threshold no longer allows hex/base32 subdomain labels.** Dictionary and hyphenated labels (`customer-production.us-east-1.api.example.com`) are not affected.

To allow a legitimate service that uses hex/base32 subdomains by design, add it to `subdomain_entropy_exclusions` (the targeted escape hatch). Setting `subdomain_entropy_threshold: 0` disables subdomain scanning entirely, including these structural signals.

**Residual gaps (by design, to bound false positives):** base32 labels with fewer than two digits, mixed-charset labels under 16 chars, and two-label chunks are not flagged. These are accepted false-negative tradeoffs; tighten with a custom domain blocklist if your threat model requires it.

## Tuning Response Scanning

Response injection patterns can flag legitimate content: documentation about AI safety, security research pages, or sites that discuss prompt engineering. To see which pattern matched a blocked body and where, save the body and run `pipelock explain response --config <file> < body`.

There are two knobs here and they are not interchangeable. Start with the narrow one.

**One non-core pattern firing on one destination: use `suppress`.** This drops only the named non-core pattern for URLs matching the path glob, and leaves every other response control on that host intact. Core response floor patterns cannot be suppressed. Declare one host + one core pattern in `response_scanning.core_observe_exceptions` (reason, owner, expiry ≤30 days) instead: the finding is kept and logged as `core_observed`, only the block is withheld. Fixing the pattern's precision is the alternative when the pattern itself is wrong rather than the destination.

```yaml
suppress:
  - rule: "Jailbreak Attempt"
    path: "*docs.vendor.example*"
    reason: "vendor docs explain injection defenses in prose"
```

Suppressions apply per normalization pass to configurable patterns, so a suppressed match cannot mask a later encoded finding on the same body. Compiled core matches are never suppression candidates. Suppressed non-core findings still appear in logs with `suppressed: true`.

**Whole-host trust: use `exempt_domains`, and know what it costs.** This is the broadest response-side control. Forward, TLS-intercepted, and reverse traffic refuses every `206` and `304` with `response_incomplete` before response-scan exemptions, Shield exemptions, media policy, or budget truncation. For forward-proxy and TLS-intercepted traffic, an exempt host's complete response streams through untouched: no injection scan, and also no media metadata strip, no Browser Shield rewrite, and no response scan-cap block. Request-side DLP, redaction, SSRF, authority checks, and budget accounting still run. Reach for it when you trust the host wholesale or need large downloads byte-intact, not to silence one pattern.

```yaml
response_scanning:
  enabled: true
  action: block
  exempt_domains:
    - "docs.vendor.example"
    - "*.docs.vendor.example"
```

With `response_scanning.enabled: false`, only the immutable core response floor scans responses; the configurable layer is off. `exempt_domains` still applies to that core floor: a core finding on a listed host is downgraded to `warn` and forwarded rather than blocked, so the list is not dormant. Remove the host if the core floor should still block there. If a host cannot be intercepted at all, for example because of certificate pinning, prefer `tls_interception.passthrough_domains` instead. See [configuration.md](configuration.md) for the full response-scanning reference.

Changing the whole response scanner to `warn` lets configurable injection findings through on every destination. Reserve that for a deliberate isolated audit trial; use the scoped correction above for an individual false positive and recheck both the legitimate response and a synthetic negative case.

## Rolling out a new DLP pattern safely

When you add a custom DLP pattern, the pattern may trigger on traffic you didn't anticipate. Shipping a pattern in audit-only mode first lets you watch for false positives on real traffic without breaking legitimate workflows.

Set `action: warn` on the individual pattern (not the top-level `dlp.action`, which is reserved):

```yaml
dlp:
  patterns:
    - name: "VendorInternalToken"
      regex: "vendor_[A-Za-z0-9]{32}"
      severity: high
      action: warn        # audit-only for rollout
      exempt_domains:
        - "billing.vendor.example"
```

Warn matches from that pattern appear in your audit sink (webhook, syslog, OTLP) with the pattern name, severity, transport, and request context, but the request is not blocked. Tune the regex and `exempt_domains` until the signal is clean, then remove the `action` line to return the pattern to default blocking behavior.

Only `action: warn` and empty string are accepted on DLP patterns. `block`, `strip`, `ask`, `redirect`, or any other value is rejected at config load.

## Tuning Cross-Request Detection

The entropy budget tracks cumulative high-entropy data across requests in a session. High-traffic API domains can exhaust the budget with legitimate traffic.

Exempt trusted high-volume domains:

```yaml
cross_request_detection:
  entropy_budget:
    exempt_domains:
      - "api.anthropic.com"
      - "api.openai.com"
```

You can also increase the budget window:

```yaml
cross_request_detection:
  entropy_budget:
    bits_per_window: 1000000
    window_minutes: 10
```

## Common False Positive Scenarios

| Scenario | Scanner | Pattern | Fix |
|----------|---------|---------|-----|
| API returns docs that trigger a non-core response rule | response | Jailbreak Attempt | Add a `suppress` entry for `Jailbreak Attempt` scoped to that host's URLs. For a core response floor match, declare a `response_scanning.core_observe_exceptions` entry for that host and pattern instead. Use `response_scanning.exempt_domains` only to trust the whole host, which also drops media stripping, Browser Shield, and the response size cap there |
| URL contains UUID path segments | entropy | (path entropy) | Raise `entropy_threshold` or add to `subdomain_entropy_exclusions` |
| Base64-encoded JWT in Authorization header | dlp | JWT Token | If the JWT is intentionally sent to a controlled endpoint, add a narrowly path-scoped `suppress` entry for `JWT Token`. Header and body DLP read `suppress`; per-pattern `exempt_domains` only affects URL scans |
| High-entropy CDN URLs | entropy | (subdomain entropy) | Add CDN to `subdomain_entropy_exclusions` |
| Service with long hex/base32 subdomain labels | subdomain_entropy | (structural hostname-exfil signal) | Add the host to `subdomain_entropy_exclusions` (raising the threshold does not allow encoded labels) |
| Internal API keys matching AWS format, in a URL or query | core_dlp | AWS Access ID | The compiled core URL floor does not consult `suppress` or operator `exempt_domains`. Fix the pattern precision; structurally valid S3 presigned URLs already use the narrow built-in carve-out described below |
| Internal API keys matching AWS format, in a request body or header | body_dlp/header_dlp | AWS Access ID | Core DLP names cannot be suppressed. Fix the pattern precision or use a distinct non-core custom pattern for a different credential format |
| GET to an AWS S3 presigned URL (issuer's bucket) | dlp | AWS Access ID | None required — handled automatically. The scanner detects a structurally valid SigV4 query set (all six parameters required exactly once: `X-Amz-Algorithm=AWS4-HMAC-SHA256`, `X-Amz-Credential=<KeyID>/<YYYYMMDD>/<region>/<service>/aws4_request`, `X-Amz-Date`, `X-Amz-SignedHeaders`, `X-Amz-Signature`, `X-Amz-Expires` as a positive integer no greater than 604800) hosted on an `amazonaws.com` (or `amazonaws.com.cn`) endpoint, and exempts only the access-key component inside the credential value. `<region>` and `<service>` must be lowercase letters, digits and single hyphens, at most 64 characters each, and nothing may follow `aws4_request`; any other scope falls back to normal DLP (and redaction). The same access-key elsewhere in the URL — path, hostname, other query params, ordered subsequence concatenation — still blocks. Duplicate fields, mismatched scope dates, overlong key prefixes, non-AWS hosts, and bogus algorithms all fall back to normal DLP. SigV4 carve-outs are adaptive-neutral: they neither poison the threat score nor earn clean-decay. An `X-Amz-Expires` above 24h attaches an info-tier `SigV4 Long Expiry` warn finding for audit visibility but does not block; above 604800 seconds (7 days) the carve-out does not apply at all and the access-key ID blocks. |
| WebSocket frames with encoded binary data | dlp | Environment Variable Secret | Add a `suppress` entry for `Environment Variable Secret` scoped to that upstream URL. Per-pattern `exempt_domains` only affects URL scans and does not apply to WebSocket frame content. |
| Test fixtures containing fake secrets | dlp | (multiple) | Use `pipelock:ignore` inline comments |
| Security research site with injection examples | core_response | Credential Solicitation | Core response floor names cannot be suppressed. Declare a `response_scanning.core_observe_exceptions` entry for that host and pattern, or fix pattern precision; `exempt_domains` is the whole-host fallback |
| Hash-based object storage paths | entropy | (path entropy) | Add storage domain to `subdomain_entropy_exclusions` |

## Deliberate Audit Rollouts

Audit mode is an explicit rollout choice for an isolated test environment with synthetic data and separately enforced egress controls. It can forward requests containing detected credentials, including core URL/request-body DLP matches, and is not the default recovery for a false positive. SSRF, fail-closed transport checks, and adaptive escalation can still block; audit does not mean every request is allowed. Preserve the working policy and use a separate output file:

```bash
pipelock generate config --preset audit > pipelock-audit-trial.yaml
```

Before starting the trial, set `logging.output` to `file` and `logging.file` to
`pipelock-audit.log` in `pipelock-audit-trial.yaml`. The audit preset otherwise
writes to stdout, so it does not create the log used below.

To transition a deliberate audit trial to enforcement:

1. Run representative synthetic traffic in the isolated trial
2. Review all trial events: `pipelock logs --file pipelock-audit.log`. Include findings that audit mode allowed through, not only blocked events.
3. For each finding, decide: real threat or false positive?
4. Add suppressions and exemptions for confirmed false positives
5. Restore the intended enforcement policy and recheck each affected surface
6. Confirm legitimate traffic succeeds and the relevant negative checks still block before using the policy outside the trial

## Reporting False Positives

If you find a pattern that consistently produces false positives on common traffic, file an issue:

**[github.com/luckyPipewrench/pipelock/issues](https://github.com/luckyPipewrench/pipelock/issues)**

Include:
- The log entry (scanner, rule, severity)
- Your config (redact secrets and internal domains)
- What the legitimate traffic looks like
- Why the match is incorrect

Every confirmed false positive becomes a regression test in the pipelock test suite.
