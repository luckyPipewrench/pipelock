# False Positive Tuning

When pipelock blocks or warns on legitimate traffic, this guide walks you through identifying the source, suppressing known-good findings, and tuning thresholds so the scanner stays useful without getting in the way.

**Start in audit mode.** If you're seeing unexpected blocks, switch to audit first. Audit logs everything but blocks nothing, giving you a clear picture of what's firing before you make changes.

```bash
pipelock generate config --preset audit > pipelock.yaml
```

## Identifying Which Scanner Triggered

Every pipelock log entry includes a `scanner` field and a `rule` field. These tell you exactly which layer flagged the request and which pattern matched.

Scanner types:

| Scanner | What it checks |
|---------|---------------|
| `dlp` | Secret patterns (API keys, tokens, credentials, crypto keys) |
| `response_scan` | Injection patterns in content returned to the agent |
| `entropy` | Path and subdomain entropy (high-randomness URL segments) |
| `ssrf` | Private IPs, cloud metadata endpoints, DNS rebinding |
| `tool_policy` | MCP tool call rules (destructive ops, credential access) |
| `tool_chain` | Sequences of MCP tool calls matching attack patterns |
| `blocklist` | Domain blocklist matches |

Check recent findings:

```bash
pipelock logs --file pipelock-audit.log --last 50
pipelock logs --file pipelock-audit.log --filter blocked
```

Each finding includes an `event` field and the `scanner` that triggered. For DLP findings, the `reason` field names the matched pattern (e.g., "AWS Access ID", "GitHub Token"). For response scanning, the `patterns` field lists which patterns matched. Use these names when writing suppressions.

## Suppressing Specific Findings

Add suppressions to your config when you know a finding is safe. Each entry takes a `rule` (pattern name), `path` (URL or glob pattern), and optional `reason` for the audit trail.

```yaml
suppress:
  - rule: "Environment Variable Secret"
    path: "api.example.com/v2/*"
    reason: "API uses high-entropy path segments for request IDs"
  - rule: "AWS Access ID"
    path: "internal-testing.example.com/*"
    reason: "Test environment uses canary-format keys"
```

Suppressed findings still appear in logs with `suppressed: true`, so you can review them later.

For inline suppression in git-scanned files, add a `pipelock:ignore` comment on the line above:

```python
# pipelock:ignore -- test fixture, not a real key
TEST_KEY = "AKIAIOSFODNN7EXAMPLE"
```

See [docs/guides/suppression.md](guides/suppression.md) for the full suppression reference.

## Tuning DLP Patterns

### Using only your own patterns

By default, pipelock merges your custom patterns with the 48 built-in defaults. To use only your own patterns (disabling all built-ins), set `include_defaults: false`:

```yaml
dlp:
  include_defaults: false
  patterns:
    - name: "internal_api_key"
      regex: "INTERNAL-[A-Z0-9]{32}"
      severity: "high"
```

### Per-pattern domain exemptions

Each DLP pattern supports an `exempt_domains` field. To exempt a domain for a specific pattern, add it as a custom pattern entry with the exemption. When `include_defaults` is true, custom patterns with the same name override the built-in:

```yaml
dlp:
  include_defaults: true
  patterns:
    - name: "AWS Access ID"
      regex: "(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16,}"
      severity: "critical"
      exempt_domains:
        - "internal-testing.example.com"
```

This keeps the pattern active everywhere else while skipping it for the specified domain.

### Suppressing specific findings

For URL-path-level suppression (finer than domain exemption), use `suppress` entries at the top level of your config. See the [Suppressing Specific Findings](#suppressing-specific-findings) section above.

## Tuning Entropy Thresholds

Path entropy and subdomain entropy are the most common false positive sources. APIs that use UUIDs, base64-encoded IDs, or hash-based URLs in their paths trigger entropy checks.

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

## Tuning Response Scanning

Response injection patterns can flag legitimate content: documentation about AI safety, security research pages, or sites that discuss prompt engineering.

Exempt trusted content domains:

```yaml
response_scanning:
  enabled: true
  action: warn
  exempt_domains:
    - "docs.example.com"
    - "*.readthedocs.io"
```

Switching from `block` to `warn` for response scanning gives visibility without interrupting the agent. This is useful during initial deployment when you're learning what your agent fetches.

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
| API returns docs about prompt injection | response | Prompt Injection | Exempt the docs domain via `response_scanning.exempt_domains` |
| URL contains UUID path segments | entropy | (path entropy) | Raise `entropy_threshold` or add to `subdomain_entropy_exclusions` |
| Base64-encoded JWT in Authorization header | dlp | JWT Token | Add per-pattern `exempt_domains` for the auth provider |
| High-entropy CDN URLs | entropy | (subdomain entropy) | Add CDN to `subdomain_entropy_exclusions` |
| Internal API keys matching AWS format | dlp | AWS Access ID | Add to `suppress` with path and reason |
| WebSocket frames with encoded binary data | dlp | Environment Variable Secret | Exempt the WebSocket upstream domain |
| Test fixtures containing fake secrets | dlp | (multiple) | Use `pipelock:ignore` inline comments |
| Security research site with injection examples | response | Credential Solicitation | Exempt via `response_scanning.exempt_domains` |
| Hash-based object storage paths | entropy | (path entropy) | Add storage domain to `subdomain_entropy_exclusions` |

## Transitioning from Audit to Enforcement

1. Run audit mode for a full agent work session (at least a few hours of real usage)
2. Review findings: `pipelock logs --file pipelock-audit.log --filter blocked`
3. For each finding, decide: real threat or false positive?
4. Add suppressions and exemptions for confirmed false positives
5. Switch to balanced mode with `action: warn` on scanners you're less sure about
6. After a week of clean warn-mode operation, switch to `action: block`

## Reporting False Positives

If you find a pattern that consistently produces false positives on common traffic, file an issue:

**[github.com/luckyPipewrench/pipelock/issues](https://github.com/luckyPipewrench/pipelock/issues)**

Include:
- The log entry (scanner, rule, severity)
- Your config (redact secrets and internal domains)
- What the legitimate traffic looks like
- Why the match is incorrect

Every confirmed false positive becomes a regression test in the pipelock test suite.
