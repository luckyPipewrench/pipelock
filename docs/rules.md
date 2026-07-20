# Community Rules

Pipelock ships with built-in DLP patterns, injection detection, and tool-poison scanners. Community rule bundles extend these defaults with additional detections that ship on a faster cadence than the core binary.

## Installing a Bundle

```bash
# Install the official community bundle (requires network access)
pipelock rules install pipelock-community

# Install from a third-party HTTPS source
pipelock rules install --source https://example.com/my-bundle/bundle.yaml my-bundle

# Install from a local path (signature verification skipped)
pipelock rules install --path /path/to/bundle/ --allow-unsigned
```

Bundles are stored in `$XDG_DATA_HOME/pipelock/rules/` by default (typically `~/.local/share/pipelock/rules/`). Override with the `--rules-dir` flag or the `rules_dir` config field.

> **Note:** Official bundle verification works in source builds because the official rules signing public key is compiled into the source. Release binaries additionally embed the rules keyring via ldflags. Use `trusted_keys` for third-party bundles signed by keys outside the official keyring.

## Updating and Removing

```bash
# Update to the latest version
pipelock rules update pipelock-community

# List installed bundles
pipelock rules list

# Show diff between installed and available versions
pipelock rules diff pipelock-community

# Remove a bundle
pipelock rules remove pipelock-community
```

## Status

```bash
pipelock rules status
```

Reports the overall health of the rules stack: the immutable core tier, the standard-tier source and pattern counts, every installed bundle's tier/version/rule counts/signed status, and any errors or warnings from the last load. Returns non-zero when any bundle has an error (e.g., unknown `required_features`, signature failure) even if some bundles loaded successfully — in that case the proxy still starts, but the status command surfaces what's degraded.

Add `--json` for machine-readable output suitable for piping into dashboards or CI checks:

```bash
pipelock rules status --json | jq '.healthy'
```

## Tiers

Every bundle declares a `tier`. Tiers describe source and trust, not rule quality:

| Tier | Who ships it | Trust expectation |
|------|--------------|-------------------|
| `standard` | Pipelock maintainers | Signed with the embedded production key; ships as the built-in detection floor |
| `community` | Community contributors via `pipelock-community` | Signed with the production key; reviewed in the public bundle repo |
| `pro` | Paid-tier customers (future) | Signed with a delegated per-tier key; gated by license when loaded |

The core scanner runs before any bundle and cannot be replaced or disabled. Standard-tier rules load from the binary embed and cannot be replaced from disk either: there is no config field that repoints them, which is what keeps a writable path from swapping out standard detection. `pipelock rules status` reports the tier's origin in its `standard_dlp_source` and `standard_response_source` output fields.

Bundles cannot override or disable the core or standard tiers. They only extend detection.

## RequiredFeatures

A bundle declares the engine features its rules need. Unknown features block the bundle at load time with a clear error:

```yaml
format_version: 2
name: my-company-rules
version: "2026.03.1"
tier: community
required_features:
  - dlp           # built-in DLP scanner
  - checksum      # post-match checksum validators (luhn, mod97, aba)
  - response      # response scanning
rules:
  # ...
```

Valid feature names are 1-64 lowercase alphanumeric characters with underscores. When an older pipelock binary encounters a bundle that requires a feature it doesn't support, the bundle fails to load rather than silently dropping the feature-dependent rules. This prevents detection drift between the bundle author's expectations and the running binary.

## Core SSRF Literal

The immutable core scanner includes unconditional private-IP literal enforcement — it blocks literal RFC 1918 ranges, loopback, link-local, and cloud metadata addresses regardless of bundle tier, config, or explicit allowlist. This is a separate layer from the standard SSRF scanner and cannot be disabled.

If you need to reach a private IP for legitimate internal use, do not disable pipelock — use the forward proxy's domain allowlist (for hostname-based internal services) or scope pipelock to a narrower set of agents.

## How Rules Are Loaded

At startup, pipelock scans the rules directory for installed bundles. Each bundle's rules are merged with the built-in patterns:

- **DLP rules** are added to the DLP pattern list alongside built-in patterns
- **Injection rules** are added to the response scanning pattern list
- **Tool-poison rules** are added to the tool description scanner

Bundle rules cannot override or disable built-in patterns. They are additive only.

## Configuration

```yaml
# pipelock.yaml
rules:
  rules_dir: ~/.local/share/pipelock/rules  # default ($XDG_DATA_HOME/pipelock/rules)
  min_confidence: medium                    # skip experimental rules (low confidence)
  include_experimental: false               # default: only stable rules are active
  allow_degraded: false                     # strict mode refuses installed-bundle integrity failures
  # trusted_keys:                           # additional trusted public keys (beyond embedded keyring)
  #   - name: "vendor-security"
  #     public_key: "64-char-hex-encoded-ed25519-public-key"
```

## Degraded Bundle State

Pipelock separates rule-bundle load failures into two operator classes:

- **Integrity failures:** bad signatures, missing or mismatched `bundle.lock`, bundle hash mismatch, malformed installed bundle content, expired bundles, signer/tier mismatch, and freshness rollback state tampering.
- **Availability failures:** missing optional rules directory, bundle file read/stat failures, freshness lock failures, or a bundle that requires a newer engine feature.

In `mode: strict`, an integrity failure for an installed bundle refuses startup unless `rules.allow_degraded: true` is explicitly set. The error names the bundle and class so the operator can verify or reinstall the bundle before retrying. Availability failures keep the process available but mark the bundle state degraded.

In non-strict modes, Pipelock starts with the remaining rules but emits a structured `rule_bundle_degraded` audit event and a startup warning. `/stats` reports degraded bundle count and names under `rule_bundles`; `/metrics` exposes `pipelock_rule_bundles_degraded`.

On hot reload, a clean deletion of a previously live bundle is treated as a coverage drop. Strict mode rejects that reload and keeps the running config unless `rules.allow_degraded: true` is set on the candidate config. Non-strict modes allow the reload but emit a warning and audit event naming the bundle and pattern count dropped.

`rules.allow_degraded` is an emergency override, not a normal operating mode. Use it only after confirming the bundle store is intentionally unavailable or after choosing to continue while restoring bundle integrity.

## Trust Model

Bundles are Ed25519-signed YAML files. Pipelock verifies signatures against a keyring before loading rules.

### Official bundles

Official bundles (like `pipelock-community`) are signed with the production key compiled into the source and also embedded in release binaries at build time. No additional configuration is needed.

### Third-party bundles

Organizations can create and sign their own bundles. Add their public key to `trusted_keys` in your config. Pipelock verifies third-party signatures the same way it verifies official ones.

### Unsigned bundles

The `--allow-unsigned` flag skips signature verification during install. Use this only for local testing. Unsigned bundles log a warning at startup.

### Bundle keyring separated from the license key

As of v2.5.0 the bundle-signing keyring is stored and loaded independently from the license key. Rotating one does not force rotating the other. The migration is automatic on first load; bundles signed under the prior layout verify unchanged. Operators running a custom `trusted_keys` list are unaffected.

## Multi-bundle layout

The `pipelock-rules` repo ships a multi-bundle directory layout so each bundle is signed and versioned independently. A bundle is identified by name and tier, not by file location, so operators can install only the bundles they need. Install several bundles side by side; each one runs in addition to the core and standard tiers:

```bash
pipelock rules install pipelock-community
pipelock rules install --source https://example.com/finance-pii/bundle.yaml finance-pii
```

`pipelock rules list` shows every installed bundle with its tier, version, and rule counts. Bundles are additive — they cannot override or disable the core or standard tiers, and they cannot override each other; identical rules across bundles dedupe at load time.

The official registry also publishes the independently versioned
`healthcare-phi-pii` community bundle for regex-detectable healthcare and
financial identifiers.

## Verifying Signatures

```bash
# Re-verify all installed bundles against the embedded keyring
pipelock rules verify
```

## Creating Your Own Bundle

A bundle is a single YAML file with a header and a list of rules:

```yaml
format_version: 2
name: my-company-rules
version: "2026.04.1"
author: vendor-security
description: "Internal detection patterns for Vendor Corp"
min_pipelock: "2.2.0"
tier: community
monotonic_version: 1
published_at: "2026-04-16T00:00:00Z"
expires_at: "2027-04-16T00:00:00Z"
required_features:
  - dlp

rules:
  - id: dlp-internal-api-key
    type: dlp
    status: stable
    name: "Vendor Internal API Key"
    description: "Detects Vendor Corp internal API keys"
    severity: critical
    confidence: high
    pattern:
      regex: 'vendor_[a-zA-Z0-9]{32}'
```

DLP rules may set `pattern.validator` to `luhn`, `mod97`, `aba`, or `wif` when
the identifier carries that checksum. Pipelock applies the validator after a
regex match, so malformed lookalikes do not become DLP findings. Bundle
authors should declare `required_features: ["checksum"]` and set
`min_pipelock` to the oldest Pipelock release whose rule-bundle loader supports
the `pattern.validator` field.

`format_version: 1` bundles still load for backwards compatibility, but new bundles should use `format_version: 2` so they can declare `tier`, `required_features`, and freshness metadata. The v2 validation also requires `monotonic_version`, `published_at`, and `expires_at`.

### Rule types

| Type | `type` value | Merged with |
|------|-------------|-------------|
| DLP pattern | `dlp` | `dlp.patterns` |
| Injection pattern | `injection` | `response_scanning.patterns` |
| Tool poison pattern | `tool-poison` | `mcp_tool_scanning` descriptions |

### Signing your bundle

```bash
# Generate a keypair for your organization
pipelock keygen my-org

# Sign the bundle (uses the keystore at ~/.pipelock/)
pipelock sign bundle.yaml --agent my-org

# Distribute: bundle.yaml + bundle.yaml.sig + your public key hex
```

Users add your public key to their `trusted_keys` config to verify your bundles.

## Hosting

The official community bundle is hosted at `pipelab.org/rules/`. The `pipelock rules install` command fetches from this URL by default. Self-hosted bundles can be served from any HTTPS endpoint using the `--source` flag.

## Version Format

Bundles use CalVer: `YYYY.MM.patch` (e.g., `2026.03.1`). The `min_pipelock` field ensures compatibility with the installed binary version.
