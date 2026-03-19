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

Bundles are stored in `~/.pipelock/rules/` by default. Override with the `--rules-dir` flag or the `rules_dir` config field.

> **Note:** Official bundle verification requires the embedded keyring, which is present in release binaries (Homebrew, GitHub Releases, Docker). Source builds via `go install` do not include the keyring unless built with the release ldflags. Source-build users must add the official public key to `trusted_keys` in their config for remote installs, or download the bundle manually and use `--path` with `--allow-unsigned`.

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
  rules_dir: ~/.pipelock/rules    # default
  min_confidence: medium          # skip experimental rules (low confidence)
  include_experimental: false     # default: only stable rules are active
  # trusted_keys:                 # additional trusted public keys (beyond embedded keyring)
  #   - name: "acme-security"
  #     public_key: "64-char-hex-encoded-ed25519-public-key"
```

## Trust Model

Bundles are Ed25519-signed YAML files. Pipelock verifies signatures against a keyring before loading rules.

### Official bundles

Official bundles (like `pipelock-community`) are signed with the production key embedded in the binary at build time. No additional configuration is needed.

### Third-party bundles

Organizations can create and sign their own bundles. Add their public key to `trusted_keys` in your config. Pipelock verifies third-party signatures the same way it verifies official ones.

### Unsigned bundles

The `--allow-unsigned` flag skips signature verification during install. Use this only for local testing. Unsigned bundles log a warning at startup.

## Verifying Signatures

```bash
# Re-verify all installed bundles against the embedded keyring
pipelock rules verify
```

## Creating Your Own Bundle

A bundle is a single YAML file with a header and a list of rules:

```yaml
name: my-company-rules
version: "2026.03.1"
min_pipelock: "1.4.0"
description: Internal detection patterns for Acme Corp
rules:
  - id: dlp-internal-api-key
    type: dlp
    name: "Acme Internal API Key"
    regex: 'acme_[a-zA-Z0-9]{32}'
    severity: critical
    confidence: high
```

### Rule types

| Type | `type` value | Merged with |
|------|-------------|-------------|
| DLP pattern | `dlp` | `dlp.patterns` |
| Injection pattern | `injection` | `response_scanning.patterns` |
| Tool poison pattern | `tool_poison` | `mcp_tool_scanning` descriptions |

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
