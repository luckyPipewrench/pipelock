# Agent Firewall Policy Specification v0.1

**Status:** Draft
**Version:** 0.1.0
**Authors:** Pipelock maintainers

This specification defines a minimal, portable policy format for agent firewalls. The goal is to standardize how egress rules, DLP actions, audit events, and MCP scan hooks are expressed, so policies can be shared across tools and organizations.

Pipelock implements this spec natively. Other agent firewall implementations can adopt it to enable policy portability.

## Design Principles

1. **Minimal.** Only fields that affect security decisions. No UI preferences, no deployment config, no vendor-specific extensions in the core spec.
2. **Declarative.** Policies describe what to allow/deny, not how to implement it. Enforcement is up to the runtime.
3. **Composable.** Multiple policies can be merged. Later rules override earlier ones by name.
4. **Auditable.** Every policy decision should produce a structured log entry that references the rule that triggered it.

## Policy Document

A policy document is a YAML file with these top-level keys:

```yaml
policy_version: "0.1"
name: "production-agents"
description: "Policy for production AI agent fleet"

egress: { ... }
dlp: { ... }
response: { ... }
mcp: { ... }
audit: { ... }
```

All sections are optional. Missing sections mean "no opinion" (defer to runtime defaults).

## Egress Rules

Control which domains and IP ranges the agent can reach.

```yaml
egress:
  default: deny              # deny or allow
  rules:
    - name: "LLM providers"
      domains:
        - "*.anthropic.com"
        - "*.openai.com"
        - "api.together.xyz"
      action: allow

    - name: "Known exfiltration targets"
      domains:
        - "*.pastebin.com"
        - "*.transfer.sh"
        - "file.io"
        - "requestbin.net"
      action: deny

    - name: "Internal networks"
      cidrs:
        - "10.0.0.0/8"
        - "172.16.0.0/12"
        - "192.168.0.0/16"
        - "169.254.0.0/16"
      action: deny
```

### Egress Rule Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Human-readable rule identifier |
| `domains` | string[] | no | Domain patterns (supports `*` wildcard prefix) |
| `cidrs` | string[] | no | CIDR ranges (IPv4 and IPv6) |
| `action` | string | yes | `allow` or `deny` |

Rules are evaluated top-to-bottom. First match wins. If no rule matches, `default` applies.

Domain matching is case-insensitive. `*.example.com` matches `api.example.com` but not `example.com` itself. Use both `example.com` and `*.example.com` to cover both.

## DLP Rules

Define patterns for detecting secrets and sensitive data in URLs, request bodies, and tool arguments.

```yaml
dlp:
  scan_environment: true       # Check env vars for leaked values
  min_env_length: 16           # Min env var value length to flag
  patterns:
    - name: "Anthropic API Key"
      regex: 'sk-ant-[a-zA-Z0-9\-_]{10,}'
      severity: critical
      action: block

    - name: "AWS Access Key"
      regex: '(AKIA|ASIA)[A-Z0-9]{16,}'
      severity: critical
      action: block

    - name: "Credential in URL"
      regex: '(password|token|secret|api_?key)=[^\s&]{8,}'
      severity: high
      action: warn
```

### DLP Pattern Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Pattern identifier (used in audit events) |
| `regex` | string | yes | Case-insensitive regex |
| `severity` | string | yes | `critical`, `high`, `medium`, `low` |
| `action` | string | no | `block` or `warn` (overrides global DLP action) |

Regexes are always applied case-insensitive. Implementations should support at minimum: PCRE-compatible syntax, character classes, alternation, and quantifiers.

### Encoding Handling

Implementations MUST attempt to decode content before pattern matching:
- Base64 (standard and URL-safe, with and without padding)
- Hex encoding
- URL encoding (iterative, handling multi-layer encoding)

This is not optional. Without encoding-aware matching, DLP is trivially bypassed.

## Response Scanning

Detect prompt injection in fetched content and MCP tool results.

```yaml
response:
  action: warn                 # block, strip, warn, or ask
  patterns:
    - name: "Prompt Injection"
      regex: '(?i)(ignore|disregard)\s+(all\s+)?(previous|prior)\s+(instructions|prompts)'

    - name: "System Override"
      regex: '(?i)(you\s+are|act\s+as)\s+(now\s+)?(a|an|my)\s+'

    - name: "Jailbreak Attempt"
      regex: '(?i)(DAN|developer)\s+mode'
```

### Response Actions

| Action | Behavior |
|--------|----------|
| `block` | Reject the response entirely |
| `strip` | Remove matched text, return the rest |
| `warn` | Log the finding, return content unchanged |
| `ask` | Pause for human approval (requires interactive terminal) |

### Normalization Requirements

Implementations SHOULD apply these normalizations before pattern matching (in order):
1. Strip zero-width and invisible Unicode characters
2. Apply NFKC Unicode normalization
3. Map confusable characters to ASCII equivalents
4. Strip combining marks

Without normalization, injection detection is trivially bypassed with Unicode tricks.

## MCP Hooks

Rules for MCP tool call scanning, tool description validation, and chain detection.

```yaml
mcp:
  input_scanning:
    enabled: true
    action: warn
    on_parse_error: block       # What to do with malformed JSON-RPC

  tool_scanning:
    enabled: true
    action: warn
    detect_drift: true          # Alert on tool description changes

  tool_policy:
    action: warn
    rules:
      - name: "Block shell execution"
        tool_pattern: "execute_command|run_terminal|bash"
        action: block

      - name: "Warn on file writes"
        tool_pattern: "write_file|create_file"
        arg_pattern: '/etc/.*|/usr/.*|~/.ssh/.*'
        action: warn

  session_binding:
    enabled: true
    unknown_tool_action: warn

  chain_detection:
    enabled: true
    action: warn
    window_size: 20
    window_seconds: 300
    max_gap: 3
```

### Tool Policy Rule Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Rule identifier |
| `tool_pattern` | string | yes | Regex matching tool name |
| `arg_pattern` | string | no | Regex matching argument values |
| `action` | string | no | `block` or `warn` |

## Audit Event Format

Every policy decision produces a structured audit event. This is the canonical format:

```json
{
  "timestamp": "2026-02-28T15:04:05.000Z",
  "level": "warn",
  "event": "blocked",
  "scanner": "dlp",
  "rule": "Anthropic API Key",
  "severity": "critical",
  "method": "GET",
  "url": "https://example.com/?key=sk-ant-...",
  "agent": "my-bot",
  "client_ip": "127.0.0.1",
  "request_id": "abc123",
  "mitre_technique": "T1048",
  "instance_id": "prod-agent-1"
}
```

### Required Audit Fields

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | ISO 8601 | When the event occurred |
| `level` | string | `info`, `warn`, or `critical` |
| `event` | string | Event type: `allowed`, `blocked`, `anomaly`, etc. |
| `scanner` | string | Which scanner triggered the event |
| `rule` | string | Pattern/rule name that matched |

### Optional Audit Fields

| Field | Type | Description |
|-------|------|-------------|
| `severity` | string | Finding severity (from DLP/response pattern) |
| `method` | string | HTTP method |
| `url` | string | Target URL (may be truncated) |
| `agent` | string | Agent identifier |
| `client_ip` | string | Source IP (HTTP transports only, empty for stdio MCP) |
| `request_id` | string | Unique request identifier (HTTP transports only, empty for stdio MCP) |
| `mitre_technique` | string | MITRE ATT&CK technique ID |
| `instance_id` | string | Pipelock instance identifier |
| `score` | number | Threat score (if adaptive enforcement is enabled) |

### MITRE ATT&CK Mapping

Implementations SHOULD include MITRE technique IDs in audit events where applicable:

| Detection | Technique ID | Name |
|-----------|-------------|------|
| DLP / secret exfiltration | T1048 | Exfiltration Over Alternative Protocol |
| SSRF / private IP access | T1046 | Network Service Discovery |
| Prompt injection | T1059 | Command and Scripting Interpreter |
| Tool poisoning | T1195.002 | Supply Chain: Software Supply Chain |
| Session anomaly | T1078 | Valid Accounts |
| Domain blocklist violation | T1071.001 | Application Layer Protocol: Web |
| Rate limit / data budget | T1030 | Data Transfer Size Limits |

## Policy Merging

When multiple policies are combined (org-wide + team + project), merge rules:

1. Later policies override earlier ones by section
2. Within `egress.rules`, `dlp.patterns`, etc., rules merge by `name`
3. If two rules share a name, the later one wins entirely (no field-level merge)
4. `egress.default` is overridden by the last policy that sets it

This allows organizations to set a baseline policy and teams to customize it.

## Validation

Implementations MUST validate policies at load time:

- All regex patterns compile without error
- All `action` values are recognized
- All `severity` values are recognized
- Strict mode (`egress.default: deny`) has at least one `allow` rule
- CIDR values parse correctly

Invalid policies MUST be rejected entirely (fail-closed). Partial application of a broken policy is a security risk.

## Versioning

The `policy_version` field uses semver. Implementations MUST reject policies with a major version they don't support. Minor version bumps add optional fields. Patch version bumps are documentation-only.

## Example: Minimal Production Policy

```yaml
policy_version: "0.1"
name: "minimal-production"

egress:
  default: deny
  rules:
    - name: "LLM APIs"
      domains: ["*.anthropic.com", "*.openai.com"]
      action: allow
    - name: "Package registries"
      domains: ["registry.npmjs.org", "pypi.org", "pkg.go.dev"]
      action: allow

dlp:
  scan_environment: true
  patterns:
    - name: "API Keys"
      regex: 'sk-[a-zA-Z0-9\-_]{20,}'
      severity: critical

response:
  action: block

mcp:
  input_scanning:
    enabled: true
    action: block
  tool_policy:
    action: warn
    rules:
      - name: "No shell"
        tool_pattern: "execute_command|bash|shell"
        action: block

audit: {}
```

## Relationship to Pipelock Config

Pipelock's YAML config (`pipelock.yaml`) is a superset of this spec. It includes deployment fields (`listen`, `timeout_seconds`, etc.) alongside policy fields. The policy fields map directly:

| Policy Spec | Pipelock Config |
|-------------|----------------|
| `egress.default` | `mode: strict` + `api_allowlist` |
| `egress.rules[].domains` | `api_allowlist` + `monitoring.blocklist` |
| `dlp.patterns` | `dlp.patterns` |
| `response.action` | `response_scanning.action` |
| `mcp.*` | `mcp_input_scanning`, `mcp_tool_scanning`, etc. |
| `audit` | `logging` + `emit` |

See [Configuration Reference](configuration.md) for the full pipelock config documentation.
