# False Positive Tuning

This guide covers techniques for managing DLP pattern false positives
in pipelock, including the per-pattern warn mode for safe rollout of new patterns.

## Staging new DLP patterns with warn mode

When deploying a new DLP pattern to production, there is always a risk of
false positives blocking legitimate traffic. Warn mode lets you observe what
a pattern would match in production without taking enforcement action.

### The rollout workflow

1. **Add the pattern with `action: warn`:**

```yaml
dlp:
  patterns:
    - name: my-new-pattern
      regex: 'my-prefix-[A-Za-z0-9]{20,}'
      severity: high
      action: warn
```

2. **Deploy and observe.** The pattern matches traffic but requests are not
   blocked. When the runtime warn hook is configured (see below), matches
   emit `dlp_warn` audit events. Without the hook, warn matches are still
   tracked in the scanner result's `InformationalMatches` field.

3. **Review matches.** Check the `pattern`, `severity`, and `transport` fields
   in the audit event (when the warn hook is active) or the scan API response
   to determine if the matches are true positives or false positives.
   Adjust the regex if needed.

4. **Promote to enforce.** When confident the pattern has an acceptable
   false positive rate, remove the `action: warn` line (or delete the field
   entirely). The pattern defaults to enforce mode on the next config reload.

```yaml
dlp:
  patterns:
    - name: my-new-pattern
      regex: 'my-prefix-[A-Za-z0-9]{20,}'
      severity: high
      # action removed — pattern now enforces
```

### How warn mode works

Warn-mode patterns are evaluated through the same scanning pipeline as
enforced patterns (URL DLP, text DLP, encoded variants, cross-request
detection). The difference is purely in how the match result is handled:

- **Enforced patterns** produce a block/strip action on the applicable transport.
- **Warn patterns** allow the request to proceed. When the warn hook is
  active, they also emit `dlp_warn` audit events.

Warn mode applies to all DLP scanning surfaces: fetch proxy, forward proxy,
CONNECT, WebSocket, MCP input scanning, request body scanning, and
cross-request fragment detection.

### Warn hook

The scanner provides a package-level hook (`scanner.DLPWarnHook`) that the
runtime can set to route warn events to the audit logger. When the hook is
wired, each warn-mode match emits a `dlp_warn` event with `pattern`,
`severity`, and `transport` fields. The `LogDLPWarn` method on the audit
logger provides the canonical event format.

When the hook is not configured, warn matches still allow traffic through
and are reported in the scan result's `InformationalMatches` / `WarnMatches`
fields, but no audit event is emitted.

### Restrictions

- **Built-in default patterns cannot be set to warn.** These are the
  immutable safety floor and always enforce.
- **Only `warn` is accepted as a per-pattern action.** Other actions
  (`block`, `strip`, `redirect`, `ask`) are not valid at the pattern level.
  Transport-level action configuration (`request_body_scanning.action`,
  `mcp_input_scanning.action`, etc.) controls enforcement for enforced matches.
- **Warn mode applies to DLP patterns only.** Blocklist entries, response
  scanning patterns, and chain detection rules do not support per-rule warn
  mode in this release.

## Other false positive tuning techniques

### Exempt domains

Use `exempt_domains` on a DLP pattern to skip enforcement for specific
trusted destinations:

```yaml
dlp:
  patterns:
    - name: github-token
      regex: 'ghp_[A-Za-z0-9]{36}'
      severity: critical
      exempt_domains:
        - "api.github.com"
        - "*.github.com"
```

### Suppression rules

The `suppress` configuration section lets you suppress specific scanner
findings by scanner name and pattern. See the [suppression guide](suppression.md).
