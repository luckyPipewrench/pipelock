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
   tracked in the scanner result (`InformationalMatches` for text DLP,
   `WarnMatches` for URL DLP).

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
  scanning patterns, and chain detection rules. Per-rule warn for those
  rule types may be added in a future release.

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
findings by scanner name and pattern. It applies only to non-core rules; core
DLP and core response floor names fail config validation. See the
[suppression guide](suppression.md).

### Browser session cookies on intercepted HTTPS

Sites often put values in their own cookies that look like credentials to DLP: a load-balancer cookie containing an AWS-key-shaped run, or a session cookie that is a JWT. When a browser signs in through Pipelock's TLS interception, header DLP would block the site's own cookie on the next request.

A cookie the destination issued, and that goes back to that exact destination, discloses nothing the destination does not already hold. Pipelock therefore leaves such a cookie out of header DLP. The rule is `request_body_scanning.issuer_bound_session_cookies`, and it is on by default. It takes effect only when `tls_interception.enabled` is true and request body and header scanning are enabled, because intercepted HTTPS responses are the only place Pipelock can see a site issue a cookie. Set it to `false` to scan every cookie as before.

How it decides:

- Pipelock records a keyed digest of each cookie name and value from a `Set-Cookie` header on an intercepted HTTPS response that was allowed and delivered to the client. A blocked or undelivered response records nothing. The cookie value itself is never stored.
- On a later intercepted HTTPS request from the same agent session, Pipelock splits each `Cookie` header into name=value pairs. A pair is left out of the header DLP scan only if that session received exactly that name and value from the same host and port, the request path is within the cookie's path, and the cookie has not expired. Every other pair in the same header is still scanned, and the forwarded request is not changed.
- The binding follows the cookie's own scope, as a browser applies it. A cookie with no `Domain` attribute returns only to the host that set it. A cookie set with `Domain=vendor.example` by `app.vendor.example` is also recognized when the browser sends it to `api.vendor.example`, because the issuer scoped it to that domain. A `Domain` that does not contain the issuing host, a public suffix such as `co.uk`, or any `Domain` on an IP-address host is ignored, exactly as a browser rejects it, and that cookie is scanned everywhere.
- Each skipped pair that would have matched a DLP pattern writes a `dlp_issuer_cookie_allow` audit event naming the cookie name, the pattern and the destination host. The value is never logged.
- Cookies up to 4096 bytes are remembered, per RFC 6265. Evidence has per-session and global limits. The proxy saves the HMAC key and keyed digests in `$XDG_STATE_HOME/pipelock/proxy/issuer-cookies.json` (default `~/.local/state/pipelock/proxy/issuer-cookies.json`). Under `pipelock contain`, the managed service sets `XDG_STATE_HOME` to `/var/lib/pipelock/state`, because the sandboxed service can write only its data directory. The file is `0600` and its directory is `0750`. Writes are limited to once every three seconds, with a final write on graceful shutdown. A crash can lose the latest few seconds.
- Evidence survives a proxy restart or a config reload while the rule, TLS interception, and header scanning stay enabled. Other config changes keep the evidence. Disabling any prerequisite clears it, and re-enabling starts empty. If the file is missing, invalid, too large, or inaccessible, the proxy starts with no evidence and scans every cookie. After a failed write, the proxy attempts to remove the older disk snapshot so an evicted cookie cannot return after restart. If storage also prevents removal, the old file may remain until an operator fixes access. When a size limit evicts evidence, that cookie is scanned again.

What it does not cover: the same value in any other header (including `Authorization`), in the URL or in the body is scanned as usual; so is the value sent to any other host or port, over cleartext HTTP, after it expires, or by a different agent session. CONNECT tunnels that are not intercepted, and the forward proxy's plain HTTP path, never record issuance and never receive the allowance.

### Presigned URLs inside request bodies

An API may accept an AWS SigV4 presigned URL in a request body so it can fetch an attachment. That URL contains an AWS access-key ID, so the immutable DLP floor blocks it even though the full URL is a scoped capability. Do not add a core-pattern suppression.

Add an exact, expiring `request_body_scanning.sigv4_credential_routes` entry for the outbound HTTPS endpoint instead. Pin the host, canonical path, HTTP method, and content type. Pipelock exempts only the access-key ID inside a complete, structurally valid presigned URL on that route. A malformed URL, bare key, second credential, header value, different route, or non-HTTPS request still blocks.

```yaml
request_body_scanning:
  sigv4_credential_routes:
    - host: api.vendor.example
      path: /v1/graphql
      content_types: [application/json]
      methods: [POST]
      reason: register attachment URL
      owner: platform team
      expires: 2026-10-15 # temporary credential-floor exception; 30-day maximum
```

The expiry is temporary and may be no more than 30 days ahead. Shorten the exception, or move the credential handoff out of the request body for a permanent integration. Deploy the supporting Pipelock version before adding this field to shared configuration. Older versions reject unknown fields instead of ignoring them.

### Opaque content entropy

The `content_entropy` detector (`request_body_scanning.content_entropy_*`) flags
high-entropy body, WebSocket, and A2A content that matches no credential pattern.
Because a content-addressed hash or an encrypted upload has the same shape as a
hex-encoded secret, it can false-positive on legitimate opaque traffic.

The detector ships `warn` in the general presets, so out of the box a false
positive is an audit line, not a block. Tune before setting
`request_body_scanning.content_entropy_action: block` for the deployment or
selecting a blocking preset (strict/hostile presets already block):

- **Narrowest first:** for an HTTPS request-body endpoint, add an exact,
  expiring `request_body_scanning.content_entropy_warn_routes` entry. The
  entropy finding remains visible while DLP, prompt injection, address, body
  size, and redirect checks keep their normal actions.
- **WebSocket:** use `websocket_proxy.content_entropy_exclusions` for a
  WebSocket-only endpoint. Route warning entries do not affect WebSocket or
  A2A entropy scanning.
- **Broader:** a host in `request_body_scanning.content_entropy_exclusions`
  skips request-body entropy across every path on that host. If the host is
  fully trusted, `trusted_domains` covers it for
  entropy and other destination-trust checks at once.
- **Global (last resort):** raising `request_body_scanning.content_entropy_threshold`
  lowers sensitivity for every destination. Prefer an exact route warning.

`content_entropy_min_length` applies to both individual leaves and their stable
aggregate views. Raising it can reduce flags for one short identifier, but a
collection of short identifiers may still exceed the aggregate floor. Prefer
an exact route warning when opaque identifiers are normal at one HTTPS endpoint.
