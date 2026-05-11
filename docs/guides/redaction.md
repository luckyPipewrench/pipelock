# Request Redaction

Pipelock can rewrite matched secrets and sensitive identifiers before a request leaves the agent. The redactor walks JSON payloads, replaces matched values with typed placeholders such as `<pl:aws-access-key:1>`, then runs the normal request-side DLP scan on the rewritten bytes.

## Coverage

- HTTP request bodies on fetch, forward, reverse, and TLS-intercepted CONNECT paths
- Outbound WebSocket client messages sent through `/ws`
- MCP `tools/call` `params.arguments` across stdio, HTTP/SSE, listener, and WebSocket transports

The same matcher and profile selection are used across all of those surfaces.

## Production Example

```yaml
request_body_scanning:
  enabled: true
  action: warn

redaction:
  enabled: true
  default_profile: code
  profiles:
    code:
      classes:
        - aws-access-key
        - google-api-key
        - github-token
        - slack-token
        - jwt
        - ssh-private-key
    business:
      classes:
        - email
        - fqdn
        - ipv4
        - ipv6
      dictionaries:
        - customer-hosts
  dictionaries:
    customer-hosts:
      class: customer-host
      entries:
        - acme.internal
        - billing.acme.internal
      word_boundary: true
      priority: 80
  allowlist_unparseable:
    - api.anthropic.com
    - api.openai.com
  allowlist_unparseable_routes:
    - host: login.microsoftonline.com
      methods: [POST]
      path_suffixes: [/oauth2/v2.0/token]
      content_types: [application/x-www-form-urlencoded]
  providers:
    acme_llm:
      host_patterns:
        - api.acme-llm.example
      path_prefixes:
        - /v1/messages
      parser: json
```

Use a narrow `code` profile for developer traffic and add broader `business` profiles only where you intentionally want hostnames, emails, or customer literals rewritten before they reach upstream systems.

## Fail-Closed Rules

- `redaction.enabled: true` requires `request_body_scanning.enabled: true`.
- Only complete JSON payloads are rewritten.
- Non-JSON HTTP bodies and complete non-JSON WebSocket messages are blocked unless the destination host is on `allowlist_unparseable` or the request matches `allowlist_unparseable_routes`.
- Outbound WebSocket fragments are blocked while redaction is enabled because partial JSON messages cannot be rewritten safely.
- Malformed JSON, numeric scalars containing secrets, key-collision rewrites, or redaction limits being exceeded all block the request instead of forwarding partially transformed data.

`allowlist_unparseable` accepts bare lowercase hostnames only. Do not include schemes, paths, or ports. Use it sparingly for trusted endpoints that legitimately require non-JSON request formats.

Prefer `allowlist_unparseable_routes` for OAuth token endpoints and upload paths. Each route requires a bare lowercase `host` plus at least one additional constraint: `methods`, `path_prefixes`, `path_suffixes`, or `content_types`. Matching requests skip only the JSON rewrite gate; request body and header scanning still run.

## Provider Parsers

Pipelock ships parser profiles for Anthropic, OpenAI, and Gemini. All three use the same `json` parser, which walks every string scalar in the request body. Provider matching is only for parser selection and receipt labeling; it does not exempt `system`, `tools`, `messages`, Gemini `contents`, or any other field from redaction.

Third-party JSON providers can be added under `redaction.providers` with `host_patterns`, optional `path_prefixes`, and `parser: json`. Unknown JSON providers still fall back to the generic JSON parser, so a missing provider profile does not become a redaction bypass.

## Receipts

Successful rewrites add a `redaction` block to the signed action receipt:

```json
{
  "redaction": {
    "profile": "code",
    "provider": "gemini",
    "parser": "json",
    "total_redactions": 2,
    "by_class": {
      "aws-access-key": 1,
      "fqdn": 1
    }
  }
}
```

The receipt never stores the original plaintext. If nothing was rewritten, the `redaction` field is omitted so non-redacted receipts stay byte-identical to prior releases.
