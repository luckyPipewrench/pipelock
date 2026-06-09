# Configuration Reference

Pipelock uses a single YAML config file. Generate a starter config:

```bash
pipelock generate config --preset balanced > pipelock.yaml
pipelock run --config pipelock.yaml
```

Or scan your project and get a tailored config:

```bash
pipelock audit ./my-project -o pipelock.yaml
```

## Hot Reload

Config changes are picked up automatically via file watcher or SIGHUP signal (100ms debounce). Most fields reload without restart. Fields that require a restart are marked below.

On reload, the scanner and session manager are atomically swapped. Kill switch state (all 4 sources) is preserved. Existing MCP sessions retain the old scanner until the next request.

If a reload fails validation (invalid regex, security downgrade), the old config is retained and a warning is logged.

**Reload exceptions:** the Sentry crash-report scrubber captures the DLP pattern list at startup and does **not** update on reload. If you add DLP patterns used to scrub Sentry events, restart pipelock to propagate them. A warning is logged on any reload that changes `dlp.patterns` while Sentry is enabled: `DLP patterns changed; Sentry scrubber uses init-time patterns until restart`.

**Strict parsing:** Pipelock rejects unknown top-level and nested YAML fields at startup, and it only accepts a single YAML document per config file. Trailing `---` documents are a hard error. This prevents typos from silently disabling controls and blocks shadow-config bypasses.

## Top-Level Fields

```yaml
version: 1                    # Config schema version (currently 1)
mode: balanced                # "strict", "balanced", or "audit"
enforce: true                 # false = detect without blocking (warning-only)
explain_blocks: false         # true = include fix hints in block responses
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `version` | int | `1` | Config schema version |
| `mode` | string | `"balanced"` | Operating mode (see [Modes](#modes)) |
| `enforce` | bool | `true` | When false, all blocks become warnings |
| `explain_blocks` | bool | `false` | Include actionable hints in block responses |

### Block Hints (`explain_blocks`)

When enabled, blocked responses include a hint explaining why the request was blocked and how to fix it. Fetch proxy responses get a `hint` field in the JSON body. CONNECT and WebSocket rejections get an `X-Pipelock-Hint` response header.

```yaml
explain_blocks: true
```

**Security note:** Hints expose scanner names and config field names (e.g., "Add to api_allowlist", "Add a suppress entry"). This is useful for debugging but reveals your security policy to the agent. **Default: false (opt-in).** Enable when you trust your agent or need easier debugging. Leave disabled in production where untrusted agents could use hints to craft bypasses.

### Modes

| Mode | Behavior | Use Case |
|------|----------|----------|
| **strict** | Allowlist-only. Only `api_allowlist` domains pass. | Regulated industries, high-security |
| **balanced** | Blocks known-bad, detects suspicious. All domains reachable. | Most developers (default) |
| **audit** | Logs everything, blocks nothing. | Evaluation before enforcement |

## API Allowlist

Domains that are always allowed in strict mode. In balanced/audit mode, these are exempt from the domain blocklist.

```yaml
api_allowlist:
  - "*.anthropic.com"
  - "*.openai.com"
  - "*.discord.com"
  - "github.com"
  - "api.slack.com"
```

Supports wildcards (`*.example.com` matches `api.example.com` **and** the apex `example.com` itself). Case-insensitive.

## Fetch Proxy

The HTTP fetch proxy listens for requests on `/fetch?url=...` and returns extracted text content.

```yaml
fetch_proxy:
  listen: "127.0.0.1:8888"
  timeout_seconds: 30
  max_response_mb: 10
  user_agent: "Pipelock Fetch/1.0"
  monitoring:
    max_url_length: 2048
    entropy_threshold: 4.5
    max_requests_per_minute: 60
    max_data_per_minute: 0        # bytes/min per domain (0 = disabled)
    blocklist:
      - "*.pastebin.com"
      - "*.hastebin.com"
      - "*.transfer.sh"
      - "file.io"
      - "requestbin.net"
    subdomain_entropy_exclusions:
      - "files.pythonhosted.org"
      - "pypi.org"
      - "objects.githubusercontent.com"
```

| Field | Default | Description |
|-------|---------|-------------|
| `listen` | `127.0.0.1:8888` | Listen address |
| `timeout_seconds` | `30` | HTTP request timeout |
| `max_response_mb` | `10` | Max response body size |
| `user_agent` | `Pipelock Fetch/1.0` | User-Agent header sent upstream |
| `monitoring.max_url_length` | `2048` | URLs longer than this are blocked |
| `monitoring.entropy_threshold` | `4.5` | Shannon entropy threshold for path segments |
| `monitoring.max_requests_per_minute` | `60` | Per-domain rate limit |
| `monitoring.max_data_per_minute` | `0` | Per-domain byte budget (0 = disabled) |
| `monitoring.blocklist` | 5 domains | Blocked exfiltration targets |
| `monitoring.subdomain_entropy_exclusions` | `files.pythonhosted.org`, `pypi.org`, `objects.githubusercontent.com` | Domains excluded from subdomain and path entropy checks; override to replace defaults, or set an empty list to disable exclusions entirely (query entropy still checked) |

**Entropy guidance:**
- English text: 3.5-4.0 bits/char
- Hex/commit hashes: ~4.0
- Base64-encoded data: 4.0-4.5
- Random/encrypted: 5.5-8.0

The default threshold (4.5) allows commit hashes and base64-encoded filenames while flagging encrypted blobs. Lower it (3.5) for strict mode. Raise it (5.0) for development environments where base64 URLs are common.

**Subdomain entropy exclusions** skip subdomain and path entropy checks for specific domains, but query parameter entropy is still checked. Defaults cover package/object hosts that use hash-like routing paths (`files.pythonhosted.org`, `pypi.org`, `objects.githubusercontent.com`). This is also useful for APIs that embed tokens in URL paths (e.g., Telegram bot API). Supports wildcard matching (`*.example.com`).

```yaml
fetch_proxy:
  monitoring:
    subdomain_entropy_exclusions:
      - "api.telegram.org"
```

**Query entropy exclusions** skip only the query-string entropy gate for specific domains. Subdomain entropy, path entropy, DLP, SSRF, rate limits, and data budgets still apply. This is intended for endpoints whose query parameters legitimately carry high-entropy opaque values, such as S3 pre-signed URLs. Supports the same exact-host and `*.example.com` wildcard matching rules.

```yaml
fetch_proxy:
  monitoring:
    query_entropy_exclusions:
      - "examplebucket.s3.amazonaws.com"
```

**Path entropy and governed API routes.** Path entropy is *also* skipped
automatically on any path you already govern with a [`request_policy`](#request-policy)
route that names **both** a host **and** path constraints (`path_patterns` or
`path_prefixes`). The reasoning: if you wrote explicit path rules for a host, the
blunt entropy heuristic is redundant on those exact paths, and it otherwise
false-positives on legitimate high-entropy REST resource ids (an opaque id
segment in `/v1/messages/{id}` reads as a "high entropy path segment"). This is
the recommended way to run an agent against a TLS-intercepted REST API whose URLs
carry opaque ids.

This exemption is deliberately narrow:

- It is **path-only**. Subdomain entropy, query entropy, DLP, and SSRF stay fully
  active on the same request.
- It applies **only to paths your route matches**. Other paths on the same host
  still get path entropy.
- A route with **no host**, or with **no path constraints**, never exempts
  anything (a hostless route would otherwise match every host).
- Shadow rules never exempt, because they do not enforce `request_policy`.

> **Operator note:** the skip covers exactly the paths your route patterns match.
> If your agent calls API paths your `request_policy` route does not cover, widen
> the route's `path_patterns`/`path_prefixes` to include them (or add the host to
> `subdomain_entropy_exclusions`), otherwise those paths still get path entropy.

## Forward Proxy

Standard HTTP CONNECT tunneling. Agents set `HTTPS_PROXY=http://127.0.0.1:8888`, and HTTP clients that honor proxy settings flow through pipelock. Pair this with containment, sandboxing, or deployment policy when non-cooperative tools are in scope.

```yaml
forward_proxy:
  enabled: false                # Requires restart to change
  max_tunnel_seconds: 300
  idle_timeout_seconds: 120
  sni_verification: true        # Verify TLS SNI matches CONNECT target
  redirect_websocket_hosts: []  # Redirect WS hosts to /ws proxy
```

| Field | Default | Restart? | Description |
|-------|---------|----------|-------------|
| `enabled` | `false` | **Yes** | Enable CONNECT tunnel proxy |
| `max_tunnel_seconds` | `300` | No | CONNECT setup/dial deadline before the tunnel is established |
| `idle_timeout_seconds` | `120` | No | Kill established tunnels after this much inactivity |
| `sni_verification` | `true` | No | Verify TLS ClientHello SNI matches the CONNECT target hostname. Blocks domain fronting (MITRE T1090.004). Set to `false` to disable. |
| `redirect_websocket_hosts` | `[]` | No | Redirect matching hosts to /ws |

## TLS Interception

Enables TLS MITM on CONNECT tunnels, allowing pipelock to decrypt, scan, and re-encrypt HTTPS traffic. When enabled, request bodies and headers are scanned for secret exfiltration, and responses are scanned for prompt injection, closing the CONNECT tunnel body-blindness gap.

Requires a CA certificate trusted by the agent. Generate one with `pipelock tls init` and install it with `pipelock tls install-ca`.

```yaml
tls_interception:
  enabled: false
  ca_cert: ""                    # path to CA cert PEM (default: ~/.pipelock/ca.pem)
  ca_key: ""                     # path to CA key PEM (default: ~/.pipelock/ca-key.pem)
  passthrough_domains:           # domains to splice (not intercept)
    - "*.googlevideo.com"
  cert_ttl: "24h"
  cert_cache_size: 10000
  max_response_bytes: 5242880    # 5MB; responses larger than this are blocked
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable TLS interception on CONNECT tunnels |
| `ca_cert` | `""` | Path to CA certificate PEM. Empty resolves to `~/.pipelock/ca.pem` |
| `ca_key` | `""` | Path to CA private key PEM. Empty resolves to `~/.pipelock/ca-key.pem` |
| `passthrough_domains` | `["*.googlevideo.com"]` | Domains to splice (pass through without interception). Supports `*.example.com` wildcards (also matches apex `example.com`). |
| `cert_ttl` | `"24h"` | TTL for forged leaf certificates (Go duration string) |
| `cert_cache_size` | `10000` | Max cached leaf certificates. Evicts oldest when full. |
| `max_response_bytes` | `5242880` | Max response body to buffer for scanning. Responses exceeding this are blocked (fail-closed). |

**Setup:**

```bash
# Generate a CA key pair
pipelock tls init

# Install the CA into the system trust store (macOS/Linux)
pipelock tls install-ca

# Or export the CA cert for manual installation
pipelock tls show-ca
```

**Scanning behavior:** When a CONNECT tunnel is intercepted, pipelock terminates TLS with the client using a forged certificate, then opens a separate TLS connection to the upstream server. Inner HTTP requests are served via Go's `http.Server`, enabling:

- **Request body DLP:** same scanning as `request_body_scanning` (JSON, form, multipart extraction + DLP patterns)
- **Request header DLP:** same scanning as `request_body_scanning.scan_headers`
- **Authority enforcement:** the `Host` header must match the CONNECT target. Mismatches are blocked (prevents domain fronting inside encrypted tunnels).
- **Response injection scanning:** buffered responses scanned through the `response_scanning` pipeline before forwarding to the agent
- **Compressed response blocking:** responses with non-identity `Content-Encoding` are blocked (fail-closed, since compressed bytes evade regex DLP)

**Fail-closed behaviors:**
- Responses exceeding `max_response_bytes` are blocked
- Compressed responses (gzip, deflate, br) are blocked
- Response read errors are blocked
- Authority mismatch (Host header differs from CONNECT target) is blocked

**Passthrough domains:** Domains in `passthrough_domains` are spliced (bidirectional byte copy) without interception, preserving end-to-end TLS. Use this for domains where certificate pinning prevents interception or where you trust the destination. Supports exact match and wildcard prefix (`*.example.com` matches `sub.example.com` and the apex `example.com`).

**Best practice -- package registries and LLM providers:** Always add package registries (npm, pypi, Go proxy) and LLM API endpoints to `passthrough_domains`, not just `exempt_domains`. Using `exempt_domains` alone is a response-scanning decision, not a TLS-routing decision: the connection is still MITM-ed, clients that reject the generated certificate can still fail the TLS handshake, and pipelock still spends CPU generating certificates for traffic you do not intend to inspect. Passthrough skips interception entirely.

```yaml
passthrough_domains:
  - "registry.npmjs.org"       # npm packages
  - "pypi.org"                 # Python packages
  - "*.pypi.org"
  - "files.pythonhosted.org"   # pip downloads
  - "proxy.golang.org"         # Go modules
  - "*.anthropic.com"          # LLM provider
  - "*.openai.com"             # LLM provider
```

## Request Body Scanning

Scans request bodies and headers for secret exfiltration and prompt injection before traffic leaves the protected agent path. Catches secrets and instruction-smuggling payloads in POST/PUT/PATCH bodies, JSON keys and values, form-urlencoded fields, outbound WebSocket client frames, reverse-proxy requests, intercepted CONNECT traffic, and Authorization/Cookie headers that bypass URL-level scanning.

**Scope:** Forward HTTP proxy (`HTTPS_PROXY` and `HTTP_PROXY` absolute-URI requests), reverse proxy, outbound WebSocket client text messages, fetch handler headers, and intercepted CONNECT tunnels (when `tls_interception.enabled` is true).

```yaml
request_body_scanning:
  enabled: false
  action: warn              # warn or block (no strip for bodies)
  max_body_bytes: 5242880   # 5MB; fail-closed above this
  scan_headers: true        # scan request headers for DLP
  header_mode: sensitive    # "sensitive" (listed headers) or "all" (everything except ignore list)
  sensitive_headers:
    - Authorization
    - Cookie
    - X-Api-Key
    - X-Token
    - Proxy-Authorization
    - X-Goog-Api-Key
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable request body/header DLP scanning and request body prompt-injection scanning |
| `action` | `warn` | `warn` logs ordinary findings, `block` rejects ordinary findings (requires enforce mode). Critical DLP and prompt-injection hard-blocks still reject non-provider destinations in enforce mode. |
| `max_body_bytes` | `5242880` | Max body size to buffer; bodies exceeding this are always blocked (fail-closed) |
| `scan_headers` | `true` | Scan request headers for DLP patterns |
| `header_mode` | `sensitive` | `sensitive`: scan only listed headers. `all`: scan all headers except ignore list |
| `sensitive_headers` | (see above) | Headers to scan in `sensitive` mode |
| `ignore_headers` | (hop-by-hop + structural) | Headers to skip in `all` mode |

**Content-type dispatch:** JSON bodies have string values and object keys extracted recursively. Form-urlencoded bodies are parsed as ordered key-value pairs so split instruction phrases preserve wire order. Multipart form data scans all part headers plus all part bodies regardless of declared `Content-Type` (max 100 parts), and decodes `Content-Transfer-Encoding: base64` / `quoted-printable` before scanning. Text/* and XML bodies are scanned as raw text. Unknown content types get a fallback raw-text scan (never skipped, preventing `Content-Type` spoofing bypass).

**Fail-closed behaviors** (always blocked regardless of `action` setting):
- Bodies exceeding `max_body_bytes`
- Compressed bodies (`Content-Encoding: gzip/deflate/br`): compressed bytes evade regex DLP
- Body read errors: prevents forwarding empty/corrupt bodies
- Invalid JSON bodies
- Invalid form-urlencoded bodies: prevents parser differential attacks
- Multipart missing `boundary` parameter
- Multipart with more than 100 parts
- Multipart part exceeding `max_body_bytes`
- Multipart filename exceeding 256 bytes: prevents secret exfiltration via long filenames

**Header scanning:** Headers are scanned regardless of destination host. An agent can exfiltrate secrets via `Authorization: Bearer <secret>` to any host, including allowlisted ones. The URL allowlist controls URL-level blocking, not header DLP bypass.

**Security hard-blocks:** In enforce mode, critical-severity DLP findings in request bodies hard-block with `X-Pipelock-Block-Reason: dlp_match` even when `request_body_scanning.action: warn`. Request-body prompt-injection findings hard-block non-provider destinations with `X-Pipelock-Block-Reason: prompt_injection`. Operators that need audit-only rollout for selected critical patterns can set those individual patterns to `action: warn` or run the deployment with `enforce: false`.

**Note on `scan_headers`:** The config default is `true`, but omitting the field from your YAML file gives `false` (Go's zero value overrides the default). Always set `scan_headers: true` explicitly in your config if you want header scanning enabled.

## Redaction

Optional request-side redaction rewrites matched JSON scalars before a request is forwarded upstream. It runs before request-body DLP so warn-mode traffic still forwards the redacted payload instead of the original secret. The same matcher is used for HTTP request bodies, outbound WebSocket client messages, and MCP `tools/call` `params.arguments` across stdio, HTTP/SSE, and WebSocket transports.

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
  limits:
    max_body_bytes: 10485760
    max_redactions_per_request: 10000
    max_depth: 64
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable request-side redaction |
| `default_profile` | `""` | Profile name applied when redaction is enabled |
| `profiles` | `{}` | Named profile map |
| `profiles.<name>.classes` | `[]` | Built-in redaction classes enabled for the profile |
| `profiles.<name>.dictionaries` | `[]` | Named custom dictionaries attached to the profile |
| `dictionaries` | `{}` | Custom literal dictionaries |
| `dictionaries.<name>.class` | required when used | Placeholder and receipt class tag for dictionary hits |
| `dictionaries.<name>.entries` | `[]` | Inline literal strings to redact |
| `dictionaries.<name>.entries_file` | `""` | YAML/JSON file containing a string list |
| `dictionaries.<name>.case_insensitive` | `false` | Case-insensitive dictionary matching |
| `dictionaries.<name>.word_boundary` | `false` | Require word boundaries around dictionary entries |
| `dictionaries.<name>.priority` | `0` | Overlap priority versus built-in classes |
| `providers` | Anthropic/OpenAI/Gemini built-ins | Provider parser profiles for host/path matching |
| `providers.<name>.host_patterns` | required when used | Bare hostnames or leading-wildcard host patterns |
| `providers.<name>.path_prefixes` | `[]` | Optional path prefixes that select the provider profile |
| `providers.<name>.parser` | `json` | Parser implementation. v1 supports `json` |
| `limits.max_body_bytes` | `10485760` | Max JSON body size the redactor will rewrite |
| `limits.max_redactions_per_request` | `10000` | Fail-closed cap on unique placeholders per request |
| `limits.max_depth` | `64` | Max JSON nesting depth the redactor will traverse |
| `strict_reload` | `false` | Fail reload closed if an active dictionary disappears or corrupts |
| `allowlist_unparseable` | `[]` | Bare hostnames allowed to pass non-JSON bodies/messages unchanged |
| `allowlist_unparseable_routes` | `[]` | Route-scoped non-JSON exceptions with `host` plus at least one of `methods`, `path_prefixes`, `path_suffixes`, or `content_types` |

**Requirements and fail-closed behavior:**
- `redaction.enabled: true` requires `request_body_scanning.enabled: true` because the rewrite hook lives in the request-body scan path.
- Rewrites only operate on complete JSON payloads. Non-JSON HTTP bodies and non-JSON complete WebSocket messages are blocked unless the destination host is on `allowlist_unparseable` or the request matches `allowlist_unparseable_routes`.
- Outbound WebSocket fragments are blocked while redaction is enabled. The proxy cannot safely rewrite partial JSON messages.
- Successful rewrites add a `redaction` summary to the signed action receipt only when one or more values were replaced; untouched requests keep the legacy receipt bytes unchanged.

Hash redaction classes require a self-labeled prefix such as `sha256:<64 hex chars>` or `sha-256=<64 hex chars>`. Bare fixed-width hex strings are left alone so opaque OAuth client secrets and session tokens are not corrupted. AWS SigV4 pre-signed URLs also keep the access-key ID inside a structurally valid `X-Amz-Credential` parameter unchanged; the same access-key shape is still redacted everywhere else.

## Request Policy

Allow-by-default deny/warn safety rails on outbound HTTP API operations. A request forwards unless a rule matches; there is deliberately no section-level `default_action` knob, so the section can never be configured into default-deny. Request policy is not a DLP scanner and not a behavioral allowlist. It composes with both. It runs **before** the learn-lock contract gate so a contract allow can never suppress an operation-policy block, and it is independent of `request_body_scanning` (it reads a body itself only when a route-matched operation predicate or batch endpoint needs one).

Rules match on route (host, effective HTTP method, normalized path, content type) and, optionally, on an extracted GraphQL operation predicate.

```yaml
request_policy:
  enabled: true
  on_parse_error: block         # block (default) | warn | allow
  on_opaque_operation: block    # block (default) | warn | allow
  rules:
    - name: "block-graphql-account-mutations"
      action: block
      reason: "account-state mutations require human review"
      route:
        hosts: ["api.example.com", "*.example.net"]
        methods: ["POST"]
        path_prefixes: ["/graphql"]
        content_types: ["application/json"]
      graphql:
        operation_types: ["mutation"]
        root_field_patterns: ["^delete", "^transfer"]
    - name: "warn-on-admin-deletes"
      action: warn
      shadow: true
      reason: "shadow rollout of admin DELETE guard"
      route:
        hosts: ["api.example.com"]
        methods: ["DELETE"]
        path_patterns: ['^/admin/']
  batch:
    - route:
        hosts: ["api.example.com"]
        methods: ["POST"]
        path_prefixes: ["/$batch"]
      requests_field: "requests"
      method_field: "method"
      url_field: "url"
      body_field: "body"
      max_sub_requests: 64
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable request policy. When disabled the matcher allows everything. |
| `on_parse_error` | `"block"` | Action when an operation predicate's route matches but the body fails to parse: `block`, `warn`, or `allow`. Fail-closed default. |
| `on_opaque_operation` | `"block"` | Action when an operation predicate's route matches but the operation is opaque (for example a GraphQL Automatic Persisted Query that ships only a hash): `block`, `warn`, or `allow`. Fail-closed default. |
| `rules` | `[]` | Operation safety-rail list. |
| `batch` | `[]` | JSON batch endpoints whose sub-requests are evaluated recursively. |

**Rule fields:**
- `name:` bounded, metric-label-safe rule identifier.
- `action:` `block` or `warn`. Per-rule only. There is no section-level default.
- `shadow:` when `true`, log the would-be action and forward anyway. A shadow match never enforces, and an enforced match always wins over a shadow match of equal strictness.
- `reason:` operator-facing explanation surfaced on the block. Never logged with request content.
- `route:` which requests the rule applies to (see below).
- `graphql:` optional GraphQL operation predicate (see below).

When a rule sets both `route` and `graphql`, **both must match**: the route selects the request, then the predicate is evaluated against the operations extracted from its body.

**Route fields** (`route`): an empty constraint matches any value for that dimension; a request matches the route only when every non-empty constraint is satisfied. Within a single dimension (multiple hosts, or `path_prefixes` plus `path_patterns`) matching is OR.

| Field | Description |
|-------|-------------|
| `hosts` | Exact host or `*.suffix` wildcard. A `*.example.com` pattern matches the apex `example.com` and any subdomain. Normalized (lowercased, port and trailing dot stripped). |
| `methods` | HTTP verbs, normalized to uppercase. Matched against the **effective** method (see method-override note below). |
| `path_prefixes` | Literal prefixes of the normalized path. |
| `path_patterns` | RE2 patterns against the normalized path. Path case is preserved during normalization (IDs are case-sensitive); use a `path_pattern` for case-insensitive matching. |
| `content_types` | Media types with parameters (charset, boundary) stripped, lowercased. |

Paths are normalized before matching: bounded repeated percent-decoding (so a multi-encoded `..%252e` segment cannot hide from dot-segment removal), per-segment `;parameter` stripping, and dot-segment / double-slash collapsing.

**Method-override handling:** a request that tunnels a different method through `X-HTTP-Method-Override`, `X-Method-Override`, or `X-HTTP-Method` is evaluated against **both** the base method and the overridden method, and the stricter result wins. This stops a `POST` with `X-HTTP-Method-Override: DELETE` from dodging a `DELETE`-scoped rule, and equally stops a real `POST` from being downgraded by an override the upstream ignores.

**GraphQL predicate fields** (`graphql`): applied after the route matches. A request matches when **any** extracted operation satisfies the predicate. Every operation in a document or batch is evaluated, never just the first. At least one of the two fields must be set.

| Field | Description |
|-------|-------------|
| `operation_types` | `query`, `mutation`, and/or `subscription`. When set, the operation kind must be in this list. |
| `root_field_patterns` | RE2 patterns against the operation's resolved root field names. Aliases are resolved to the real field and top-level fragment spreads / inline fragments are expanded, so a deny rule matches the field that actually executes, not a cosmetic alias or a field hidden inside a fragment. |

GraphQL operations are extracted from `application/json` bodies (single object or batched array) and from GraphQL-over-GET query strings (`?query=...&operationName=...`). A body that is not valid GraphQL-over-HTTP JSON, or that contains a query that fails to parse, fails closed via `on_parse_error`. A request element carrying no inline query (an APQ hash, an empty/missing `query`) is opaque and fails closed via `on_opaque_operation`. Duplicate fragment names, fragment cycles, unresolved spreads, and expansion-budget exhaustion all make the document unclassifiable and fail closed.

> **Scope GraphQL rules by path, not content type.** A GraphQL-over-GET request carries no body and therefore no `Content-Type`, so a rule whose route sets `content_types: ["application/json"]` silently never matches the GET form, even though the engine still extracts the operation from the `?query=` string. Constrain GraphQL rules with `path_prefixes` / `path_patterns` for the GraphQL endpoint, or leave `content_types` empty, so one rule covers both the POST-body and GET-query transports.

### Discriminator predicate

As an alternative to the GraphQL predicate, a rule can carry a `discriminator` predicate that matches a single top-level JSON body field against RE2 value patterns. This handles non-GraphQL JSON APIs that signal the operation through a discriminator key (an action, type, or command field).

```yaml
  rules:
    - name: "block-account-close-commands"
      action: block
      reason: "account-close commands require human review"
      route:
        hosts: ["api.example.com"]
        methods: ["POST"]
        path_prefixes: ["/rpc"]
        content_types: ["application/json"]
      discriminator:
        field: "action"
        value_patterns: ["^account\\.close$", "^account\\.delete$"]
```

| Field | Description |
|-------|-------------|
| `field` | The top-level JSON object key carrying the operation discriminator. A dotted name is treated as a single literal key today; nested paths are a future extension. |
| `value_patterns` | RE2 patterns matched against the string value at `field`. The predicate matches when any pattern matches. At least one pattern is required (a discriminator with no patterns can never match). |

Semantics, all fail-closed:

- A string value at `field` is matched against `value_patterns`; the predicate matches when any pattern matches.
- An absent `field` does not match. The allow-by-default rail forwards unless another rule matches.
- A present but non-string value, a top-level body that is not a JSON object, or a duplicated target key is opaque and fails closed via `on_opaque_operation`.
- A body that is not valid JSON fails closed via `on_parse_error`.

A rule may set both `graphql` and `discriminator`; when it does, both predicates must match (in addition to the route). The discriminator predicate is evaluated on every HTTP transport and per WebSocket text frame, the same surfaces as the GraphQL predicate, and it folds into the canonical policy hash.

### Batch endpoints

A JSON batch endpoint wraps multiple sub-requests in one outer request, each carrying its own method, URL, and body. When an outer request route-matches a `batch` entry, request policy parses the envelope and evaluates **every** sub-request against the full rule set: host inherited from the outer request, plus the sub-request's effective method, normalized path, and any GraphQL operation in its body or URL query. The strictest decision across all sub-requests wins, so a dangerous operation cannot evade a rule by being wrapped in a batch.

| Field | Default | Description |
|-------|---------|-------------|
| `route` | n/a | Which requests are treated as a batch envelope (same route fields as a rule). |
| `requests_field` | `"requests"` | JSON field holding the sub-request array. |
| `method_field` | `"method"` | Sub-request method field. |
| `url_field` | `"url"` | Sub-request URL/path field. |
| `body_field` | `"body"` | Sub-request body field. |
| `max_sub_requests` | `64` | Cap on sub-requests evaluated per batch. Over the cap, the envelope fails closed via `on_parse_error`. |

The envelope field names default to the common OData-style JSON batch shape (`requests[].{method,url,body}`); override them for a differently shaped envelope. A sub-request whose method or URL field is missing or not a string fails closed (it must not silently evaluate as `method="" path="/"`). Nested batches are expanded up to a fixed depth; beyond that depth a sub-request that itself targets a batch endpoint fails closed regardless of configuration. An unread, oversize, or unparseable envelope fails closed via `on_parse_error`.

### Transport coverage

Request policy is enforced on the fetch proxy, forward proxy, CONNECT, TLS interception, reverse proxy, and redirect hops. On every HTTP transport it runs before the contract gate. WebSocket is covered on two surfaces: the upgrade handshake is matched route-only (host, `GET` method, path, content type), and once the socket is open each complete, UTF-8-validated client text frame is evaluated per frame as an operation body over the handshake route (the upgrade is a `GET`, so the effective method is `GET`). The per-frame body-predicate gate is checked against the live matcher on each frame rather than cached at upgrade, so a hot-reloaded rule applies to already-open sockets, and benign routes still pay no JSON-parse cost. Fragmented frames and binary frames are not evaluated as operation bodies (documented limit).

When a route-matched operation predicate or batch endpoint needs a body that cannot be inspected, the request is blocked outright, independent of the `on_parse_error` / `on_opaque_operation` settings (those apply only to a fully-read body that fails to parse). A body counts as uninspectable when it is unread, exceeds `request_body_scanning.max_body_bytes` (default 5 MiB), or hits a read error. The bounded read has already consumed the body stream, so the request can no longer be forwarded intact.

### Enforcement, audit, and receipts

A matched rule records a decision metric and an audit event with bounded, operator-defined labels only, never body or matched content. An enforced (non-shadow) `block` returns HTTP 403 with the `request_policy_deny` block reason and, when a receipt emitter is configured, a correlated receipt. `warn` and `shadow` matches are logged and counted, then forwarded.

## WebSocket Proxy

Bidirectional WebSocket scanning via `/ws?url=ws://upstream:9090/path`. Text frames are scanned through the full DLP + injection pipeline. Fragment reassembly handles split messages in scan-only mode; when `redaction.enabled` is on, outbound fragmented client messages fail closed because the proxy only rewrites complete JSON messages.

```yaml
websocket_proxy:
  enabled: false                # Requires restart to change
  max_message_bytes: 1048576    # 1MB
  max_concurrent_connections: 128
  scan_text_frames: true
  allow_binary_frames: false
  strip_compression: true       # Required for scanning
  max_connection_seconds: 3600
  idle_timeout_seconds: 300
  origin_policy: rewrite        # rewrite, forward, or strip
  forward_cookies: false
```

| Field | Default | Restart? | Description |
|-------|---------|----------|-------------|
| `enabled` | `false` | **Yes** | Enable /ws endpoint |
| `max_message_bytes` | `1048576` | No | Max assembled message size |
| `max_concurrent_connections` | `128` | No | Connection limit |
| `scan_text_frames` | `true` | No | DLP + injection on text frames |
| `allow_binary_frames` | `false` | No | Allow binary frames (not scanned) |
| `strip_compression` | `true` | No | Force uncompressed (required for scanning) |
| `max_connection_seconds` | `3600` | No | Upstream WebSocket setup/dial deadline |
| `idle_timeout_seconds` | `300` | No | Close established connections after this much inactivity |
| `origin_policy` | `"rewrite"` | No | Origin header: rewrite, forward, or strip |
| `forward_cookies` | `false` | No | Forward client Cookie headers to upstream |

## DLP (Data Loss Prevention)

Scans URLs for secrets and sensitive data using regex patterns. Built-in patterns cover API keys, tokens, credentials, and prompt injection indicators. Runs before DNS resolution to prevent exfiltration via DNS queries. Matching is always case-insensitive.

```yaml
dlp:
  scan_env: true
  secrets_file: ""              # path to known-secrets file
  min_env_secret_length: 16
  include_defaults: true        # merge user patterns with built-in patterns
  patterns:
    - name: "Custom Token"
      regex: 'myapp_[a-zA-Z0-9]{32}'
      severity: critical
    - name: "Telegram Bot Token"
      regex: '[0-9]{8,10}:[A-Za-z0-9_-]{35}'
      severity: critical
      exempt_domains:            # skip this pattern for these destinations
        - "api.telegram.org"
```

| Field | Default | Description |
|-------|---------|-------------|
| `scan_env` | `true` | Scan environment variables for leaked values |
| `secrets_file` | `""` | Path to file with known secrets (one per line) |
| `min_env_secret_length` | `16` | Min env var value length to consider |
| `include_defaults` | `true` | Merge your patterns with the 62 built-in patterns |
| `patterns` | 62 built-in | DLP credential detection patterns |
| `patterns[].validator` | `""` | Post-match checksum validator: `luhn`, `mod97`, `aba`, or `wif` |
| `patterns[].exempt_domains` | `[]` | Domains where this pattern is not enforced (wildcard supported) |
| `patterns[].action` | `""` | Per-pattern action override. Only `warn` is supported. When set to `warn`, matches allow traffic through without enforcement. See the [false positive tuning guide](guides/false-positive-tuning.md) for the rollout workflow. Built-in default patterns cannot be set to warn. |

There is no top-level `dlp.action` setting. DLP enforcement is transport-specific:

- URL/query scanning uses global `mode` plus `enforce` (`mode: audit` or `enforce: false` logs but does not block).
- HTTP request body/header scanning uses `request_body_scanning.action`.
- MCP input scanning uses `mcp_input_scanning.action`.
- `response_scanning.action: strip` is for inbound prompt-injection response rewriting, not DLP.

### Validated Patterns (Financial DLP)

Some patterns include a `validator` field for post-match checksum verification. When set, regex matches are passed through a checksum algorithm before being flagged. This eliminates false positives from random numbers that happen to match the pattern format.

Built-in validated patterns:
- **Credit Card Number** (`validator: luhn`) — Visa, Mastercard (including 2-series), Amex, Discover, JCB. Luhn checksum rejects ~90% of false positives.
- **IBAN** (`validator: mod97`) — International Bank Account Numbers. Validates ISO 13616 country codes and ISO 7064 mod-97 checksum. Rejects ~99% of false positives.
- **Bitcoin WIF Private Key** (`validator: wif`) — Base58Check decoding with SHA-256d checksum verification. Validates mainnet version byte (0x80) and 32/33-byte payload. Eliminates false positives from text that happens to contain 51-52 characters of the base58 alphabet.

To add ABA routing numbers (not in defaults due to higher false positive rate):

```yaml
dlp:
  patterns:
    - name: "ABA Routing Number"
      regex: '\b\d{9}\b'
      severity: low
      validator: aba
```

### Pattern Merging

When `include_defaults` is true (default), your patterns are merged with the built-in set by name. If you define a pattern with the same name as a built-in, yours overrides it. New built-in patterns added in future versions are automatically included.

Set `include_defaults: false` to use only your patterns.

### Per-Pattern Domain Exemptions

Use `exempt_domains` to skip a specific DLP pattern for specific destination domains. Other patterns still fire, and response scanning remains active. Supports wildcard matching (`*.example.com` matches `sub.example.com` and `example.com`).

**Scope:** `exempt_domains` applies to URL-based scanning only (fetch proxy, forward proxy, WebSocket, TLS intercept). It does not apply to MCP input scanning (which has no destination domain) or environment variable leak detection (`scan_env`). To suppress those, use the `suppress` section.

This is useful for APIs that embed credentials in URL paths by design (e.g., Telegram bot API uses `/bot<token>/sendMessage`). The token should be allowed when talking to Telegram but blocked if it appears in requests to other domains.

To exempt a built-in pattern, override it by name and add `exempt_domains`:

```yaml
dlp:
  patterns:
    - name: "Anthropic API Key"    # same name as built-in — overrides it
      regex: 'sk-ant-[a-zA-Z0-9\-_]{10,}'
      severity: critical
      exempt_domains:
        - "*.anthropic.com"
```

### Built-in DLP Patterns (62)

| Pattern | Regex Prefix | Severity |
|---------|-------------|----------|
| Anthropic API Key | `sk-ant-` | critical |
| OpenAI API Key | `sk-proj-` | critical |
| OpenAI Service Key | `sk-svcacct-` | critical |
| Fireworks API Key | `fw_` | critical |
| AWS Access Key ID | `AKIA\|A3T\|AGPA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA\|ASIA` | critical |
| Google API Key | `AIza` | critical |
| Google OAuth Client Secret | `GOCSPX-` | critical |
| Google OAuth Token | `ya29.` | high |
| Google OAuth Client ID | `*.apps.googleusercontent.com` | medium |
| Stripe Key | `[sr]k_live\|test_` | critical |
| Stripe Webhook Secret | `whsec_` | critical |
| GitHub Token | `gh[pousr]_` | critical |
| GitHub Fine-Grained PAT | `github_pat_` | critical |
| GitLab PAT | `glpat-` | critical |
| GitLab Deploy Token | `gldt-` | critical |
| GitLab Runner Token | `glrt-` / `glrtr-` | critical |
| GitLab CI Job Token | `glcbt-` | critical |
| GitLab Pipeline Trigger Token | `glptt-` | critical |
| GitLab OAuth Application Secret | `gloas-` | critical |
| GitLab SCIM Token | `glsoat-` | critical |
| GitLab Service Token | `gl(ft\|imt\|agent\|wt\|ffct)-` | critical |
| PostgreSQL Connection String | `postgres(ql)://user:pass@` | critical |
| MySQL Connection String | `mysql://user:pass@` | critical |
| MongoDB Connection String | `mongodb(+srv)://user:pass@` | critical |
| Redis Connection String | `redis(s)://user:pass@` | critical |
| GCP Service Account Key (always-on core pattern, not part of the 62 default count) | `"type":"service_account"` | critical |
| GCP Service Account Private Key ID | `"private_key_id":"<40 hex>"` | high |
| Azure Storage Account Key | `AccountKey=<88-char base64>` | critical |
| Azure SAS Token | `sig=<base64>%3D` | high |
| Slack Token | `xox[bpras]-` | critical |
| Slack App Token | `xapp-` | critical |
| Discord Bot Token | `[MN][A-Za-z0-9]{23,}` | critical |
| Twilio API Key | `SK[a-f0-9]{32}` | critical |
| SendGrid API Key | `SG.` | critical |
| Mailgun API Key | `key-[a-zA-Z0-9]{32}` | critical |
| New Relic API Key | `NRAK-` | critical |
| Hugging Face Token | `hf_` | critical |
| Databricks Token | `dapi` | critical |
| Replicate API Token | `r8_` | critical |
| Together AI Key | `tok_` | critical |
| Pinecone API Key | `pcsk_` | critical |
| Groq API Key | `gsk_` | critical |
| xAI API Key | `xai-` | critical |
| DigitalOcean Token | `dop_v1_` | critical |
| HashiCorp Vault Token | `hvs.` + 24+ alphanumeric chars | critical |
| Vercel Token | `vercel_\|vc[piark]_` | critical |
| Supabase Service Key | `sb_secret_<22-char-random>_<8-char-checksum>` | critical |
| npm Token | `npm_` | critical |
| PyPI Token | `pypi-AgE` | critical |
| Linear API Key | `lin_api_` + 40+ alphanumeric chars | high |
| Notion API Key | `ntn_` | high |
| Sentry Auth Token | `sntrys_` + 40+ alphanumeric chars | high |
| JWT Token | `ey...\..*\.` | high |
| Private Key Header | `-----BEGIN.*PRIVATE KEY-----` | critical |
| Bitcoin WIF Private Key | `[5KL]` + base58 | critical |
| Extended Private Key | `[xyzt]prv` + base58 | critical |
| Ethereum Private Key | `0x` + 64 hex | critical |
| Social Security Number | `\b\d{3}-\d{2}-\d{4}\b` | critical |
| Credit Card Number | BIN prefix + Luhn checksum | medium |
| IBAN | `[A-Z]{2}\d{2}` + mod-97 checksum | medium |
| Credential in URL | `password\|token\|secret=value` | high |
| Prompt Injection | `(ignore\|disregard\|forget)...previous...instructions` | high |
| System Override | `system:` | high |
| Role Override | `you are now (DAN\|evil\|unrestricted)` | high |
| New Instructions | `(new\|updated) (instructions\|directives)` | high |
| Jailbreak Attempt | `DAN\|developer mode\|sudo mode` | high |
| Hidden Instruction | `do not reveal this to the user` | high |
| Behavior Override | `from now on you (will\|must)` | high |
| Encoded Payload | `decode this from base64 and execute` | high |
| Tool Invocation | `you must (call\|execute) the (function\|tool)` | high |
| Authority Escalation | `you have (admin\|root) (access\|privileges)` | high |
| Instruction Downgrade | `treat previous instructions as (outdated\|optional)` | high |
| Instruction Dismissal | `set the previous instructions aside` | high |
| Priority Override | `prioritize the (task\|current) (request\|input)` | high |

### Environment Variable Leak Detection

When `scan_env: true`, pipelock reads all environment variables at startup and flags URLs containing any env value that is:
- 16+ characters (configurable via `min_env_secret_length`)
- Shannon entropy > 3.0 bits/char
- Checked in raw form, base64, hex, and base32 encodings

This catches leaked API keys even without a specific DLP pattern for that provider.

## Seed Phrase Detection

Detects BIP-39 mnemonic seed phrases in URLs, request bodies, headers, MCP tool arguments, WebSocket frames, and cross-request fragment reassembly. Seed phrase compromise is permanent and irreversible, making this a critical detection layer for crypto-adjacent deployments.

```yaml
seed_phrase_detection:
  enabled: true          # default: true (security default)
  min_words: 12          # minimum consecutive BIP-39 words to trigger (12, 15, 18, 21, or 24)
  verify_checksum: true  # default: true (validates BIP-39 SHA-256 checksum, eliminates FPs)
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Enable BIP-39 seed phrase detection |
| `min_words` | int | `12` | Minimum consecutive BIP-39 words to trigger. Must be 12, 15, 18, 21, or 24. |
| `verify_checksum` | bool | `true` | Validate the BIP-39 SHA-256 checksum. Reduces false positives by 16x for 12-word phrases, 256x for 24-word. |

The detector uses a dedicated scanner (not regex). It tokenizes text, runs a sliding window over the 2048-word BIP-39 English dictionary, and validates the checksum. Detection covers varied separators (spaces, commas, newlines, dashes, tabs, pipes).

Action follows the transport-level DLP action: URL scan always blocks, MCP input uses `mcp_input_scanning.action`, body/header uses `request_body_scanning.action`.

### Per-Pattern Warn Mode (DLP Rollout)

Individual DLP patterns can carry an explicit `action: warn` to run in audit-only mode. Warn matches route to an informational channel and emit audit events through the runtime lifecycle, but do not trigger enforcement. Use this to roll out new detections on production traffic before flipping them to default (block).

```yaml
dlp:
  patterns:
    - name: "AcmeInternalToken"
      regex: "acme_[A-Za-z0-9]{32}"
      severity: high
      action: warn          # audit-only; does not block
```

Only `action: warn` and omitted (empty) are accepted on a per-pattern basis. `block`, `strip`, `ask`, `redirect`, or any other value is rejected at config load. The top-level `dlp.action` field is still reserved — it rejects every value including `block`.

Matches from warn patterns appear in scan results as `InformationalMatches` (distinct from `Matches`) and emit structured audit events with the matched pattern name, severity, transport, and request context via the `DLPWarnHook`. Standard emission sinks (webhook, syslog, OTLP) pick these up.

Recommended rollout flow:

1. Ship the pattern with `action: warn`.
2. Deploy and watch the audit sink for hits against real traffic.
3. Tune the regex + `exempt_domains` until false-positive rate is acceptable.
4. Remove the `action` line (or set it to empty string) to revert the pattern to normal DLP enforcement semantics — the actual verdict then follows the transport-level DLP action and the session's `mode`/`enforce` state rather than being unconditionally block.
5. Roll out the change through your normal config-review process.

## Response Scanning

Scans fetched content for prompt injection before returning to the agent. Uses a 6-pass normalization pipeline: zero-width stripping, word boundary reconstruction, leetspeak folding, optional-whitespace matching, vowel folding, and encoding detection.

```yaml
response_scanning:
  enabled: true
  action: warn                  # block, strip, warn, or ask
  ask_timeout_seconds: 30       # HITL approval timeout
  include_defaults: true
  exempt_domains:               # skip injection scanning for these hosts
    - "api.openai.com"
    - "*.anthropic.com"
  size_exempt_domains:          # trusted large-download hosts; scan cap only
    - "downloads.example.com"
  patterns:
    - name: "Custom Injection"
      regex: 'override system prompt'
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable response scanning |
| `action` | `"warn"` | block, strip, warn, or ask (HITL) |
| `ask_timeout_seconds` | `30` | Timeout for human-in-the-loop approval |
| `include_defaults` | `true` | Merge with 29 built-in patterns |
| `exempt_domains` | `[]` | Hosts to skip injection scanning for (DLP still applies on outbound). Supports `*.example.com` wildcards (also matches the apex `example.com`). |
| `size_exempt_domains` | `[]` | Trusted hosts whose oversized forward-proxy or TLS-intercepted responses may stream through instead of failing the scan ceiling. Request-side scanning and budget accounting still run. |
| `patterns` | 29 built-in | Injection and state/control poisoning patterns |

**Built-in patterns (29):** Prompt-injection and state/control poisoning coverage includes jailbreak phrases, system overrides, role overrides, instruction manipulation, encoded payloads, tool invocation commands, authority escalation, credential solicitation, credential path directives, auth material requirements, memory persistence directives, preference poisoning, covert-action directives, silent credential handling, and CJK-language override patterns. All patterns use DOTALL mode to match across newlines in multiline tool output.

**Actions:**
- **block:** reject the response entirely, agent gets an error
- **strip:** redact matched text, return cleaned content
- **warn:** log the match, return content unchanged
- **ask:** pause and prompt the operator for approval (requires TTY)

**Exempt domains:** LLM provider APIs (OpenAI, Anthropic, etc.) return instruction-like text as part of normal operation, which can trigger false positives. Use `exempt_domains` to skip injection scanning for trusted providers. DLP scanning on the outbound request still runs — only the response injection scan is skipped. Applies to fetch proxy, forward proxy, CONNECT (TLS intercept), WebSocket, and reverse proxy. Does not affect MCP response scanning (tool results use a separate trust model).

For forward-proxy and TLS-intercepted traffic, an exempt host's response streams through untouched when `response_scanning.enabled` is true: no buffering, response scan-cap block, media metadata strip, Browser Shield rewrite, or injection scan is applied to that trusted response. Request-side DLP, redaction, SSRF, authority checks, and budget accounting still run. If a host needs full byte-preserving passthrough without MITM, prefer `tls_interception.passthrough_domains`.

Non-exempt responses that must be buffered for response scanning, Browser Shield, or media policy block fail-closed if they exceed the configured scan cap (`fetch_proxy.max_response_mb` or `tls_interception.max_response_bytes`). The block uses reason code `response_size` and names the host, observed size, scan ceiling, and the knob to raise. Data-budget truncation is separate and remains an explicit budget policy.

Use `size_exempt_domains` for trusted large-download hosts when the default fail-closed scan ceiling blocks legitimate artifacts such as package headers, signed binaries, or model weights. This exemption is narrower than `exempt_domains`: it only takes effect after the response exceeds the scan cap. Smaller responses from the same host still take the normal buffered scanning path. The exemption applies only to the forward proxy and TLS interception; reverse-proxy / MCP-HTTP responses and compressed (`Content-Encoding`) responses still fail closed when they cannot be fully scanned, regardless of this list.

### Generic SSE streaming (`response_scanning.sse_streaming`)

Inline body scanning of `text/event-stream` responses for non-A2A LLM traffic (OpenAI chat completions, Anthropic messages, Kilo Gateway, generic LLM SSE). Without this, streaming responses fall back to the buffered scan path, which caps the body at the proxy's max-body limit and breaks per-event flushing — the agent waits for the whole response before seeing any tokens.

```yaml
response_scanning:
  sse_streaming:
    enabled: true                 # generic SSE inline scanning (default true)
    action: block                 # block or warn
    max_event_bytes: 65536        # per-event data-payload ceiling (default 64 KB; excludes metadata)
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Run per-event DLP + injection scanning on non-A2A SSE responses. When `false`, SSE responses still stream with per-read flushing — they are NOT silently downgraded to the buffered path. |
| `action` | `block` | `block` terminates the stream on detection. `warn` logs an anomaly and continues forwarding events. |
| `max_event_bytes` | `65536` | Per-event data-payload ceiling. Measures only the bytes inside the SSE `data:` field(s) — `event:`, `id:`, and `retry:` metadata are not counted. Events exceeding this are treated as findings and fail closed. Set higher only for providers with genuinely large single events. |

**Behavior:**
- Each event's `data:` payload is fed through the same DLP + injection patterns used for buffered response scanning.
- Clean events flush to the client immediately. In block mode, the first detected event terminates the stream; later events are not forwarded. In warn mode, findings are logged and forwarding continues.
- `response_scanning.exempt_domains` still pins prompt-injection findings to visibility-only for trusted hosts. DLP findings are not exempted.
- Global `suppress` rules apply before SSE action selection.
- Compressed SSE (`gzip`, `br`, `zstd`) is fail-closed-blocked on every transport. The streaming scanner is never given compressed bytes.
- Receipts use the `sse_stream` layer label (A2A keeps its existing `a2a_stream` label so dashboards stay continuous).

**Limitations (v1):**
- Cross-event payload splitting (a secret broken across two sequential events) is NOT detected. A2A traffic still gets cross-event scanning via the A2A scanner's rolling tail; generic SSE does not in v1.

See [`docs/guides/sse-streaming.md`](guides/sse-streaming.md) for the full guide with transport coverage, fail-closed behavior, and adversarial test matrix.

## MCP Input Scanning

Scans JSON-RPC requests from agent to MCP server for DLP leaks and injection in tool arguments.

```yaml
mcp_input_scanning:
  enabled: true
  action: warn
  on_parse_error: block         # block or forward
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable input scanning |
| `action` | `"warn"` | warn or block |
| `on_parse_error` | `"block"` | What to do with malformed JSON-RPC |

Auto-enabled when running `pipelock mcp proxy`.

If top-level `redaction.enabled` is also set, `tools/call` `params.arguments` are rewritten through the same matcher before input DLP runs. The behavior is identical across stdio, HTTP/SSE upstream mode, HTTP listener mode, and MCP-over-WebSocket.

## MCP Tool Scanning

Scans `tools/list` responses for poisoned tool definitions and detects mid-session description changes (rug pulls). Extracts text from all schema fields that an LLM might ingest: `description`, `title`, `default`, `const`, `enum`, `examples`, `pattern`, `$comment`, and vendor extensions (`x-*`). Recurses through composition keywords (`allOf`, `anyOf`, `oneOf`, `$defs`, `if`/`then`/`else`) and extracts string leaves from nested objects and arrays.

```yaml
mcp_tool_scanning:
  enabled: true
  action: warn
  detect_drift: true
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable tool description scanning |
| `action` | `"warn"` | warn or block |
| `detect_drift` | `false` | Alert on tool description changes |

## MCP Tool Policy

Pre-execution rules that block or warn before tool calls reach the MCP server. Ships with 17 built-in rules covering destructive operations, credential access, network exfiltration, persistence mechanisms, and encoded command execution.

```yaml
mcp_tool_policy:
  enabled: true
  action: warn
  rules:
    - name: "Block shell execution"
      tool_pattern: "execute_command|run_terminal"
      action: block
    - name: "Warn on sensitive writes"
      tool_pattern: "write_file"
      arg_pattern: '/etc/.*|/usr/.*'
      action: warn
    - name: "Block shadow file reads"
      tool_pattern: "read_file"
      arg_pattern: '/etc/shadow'
      arg_key: '^(file_?path|target)$'
      action: block
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable tool policy |
| `action` | `"warn"` | Default action for rules without override |
| `rules` | 17 built-in | Policy rule list |

**Rule fields:**
- `name:` rule identifier
- `tool_pattern:` regex matching tool name
- `arg_pattern:` regex matching argument values (optional; omit for tool-name-only rules)
- `arg_key:` regex scoping `arg_pattern` to specific top-level argument keys (optional; requires `arg_pattern`). Without `arg_key`, `arg_pattern` checks values from all argument keys. Values under matching keys are extracted recursively.
- `action:` per-rule override (warn, block, or redirect)
- `redirect_profile:` reference to a named redirect profile (required when `action: redirect`)

Shell obfuscation detection is built-in: backslash escapes, `$IFS` substitution, brace expansion, and octal/hex escapes are decoded before matching. See [Redirect Action (v2.0)](#redirect-action-v20) for redirect profile configuration.

## MCP Session Binding

Pins tool inventory on the first `tools/list` response. Subsequent tool calls are validated against this baseline. Unknown tools trigger the configured action.

```yaml
mcp_session_binding:
  enabled: true
  unknown_tool_action: warn
  no_baseline_action: warn
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable session binding |
| `unknown_tool_action` | `"warn"` | Action on tools not in baseline |
| `no_baseline_action` | `"warn"` | Action if no baseline exists |

Tool baseline caps at 10,000 tools per session to prevent memory exhaustion.

## MCP WebSocket Listener

Controls inbound WebSocket connections when the MCP proxy runs in listener mode with a `ws://` or `wss://` upstream. Loopback origins are always allowed.

```yaml
mcp_ws_listener:
  allowed_origins:
    - "https://example.com"
  max_connections: 100
```

| Field | Default | Description |
|-------|---------|-------------|
| `allowed_origins` | `[]` | Additional browser origins to allow (loopback always allowed) |
| `max_connections` | `100` | Max concurrent inbound WebSocket connections |

## Session Profiling

Per-session behavioral analysis that detects domain bursts and volume spikes.

```yaml
session_profiling:
  enabled: true
  anomaly_action: warn
  domain_burst: 5
  window_minutes: 5
  volume_spike_ratio: 3.0
  max_sessions: 1000
  session_ttl_minutes: 30
  cleanup_interval_seconds: 60
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable profiling |
| `anomaly_action` | `"warn"` | warn or block on anomaly |
| `domain_burst` | `5` | New unique domains in window to flag |
| `window_minutes` | `5` | Rolling window duration |
| `volume_spike_ratio` | `3.0` | Spike threshold (ratio of avg) |
| `max_sessions` | `1000` | Hard cap on concurrent sessions |
| `session_ttl_minutes` | `30` | Idle session eviction |
| `cleanup_interval_seconds` | `60` | Background cleanup interval |

## Adaptive Enforcement

Per-session threat score that accumulates across scanner hits and decays on clean requests. When the score exceeds the threshold, the session escalates through levels (elevated → high → critical). At each level, the `levels` configuration upgrades warn and ask actions to block, or denies all traffic.

```yaml
adaptive_enforcement:
  enabled: true
  escalation_threshold: 5.0
  decay_per_clean_request: 0.5
  cooperative_tool_downweight: true
  levels:
    elevated:
      upgrade_warn: block       # warn→block when session is elevated
    high:
      upgrade_warn: block
      upgrade_ask: block        # ask→block when session is high risk
    critical:
      upgrade_warn: block
      upgrade_ask: block
      block_all: true           # deny all requests when session is critical
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable adaptive enforcement |
| `escalation_threshold` | `5.0` | Score before first escalation. Lower values escalate faster. |
| `decay_per_clean_request` | `0.5` | Score reduction per clean request. Lower values slow trust recovery. |
| `cooperative_tool_downweight` | `true` | Downweight domain-burst and IP-domain-burst adaptive signals from known cooperative tool user agents such as `yt-dlp`, package managers, `curl`, and `git`. |
| `levels` | *(see below)* | Per-level enforcement upgrades |

### Escalation Levels

Sessions progress through three levels as threat score accumulates past `escalation_threshold` multiples. Each level can independently upgrade action severity.

| Level | Trigger | Description |
|-------|---------|-------------|
| `elevated` | Score ≥ threshold × 1 | First escalation. Session shows suspicious behavior. |
| `high` | Score ≥ threshold × 2 | Second escalation. Session is actively concerning. |
| `critical` | Score ≥ threshold × 3 | Third escalation. Session is high-confidence threat. |

### Level Actions

Each level accepts the following fields. All fields use **pointer semantics**:

- **Omit the field** (or omit `levels` entirely) to apply the default behavior.
- **Set to `"block"`** to upgrade that action class at this level.
- **Set to `""`** (empty string) to explicitly disable an upgrade (softening from a parent config).

**Monotonic enforcement:** higher levels must never be weaker than lower levels. If `elevated.upgrade_warn: block`, then `high` and `critical` must also have `upgrade_warn: block` (or omit it for the default, which is `block`). Pipelock validates this at config load time and rejects violations.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `upgrade_warn` | `*string` | `nil` → `"block"` at all levels | Upgrade `warn` actions to `block` at this level |
| `upgrade_ask` | `*string` | `nil` → `""` at elevated; `"block"` at high and critical | Upgrade `ask` (HITL) actions to `block` at this level |
| `block_all` | `*bool` | `nil` → `false` at elevated and high; `true` at critical | Deny all traffic for this session regardless of action |

**Default behavior when `levels` is omitted:**

| Level | upgrade_warn | upgrade_ask | block_all |
|-------|-------------|-------------|-----------|
| elevated | block | — | false |
| high | block | block | false |
| critical | block | block | true |

### De-escalation

Sessions at `block_all` recover autonomously via a background sweep that runs
every 30 seconds. If a session has been at its current escalation level for
longer than 5 minutes, it is automatically stepped down one level. Recovery
also triggers on the next incoming request, WebSocket frame, or MCP message
after the timer expires (on-entry fast path). The session must accumulate new real signals to re-escalate.

De-escalation drops one level per 5-minute period. A session at critical with no activity takes 15 minutes (3 periods) to return to normal. Each de-escalation resets the threat score to half the current threshold to prevent immediate re-escalation from stale points.

When a session is at a `block_all` level, blocked retries do not refresh the session's idle timer. This allows idle eviction to eventually clean up sessions that are no longer generating traffic, preventing zombie sessions from persisting indefinitely.

### Domain Burst Scoring

Session profiling detects domain bursts (many unique domains in a short window). When the burst threshold is crossed, the anomaly is signaled once per window with the configured score. Subsequent requests in the same window still trigger the configured `anomaly_action` (block or warn) but do not add further adaptive score, preventing burst detection from driving sessions to critical on its own. IP-wide domain bursts are tracked separately to catch agent-identity rotation from a single client IP. When `cooperative_tool_downweight` is enabled, burst signals from known cooperative tool user agents are reduced instead of scored at full browser-like weight.

## Kill Switch

Emergency deny-all with four independent activation sources (`enabled`, `sentinel_file`, `api`, `SIGUSR1`). Any one active denies normal traffic (OR-composed) except for configured exemptions (`health_exempt`, `metrics_exempt`, `api_exempt`, `allowlist_ips`). See [Kill Switch](../README.md#kill-switch) for operational details.

> **Heads-up on `enabled`:** the `enabled` field is a source, not a subsystem switch. Setting `enabled: true` immediately activates the kill switch and denies all traffic from startup (all requests return HTTP 503). To configure the API/signal/sentinel sources for future activation without engaging the kill switch at startup, leave `enabled: false`.

```yaml
kill_switch:
  enabled: false
  sentinel_file: /tmp/pipelock-kill   # example path; default is "" (disabled)
  message: "Emergency deny-all active"
  health_exempt: true
  metrics_exempt: true
  api_exempt: true
  api_token: ""                 # Required for API source
  api_listen: ""                # Requires restart. Separate port for operator API.
  allowlist_ips: []             # IPs that bypass kill switch
```

| Field | Default | Restart? | Description |
|-------|---------|----------|-------------|
| `enabled` | `false` | No | Config-source activation. `true` = kill switch active immediately (deny-all). Not a subsystem enable. |
| `sentinel_file` | `""` | No | File presence activates kill switch |
| `message` | `"Emergency deny-all active"` | No | Rejection message |
| `health_exempt` | `true` | No | /health bypasses kill switch |
| `metrics_exempt` | `true` | No | /metrics bypasses kill switch |
| `api_exempt` | `true` | No | /api/v1/* bypasses kill switch |
| `api_token` | `""` | No | Bearer token for API endpoints. Can be overridden by `PIPELOCK_KILLSWITCH_API_TOKEN` env var. |
| `api_listen` | `""` | **Yes** | Separate listen address for API |
| `allowlist_ips` | `[]` | No | IPs always allowed through |

**Port isolation:** When `api_listen` is set, the kill switch and session admin APIs run on a dedicated port. The main proxy port has no API routes, preventing agents from deactivating their own kill switch or resetting their own sessions.

**Environment variable override:** Set `PIPELOCK_KILLSWITCH_API_TOKEN` to override `api_token` from the config file. This is useful for Kubernetes deployments where the config file lives in a ConfigMap (plaintext in etcd) but the token should come from a Secret:

```yaml
env:
  - name: PIPELOCK_KILLSWITCH_API_TOKEN
    valueFrom:
      secretKeyRef:
        name: pipelock-secrets
        key: killswitch-api-token
```

### Session Admin API

When `kill_switch.api_token` is configured, the session admin API is available alongside the kill switch endpoints. Uses the same bearer token authentication and port isolation.

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/sessions` | GET | List all tracked sessions, optionally filtered by `?tier=none\|soft\|hard\|drain\|normal` |
| `/api/v1/sessions/{key}` | GET | Full detail snapshot: tier entry time, in-flight, recent events |
| `/api/v1/sessions/{key}/explain` | GET | Trigger/evidence/next de-escalation estimate for a session |
| `/api/v1/sessions/{key}/reset` | POST | Reset enforcement state for a client identity |
| `/api/v1/sessions/{key}/terminate` | POST | Destructive full tear-down (cancel in-flight, clear CEE) |
| `/api/v1/sessions/{key}/airlock` | POST | Transition the session's airlock tier (admin override) |
| `/api/v1/sessions/{key}/task` | POST | Rotate the session's task boundary |
| `/api/v1/sessions/{key}/trust` | POST | Grant a task-scoped trust override |
| `/api/v1/adaptive/status` | GET | Summarize adaptive state, escalation counts, recent event counts, and top anomalies |
| `/api/v1/adaptive/flush` | POST | Reset identity-session adaptive state and clear shared IP-domain burst tracking |
| `/api/v1/adaptive/whoami` | GET | Show the caller's client-IP/session classification as seen by the proxy |

The `{key}` parameter is URL-encoded. For example, `my-agent|10.0.0.1` becomes `my-agent%7C10.0.0.1`.

**Reset scope:** identity-family scoped. Resetting a session clears the session's threat score, escalation level, and block_all flag. It also clears shared IP-level burst tracking for the client IP and cross-request exfiltration (CEE) state. Other sessions on the same IP will have their burst state cleared as a side effect.

**Rate limiting:** every mutating action (`reset`, `airlock`, `task`, `trust`, `terminate`) and every detail lookup (`inspect`, `explain`) is rate-limited to 10 requests per minute per action. Each action tracks its own sliding-window counter so abuse of one endpoint cannot starve another — an operator can still hit `/reset` or `/airlock` during incident response even if `/task` or `/trust` is under load. Only `GET /api/v1/sessions` (the list endpoint) is unbounded; it is used as the entry point for recovery tooling and has no destructive side effect. Responses that hit the limit return `429 Too Many Requests` with `Retry-After: 60`.

Sessions are classified as `identity` (operator-targetable, e.g. `my-agent|10.0.0.1`) or `invocation` (internal MCP sessions, e.g. `mcp-stdio-42`). Only identity sessions can be reset, mutated, or terminated.

**Operator CLI:** the session admin API is exposed through `pipelock session <subcommand>` for airlock recovery and `pipelock adaptive <subcommand>` for fleet-level adaptive state. See [cli/session.md](cli/session.md) and [cli/adaptive.md](cli/adaptive.md) for the operator references.

**Token hot-reload:** `kill_switch.api_token` is hot-reloaded on SIGHUP or fsnotify config-file changes. Rotating the token in YAML (or via the `PIPELOCK_KILLSWITCH_API_TOKEN` env var, which wins over YAML) takes effect on the next admin API call without restarting the proxy. The previous bearer credential is revoked atomically: requests in flight at the moment of rotation complete against the token they were issued against; subsequent requests must present the new bearer. Setting `api_token` to the empty string disables the endpoint (HTTP 503) without tearing down the listener, so an operator can revoke access during an incident and restore it later with a second reload.

### Airlock

Per-session graduated quarantine with timer-based recovery. When adaptive enforcement escalates a session, the airlock state machine can transition the session through `soft` (observe-only), `hard` (reads allowed, writes blocked, long-lived connections torn down), and `drain` (no new traffic, existing in-flight requests complete within `drain_timeout_seconds`). All three tiers are **timed quarantines** that auto-recover back down through lower tiers as `soft_minutes`/`hard_minutes`/`drain_minutes` expire — `drain` is not a terminal state and is not equivalent to `POST /api/v1/sessions/{key}/terminate`. Operators can override the tier at any time through the session admin API or the `pipelock session` CLI; explicit termination (the destructive reset) lives behind the dedicated `terminate` endpoint.

> **Airlock requires triggers:** `airlock.enabled: true` alone is a no-op. Configure at least one trigger (`triggers.on_high`, `triggers.on_critical`) to specify which tier fires at each adaptive escalation level. All shipped presets wire `on_high: soft` + `on_critical: hard` by default. Freehand configs that set `enabled: true` with no triggers will reach critical escalation without ever entering airlock.

```yaml
airlock:
  enabled: false
  triggers:
    on_elevated: none       # no airlock on elevated
    on_high: soft           # soft quarantine on high
    on_critical: hard       # hard quarantine on critical
  timers:
    soft_minutes: 5         # soft tier auto-recovers after 5 minutes
    hard_minutes: 15        # hard tier auto-drops to soft after 15 minutes
    drain_minutes: 0        # drain timer disabled
    drain_timeout_seconds: 30  # drain deadline for in-flight completion
```

## Event Emission

Forward audit events to external systems. Three independent sinks (webhook, syslog, OTLP), each with its own severity filter. Emission is fire-and-forget and never blocks the proxy.

```yaml
emit:
  instance_id: "prod-agent-1"
  webhook:
    url: "https://your-siem.example.com/webhook"
    min_severity: warn
    auth_token: ""
    timeout_seconds: 5
    queue_size: 64
  syslog:
    address: "udp://syslog.example.com:514"
    min_severity: warn
    facility: local0
    tag: pipelock
  otlp:
    endpoint: "http://otel-collector:4318"
    min_severity: warn
    headers:
      Authorization: "Bearer <token>"
    timeout_seconds: 10
    queue_size: 256
    gzip: false
```

| Field | Default | Description |
|-------|---------|-------------|
| `instance_id` | hostname | Identifies this instance in events |
| `webhook.url` | `""` | Webhook endpoint URL |
| `webhook.min_severity` | `"warn"` | info, warn, or critical |
| `webhook.auth_token` | `""` | Bearer token for webhook |
| `webhook.timeout_seconds` | `5` | HTTP timeout |
| `webhook.queue_size` | `64` | Async buffer size (overflow = drop + metric) |
| `syslog.address` | `""` | Syslog address (e.g., `udp://host:514`) |
| `syslog.min_severity` | `"warn"` | info, warn, or critical |
| `syslog.facility` | `"local0"` | Syslog facility |
| `syslog.tag` | `"pipelock"` | Syslog tag |
| `otlp.endpoint` | `""` | OTLP collector base URL (e.g., `http://collector:4318`). `/v1/logs` appended automatically. |
| `otlp.min_severity` | `"warn"` | info, warn, or critical |
| `otlp.headers` | `{}` | Custom HTTP headers (authentication, tenant routing) |
| `otlp.timeout_seconds` | `10` | Per-request HTTP timeout |
| `otlp.queue_size` | `256` | Async buffer size (overflow = drop) |
| `otlp.gzip` | `false` | Compress request bodies with gzip |

OTLP events are sent as log records over HTTP/protobuf. Each pipelock audit event maps to one OTLP LogRecord with `service.name=pipelock` as a resource attribute. Retries on 429, 502, 503, 504, and network errors with bounded exponential backoff (3 attempts, 1s/2s/4s). 500 and 501 are not retried. No gRPC, no batching timer.

**Severity levels** (hardcoded per event type, not configurable):
- **critical:** kill switch deny, adaptive escalation to critical level (enforcement upgraded across all transports)
- **warn:** blocked requests, anomalies, session events, MCP unknown tools, scan hits
- **info:** allowed requests, tunnel open/close, WebSocket open/close, config reload

## Tool Chain Detection

Detects attack patterns in sequences of MCP tool calls using subsequence matching with gap tolerance.

```yaml
tool_chain_detection:
  enabled: true
  action: warn
  window_size: 20
  window_seconds: 60
  max_gap: 3
  tool_categories: {}           # map tool names to categories
  pattern_overrides: {}         # per-pattern action overrides
  sensitivity_labels: {}        # override lethal-trifecta source/sink labels
  custom_patterns: []
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable chain detection |
| `action` | `"warn"` | warn or block |
| `window_size` | `20` | Tool calls retained in history |
| `window_seconds` | `60` | Time-based history eviction |
| `max_gap` | `3` | Max innocent calls between pattern steps |
| `tool_categories` | `{}` | Map tool names to built-in categories |
| `pattern_overrides` | `{}` | Per-pattern action override |
| `sensitivity_labels` | `{}` | Override keyword-based lethal-trifecta classification. Valid labels are `untrusted_source`, `sensitive_source`, and `external_sink`; values are exact tool names or glob patterns. |
| `custom_patterns` | `[]` | Custom attack sequences |

Ships with 10 built-in patterns covering reconnaissance, credential theft, data staging, persistence, and exfiltration chains. The built-in lethal-trifecta detector watches for `untrusted_source -> sensitive_source -> external_sink` sequences. Use `sensitivity_labels` when your tool names do not carry enough semantic signal for the keyword fallback, and use `pattern_overrides.lethal-trifecta` to change that detector's action.

## Cross-Request Exfiltration Detection

Detects secrets split across multiple requests within a session. Two independent mechanisms (entropy budget and fragment reassembly) can run together or separately. Both feed into adaptive enforcement scoring.

```yaml
cross_request_detection:
  enabled: false
  action: warn
  entropy_budget:
    enabled: false
    bits_per_window: 4096
    window_minutes: 5
    action: block
  fragment_reassembly:
    enabled: false
    max_buffer_bytes: 65536
    window_minutes: 5
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable cross-request detection |
| `action` | `"block"` | Default action for sub-features that don't override |

### Entropy Budget

Tracks cumulative Shannon entropy of all outbound payloads (URLs, request bodies, MCP JSON-RPC payloads, WebSocket frames) per session within a sliding time window. When total entropy bits exceed the budget, the configured action fires.

| Field | Default | Description |
|-------|---------|-------------|
| `entropy_budget.enabled` | `false` | Enable entropy budget tracking |
| `entropy_budget.bits_per_window` | `4096` | Max entropy bits allowed per session per window before triggering |
| `entropy_budget.window_minutes` | `5` | Sliding window duration in minutes |
| `entropy_budget.action` | `"warn"` | Action when budget is exceeded (warn or block) |
| `entropy_budget.exempt_domains` | `[]` | Domains excluded from entropy budget recording. DLP pattern matching still runs on exempt domains. Supports exact hostnames and `*.example.com` wildcards (also matches apex `example.com`). |

**Tuning:** The default 4096 bits per 5-minute window allows roughly 500 characters of random data across URL query parameters and path segments. This is appropriate when scanning URL-level traffic only.

**With TLS interception enabled**, request bodies are also scanned for entropy. A single LLM API call body (conversation context) can contain 100,000+ bits of entropy. Set `bits_per_window` to `500000` or higher when using `tls_interception` with cross-request detection, and add your LLM provider to `exempt_domains`:

```yaml
cross_request_detection:
  enabled: true
  entropy_budget:
    enabled: true
    bits_per_window: 500000
    exempt_domains:
      - "*.anthropic.com"
      - "*.openai.com"
      - "*.minimax.io"
```

### Fragment Reassembly

Buffers outbound payloads (URLs, request bodies, MCP JSON-RPC payloads, WebSocket frames) per session and re-scans the concatenated content against DLP patterns on every request (synchronous, pre-forward). Catches secrets split across multiple requests that individually look clean.

| Field | Default | Description |
|-------|---------|-------------|
| `fragment_reassembly.enabled` | `false` | Enable fragment reassembly |
| `fragment_reassembly.max_buffer_bytes` | `65536` | Max buffer size per session (64 KB). Older fragments are evicted when exceeded. |
| `fragment_reassembly.window_minutes` | `5` | Fragment retention window in minutes. Fragments older than this are pruned. |

**Memory:** Each tracked session uses up to `max_buffer_bytes`. With 10,000 concurrent sessions (hard cap), the worst-case memory is `max_buffer_bytes * 10000` (640 MB at defaults). Reduce `max_buffer_bytes` in memory-constrained environments.

**Scope note:** Cross-request detection scans all outbound content visible to the proxy: URLs, request bodies, MCP JSON-RPC payloads, and WebSocket frames. CONNECT tunnels without TLS interception only expose the target hostname (entropy tracking only). Enable `tls_interception` for full cross-request coverage on tunneled traffic.

## Finding Suppression

Suppress known false positives by rule name and path/URL pattern.

```yaml
suppress:
  - rule: "Jailbreak Attempt"
    path: "*/robots.txt"
    reason: "robots.txt content triggers developer mode regex"
```

| Field | Description |
|-------|-------------|
| `rule` | Pattern/rule name to suppress (required) |
| `path` | Exact path, glob, or URL suffix (required) |
| `reason` | Human-readable justification |

**Path matching:** exact (`foo.txt`), glob (`*.txt`, `vendor/**`), directory prefix (`vendor/`), basename glob (`*.txt` matches `dir/foo.txt`).

See [Finding Suppression Guide](guides/suppression.md) for the full reference.

## Git Protection

Git-aware scanning for pre-push secret detection and branch restrictions.

```yaml
git_protection:
  enabled: false
  allowed_branches: ["feature/*", "fix/*", "main"]
  allowed_push_repos: ["github.com/acme/private-*", "gitlab.com/*"]
  pre_push_scan: true
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable git protection |
| `allowed_branches` | `["feature/*", "fix/*", "main", "master"]` | Branch name patterns |
| `allowed_push_repos` | `[]` | Optional proxy-enforced allowlist for visible Git smart-HTTP pushes (`git-receive-pack`). Supported patterns include exact repos (`host/owner/repo`), owner globs (`github.com/acme/*`), and host-wide allowlists (`gitlab.com/*`). Bare `owner/repo` entries are rejected. Matching is case-insensitive. When `git_protection.enabled` is true and the allowlist is empty, visible pushes are blocked (fail-closed). Non-intercepted HTTPS CONNECT exposes only the host; enable TLS interception for repo-path enforcement. SSH pushes are opaque to the proxy and are not gated. |
| `pre_push_scan` | `true` | Scan diffs before push |

## Logging

Structured audit logging to stdout and/or file.

```yaml
logging:
  format: json
  output: stdout
  file: ""
  include_allowed: true
  include_blocked: true
```

| Field | Default | Description |
|-------|---------|-------------|
| `format` | `"json"` | json or text |
| `output` | `"stdout"` | stdout, file, or both |
| `file` | `""` | Log file path |
| `include_allowed` | `true` | Log allowed requests |
| `include_blocked` | `true` | Log blocked requests |

## Internal Networks (SSRF Protection)

Private/reserved IP ranges blocked from agent access. Post-DNS check prevents SSRF via DNS rebinding.

```yaml
internal:
  - "0.0.0.0/8"
  - "127.0.0.0/8"
  - "10.0.0.0/8"
  - "100.64.0.0/10"
  - "172.16.0.0/12"
  - "192.168.0.0/16"
  - "169.254.0.0/16"
  - "::1/128"
  - "fc00::/7"
  - "fe80::/10"
  - "224.0.0.0/4"
  - "ff00::/8"
```

All RFC 1918, RFC 4193, link-local, loopback, CGN (Tailscale/Carrier-Grade NAT), multicast, and cloud metadata ranges are blocked by default. IPv6 zone IDs (e.g. `::1%eth0`) are stripped before IP parsing to prevent bypass.

### Trusted Domains

Domains exempt from SSRF internal-IP checks. Use this when a domain legitimately resolves to a private IP (e.g., an internal API behind a VPN) and you want pipelock to allow the connection.

```yaml
trusted_domains:
  - "internal-api.example.com"
  - "*.corp.example.com"
```

| Field | Default | Description |
|-------|---------|-------------|
| `trusted_domains` | `[]` | Top-level list. Supports `*.example.com` wildcards (also matches apex `example.com`). |

**Important:** This is a **top-level** config field, not nested under `forward_proxy`. Placing it under `forward_proxy` will silently do nothing. DLP and other content scanning still runs on trusted domains -- only the SSRF IP check is bypassed.

**Strict mode:** `trusted_domains` does not override `api_allowlist`. In strict mode, a domain must be in **both** `api_allowlist` (to be reachable) and `trusted_domains` (to resolve to internal IPs). If a domain is only in `api_allowlist` and resolves internally, pipelock blocks it with a hint to add it to `trusted_domains`.

Per-agent `trusted_domains` overrides are available in agent profiles (Pro license).

### DNS Host Overrides

Static hostname-to-IP overrides used by SSRF DNS checks and the proxy dial path. Use this for reproducible local fixtures or controlled internal names when you cannot or do not want to modify system DNS.

```yaml
dns:
  host_overrides:
    fixture.example.test:
      - "127.0.0.1"
trusted_domains:
  - "fixture.example.test"
```

| Field | Default | Description |
|-------|---------|-------------|
| `dns.host_overrides` | `{}` | Map of exact hostnames to one or more IP addresses. Hostname keys are normalized case-insensitively with trailing DNS dots stripped. URL, wildcard, host:port, and IP-literal keys are rejected. |

Host overrides do not exempt a destination from SSRF blocking by themselves. If an override resolves to an internal IP, the hostname must also be present in `trusted_domains` or the target IP must be covered by `ssrf.ip_allowlist`. Raw IP targets never use `dns.host_overrides`.

### SSRF IP Allowlist

Exempt specific IP ranges from SSRF blocking. Use this when your internal services resolve to known IP ranges and you want to allow connections by IP rather than by hostname.

```yaml
ssrf:
  ip_allowlist:
    - "192.168.1.0/24"
    - "10.0.0.5/32"
```

| Field | Default | Description |
|-------|---------|-------------|
| `ssrf.ip_allowlist` | `[]` | CIDR ranges exempt from SSRF blocking. IPs in these ranges are still "internal" but explicitly trusted. |

**Complementary to `trusted_domains`:** `trusted_domains` is hostname-based trust (the domain resolves to a private IP, but you trust the domain). `ssrf.ip_allowlist` is IP-based trust (you trust the IP range regardless of which domain resolves to it). Either one exempts from SSRF blocking.

**Validation:** Entries must be canonical CIDRs (network address, not host address). `10.0.0.5/24` is rejected because the host bits are set (use `10.0.0.0/24` instead). Catch-all prefixes (`0.0.0.0/0`, `::/0`) are rejected because they would disable SSRF protection entirely.

## Presets

Seven starter configs in `configs/`:

| Preset | Mode | Response Action | MCP Policy | Best For |
|--------|------|----------------|------------|----------|
| `balanced.yaml` | balanced | warn | warn | General purpose |
| `strict.yaml` | strict | block | block | High-security |
| `audit.yaml` | audit | warn | warn | Log-only monitoring |
| `claude-code.yaml` | balanced | block | warn | Claude Code (unattended) |
| `cursor.yaml` | balanced | block | warn | Cursor IDE |
| `generic-agent.yaml` | balanced | warn | warn | New agents (tuning) |
| `hostile-model.yaml` | strict | block | block | Uncensored/abliterated models |

Key differences between presets:

| Setting | Balanced | Strict | Claude Code |
|---------|----------|--------|-------------|
| Max URL Length | 2048 | 500 | 4096 |
| Entropy Threshold | 4.5 | 3.5 | 5.0 |
| Rate Limit | 60/min | 30/min | 120/min |
| API Allowlist | LLM + comms | LLM + comms | LLM + dev tools |

### Hostile-Model Preset

The `hostile-model` preset is for agents running uncensored, abliterated, or jailbroken models where the model itself has zero safety guardrails. It assumes the model will comply with any instruction, including exfiltrating secrets or executing injected prompts.

Use this preset for:
- **Red-team testing:** exercising agent attack paths against the network layer
- **Self-hosted uncensored models:** weight-ablated models (e.g. OBLITERATUS variants) with safety refusals removed
- **Jailbroken agents:** any model that can be trivially steered past its own guardrails

What it enables beyond `strict`:
- **Every defense layer active:** forward proxy, request body scanning, WebSocket scanning, MCP input/tool/policy scanning, session binding, session profiling, adaptive enforcement, tool chain detection
- **Aggressive entropy threshold (3.0):** catches more encoded secrets at the cost of higher false-positive rates
- **Lower rate limit (15/min):** constrains exfiltration bandwidth
- **Shorter URL limit (300 chars):** reduces data budget per request
- **All MCP tool policy rules enabled:** blocks shell obfuscation, file writes outside allowed paths, and network access patterns
- **TLS interception pre-configured** (disabled by default; enable and generate a CA to activate)

The core principle: the model won't protect you, so the network layer must.

## Default Agent Identity

When pipelock runs behind a workload-local proxy configuration, incoming requests typically lack the `X-Pipelock-Agent` header because the upstream container sends traffic through `HTTPS_PROXY` without identity headers. Set `default_agent_identity` so that traffic is attributed to the workload rather than showing as `anonymous` in logs, receipts, and metrics.

```yaml
default_agent_identity: "deployment/my-agent"
```

If you also set `bind_default_agent_identity: true`, pipelock ignores caller-supplied `X-Pipelock-Agent` headers and `?agent=` query params and binds all traffic on that listener to the configured default identity. This is the recommended mode for the generated `pipelock init sidecar` companion topology.

These precedences apply to default-identity resolution after listener-level and source-CIDR resolution have been evaluated. They do not override an agent profile that matched on listener address or source CIDR.

Resolution precedence with binding disabled: context override > `X-Pipelock-Agent` header > `default_agent_identity` > `?agent=` query param > `anonymous`.

Resolution precedence with binding enabled: context override > `default_agent_identity` > `anonymous`.

`pipelock init sidecar` sets both fields automatically from the workload kind and name (e.g., `deployment/my-agent`). Override the identity with `--agent-identity`.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `default_agent_identity` | `string` | `""` (anonymous) | Operator-configured agent name used when no stronger identity source resolves the caller |
| `bind_default_agent_identity` | `bool` | `false` | Ignore caller-supplied `X-Pipelock-Agent` and `?agent=` values and bind requests to `default_agent_identity` |

## Agent Profiles

Per-agent policy overrides. When multiple agents share one pipelock instance, each agent can have its own mode, allowlist, DLP patterns, rate limits, and request budgets. Scalar fields (mode, enforce) inherit from the base config when unset. `mcp_tool_policy` replaces the base section entirely when set on an agent profile (no deep merge). `session_profiling` replaces the per-agent fields (`domain_burst`, `anomaly_action`, `volume_spike_ratio`) unconditionally while preserving global-only fields (`max_sessions`, `session_ttl_minutes`, `cleanup_interval_seconds`). `rate_limit` overrides individual rate limit fields (non-zero values win). DLP merging follows separate rules (see below).

```yaml
agents:
  claude-code:
    listeners: [":8889"]
    source_cidrs: ["10.42.3.0/24"]
    mode: strict
    api_allowlist: ["github.com", "*.githubusercontent.com"]
    dlp:
      include_defaults: true
      patterns:
        - name: "Internal Token"
          regex: 'internal_[a-zA-Z0-9]{32}'
          severity: critical
    rate_limit:
      max_requests_per_minute: 30
    session_profiling:
      domain_burst: 3
      anomaly_action: block
    mcp_tool_policy:
      enabled: true
      action: block
      rules:
        - name: "Block shell"
          tool_pattern: "bash|shell"
          action: block
    budget:
      max_requests_per_session: 500
      max_bytes_per_session: 52428800
      max_unique_domains_per_session: 50
      window_minutes: 60

  research-agent:
    listeners: [":8890"]
    mode: balanced
    enforce: false
    budget:
      max_unique_domains_per_session: 200

  _default:
    mode: balanced
```

### Agent Resolution

Pipelock resolves the agent name for each request using this priority order:

1. **Listener binding**: matched by the port the request arrived on (injected as a context override, spoof-proof)
2. **Source CIDRs**: matched by client IP against `source_cidrs` ranges defined on each agent profile
3. **Header** (`X-Pipelock-Agent`): set by the calling agent or orchestrator
4. **Query parameter** (`?agent=name`): appended to fetch/WebSocket URLs
5. **Fallback**: `_default` profile if defined, otherwise base config

Listener-based resolution is the only method that cannot be spoofed by the agent. It injects a context override that takes priority over header and query param. Header and query param methods are convenient but trust the caller. Use listeners when isolation matters.

For MCP proxy mode, the `--agent` flag resolves the profile directly at startup (not through the HTTP resolution chain).

### Override Fields

Each agent profile can override these fields:

| Field | Type | Description |
|-------|------|-------------|
| `listeners` | `[]string` | Dedicated listen addresses (e.g., `":8889"`). Pipelock opens extra ports for these. |
| `source_cidrs` | `[]string` | Client IP ranges that identify this agent (e.g., `["10.42.3.0/24"]`). |
| `mode` | `string` | `strict`, `balanced`, or `audit` |
| `enforce` | `bool` | Override global enforce setting |
| `api_allowlist` | `[]string` | Replaces the base allowlist entirely |
| `dlp` | object | DLP pattern overrides (see below) |
| `rate_limit` | object | Per-agent rate limits |
| `session_profiling` | object | Per-agent profiling thresholds |
| `mcp_tool_policy` | object | Per-agent MCP tool policy |
| `trusted_domains` | `[]string` | Per-agent SSRF-exempt domains (overrides global list) |
| `budget` | object | Request budgets (see below) |

### DLP Merge Behavior

Agent DLP overrides follow the same `include_defaults` pattern as the global DLP section:

- `include_defaults: true` (or omitted): agent patterns are appended to the base config patterns. If an agent pattern shares a name with a base pattern, the agent version wins.
- `include_defaults: false`: agent patterns replace the base patterns entirely.

### Budget Config

Budgets cap what an agent can do within a rolling time window. All fields default to `0` (unlimited).

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `max_requests_per_session` | `int` | `0` | Max HTTP requests per window |
| `max_bytes_per_session` | `int` | `0` | Max response bytes per window |
| `max_unique_domains_per_session` | `int` | `0` | Max distinct domains per window |
| `window_minutes` | `int` | `0` | Rolling window duration in minutes. `0` means the budget never resets. |
| `max_tool_calls_per_session` | `int` | `0` | Max MCP tool calls per session (0 = unlimited). **Enforced.** |
| `max_retries_per_tool` | `int` | `0` | Max times the same tool+args can be called (0 = unlimited, default 5 when set). Detects retry storms. **Enforced.** |
| `loop_detection_window` | `int` | `0` | Number of recent tool calls to track for loop/cycle detection (0 = disabled, default 20 when set). **Enforced.** |
| `max_wall_clock_minutes` | `int` | `0` | Max session duration in minutes (0 = unlimited). **Enforced.** |
| `dow_action` | `string` | `"block"` | Action when a denial-of-wallet limit is exceeded: `"block"` (reject the tool call) or `"warn"` (log and allow) |
| `max_concurrent_tool_calls` | `int` | `0` | Max parallel in-flight tool calls (0 = unlimited). **Enforced.** |
| `max_retries_per_endpoint` | `int` | `0` | Max calls to the same domain+path (0 = unlimited, default 20 when set). **Enforced.** |
| `fan_out_limit` | `int` | `0` | Max unique endpoints within the fan-out window (0 = unlimited). **Enforced.** |
| `fan_out_window_seconds` | `int` | `0` | Sliding window for fan-out detection (0 = disabled). **Enforced.** |

When a budget limit is reached:

- **Request count and domain limits** are checked before the outbound request. Exceeding either returns `429 Too Many Requests`.
- **Byte limit (fetch proxy):** the response body read is capped at the remaining byte budget. If the response exceeds the limit, it is discarded and a `429` is returned.
- **Byte limit (CONNECT/WebSocket):** streaming connections track bytes after close. The byte budget is enforced on the next admission check, not mid-stream, because tunnel data cannot be recalled after transmission.
- **DoW limits (MCP proxy):** tool call budgets are checked before each `tools/call` dispatch. When `dow_action` is `"block"`, the call is rejected with a JSON-RPC error. When `"warn"`, the call is logged and allowed through. Currently enforced: total tool call count, per-tool retry storms, loop/cycle detection, and wall-clock duration.

### Listener Binding

Each agent can bind to one or more dedicated ports via the `listeners` field. Pipelock opens these ports at startup alongside the main proxy port. Requests arriving on an agent's listener are automatically resolved to that agent without relying on headers or query params.

This is the only spoof-proof resolution method. The agent process connects to its assigned port, and pipelock knows which profile to apply based on the port alone.

```yaml
agents:
  trusted-agent:
    listeners: [":8889"]
    mode: balanced
  untrusted-agent:
    listeners: [":8890"]
    mode: strict
    budget:
      max_requests_per_session: 100
```

> **Note:** Listener bindings are set at startup. Changing `listeners` requires a process restart (not hot-reloadable).

### Source CIDR Matching

Each agent can define one or more `source_cidrs` entries. Pipelock matches the client IP of every incoming request against these CIDRs. This works for all traffic types including CONNECT tunnels, where header-based identification is not possible.

In Kubernetes, each pod has a unique IP. In Docker Compose, each container has its own. Source CIDR matching maps those IPs to agent profiles with zero agent-side configuration.

```yaml
agents:
  claude-code:
    source_cidrs: ["10.42.3.0/24"]
    mode: strict
  cursor:
    source_cidrs: ["10.42.5.0/24", "10.42.6.0/24"]
    mode: balanced
```

Resolution priority: listener binding > source CIDR > header > query param > `_default`.

CIDRs must not overlap between different agents (containment and exact matches are both rejected). Overlapping CIDRs within the same agent are allowed.

### The `_default` Profile

If defined, `_default` applies to any request that does not match a named agent. Without `_default`, unmatched requests use the base config directly.

## License Key

Multi-agent profiles (the `agents:` section) require a signed license token. The token is an Ed25519-signed JWT-like string issued by `pipelock license issue`. At startup, pipelock verifies the signature, checks expiration, and confirms the token includes the `agents` feature. If any check fails, agent profiles are disabled with a warning. All single-agent protection remains active.

New deployments may receive a root-signed intermediate certificate alongside the token. When `license_intermediate_file` is configured, Pipelock verifies the token through `token -> intermediate -> embedded root public key` and fails closed if the intermediate is malformed, expired, signed by the wrong root, or revoked by the CRL. Omitting `license_intermediate_file` preserves legacy direct-root token verification.

### Loading Sources

Pipelock checks three sources for the license token, in priority order:

| Priority | Source | Use case |
|----------|--------|----------|
| 1 (highest) | `PIPELOCK_LICENSE_KEY` env var | Containers, CI, Kubernetes Secrets |
| 2 | `license_file` config field (file path) | Secret volume mounts, file-based workflows |
| 3 (lowest) | `license_key` config field (inline) | Simple single-machine setups |

The first non-empty source wins. Later sources are not checked. `PIPELOCK_LICENSE_KEY` values containing only whitespace are treated as empty and fall through to lower-priority sources. If `license_file` is configured but the file is empty or contains only whitespace, pipelock fails with an error rather than falling back to inline `license_key`. This is fail-closed by design: a misconfigured Secret mount should not silently downgrade to an inline fallback.

**Env var (recommended for containers):**

```bash
export PIPELOCK_LICENSE_KEY="pipelock_lic_v1_eyJ..."
pipelock run --config pipelock.yaml
```

**File path:**

```yaml
license_file: /etc/pipelock/license.token    # absolute path
license_file: license.token                  # relative to config file directory
```

The file should contain only the license token string. Leading and trailing whitespace is trimmed. The file must have owner-only permissions (`0600`); group- or world-readable files are rejected. The file is read at startup. Adding or changing a license requires a restart to take effect; a config-triggered reload will detect the change but will not apply it until restart. Removing the currently active license source takes effect immediately on reload (for example, unsetting `PIPELOCK_LICENSE_KEY` or removing the active `license_file`/`license_key` entry).

**Inline (simplest):**

```yaml
license_key: "pipelock_lic_v1_eyJ..."
```

**Full example with all license fields:**

```yaml
license_key: "pipelock_lic_v1_eyJ..."        # inline token (lowest priority)
license_file: "/etc/pipelock/license.token"  # file path (medium priority)
license_crl_file: "/etc/pipelock/license.crl" # signed revocation list
license_intermediate_file: "/etc/pipelock/license-intermediate.json" # root-signed intermediate cert
license_public_key: "a1b2c3d4..."            # hex-encoded Ed25519 public key (dev builds only)
```

### Kubernetes Secret Example

Mount a license key from a Kubernetes Secret as an env var:

```yaml
env:
  - name: PIPELOCK_LICENSE_KEY
    valueFrom:
      secretKeyRef:
        name: pipelock-license
        key: token
```

Or mount the Secret as a file and reference it in config:

```yaml
license_file: /etc/pipelock/license/token
license_intermediate_file: /etc/pipelock/license/intermediate.json
```

### Key Verification

Official release builds embed the signing public key at compile time via ldflags. The embedded key takes priority over `license_public_key` and cannot be overridden by config, preventing self-signing bypasses. The `license_public_key` config field is only used in development builds where no key is embedded.

`license_crl_file` points at a signed license revocation list. It is read and verified at startup and on config reload; a revoked active license is disabled immediately. The CRL file should be mounted from trusted operator-controlled storage, not written by the agent.

`license_intermediate_file` points at the root-signed intermediate license-signing certificate. It is public cert material, not a secret, but it controls the active signing chain and should still come from trusted operator-controlled storage. Relative paths resolve against the config file directory. A configured intermediate certificate is checked at startup: a missing, unreadable, malformed, expired, or wrong-root cert emits a startup warning and disables licensed features such as multi-agent profiles and Assess signing, rather than silently downgrading to direct-root verification. It never blocks startup or single-agent protection — a licensing-tier misconfiguration must not take the proxy down, and a short-lived intermediate's expiry must not crash-loop it. Changing this field requires a restart for the new license chain to take effect.

### CLI Commands

```bash
pipelock license keygen              # generates ~/.config/pipelock/license.key + license.pub
pipelock license issue --email customer@company.com --expires 2027-03-07
pipelock license inspect TOKEN       # decode without verifying
```

A `_default` profile without any named agents does not require a license key.

### Installing a License

Use `pipelock license install` to write a license token to a file:

```bash
pipelock license install <TOKEN>                    # writes to ~/.config/pipelock/license.token
pipelock license install --path /etc/pipelock/license.token <TOKEN>  # custom path
```

The command validates the token format, writes it atomically (temp file + rename), and prints setup instructions. Point your config at the file:

```yaml
license_file: /etc/pipelock/license.token
```

Then restart pipelock to activate Pro features.

### Renewal

License tokens have a fixed expiry (typically 45 days). When your subscription renews, you receive a new token by email. To update:

1. Run `pipelock license install <NEW_TOKEN>` (overwrites the existing file)
2. Restart pipelock

The new token activates on restart. Your current token continues working until its expiry date, so there is no rush to update immediately. A config reload detects the changed license inputs but does not apply them until restart (activation requires restart; revocation is immediate).

## Scan API

Evaluation-plane HTTP listener for programmatic scanning. Disabled by default. When enabled, serves `POST /api/v1/scan` on a dedicated port with independent auth, rate limiting, and timeouts.

```yaml
scan_api:
  listen: "127.0.0.1:9090"
  auth:
    bearer_tokens:
      - "your-secret-token"
  rate_limit:
    requests_per_minute: 600   # per token
    burst: 50
  max_body_bytes: 1048576      # 1MB
  field_limits:
    url: 8192
    text: 524288               # 512KB
    content: 524288
    arguments: 524288
  timeouts:
    read: "2s"
    write: "2s"
    scan: "5s"
  connection_limit: 100
  kinds:
    url: true
    dlp: true
    prompt_injection: true
    tool_call: true
```

| Field | Default | Description |
|-------|---------|-------------|
| `listen` | `""` (disabled) | Bind address. Listener only starts when set and at least one bearer token is configured. |
| `auth.bearer_tokens` | `[]` | Bearer tokens for `Authorization` header. Compared in constant time. Required when `listen` is set. |
| `rate_limit.requests_per_minute` | `600` | Per-token rate limit. |
| `rate_limit.burst` | `50` | Burst allowance above steady-state rate. |
| `max_body_bytes` | `1048576` (1MB) | Maximum request body size. |
| `field_limits.url` | `8192` | Max bytes for `input.url` field. |
| `field_limits.text` | `524288` (512KB) | Max bytes for `input.text` field. |
| `field_limits.content` | `524288` (512KB) | Max bytes for `input.content` field. |
| `field_limits.arguments` | `524288` (512KB) | Max bytes for `input.arguments` field. |
| `timeouts.read` | `"2s"` | HTTP read timeout. |
| `timeouts.write` | `"2s"` | HTTP write timeout. |
| `timeouts.scan` | `"5s"` | Per-scan deadline. Exceeded = `scan_deadline_exceeded` error, never partial `allow`. |
| `connection_limit` | `100` | Max concurrent connections. |
| `kinds.url` | `true` | Enable `url` scan kind. |
| `kinds.dlp` | `true` | Enable `dlp` scan kind. |
| `kinds.prompt_injection` | `true` | Enable `prompt_injection` scan kind. |
| `kinds.tool_call` | `true` | Enable `tool_call` scan kind. |

All kinds are enabled by default. Set any to `false` to disable. `tool_call` DLP and prompt-injection scanning run on demand through this API regardless of the inline MCP proxy's `mcp_input_scanning.enabled` setting; that toggle controls live MCP proxy traffic, not explicit Scan API requests. Full API reference: [docs/scan-api.md](scan-api.md).

## Address Protection

Detects blockchain address poisoning attacks. Compares outbound addresses against a user-supplied allowlist of known-good destinations and flags similar-looking addresses using prefix/suffix fingerprinting. This is destination verification, not secret detection — separate from DLP.

Disabled by default. Users opt in explicitly.

```yaml
address_protection:
  enabled: true
  action: block
  unknown_action: warn
  allowed_addresses:
    - "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD18"
    - "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
  chains:
    eth: true
    btc: true
    sol: false
    bnb: true
  similarity:
    prefix_length: 4
    suffix_length: 4
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable address protection. |
| `action` | `"block"` | Action for poisoning/lookalike findings: `block` or `warn`. |
| `unknown_action` | `"allow"` | Action for valid addresses not in allowlist: `allow`, `warn`, or `block`. |
| `allowed_addresses` | `[]` | Known-good destination addresses (any supported chain format). |
| `chains.eth` | `true` | Detect Ethereum addresses (0x-prefixed, EIP-55 checksum validated). |
| `chains.btc` | `true` | Detect Bitcoin addresses (P2PKH, P2SH, Bech32/Bech32m). |
| `chains.sol` | `false` | Detect Solana addresses (base58, 32-44 chars). Disabled by default due to higher false positive risk from base58 regex. |
| `chains.bnb` | `true` | Detect BNB Smart Chain addresses (0x-prefixed, same format as ETH). |
| `similarity.prefix_length` | `4` | Characters to compare at the start of the address payload. |
| `similarity.suffix_length` | `4` | Characters to compare at the end of the address payload. |

At least one chain must be enabled when `address_protection.enabled` is `true`. All-chains-disabled with the feature enabled is rejected at validation (silent no-op prevention).

**Hot reload:** disabling address protection triggers a reload warning. Re-enabling takes effect immediately.

## File Sentry

Real-time filesystem monitoring for agent subprocesses. Detects secrets written to disk that bypass the MCP tool call path. Applies to subprocess MCP mode only (`pipelock mcp proxy -- COMMAND`).

```yaml
file_sentry:
  enabled: false
  watch_paths:
    - "."                         # required:false; degraded if unavailable
    - path: "/var/agent-secrets"  # required:true; startup fails if unavailable
      required: true
  scan_content: true
  max_file_bytes: 0             # 0 = built-in 10 MiB default
  ignore_patterns:
    - "node_modules/**"
    - ".git/**"
    - "*.o"
    - "*.so"
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable filesystem monitoring. Opt-in. |
| `watch_paths` | `[]` | Directories to monitor recursively. Relative paths are resolved against the config file directory (not CWD). Required when enabled. Entries may be bare strings or `{path, required}` mappings. Bare strings default to `required: false`. |
| `scan_content` | `true` | Run DLP scanner on modified file content. |
| `max_file_bytes` | `0` | Max watched-file bytes to read for content scanning. `0` uses the built-in 10 MiB default; negative values are rejected. |
| `ignore_patterns` | `[]` | Glob patterns for files and directories to skip. |
| `action` | `warn` | Enforcement response when an agent-attributed write matches a DLP pattern. `warn` logs the finding + records a metric (current default). `block` additionally cancels the proxy context so the MCP child terminates, preventing the agent from continuing after a detected leak. Non-agent writes (editor saves, build output) never trigger the block path. |

When a `watch_paths` entry is `required: false`, startup records a degraded path and continues if that watch cannot be installed. Set `required: true` on paths that are part of the security boundary; startup fails closed if those watches cannot be installed. Unknown fields in mapping entries are rejected so typos such as `require: true` do not silently disable the hard-fail opt-in.

Findings are reported as stderr warnings and Prometheus metrics (`pipelock_file_sentry_findings_total`). Structured audit log emission (`file_sentry_dlp` event type) is defined but not yet wired to the webhook/syslog pipeline. On Linux, process lineage tracking attributes file writes to the agent's process tree via `PR_SET_CHILD_SUBREAPER` and `/proc` walking.

`action: block` is the fail-closed enforcement boundary. The cancel fires from the consumer goroutine after the log line and metric emission, which means there is unavoidable latency between the kernel write and the proxy teardown: the file has already been written to disk by the time the scan completes. Block prevents the agent from continuing to act on the leak, it does not prevent the write itself. For write-time interception the operator must layer Landlock or a sandbox at the deployment level.

Files larger than `max_file_bytes` are skipped to bound memory use, but the skip is surfaced through the watcher's error path instead of being silently dropped. Stat/read failures are surfaced the same way. Write events are debounced (50ms quiet window) to avoid scanning partial writes.

## Community Rules

Optional signed rule bundles that extend built-in detection patterns. See [docs/rules.md](rules.md) for the full user guide.

```yaml
rules:
  rules_dir: ~/.local/share/pipelock/rules  # default ($XDG_DATA_HOME/pipelock/rules)
  min_confidence: medium          # skip low-confidence (experimental) rules
  include_experimental: false     # only load stable rules by default
  trusted_keys:                   # additional signing keys (beyond embedded keyring)
    - name: "acme-security"
      public_key: "64-char-hex-encoded-ed25519-public-key"
```

| Field | Default | Description |
|-------|---------|-------------|
| `rules_dir` | `~/.local/share/pipelock/rules` | Directory for installed bundles (`$XDG_DATA_HOME/pipelock/rules`) |
| `min_confidence` | `""` (all) | Skip rules below this confidence level |
| `include_experimental` | `false` | Include experimental rules from bundles |
| `trusted_keys` | `[]` | Additional Ed25519 public keys to trust for signature verification |

**Hot reload:** rule directory changes are not detected via hot-reload. Restart pipelock after installing or updating bundles.

## Sandbox

Process containment for agent commands using Linux kernel primitives. The agent runs in a restricted environment with controlled filesystem access, no direct network, and a filtered syscall set.

```yaml
sandbox:
  enabled: true
  best_effort: false              # degrade gracefully when namespace isolation unavailable
  strict: false                   # error if any layer unavailable (mutually exclusive with best_effort)
  workspace: /home/user/project   # agent working directory (default: CWD)
  filesystem:                     # optional Landlock overrides (default policy works for most agents)
    allow_read:
      - /usr/share/data
      - /app/                     # application code in containers
    allow_write:
      - /tmp/agent-work
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable sandbox containment |
| `best_effort` | `false` | Skip namespace isolation when unavailable (e.g. containers). Landlock + seccomp still apply. |
| `strict` | `false` | Error if any containment layer is unavailable. Mutually exclusive with `best_effort`. |
| `workspace` | CWD | Agent working directory (resolved to absolute at startup) |
| `filesystem.allow_read` | `[]` | Additional read-only filesystem paths |
| `filesystem.allow_write` | `[]` | Additional writable paths (workspace is always writable) |

If `filesystem` is omitted, the default Landlock policy is used (safe for Python/Node/Go agents without config). Read access grants execute (Landlock bundling). Write paths are also executable.

**Containment layers:**
- **Landlock LSM:** Restricts filesystem access to declared paths. Allowlist model. Protected directories (`~/.ssh`, `~/.aws`, `~/.kube`, etc.) are denied. Only dirs that exist on the system are checked.
- **Network namespaces:** Agent runs in an isolated network namespace. All HTTP/HTTPS traffic is kernel-confined to the namespace and routed through pipelock's bridge proxy. Raw socket direct egress is impossible. MCP stdio servers that act as HTTP bridges receive `HTTP_PROXY`/`HTTPS_PROXY` pointing at the in-namespace bridge, so upstream calls still traverse Pipelock's forward-proxy scanner.
- **Seccomp BPF:** Syscall allowlist (~130 safe syscalls for Go/Python/Node.js). Blocks ptrace, mount, module loading, kexec (KILL). io_uring returns EPERM (allows runtimes like Node.js 22 to fall back to epoll). Clone flags filtered to prevent namespace escape.

For sandboxed MCP stdio servers on Linux, the bridge enables forward-proxy handling internally even when `forward_proxy.enabled` is false in YAML. This is scoped to the sandbox bridge only and does not expose the normal forward proxy listener.

In `--best-effort` mode (for containers without user-namespace support), the bridge still scans traffic but network enforcement is cooperative: a child process that clears `HTTP_PROXY` / `HTTPS_PROXY` can bypass Pipelock.

**Usage:**
```bash
# Sandbox an MCP server
pipelock mcp proxy --sandbox --config pipelock.yaml -- npx server

# Sandbox a bridge-style MCP server; its outbound HTTP(S) goes through Pipelock
pipelock mcp proxy --sandbox --config pipelock.yaml -- npx -y @upstash/context7-mcp

# Sandbox a standalone command
pipelock sandbox --config pipelock.yaml -- python agent.py

# Pass environment variables to sandboxed process
pipelock sandbox --env API_KEY --env HOME=/app -- node server.js

# Best-effort mode for containers (Landlock + seccomp, no namespace)
pipelock sandbox --best-effort -- python agent.py

# Check sandbox capabilities without launching
pipelock sandbox --dry-run --json -- python agent.py
```

**Environments:**

| Environment | Layers | Notes |
|-------------|--------|-------|
| Bare metal / VM (Linux) | 3/3 | Full containment: Landlock + seccomp + network namespace |
| Containers (`--best-effort`) | 2/3 | Landlock + seccomp. Network via HTTP_PROXY + NetworkPolicy. |
| macOS | sandbox-exec | Apple SBPL profiles for filesystem + network restriction |

**Requirements:** Linux 5.13+ (Landlock ABI v1). Unprivileged on bare metal. macOS 13+ for sandbox-exec. Containers may need `--best-effort` if default seccomp blocks `CLONE_NEWUSER`.

**`--best-effort` is a degraded mode with a known bypass vector.** When user namespaces are unavailable — either the container runtime's seccomp profile blocks `CLONE_NEWUSER` or the host has `kernel.unprivileged_userns_clone=0` (default on some Debian-derivative kernels) — pipelock cannot create a network namespace for the child, so outbound traffic is enforced only by `HTTP_PROXY` / `HTTPS_PROXY` environment variables. A process inside the sandbox that explicitly `unset`s those vars, or makes a raw socket call without consulting the proxy env, will connect directly to the network and bypass pipelock's scanning pipeline. Pipelock emits a loud startup `WARNING` line alongside the `DEGRADED` status whenever this path is taken, on both `pipelock sandbox` and `pipelock mcp proxy --sandbox-best-effort`. For deployments that need kernel-level enforcement, either (1) make `CLONE_NEWUSER` available (adjust the runtime's seccomp profile or set `kernel.unprivileged_userns_clone=1`) so pipelock can run full 3/3 containment, or (2) use the companion-proxy topology from `pipelock init sidecar` — putting pipelock in a separate pod with a NetworkPolicy that restricts the agent pod's egress to the pipelock Service IP is the kernel-enforced equivalent of a network namespace.

## Config Audit Scoring (v2.6)

Score a pipelock configuration for security posture. Evaluates 23 categories with a 170-point budget and produces a normalized 0-100 percentage, letter grade, and actionable recommendations.

```bash
pipelock audit score --config pipelock.yaml
pipelock audit score --config pipelock.yaml --json
```

**Categories scored:** DLP (pattern count, env scanning, entropy), response scanning (enabled, action, pattern count), MCP tool scanning, MCP tool policy (rule count, blocking rules, overpermission), MCP input scanning, MCP session binding, kill switch (source count), enforcement mode, domain blocklist, adaptive enforcement, tool chain detection, sandbox, live-lock contracts, redaction, browser shield, mediation envelope, flight recorder, request body scanning, cross-request detection, address protection, seed-phrase detection, git protection, and file sentry.

**Tool policy overpermission audit:** flags wildcard `arg_pattern` values, high-risk tool patterns with non-blocking actions, and policies with no effective blocking rules. Respects section-level default action inheritance.

## Redirect Action (v2.0)

A policy action that rewrites dangerous tool execution to a safer target instead of blocking outright.

```yaml
mcp_tool_policy:
  enabled: true
  action: warn
  redirect_profiles:
    fetch_proxy:
      exec: ["/proc/self/exe", "internal-redirect", "fetch-proxy"]
      preserve_argv: true
      reason: "Route outbound fetches through audited proxy"
  rules:
    - name: shell-egress
      tool_pattern: '(?i)^(bash|shell|exec)$'
      arg_pattern: '(?i)\b(curl|wget)\b'
      action: redirect
      redirect_profile: fetch_proxy
```

| Field | Description |
|-------|-------------|
| `redirect_profiles` | Named redirect targets with exec command and reason |
| `redirect_profile` | Per-rule reference to a named profile |
| `action: redirect` | New action alongside block, warn, ask, strip, forward |

Redirect failure falls through to block (fail-closed). Every redirect emits a structured audit event with the original command, redirect target, policy rule, and reason.

## Canary Tokens (v2.1)

Synthetic secrets injected into the agent's environment. If pipelock detects a canary in any outbound request, it's irrefutable proof of compromise -- not a heuristic, but a known-fake value that should never appear in traffic.

```yaml
canary_tokens:
  enabled: true
  tokens:
    - name: "aws_canary"
      value: "canary-aws-trap-value-0x42a7"
      env_var: "AWS_ACCESS_KEY_ID"  # optional: inject as env var
    - name: "db_canary"
      value: "postgres://canary:trap@honeypot.internal/fake"
    - name: "api_canary"
      value: "sk_test_CANARY_4eC39HqLyjWDarjtT1zdp7dc"
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable canary token detection |
| `tokens[].name` | (required) | Human-readable name for the canary |
| `tokens[].value` | (required) | The exact string to detect in outbound traffic |
| `tokens[].env_var` | (optional) | Environment variable to inject the canary into |

Canary checks run after DLP as a safety net (exact string match, O(1) per token). If a DLP pattern already matched, the canary check is skipped. Detection emits a high-severity event with full request context. Use `pipelock canary generate` to create sample configurations.

## Flight Recorder (v2.1)

Hash-chained, tamper-evident evidence log. Every scanner verdict, tool call, and session event is recorded to JSONL with SHA-256 hash chains and optional Ed25519 signed checkpoints.

```yaml
flight_recorder:
  enabled: true
  dir: /var/lib/pipelock/evidence
  checkpoint_interval: 1000
  retention_days: 90
  redact: true
  sign_checkpoints: true
  signing_key_path: "/path/to/signing-key"
  max_entries_per_file: 10000
  raw_escrow: false
  escrow_public_key: ""
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable evidence recording |
| `dir` | (required if enabled) | Directory for evidence files |
| `checkpoint_interval` | `1000` | Entries between signed checkpoints |
| `retention_days` | `0` | Auto-expire files after N days (0 = keep forever) |
| `redact` | `true` | DLP-redact evidence content before writing. Receipt entries get field-level redaction (target/pattern scrubbed, signature preserved). |
| `sign_checkpoints` | `true` | Ed25519 sign checkpoint entries |
| `signing_key_path` | (empty) | Ed25519 private key for signed action receipts. When set, every proxy decision produces a signed receipt. Without it, the flight recorder can still write non-receipt evidence entries. Generate a key with `pipelock keygen <name>`. Verify receipts with `pipelock verify-receipt <file>`. In `pipelock run`, changing the configured path requires restart; reload re-reads updated key bytes only when the same path stays configured. |
| `max_entries_per_file` | `10000` | Rotate to a new file after this many entries |
| `raw_escrow` | `false` | Encrypt raw (pre-redaction) detail to sidecar files |
| `escrow_public_key` | (required if raw_escrow) | X25519 public key (hex) for escrow encryption |

Evidence files are named `evidence-<session>-<seq>.jsonl`. Each entry contains a SHA-256 hash of its predecessor, forming a tamper-evident chain. Action receipts form a second chain within the evidence log (each receipt links to the previous receipt via `chain_prev_hash`). Breaking either chain is detectable by `pipelock integrity verify`.

## Learn and Lock

Per-agent behavioral-contract workflow. The `learn` block controls where observation evidence is written, how privacy salt is resolved, and which inference floors the compiler uses.

```yaml
learn:
  enabled: false
  capture_dir: /var/lib/pipelock/learn
  privacy:
    salt_source: "${PIPELOCK_LEARN_SALT}"
    public_allowlist_default: true
  inference:
    floors:
      min_sessions: 5
      min_events: 20
      min_windows: 3
    normalization:
      algorithm: frequency_weighted_entropy_v1
      min_events: 10
      min_distinct_values: 5
      entropy_threshold_bits: 3.0
      reserved_segments_extra: []
      cardinality_cap_per_host: 1000
      tail_promotion_block_pct: 5.0
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable the learn observation configuration. When true, `capture_dir` is required. |
| `capture_dir` | `""` | Absolute directory for recorder JSONL evidence used by `pipelock learn observe`, `compile`, and `shadow`. Use durable storage for production captures. |
| `privacy.salt_source` | `""` | Salt resolver for privacy-sensitive dimensions: `${VAR}` reads an environment variable, `file:/abs/path` reads a file, any other string is treated as a literal salt. |
| `privacy.public_allowlist_default` | `true` | Use the built-in public allowlist when no explicit privacy allowlist is configured. |
| `inference.floors.min_sessions` | `5` | Minimum distinct sessions before a rule can be classified stable. |
| `inference.floors.min_events` | `20` | Minimum matching events before a rule can be classified stable. |
| `inference.floors.min_windows` | `3` | Minimum observation windows before a rule can be classified stable. |
| `inference.normalization.algorithm` | `frequency_weighted_entropy_v1` | Path-normalization algorithm. This is the only accepted value in v2.4. |
| `inference.normalization.min_events` | `10` | Minimum events in a host/method/path bucket before segment collapse is eligible. |
| `inference.normalization.min_distinct_values` | `5` | Minimum distinct segment values before a segment position can collapse. |
| `inference.normalization.entropy_threshold_bits` | `3.0` | Frequency-weighted entropy threshold for segment collapse. |
| `inference.normalization.reserved_segments_extra` | `[]` | Extra sensitive path segments that must never be collapsed. Extends the built-in reserved list; it cannot remove built-ins. |
| `inference.normalization.cardinality_cap_per_host` | `1000` | Per-host cap for distinct path families before overflow enters the `_other` tail bucket. |
| `inference.normalization.tail_promotion_block_pct` | `5.0` | Promotion block threshold when the `_other` tail bucket exceeds this percentage of host traffic. |

`pipelock learn observe --capture-dir <abs-dir>` uses the same runtime as `pipelock run --capture-output`; it validates the capture directory and writes hash-chained recorder JSONL. `pipelock learn compile --agent <name>` signs candidate contracts with the agent's keystore key; generate one first with `pipelock keygen <name>` or pass `--keystore` / `--compile-key-agent` for a different key. `pipelock learn shadow` requires `--contract-key` unless you explicitly use the diagnostics-only `--allow-unsigned-contract-for-diagnostics` flag.

For the end-to-end operator flow, see [Learn-and-Lock](guides/learn-and-lock.md).

### Live lock (runtime active-set)

The `learn` block above governs the observation, compile, and shadow phases. The `learn_lock` block governs the runtime path: which active-manifest directory the proxy watches, which roster pins the signing keys, and which mode the gate runs in. The two blocks are independent and can be enabled separately. `learn_lock` is opt-in and default-off; with it disabled the proxy never resolves an active contract and behaves identically to v2.3 (scanner-only).

```yaml
learn_lock:
  enabled: false
  mode: shadow
  store_dir: /var/lib/pipelock/contracts/active
  roster_path: /etc/pipelock/roster.json
  environment:
    id: production
    tenant: ""
    deployment_id: ""
  pinned_root_fingerprint: sha256:0000000000000000000000000000000000000000000000000000000000000000
  minimum_signatures: 1
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable the live-lock runtime. When false, the proxy ignores any active manifest and runs as scanner-only. When true, every other field below is required; partial config is rejected at startup so a half-wired lock never silently downgrades. |
| `mode` | `shadow` (when `enabled` is true) | Gate semantics: `live` enforces (block on contract deny), `shadow` evaluates and emits drift but never blocks, `capture` is silent. Empty or unknown values resolve to `shadow`, so a misconfigured lock fails toward observation rather than enforcement. |
| `store_dir` | `""` | Absolute path to the active-manifest store (the directory containing `active.json` plus the `history/` chain). Required when `enabled` is true. The runtime watches this directory via fsnotify with a 100ms debounce and a 2s maximum-debounce cap; reload is fail-closed on initial load and missed-promote recovery walks the accepted-history chain. |
| `roster_path` | `""` | Absolute path to the deployment-level roster JSON file naming which signing keys are authorised for which purposes. Required when `enabled` is true. The roster's root fingerprint must match `pinned_root_fingerprint`. |
| `environment.id` | `""` | Deployment environment identifier (e.g., `production`, `staging`). Required key when `enabled` is true; non-empty value enforced by validation. |
| `environment.tenant` | `""` | Tenant scope for contract activation. Required key when `enabled` is true; explicit empty string means intentionally unscoped tenant. |
| `environment.deployment_id` | `""` | Deployment scope identifier. Required key when `enabled` is true; explicit empty string means intentionally unscoped deployment axis. |
| `pinned_root_fingerprint` | `""` | Canonical sha256 fingerprint of the trust roster root key: literal `sha256:` prefix followed by 64 lowercase hex characters. Active manifests must chain to a roster signed by this root; mismatch fails closed at load. Required when `enabled` is true. |
| `minimum_signatures` | `1` | Minimum number of valid manifest signatures the loader accepts. Higher values require dual control on promotes. Defaults to `1` when `0` or negative. |

The `environment` block is a required nested mapping with all three keys present. The store compares the manifest's environment tuple against the loader's tuple by exact byte-equality, so a production cluster cannot accidentally enforce a staging contract and a multi-tenant deployment cannot enforce another tenant's contract. The old string form (`environment: production`) is rejected at config load with a migration error pointing at the nested form.

Mode resolution: `EffectiveMode()` reads the field above, returning `live`, `shadow`, or `capture`; any other value resolves to `shadow`. This means a typo in `mode` does not silently enable enforcement.

Restart vs reload: `enabled`, `store_dir`, `roster_path`, `environment.*`, and `pinned_root_fingerprint` require a process restart to change. `mode` and `minimum_signatures` are picked up by the next active-manifest reload.

## Health Watchdog

Wedge detection for `/health`. The watchdog is enabled by default and turns `/health` into a real liveness signal: HTTP 503 when scanner/config/session/kill-switch/watchdog health is bad, HTTP 200 when all tracked subsystems are healthy.

```yaml
health_watchdog:
  enabled: true
  interval_seconds: 2
  expose_subsystems: false
```

| Field | Default | Restart? | Description |
|-------|---------|----------|-------------|
| `enabled` | `true` | Yes | Enable internal wedge detection. Set false only if an external supervisor provides equivalent checks and you want legacy always-200 health behavior. |
| `interval_seconds` | `2` | Yes | Watchdog tick rate. The stale threshold is 3x this interval. |
| `expose_subsystems` | `false` | Yes | Include the per-subsystem boolean map in `/health` responses. The HTTP status still reflects wedges when false; only the detailed map is hidden. |

Omitting `health_watchdog`, setting it to YAML null, or leaving `enabled` blank all preserve the default `enabled: true`. Settings are operational and excluded from the canonical policy hash. Changing them on hot reload logs a warning and requires restart.

For response examples and Kubernetes probe guidance, see [Health Endpoint and Wedge-Detection Watchdog](guides/health.md).

## A2A Scanning (v2.1)

Scanning for Google A2A (Agent-to-Agent) protocol traffic. Detects A2A messages in forward proxy and MCP HTTP proxy paths. Applies field-aware content inspection with URL/text/secret classification.

```yaml
a2a_scanning:
  enabled: true
  action: block
  scan_agent_cards: true
  detect_card_drift: true
  session_smuggling_detection: true
  max_context_messages: 100
  max_contexts: 1000
  scan_raw_parts: true
  max_raw_size: 1048576
  # Agent Card signature verification (independent attestation). See below.
  require_signed_agent_cards: false
  trusted_agent_card_keys:
    - key_id: vendor-agent-v1
      public_key: pipelock-ed25519-public-v1...   # or raw hex
      allowed_origins:
        - https://agent.example.com
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable A2A protocol detection and scanning |
| `action` | `warn` | Action on findings: `block` or `warn` |
| `scan_agent_cards` | `true` | Scan Agent Card skill descriptions for injection |
| `detect_card_drift` | `true` | Detect Agent Card modification mid-session (rug-pull) |
| `session_smuggling_detection` | `true` | Track contextId to detect session smuggling |
| `max_context_messages` | `100` | Per-context message cap |
| `max_contexts` | `1000` | Total tracked contexts |
| `scan_raw_parts` | `true` | Decode and scan text-like `Part.raw` fields |
| `max_raw_size` | `1048576` | Max encoded size for `Part.raw` decoding (bytes) |
| `require_signed_agent_cards` | `false` | Treat an **unsigned** Agent Card as a finding (enforced at `action`). When `false`, unsigned cards keep their existing scan/drift behavior. |
| `trusted_agent_card_keys` | _(none)_ | Operator-pinned Ed25519 signing keys, each scoped to one or more origins. When non-empty, signed cards are cryptographically verified. |

A2A detection works on the forward proxy (CONNECT and plain HTTP) and MCP HTTP proxy paths. Agent Cards are scanned for skill description poisoning. Card drift detection tracks cards by URL + auth fingerprint and alerts on mid-session changes.

### Agent Card Signature Verification

An Agent Card may carry a JWS signature (RFC 7515) attesting that the card was published by a particular signer. Pipelock can independently verify that signature against keys **the operator trusts** — this is independent attestation, not vendor self-attestation. Detection and enforcement here are free-tier; no license is required.

Configure one or more `trusted_agent_card_keys`:

| Field | Required | Description |
|-------|----------|-------------|
| `key_id` | yes | Operator label, unique. Matched against the JWS `kid` header as a lookup **hint only** — never as authority. |
| `public_key` | yes | Ed25519 public key, `pipelock-ed25519-public-v1` form or raw hex. |
| `allowed_origins` | yes | Origins (`scheme://host[:port]`, no path) this key may sign cards for. A signature is only accepted on a card fetched from a listed origin. |

Behavior when at least one trusted key is configured:

- **Signed card, signature verifies** against a trusted key scoped to the card's origin → allowed; a positive attestation receipt is emitted (`a2a_card_signature` layer).
- **Signed card, no trusted-and-valid signature** (forged, wrong key, untrusted, substituted, origin mismatch, `alg: none`, non-EdDSA, empty/short signature, duplicate top-level keys, trailing tokens) → finding + receipt, **enforced at `a2a_scanning.action`**. Set `action: block` to reject. The preimage is the card with its `signatures` member removed, canonicalized per RFC 8785 (JCS).
- **Unsigned card** → existing scan/drift behavior, unless `require_signed_agent_cards: true`, in which case it is a finding enforced at `action`.

Notes and honest scope:

- Only `EdDSA` (Ed25519) signatures are verified. Cards signed with other algorithms cannot match a trusted key and therefore fail verification when verification is active.
- `require_signed_agent_cards: true` requires at least one trusted key (otherwise every card would be rejected); this combination is rejected at config load.
- Verification fires on every surface that delivers an Agent Card as a single body: forward proxy (plain HTTP and CONNECT/TLS-intercept) and MCP HTTP. A2A SSE streams carry task/message events, not Agent Cards, so there is no card-signature step on the SSE path.
- Revoking trust is a config edit: remove the key (or its origin) and reload. Hot reload swaps the trusted-key set atomically; a reduced key set logs a downgrade warning.

## MCP Binary Integrity (v2.1)

Pre-spawn SHA-256 hash verification for MCP server subprocesses. Prevents tampered or substituted binaries from being executed.

```yaml
mcp_binary_integrity:
  enabled: true
  manifest_path: /etc/pipelock/binary-manifest.json
  action: warn
  require_signature: false
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable binary hash verification before spawn |
| `manifest_path` | (required if enabled) | Path to JSON hash manifest |
| `action` | `warn` | Action on hash mismatch: `block` or `warn` |
| `require_signature` | `false` | Verify a detached manifest signature before using the manifest |
| `signature_path` | `<manifest_path>.sig` | Detached signature path when signatures are required |
| `trusted_signer` | (required when signatures are required) | Keystore identity used to verify the manifest signature |
| `keystore` | `~/.pipelock` | Keystore used for the trusted signer lookup |

The manifest is a JSON file mapping binary paths to expected SHA-256 hashes. Pipelock resolves shebangs and versioned interpreters (e.g., `python3.11`) before hashing. Generate, preflight, and sign the manifest with `pipelock mcp integrity manifest`; see [MCP integrity manifest tooling](cli/mcp-integrity.md).

## Taint-Aware Policy Escalation (v2.1)

Classifies each session by how recently it observed untrusted content and escalates scrutiny on protected operations. A session that just fetched a blog post cannot, without a trust override, then edit a file under `*/auth/*`. Runs across fetch, forward proxy, WebSocket, MCP stdio, MCP HTTP/SSE, and A2A.

```yaml
taint:
  enabled: true                        # default: true
  policy: balanced                     # strict, balanced, permissive (default: balanced)
  recent_sources: 10                   # bounded history of recent taint-raising events (default: 10)
  allowlisted_domains:                 # fetches from these domains do NOT raise session taint
    - "docs.anthropic.com"
    - "docs.github.com"
    - "developer.mozilla.org"
  protected_paths:                     # tainted sessions are blocked (or escalated) on these paths
    - "*/auth/*"
    - "*/security/*"
    - "*/.github/workflows/*"
    - "*/.env*"
    - "*/secrets*"
    - "*/policy*"
    - "*/sandbox*"
  elevated_paths:                      # tainted sessions trigger warn/ask on these paths
    - "*/config/*"
    - "*/middleware*"
  trust_overrides:                     # narrow, expiring exemptions for specific workflows
    - scope: "action"                  # config-file scopes are "action" or "source"
      source_match: "docs.example.com"
      action_match: "*/config/db.yaml"
      expires_at: "2026-06-01T00:00:00Z"
      granted_by: "platform-team"
      reason: "migration runbook"
    - scope: "source"
      source_match: "developer.mozilla.org"
      expires_at: "2026-06-01T00:00:00Z"
      granted_by: "platform-team"
      reason: "allowlisted reference workflow"
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `true` | Master switch. Omit to get the security default (enabled). |
| `policy` | string | `balanced` | `strict` is the most conservative taint policy, `balanced` is the security default, and `permissive` observes taint without changing enforcement. |
| `recent_sources` | int | `10` | How many recent taint sources to keep per session for receipt reporting. |
| `allowlisted_domains` | []string | 3 high-trust documentation domains | Responses from these domains do not raise taint. Supports `MatchDomain` wildcards. |
| `protected_paths` | []string | 7 patterns (see above) | Globs for file paths or tool args that are blocked for tainted sessions. |
| `elevated_paths` | []string | `*/config/*`, `*/middleware*` | Globs that trigger warn/ask rather than block. |
| `trust_overrides` | []object | empty | Narrow exemptions (see below). |

### Trust overrides

`trust_overrides` grants a scoped, time-limited exemption that lets a tainted session perform an otherwise-blocked action.

| Field | Description |
|-------|-------------|
| `scope` | `action` (requires `action_match`, optional `source_match`) or `source` (requires `source_match`, optional `action_match`). |
| `source_match` | Glob over the URL/domain that originated the taint. Required for `scope: source`; optional additional filter for `scope: action`. |
| `action_match` | Glob over the path or tool-arg being attempted. Required for `scope: action`; optional additional filter for `scope: source`. |
| `expires_at` | RFC3339 timestamp. After this instant the override is ignored. |
| `granted_by` | Free-text owner attribution. Appears in receipts. |
| `reason` | Free-text justification. Appears in receipts. |

Overrides are additive and never *remove* taint. Config-file overrides change the taint decision result to `allow` for the matching source or action while the session remains tainted. Receipts reflect that through `taint_decision_reason: "taint_trust_override"`. `authority_kind` continues to report the authority tier that backed the action (`user_broad`, `user_exact`, `operator_override`, and so on), not a synthetic `trust-override` value.

### Task boundaries

A **task boundary** scopes runtime trust overrides to an individual operation. Config-file `taint.trust_overrides` only support `action` and `source` scopes. Task-scoped overrides are runtime-only session overrides created by the session workflow or admin API. When a task ID is active, that runtime override applies only for the matching task. When the task completes or a new task starts, the override expires automatically, so the session does not carry override permissions into unrelated work.

Task boundaries are surfaced on every emitted receipt as `session_task_id`, and on the mediation envelope as the `task` wire field.

### Classification details

- **Taint level** is raised when a response arrives from a non-allowlisted domain, when an MCP tool returns content from an external source, or when prompt-injection signals fire on response content.
- **Action sensitivity** is derived from the target path (or tool-argument path) against `protected_paths` and `elevated_paths`.
- **Authority kind** records which authority tier gated the action: `external`, `policy`, `user_broad`, `user_exact`, or `operator_override`.

### Receipts

Every action taken under taint writes these fields to the signed receipt chain:

- `session_taint_level` (`trusted`, `internal_generated`, `allowlisted_reference`, `external_low_risk`, `external_untrusted`, `external_hostile`)
- `session_contaminated` (bool)
- `recent_taint_sources` (up to `recent_sources` entries)
- `session_task_id` and `session_task_label`
- `authority_kind`
- `taint_decision` and `taint_decision_reason`
- `task_override_applied` (runtime task-scoped overrides only)

The conformance suite (`sdk/conformance/`) includes golden fixtures for taint-escalated receipts so any third-party verifier can validate the taint fields byte-for-byte.

## Mediation Envelope (v2.1)

Attaches sideband metadata to proxied requests so downstream services know pipelock's verdict, action, actor identity, and receipt correlation ID without parsing logs.

HTTP requests get a `Pipelock-Mediation` header encoded as an RFC 8941 Structured Fields Dictionary. MCP requests get a `_meta["com.pipelock/mediation"]` map.

Only requests forwarded downstream carry the envelope. Blocked decisions never reach the backend, so use signed receipts rather than headers to audit blocks.

Minimal (unsigned) configuration:

```yaml
mediation_envelope:
  enabled: true
```

Signed configuration (Ed25519 HTTP Message Signatures per RFC 9421):

```yaml
mediation_envelope:
  enabled: true
  sign: true
  signing_key_path: /etc/pipelock/envelope-sign.key
  key_id: pipelock-envelope-2026-04
  signed_components:
    - "@method"
    - "@target-uri"
    - "pipelock-mediation"
    - "content-digest"
  created_skew_seconds: 60
  max_body_bytes: 1048576
  actor_format: spiffe
  trust_domain: prod.example
  signature_expires: 5m
  verify_inbound:
    enabled: true
    trust_list:
      - key_id: partner-pipelock-2026-04
        public_key: "64-char-hex-encoded-ed25519-public-key"
        well_known_url: "https://partner.example/.well-known/http-message-signatures-directory"
        trust_domains:
          - partner.example
    replay_cache:
      window: 5m
      max_entries: 10000
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable envelope injection on proxied requests |
| `sign` | `false` | Attach an RFC 9421 HTTP Message Signature alongside the envelope. Fail-closed at startup and on reload if the key is missing or unreadable. |
| `signing_key_path` | (none) | Path to the versioned pipelock Ed25519 private key used to sign the envelope. Required when `sign: true`. |
| `key_id` | `pipelock-mediation-v1` | Identifier emitted as `keyid` in the signature-input so verifiers can rotate keys. |
| `signed_components` | (see below) | Ordered list of RFC 9421 component identifiers covered by the signature. |
| `created_skew_seconds` | `60` | Clock-drift tolerance (seconds) accepted between signer and verifier. |
| `max_body_bytes` | `1048576` | Upper bound on the body drained for Content-Digest when body scanning is disabled. |
| `actor_format` | `spiffe` | Format for newly emitted `actor` values and inbound verification strictness. `spiffe` maps agent names to `spiffe://<trust_domain>/agent/<name>` and requires verified inbound actors to be valid SPIFFE IDs. `legacy` preserves the older free-form actor string and keeps inbound actor parsing permissive for migration. |
| `trust_domain` | `pipelock.local` | SPIFFE trust domain used when `actor_format: spiffe`. Must be a DNS-shaped label with no scheme, slashes, userinfo, or port. |
| `signature_expires` | `=replay_cache.window` | Per-signature lifetime emitted by the outbound signer (Go duration string). When `verify_inbound.enabled` is true, this must be `<= verify_inbound.replay_cache.window`; an explicit value larger than the window is rejected at startup so a captured signature can never outlive its replay-cache nonce. When inbound verification is disabled, any positive duration is accepted. Empty falls back to the configured replay-cache window. |
| `verify_inbound.enabled` | `false` | Require every inbound request on this listener to carry a valid Pipelock mediation signature before the inbound envelope headers are stripped. |
| `verify_inbound.trust_list` | `[]` | Trusted inbound signer keys. Each entry needs `key_id` and `public_key`; `well_known_url` documents the discovery source; optional `trust_domains` pins the key to one or more SPIFFE trust domains it is allowed to attest. |
| `verify_inbound.trust_list[].trust_domains` | `[]` | When non-empty, restricts which actor trust domains the trusted key may attest. An envelope whose actor's trust domain is not in this list fails verification. Empty preserves v2.4 migration behavior (any trust domain). Production deployments should pin each key to the partner's trust domain so a compromised partner cannot impersonate another peer. |
| `verify_inbound.replay_cache.window` | `5m` | Maximum nonce replay window for inbound signatures. The verifier rejects signatures whose declared lifetime (`expires - created`) exceeds `window + created_skew_seconds` so a captured signature cannot outlive its nonce in the cache. |
| `verify_inbound.replay_cache.max_entries` | `10000` | Bound on the in-process replay cache. Zero uses the default; set a positive value to override. |

Default `signed_components` covers `@method`, `@target-uri`, `pipelock-mediation`, and `content-digest`. Override only if your verifier requires a different component set.

When enabled, the envelope carries these wire fields:

| Wire Key | Field | Description |
|----------|-------|-------------|
| `v` | Version | Envelope schema version (currently `1`) |
| `act` | Action | Classified action type (`read`, `derive`, `write`, `delegate`, `authorize`, `spend`, `commit`, `actuate`, `unclassified`) |
| `vd` | Verdict | Enforcement verdict (`allow`, `block`, or `warn`) |
| `se` | SideEffect | Side effect description (empty when none) |
| `actor` | Actor | Agent identity string |
| `aa` | ActorAuth | Trust level of the actor field: `bound`, `matched`, `config-default`, or `self-declared` |
| `ph` | PolicyHash | First 16 bytes of SHA-256 of the active policy config (base64-encoded in MCP) |
| `rid` | ReceiptID | UUIDv7 receipt ID for correlation with flight recorder entries |
| `ts` | Timestamp | Unix timestamp (seconds) |
| `taint` | SessionTaint | Current session taint state (omitted when clean) |
| `task` | TaskID | Task boundary ID (omitted when no active task) |
| `auth` | AuthorityKind | Authority type backing this action (omitted when absent) |
| `authr` | AuthorityRef | Authority reference (omitted when absent) |
| `reauth` | RequiresReauth | `true` when the action requires re-authorization (omitted when false) |

**Inbound stripping:** Pipelock strips any inbound `Pipelock-Mediation` header and any `pipelock`-prefixed members from `Signature` and `Signature-Input` headers before processing. This prevents agents or upstream proxies from forging mediation metadata. The strip path parses `Signature` / `Signature-Input` as RFC 8941 dictionaries via httpsfv so commas inside quoted parameter values do not corrupt surviving members.

**Redirect refresh:** On every allowed redirect through the fetch or forward proxy, pipelock rebuilds the `Pipelock-Mediation` header on the redirected request so `@target-uri`, `hop`, `ph`, and `action` reflect the redirected leg. Stale `Content-Digest` is dropped and the signature is re-attached when signing is enabled. The `hop` dictionary key counts refresh hops; original requests omit it.

**Reverse-proxy signing:** Envelope signing runs in an `http.RoundTripper` wrapper installed on `httputil.ReverseProxy.Transport`, so `@target-uri` reflects the post-Director upstream URL rather than the inbound relative path.

**Inbound verification:** When `verify_inbound.enabled` is true, Pipelock verifies the inbound `Pipelock-Mediation` header and matching RFC 9421 signature against `trust_list` before stripping those headers and forwarding the request. Missing signatures fail before any request body is buffered. Signatures must include `created`, `expires`, and `nonce`; the nonce is stored in a bounded in-process replay cache. The verifier additionally enforces three federation guards: (1) the signature's declared lifetime is capped at `replay_cache.window + created_skew_seconds` so a captured signature cannot outlive its nonce in the cache, (2) when a trusted key declares `trust_domains`, the SPIFFE trust domain in the envelope's `actor` must match — preventing a compromised partner key from impersonating another peer, and (3) SPIFFE actors are parsed strictly (no userinfo, no port in trust domain, no `..` or empty path segments) so an actor allowlist comparison cannot be bypassed via traversal or smuggled authority components.

**Well-known key directory:** A signing proxy exposes its current envelope public key at `/.well-known/http-message-signatures-directory` with short cache headers. Unsigned envelope configurations return 404.

## Browser Shield

Browser Shield is opt-in. By default, `browser_shield.enabled` is `false`.
The other Browser Shield defaults are populated so operators can enable the
feature with a small config change instead of defining every rewrite knob.

Browser Shield rewrites shieldable HTML, JavaScript, and SVG responses before
they reach the agent browser. It strips browser-extension probes, hidden
agent-trap content, tracking pixels/beacons, and SVG active content covered by
the shield pipeline. It does not attempt to solve CAPTCHAs, bypass bot
management, forge browser integrity telemetry, or make unsupported websites
accessible to automation.

```yaml
browser_shield:
  enabled: true
  strictness: standard
  max_shield_bytes: 5242880
  oversize_action: scan_head
  exempt_domains:
    - challenges.cloudflare.com
    - developer.mozilla.org
    - docs.github.com
    - github.dev
    - go.dev
    - pkg.go.dev
    - vscode.dev
    - hcaptcha.com
    - www.recaptcha.net
  strip_extension_probing: true
  strip_hidden_traps: true
  strip_tracking_pixels: true
  inject_fingerprint_shims: false
  tracking_domains: []
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | bool | `false` | Master switch for response rewriting |
| `strictness` | string | `standard` | Rewrite posture: `minimal`, `standard`, or `aggressive` |
| `max_shield_bytes` | int | `5242880` (5 MiB) | Maximum shieldable response body size before `oversize_action` applies |
| `oversize_action` | string | `scan_head` | Oversize behavior: `block`, `scan_head`, or `warn`; `warn` is only valid with `strictness: minimal` |
| `exempt_domains` | []string | challenge providers plus common developer documentation/browser IDE hosts | Hostnames that bypass Browser Shield entirely |
| `strip_extension_probing` | bool | `true` | Remove browser-extension probing URLs and runtime probes |
| `strip_hidden_traps` | bool | `true` | Remove hidden prompt-trap DOM content |
| `strip_tracking_pixels` | bool | `true` | Remove tracking pixels and beacon-style calls |
| `inject_fingerprint_shims` | bool | `false` | Inject browser fingerprinting defense shims where supported |
| `tracking_domains` | []string | `[]` | Additional tracking hostnames for the shield engine |

For production soak, start with:

```yaml
browser_shield:
  enabled: true
  strictness: minimal
  oversize_action: scan_head
```

Then monitor shield receipts, response rewrite metrics, adaptive session score
movement, block deltas, and application breakage before moving to the standard
fail-closed posture. Use `oversize_action: warn` only for short, explicitly
scoped diagnostics because it returns oversized shieldable bodies unchanged.

## Media Policy (v2.1)

Controls how media responses (image, audio, video Content-Type) are handled. Pipelock cannot inspect pixels or audio frames for embedded instructions, so this section reduces exposure by stripping unused media types, enforcing size limits, surgically removing metadata from allowed images, and emitting exposure events.

```yaml
media_policy:
  enabled: true
  strip_images: false
  strip_audio: true
  strip_video: true
  allowed_image_types:
    - image/png
    - image/jpeg
  strip_image_metadata: true
  max_image_bytes: 5242880
  log_media_exposure: true
```

All boolean fields use nil-means-security-default semantics: omitting a field from YAML produces the protective default, not the Go zero value.

| Field | Type | Default (when omitted) | Description |
|-------|------|------------------------|-------------|
| `enabled` | *bool | `true` | Master switch for media policy enforcement |
| `strip_images` | *bool | `false` | Reject all `image/*` responses |
| `strip_audio` | *bool | `true` | Reject all `audio/*` responses |
| `strip_video` | *bool | `true` | Reject all `video/*` responses |
| `allowed_image_types` | []string | `["image/png", "image/jpeg"]` | Image media types allowed when `strip_images` is false |
| `strip_image_metadata` | *bool | `true` | Remove EXIF/XMP/IPTC/ICC metadata from allowed images |
| `max_image_bytes` | int64 | `5242880` (5 MiB) | Reject images larger than this before parsing (decompression bomb defense) |
| `log_media_exposure` | *bool | `true` | Emit `media_exposure` events for allowed media responses |

### Metadata stripping

For JPEG images: strips APP1 (EXIF, XMP), APP2 (ICC profile, FlashPix), and APP13 (IPTC, Photoshop) marker segments. APP0 (JFIF header) is preserved. Pixel data is never decoded or re-encoded. Bytes after the canonical EOI marker are truncated and the cleaned image is forwarded instead of failing closed.

For PNG images: strips tEXt, iTXt, zTXt (text metadata), and eXIf (EXIF) chunks. All other chunks (IHDR, IDAT, PLTE, tRNS, IEND) pass through with their original CRCs. Bytes after the canonical IEND chunk are truncated and the cleaned image is forwarded instead of failing closed.

### SVG active content hardening

SVG (`image/svg+xml`) is never in the allowed image types list. SVG is active content handled by the browser shield pipeline, which strips `<foreignObject>` elements (XSS/injection vector), `on*` event handler attributes, external `xlink:href` and `href` references, hidden `<text>` elements (invisible prompt injection), `<script>` blocks, and animation injection (`<set>`/`<animate>` targeting href).

### Validation

- `allowed_image_types` entries must be `image/*` media types with concrete subtypes (no wildcards)
- `image/svg+xml` is rejected in `allowed_image_types` (SVG is active content)
- `max_image_bytes` must be non-negative (0 means use the 5 MiB default)
- Validation runs regardless of whether `enabled` is true, so re-enabling on reload cannot introduce malformed values

## Validation Rules

The following are enforced at startup:

- Strict mode requires a non-empty `api_allowlist`
- All DLP and response patterns must compile as valid regex
- `secrets_file` must exist and not be world-readable (mode 0600 or stricter)
- MCP tool policy requires at least one rule if enabled
- Kill switch `api_listen` must differ from the main proxy listen address
- WebSocket `strip_compression` must be true when scanning is enabled
- Reverse proxy `upstream` must be a valid http:// or https:// URL when enabled

## Reverse Proxy

Generic HTTP reverse proxy mode that sits in front of any service and scans traffic bidirectionally.

```yaml
reverse_proxy:
  enabled: false
  listen: ":8890"
  upstream: "http://localhost:7899"
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable reverse proxy mode |
| `listen` | (required) | Listen address for the reverse proxy |
| `upstream` | (required) | Upstream service URL to forward to |

### Submit Profile

`profile: submit` narrows a reverse-proxy listener for controlled submission endpoints. It preserves the generic reverse-proxy body and response scanning, then adds method and path gates, a trusted upstream declaration, an explicit body cap, a per-request timeout, and a full upstream URL scan before forwarding.

```yaml
reverse_proxy:
  enabled: true
  listen: "127.0.0.1:8890"
  upstream: "https://submit.example.com:443"
  profile: submit
  allowed_methods: ["POST"]
  allowed_paths:
    - exact: "/v1/batch"
  trusted_upstream:
    host: "submit.example.com"
    port: 443
    reason: "submission endpoint"
    added: "2026-05-26"
    expires: "2026-08-24"
  max_body_bytes: 1048576
  request_timeout_seconds: 10
```

| Field | Default | Description |
|-------|---------|-------------|
| `profile` | `""` | Empty keeps generic reverse-proxy behavior. `submit` enables the constrained submission gate. |
| `allowed_methods` | `["POST"]` | HTTP methods allowed by the submit listener. Values must be known methods. |
| `allowed_paths` | required | Exact canonical paths allowed by the submit listener. Entries must start with `/`; encoded dot, slash, backslash, semicolon path parameters, and non-canonical request paths are rejected. |
| `trusted_upstream` | required | Auditable host+port trust declaration. `host` and `port` must exactly match `upstream`; IP literals are rejected; `reason` and `added` are required; expired `expires` dates fail config load. |
| `max_body_bytes` | required | Positive listener body cap. The effective cap is the smaller of this value and `request_body_scanning.max_body_bytes`. |
| `request_timeout_seconds` | required | Positive total request timeout for the submit listener, including scanning and upstream forwarding. |

`profile: submit` dials the upstream through the same SSRF-safe dial path the fetch and forward proxies use: DNS is resolved and every resolved IP is validated against the internal CIDR blocks before the connection is made, closing the DNS-rebinding window. Generic reverse-proxy mode (no `profile`) keeps the default dialer, since the operator is presumed to have already chosen that upstream. In addition, the submit listener constrains the destination to the exact configured host+port and runs the upstream URL through the scanner before forwarding.

### CLI flags

```bash
pipelock run --reverse-proxy --reverse-upstream http://localhost:7899 --reverse-listen :8890
```

### Scanning behavior

- **Request bodies:** Scanned for DLP patterns (secret exfiltration) using the `request_body_scanning` config
- **Request headers:** Scanned when `request_body_scanning.scan_headers` is enabled
- **Response bodies:** Scanned for prompt injection using the `response_scanning` config
- **Binary content:** Image, audio, and video content types skip scanning
- **Compressed bodies:** Fail-closed (blocked) on both request and response
- **Oversized bodies:** Bodies larger than 1MB pass through without scanning

### Hot-reload

The `listen`, `enabled`, and `upstream` fields cannot be changed via hot-reload (requires restart). All other scanning config (DLP patterns, response patterns, action, header mode) updates on reload.

## Live lock trust topology

The live-lock runtime activates per-agent behavioural contracts only after their candidate is signed by an operator-controlled activation key, and trusts that key only because the deployment-local roster names it under a fleet-root signature. Bootstrapping the roster is a one-time operator workflow.

Runtime config uses a nested environment tuple. All three keys are required when `learn_lock.enabled` is true. Use explicit empty strings for `tenant` or `deployment_id` only when the deployment is intentionally unscoped on that axis.

```yaml
learn_lock:
  enabled: true
  mode: shadow
  store_dir: /var/lib/pipelock/contracts/active
  roster_path: /etc/pipelock/roster.json
  environment:
    id: production
    tenant: acme
    deployment_id: prod-us-1
  pinned_root_fingerprint: sha256:<64 lowercase hex>
  minimum_signatures: 1
```

The old string form, `learn_lock.environment: production`, is not accepted by the v2.4 runtime. Migrate it to the nested block before enabling live-lock with a v2.4 binary.

### Generating the roster

Two commands compose the trust topology:

- `pipelock signing key generate --purpose <purpose> --out <path>` writes a new Ed25519 keypair to a 0o600 JSON file with explicit purpose binding. Used for deployment-level keys (root, activation, recovery).
- `pipelock signing roster build --root <root.json> --include id=,key=,purpose=,...` composes a signed `RosterEnvelope` from the root key plus a list of public-key includes. The output JSON is what `learn_lock.roster_path` consumes and what `pipelock signing roster verify` accepts.

End-to-end example:

```bash
# Generate the fleet root.
pipelock signing key generate \
  --purpose roster-root \
  --out /etc/pipelock/keys/fleet-root.json

# Generate the operator activation key.
pipelock signing key generate \
  --purpose contract-activation-signing \
  --out /etc/pipelock/keys/activation.json \
  --id activation-primary

# Per-agent compile keys (existing command, agent-scoped keystore).
pipelock keygen agent-a
pipelock keygen agent-b

# Compose and sign the roster.
pipelock signing roster build \
  --root /etc/pipelock/keys/fleet-root.json \
  --include id=activation-primary,key=/etc/pipelock/keys/activation.json,purpose=contract-activation-signing,role=operator \
  --include id=compile-agent-a,key=$HOME/.pipelock/agents/agent-a/id_ed25519.pub,purpose=contract-compile-signing \
  --include id=compile-agent-b,key=$HOME/.pipelock/agents/agent-b/id_ed25519.pub,purpose=contract-compile-signing \
  --data-class internal \
  --out /etc/pipelock/roster.json

# Verify the signed roster against the printed root fingerprint.
pipelock signing roster verify \
  --path /etc/pipelock/roster.json \
  --root-fingerprint sha256:<from-key-generate-output>
```

The fingerprint printed by `pipelock signing key generate --purpose roster-root` is what `learn_lock.pinned_root_fingerprint` consumes. Pin it once at deployment time; the runtime rejects any roster that does not chain back to that exact value.

### Refusal cases

`pipelock signing roster build` refuses with a typed error when:

- two `--include` entries share the same `id`
- an `--include` `purpose=` flag disagrees with the file's `purpose` field (only enforced when the include points at a JSON keyFile; agent keystore `.pub` files have no purpose binding and rely on the operator-supplied flag)
- the `--data-class` value is not in `{public, internal, sensitive}` (`regulated` is rejected explicitly)
- an include passes `status=root` (the root entry is auto-included from `--root`)
- the `--root` file's purpose is not `roster-root`
- the output file already exists and `--force` is not set

All key files are written with `0o600` permission via atomic temp-file-then-rename, so a partial write cannot leave a malformed key on disk.
