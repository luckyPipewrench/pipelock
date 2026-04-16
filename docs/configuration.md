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
| `monitoring.subdomain_entropy_exclusions` | `[]` | Domains excluded from subdomain and path entropy checks (query entropy still checked) |

**Entropy guidance:**
- English text: 3.5-4.0 bits/char
- Hex/commit hashes: ~4.0
- Base64-encoded data: 4.0-4.5
- Random/encrypted: 5.5-8.0

The default threshold (4.5) allows commit hashes and base64-encoded filenames while flagging encrypted blobs. Lower it (3.5) for strict mode. Raise it (5.0) for development environments where base64 URLs are common.

**Subdomain entropy exclusions** skip subdomain and path entropy checks for specific domains, but query parameter entropy is still checked. Useful for APIs that embed tokens in URL paths (e.g., Telegram bot API). Supports wildcard matching (`*.example.com`).

```yaml
fetch_proxy:
  monitoring:
    subdomain_entropy_exclusions:
      - "api.telegram.org"
```

## Forward Proxy

Standard HTTP CONNECT tunneling. Agents set `HTTPS_PROXY=http://127.0.0.1:8888` and all traffic flows through pipelock. Zero code changes needed.

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
| `max_tunnel_seconds` | `300` | No | Max tunnel lifetime |
| `idle_timeout_seconds` | `120` | No | Kill idle tunnels |
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
    - "*.anthropic.com"
  cert_ttl: "24h"
  cert_cache_size: 10000
  max_response_bytes: 5242880    # 5MB; responses larger than this are blocked
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable TLS interception on CONNECT tunnels |
| `ca_cert` | `""` | Path to CA certificate PEM. Empty resolves to `~/.pipelock/ca.pem` |
| `ca_key` | `""` | Path to CA private key PEM. Empty resolves to `~/.pipelock/ca-key.pem` |
| `passthrough_domains` | `[]` | Domains to splice (pass through without interception). Supports `*.example.com` wildcards (also matches apex `example.com`). |
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

**Best practice -- package registries and LLM providers:** Always add package registries (npm, pypi, Go proxy) and LLM API endpoints to `passthrough_domains`, not just `exempt_domains`. Using `exempt_domains` alone still MITM-s the connection, which breaks large downloads (response size limit), causes TLS handshake errors with clients that reject the generated certificate, and wastes CPU on cert generation for traffic you don't intend to scan. Passthrough skips interception entirely.

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

Scans request bodies and headers on the forward proxy path for secret exfiltration. Catches secrets in POST/PUT bodies and Authorization/Cookie headers that bypass URL-level scanning.

**Scope:** Forward HTTP proxy (`HTTPS_PROXY` absolute-URI requests), fetch handler headers, and intercepted CONNECT tunnels (when `tls_interception.enabled` is true).

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
| `enabled` | `false` | Enable request body and header DLP scanning |
| `action` | `warn` | `warn` logs only, `block` rejects (requires enforce mode) |
| `max_body_bytes` | `5242880` | Max body size to buffer; bodies exceeding this are always blocked (fail-closed) |
| `scan_headers` | `true` | Scan request headers for DLP patterns |
| `header_mode` | `sensitive` | `sensitive`: scan only listed headers. `all`: scan all headers except ignore list |
| `sensitive_headers` | (see above) | Headers to scan in `sensitive` mode |
| `ignore_headers` | (hop-by-hop + structural) | Headers to skip in `all` mode |

**Content-type dispatch:** JSON bodies have string values extracted recursively. Form-urlencoded bodies are parsed as key-value pairs. Multipart form data scans all part headers plus all part bodies regardless of declared `Content-Type` (max 100 parts), and decodes `Content-Transfer-Encoding: base64` / `quoted-printable` before scanning. Text/* and XML bodies are scanned as raw text. Unknown content types get a fallback raw-text scan (never skipped, preventing `Content-Type` spoofing bypass).

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

**Note on `scan_headers`:** The config default is `true`, but omitting the field from your YAML file gives `false` (Go's zero value overrides the default). Always set `scan_headers: true` explicitly in your config if you want header scanning enabled.

## WebSocket Proxy

Bidirectional WebSocket scanning via `/ws?url=ws://upstream:9090/path`. Text frames are scanned through the full DLP + injection pipeline. Fragment reassembly handles split messages.

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
| `max_connection_seconds` | `3600` | No | Max connection lifetime |
| `idle_timeout_seconds` | `300` | No | Idle timeout |
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
| `include_defaults` | `true` | Merge your patterns with the 48 built-in patterns |
| `patterns` | 48 built-in | DLP credential detection patterns |
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

### Built-in DLP Patterns (48)

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
| HashiCorp Vault Token | `hvs.` | critical |
| Vercel Token | `vercel_\|vc[piark]_` | critical |
| Supabase Service Key | `sb_secret_` | critical |
| npm Token | `npm_` | critical |
| PyPI Token | `pypi-` | critical |
| Linear API Key | `lin_api_` | high |
| Notion API Key | `ntn_` | high |
| Sentry Auth Token | `sntrys_` | high |
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
  patterns:
    - name: "Custom Injection"
      regex: 'override system prompt'
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable response scanning |
| `action` | `"warn"` | block, strip, warn, or ask (HITL) |
| `ask_timeout_seconds` | `30` | Timeout for human-in-the-loop approval |
| `include_defaults` | `true` | Merge with 25 built-in patterns |
| `exempt_domains` | `[]` | Hosts to skip injection scanning for (DLP still applies on outbound). Supports `*.example.com` wildcards (also matches the apex `example.com`). |
| `patterns` | 25 built-in | Injection and state/control poisoning patterns |

**Built-in patterns (25):** 13 prompt injection patterns (jailbreak phrases, system overrides, role overrides, instruction manipulation, encoded payloads, tool invocation commands, authority escalation), 6 state/control poisoning patterns (credential solicitation, credential path directives, auth material requirements, memory persistence directives, preference poisoning, silent credential handling), and 4 CJK-language override patterns (Chinese, Japanese, Korean instruction overrides and jailbreak mode). All patterns use DOTALL mode to match across newlines in multiline tool output.

**Actions:**
- **block:** reject the response entirely, agent gets an error
- **strip:** redact matched text, return cleaned content
- **warn:** log the match, return content unchanged
- **ask:** pause and prompt the operator for approval (requires TTY)

**Exempt domains:** LLM provider APIs (OpenAI, Anthropic, etc.) return instruction-like text as part of normal operation, which can trigger false positives. Use `exempt_domains` to skip injection scanning for trusted providers. DLP scanning on the outbound request still runs — only the response injection scan is skipped. Applies to fetch proxy, forward proxy, CONNECT (TLS intercept), WebSocket, and reverse proxy. Does not affect MCP response scanning (tool results use a separate trust model).

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

Session profiling detects domain bursts (many unique domains in a short window). When the burst threshold is crossed, the anomaly is signaled once per window with the configured score. Subsequent requests in the same window still trigger the configured `anomaly_action` (block or warn) but do not add further adaptive score, preventing burst detection from driving sessions to critical on its own.

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

The `{key}` parameter is URL-encoded. For example, `my-agent|10.0.0.1` becomes `my-agent%7C10.0.0.1`.

**Reset scope:** identity-family scoped. Resetting a session clears the session's threat score, escalation level, and block_all flag. It also clears shared IP-level burst tracking for the client IP and cross-request exfiltration (CEE) state. Other sessions on the same IP will have their burst state cleared as a side effect.

**Rate limiting:** every mutating action (`reset`, `airlock`, `task`, `trust`, `terminate`) and every detail lookup (`inspect`, `explain`) is rate-limited to 10 requests per minute per action. Each action tracks its own sliding-window counter so abuse of one endpoint cannot starve another — an operator can still hit `/reset` or `/airlock` during incident response even if `/task` or `/trust` is under load. Only `GET /api/v1/sessions` (the list endpoint) is unbounded; it is used as the entry point for recovery tooling and has no destructive side effect. Responses that hit the limit return `429 Too Many Requests` with `Retry-After: 60`.

Sessions are classified as `identity` (operator-targetable, e.g. `my-agent|10.0.0.1`) or `invocation` (internal MCP sessions, e.g. `mcp-stdio-42`). Only identity sessions can be reset, mutated, or terminated.

**Operator CLI:** the session admin API is also exposed through `pipelock session <subcommand>` for interactive recovery. See [cli/session.md](cli/session.md) for the full operator reference.

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
| `custom_patterns` | `[]` | Custom attack sequences |

Ships with 10 built-in patterns covering reconnaissance, credential theft, data staging, persistence, and exfiltration chains.

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
  pre_push_scan: true
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable git protection |
| `allowed_branches` | `["feature/*", "fix/*", "main", "master"]` | Branch name patterns |
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

  rook:
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
```

### Key Verification

Official release builds embed the signing public key at compile time via ldflags. The embedded key takes priority over `license_public_key` and cannot be overridden by config, preventing self-signing bypasses. The `license_public_key` config field is only used in development builds where no key is embedded.

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

All kinds are enabled by default. Set any to `false` to disable. Full API reference: [docs/scan-api.md](scan-api.md).

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
    - "."
  scan_content: true
  ignore_patterns:
    - "node_modules/**"
    - ".git/**"
    - "*.o"
    - "*.so"
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable filesystem monitoring. Opt-in. |
| `watch_paths` | `[]` | Directories to monitor recursively. Relative paths are resolved against the config file directory (not CWD). Required when enabled. |
| `scan_content` | `true` | Run DLP scanner on modified file content. |
| `ignore_patterns` | `[]` | Glob patterns for files and directories to skip. |

File sentry is alert-only in the current release. Findings are reported as stderr warnings and Prometheus metrics (`pipelock_file_sentry_findings_total`). Structured audit log emission (`file_sentry_dlp` event type) is defined but not yet wired to the webhook/syslog pipeline. On Linux, process lineage tracking attributes file writes to the agent's process tree via `PR_SET_CHILD_SUBREAPER` and `/proc` walking.

Files larger than 10MB are skipped. Write events are debounced (50ms quiet window) to avoid scanning partial writes.

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
- **Network namespaces:** Agent runs in an isolated network namespace. All traffic is kernel-forced through pipelock's bridge proxy. Raw socket bypass is impossible. For MCP (stdio), no network is needed.
- **Seccomp BPF:** Syscall allowlist (~130 safe syscalls for Go/Python/Node.js). Blocks ptrace, mount, module loading, kexec (KILL). io_uring returns EPERM (allows runtimes like Node.js 22 to fall back to epoll). Clone flags filtered to prevent namespace escape.

**Usage:**
```bash
# Sandbox an MCP server
pipelock mcp proxy --sandbox --config pipelock.yaml -- npx server

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

## Config Audit Scoring (v2.0)

Score a pipelock configuration for security posture. Evaluates 12 categories and produces a 0-100 score with letter grade and actionable recommendations.

```bash
pipelock audit score --config pipelock.yaml
pipelock audit score --config pipelock.yaml --json
```

**Categories scored:** DLP (pattern count, env scanning, entropy), response scanning (enabled, action, pattern count), MCP tool scanning, MCP tool policy (rule count, blocking rules, overpermission), MCP input scanning, MCP session binding, kill switch (source count), enforcement mode, domain blocklist, adaptive enforcement, tool chain detection, sandbox.

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
| `signing_key_path` | (empty) | Ed25519 private key for action receipts. When set, every proxy decision produces a signed receipt. Generate a key with `pipelock keygen <name>`. Verify receipts with `pipelock verify-receipt <file>`. Hot-reloadable: add, remove, or rotate keys via SIGHUP. |
| `max_entries_per_file` | `10000` | Rotate to a new file after this many entries |
| `raw_escrow` | `false` | Encrypt raw (pre-redaction) detail to sidecar files |
| `escrow_public_key` | (required if raw_escrow) | X25519 public key (hex) for escrow encryption |

Evidence files are named `evidence-<session>-<seq>.jsonl`. Each entry contains a SHA-256 hash of its predecessor, forming a tamper-evident chain. Action receipts form a second chain within the evidence log (each receipt links to the previous receipt via `chain_prev_hash`). Breaking either chain is detectable by `pipelock integrity verify`.

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
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable A2A protocol detection and scanning |
| `action` | `block` | Action on findings: `block` or `warn` |
| `scan_agent_cards` | `true` | Scan Agent Card skill descriptions for injection |
| `detect_card_drift` | `true` | Detect Agent Card modification mid-session (rug-pull) |
| `session_smuggling_detection` | `true` | Track contextId to detect session smuggling |
| `max_context_messages` | `100` | Per-context message cap |
| `max_contexts` | `1000` | Total tracked contexts |
| `scan_raw_parts` | `true` | Decode and scan text-like `Part.raw` fields |
| `max_raw_size` | `1048576` | Max encoded size for `Part.raw` decoding (bytes) |

A2A detection works on the forward proxy (CONNECT and plain HTTP) and MCP HTTP proxy paths. Agent Cards are scanned for skill description poisoning. Card drift detection tracks cards by URL + auth fingerprint and alerts on mid-session changes.

## MCP Binary Integrity (v2.1)

Pre-spawn SHA-256 hash verification for MCP server subprocesses. Prevents tampered or substituted binaries from being executed.

```yaml
mcp_binary_integrity:
  enabled: true
  manifest_path: /etc/pipelock/binary-manifest.json
  action: warn
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable binary hash verification before spawn |
| `manifest_path` | (required if enabled) | Path to JSON hash manifest |
| `action` | `warn` | Action on hash mismatch: `block` or `warn` |

The manifest is a JSON file mapping binary paths to expected SHA-256 hashes. Pipelock resolves shebangs and versioned interpreters (e.g., `python3.11`) before hashing.

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
  created_skew_seconds: 30
  max_body_bytes: 1048576
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable envelope injection on proxied requests |
| `sign` | `false` | Attach an RFC 9421 HTTP Message Signature alongside the envelope. Fail-closed at startup and on reload if the key is missing or unreadable. |
| `signing_key_path` | (none) | Path to the versioned pipelock Ed25519 private key used to sign the envelope. Required when `sign: true`. |
| `key_id` | (none) | Identifier emitted as `keyid` in the signature-input so verifiers can rotate keys. Required when `sign: true`. |
| `signed_components` | (see below) | Ordered list of RFC 9421 component identifiers covered by the signature. |
| `created_skew_seconds` | `30` | Clock-drift tolerance (seconds) accepted between signer and verifier. |
| `max_body_bytes` | `1048576` | Upper bound on the body drained for Content-Digest when body scanning is disabled. |

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

**Deferred for follow-up:** SPIFFE actor format and well-known envelope-key discovery (`/.well-known/pipelock-envelope-keys`). Until those ship, distribute the envelope public key out-of-band alongside the receipt public key and rotate via `key_id`.

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

For JPEG images: strips APP1 (EXIF, XMP), APP2 (ICC profile, FlashPix), and APP13 (IPTC, Photoshop) marker segments. APP0 (JFIF header) is preserved. Pixel data is never decoded or re-encoded.

For PNG images: strips tEXt, iTXt, zTXt (text metadata), and eXIf (EXIF) chunks. All other chunks (IHDR, IDAT, PLTE, tRNS, IEND) pass through with their original CRCs.

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
