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

Supports wildcards (`*.example.com` matches `api.example.com`). Case-insensitive.

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

**Entropy guidance:**
- English text: 3.5-4.0 bits/char
- Hex/commit hashes: ~4.0
- Base64-encoded data: 4.0-4.5
- Random/encrypted: 5.5-8.0

The default threshold (4.5) allows commit hashes and base64-encoded filenames while flagging encrypted blobs. Lower it (3.5) for strict mode. Raise it (5.0) for development environments where base64 URLs are common.

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
| `passthrough_domains` | `[]` | Domains to splice (pass through without interception). Supports `*.example.com` wildcards. |
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

**Passthrough domains:** Domains in `passthrough_domains` are spliced (bidirectional byte copy) without interception, preserving end-to-end TLS. Use this for domains where certificate pinning prevents interception or where you trust the destination. Supports exact match and wildcard prefix (`*.example.com` matches `sub.example.com`).

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

**Content-type dispatch:** JSON bodies have string values extracted recursively. Form-urlencoded bodies are parsed as key-value pairs. Multipart form data has text fields extracted (binary parts skipped, max 100 parts). Text/* and XML bodies are scanned as raw text. Unknown content types get a fallback raw-text scan (never skipped, prevents Content-Type spoofing bypass).

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
```

| Field | Default | Description |
|-------|---------|-------------|
| `scan_env` | `true` | Scan environment variables for leaked values |
| `secrets_file` | `""` | Path to file with known secrets (one per line) |
| `min_env_secret_length` | `16` | Min env var value length to consider |
| `include_defaults` | `true` | Merge your patterns with the 22 built-in patterns |
| `patterns` | 22 built-in | DLP credential detection patterns |

### Pattern Merging

When `include_defaults` is true (default), your patterns are merged with the built-in set by name. If you define a pattern with the same name as a built-in, yours overrides it. New built-in patterns added in future versions are automatically included.

Set `include_defaults: false` to use only your patterns.

### Built-in DLP Patterns (22)

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
| GitHub Token | `gh[pousr]_` | critical |
| GitHub Fine-Grained PAT | `github_pat_` | critical |
| Slack Token | `xox[bpras]-` | critical |
| Slack App Token | `xapp-` | critical |
| Discord Bot Token | `[MN][A-Za-z0-9]{23,}` | critical |
| Twilio API Key | `SK[a-f0-9]{32}` | critical |
| SendGrid API Key | `SG.` | critical |
| Mailgun API Key | `key-[a-zA-Z0-9]{32}` | critical |
| JWT Token | `ey...\..*\.` | high |
| Private Key Header | `-----BEGIN.*PRIVATE KEY-----` | critical |
| Social Security Number | `\b\d{3}-\d{2}-\d{4}\b` | critical |
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

## Response Scanning

Scans fetched content for prompt injection before returning to the agent. Uses a 6-pass normalization pipeline: zero-width stripping, word boundary reconstruction, leetspeak folding, optional-whitespace matching, vowel folding, and encoding detection.

```yaml
response_scanning:
  enabled: true
  action: warn                  # block, strip, warn, or ask
  ask_timeout_seconds: 30       # HITL approval timeout
  include_defaults: true
  patterns:
    - name: "Custom Injection"
      regex: 'override system prompt'
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable response scanning |
| `action` | `"warn"` | block, strip, warn, or ask (HITL) |
| `ask_timeout_seconds` | `30` | Timeout for human-in-the-loop approval |
| `include_defaults` | `true` | Merge with 13 built-in injection patterns |
| `patterns` | 13 built-in | Injection detection patterns |

**Actions:**
- **block:** reject the response entirely, agent gets an error
- **strip:** redact matched text, return cleaned content
- **warn:** log the match, return content unchanged
- **ask:** pause and prompt the operator for approval (requires TTY)

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

Scans `tools/list` responses for poisoned tool descriptions and detects mid-session description changes (rug pulls).

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

Pre-execution rules that block or warn before tool calls reach the MCP server. Ships with 9 built-in rules covering destructive operations, credential access, network exfiltration, and encoded command execution.

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
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable tool policy |
| `action` | `"warn"` | Default action for rules without override |
| `rules` | 9 built-in | Policy rule list |

**Rule fields:**
- `name:` rule identifier
- `tool_pattern:` regex matching tool name
- `arg_pattern:` regex matching argument values (optional)
- `action:` per-rule override (warn or block)

Shell obfuscation detection is built-in: backslash escapes, `$IFS` substitution, brace expansion, and octal/hex escapes are decoded before matching.

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

Per-session threat score that accumulates across scanner hits and decays on clean requests. When the score exceeds the threshold, enforcement escalates (warn becomes block).

```yaml
adaptive_enforcement:
  enabled: true
  escalation_threshold: 5.0
  decay_per_clean_request: 0.5
```

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable adaptive enforcement |
| `escalation_threshold` | `5.0` | Score before escalation |
| `decay_per_clean_request` | `0.5` | Score reduction per clean request |

## Kill Switch

Emergency deny-all with four independent activation sources. Any one active blocks all traffic (OR-composed). See [Kill Switch](../README.md#kill-switch) for operational details.

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
| `enabled` | `false` | No | Config-based activation |
| `sentinel_file` | `""` | No | File presence activates kill switch |
| `message` | `"Emergency deny-all active"` | No | Rejection message |
| `health_exempt` | `true` | No | /health bypasses kill switch |
| `metrics_exempt` | `true` | No | /metrics bypasses kill switch |
| `api_exempt` | `true` | No | /api/v1/* bypasses kill switch |
| `api_token` | `""` | No | Bearer token for API endpoints. Can be overridden by `PIPELOCK_KILLSWITCH_API_TOKEN` env var. |
| `api_listen` | `""` | **Yes** | Separate listen address for API |
| `allowlist_ips` | `[]` | No | IPs always allowed through |

**Port isolation:** When `api_listen` is set, the kill switch API runs on a dedicated port. The main proxy port has no API routes, preventing agents from deactivating their own kill switch.

**Environment variable override:** Set `PIPELOCK_KILLSWITCH_API_TOKEN` to override `api_token` from the config file. This is useful for Kubernetes deployments where the config file lives in a ConfigMap (plaintext in etcd) but the token should come from a Secret:

```yaml
env:
  - name: PIPELOCK_KILLSWITCH_API_TOKEN
    valueFrom:
      secretKeyRef:
        name: pipelock-secrets
        key: killswitch-api-token
```

## Event Emission

Forward audit events to external systems. Two independent sinks, each with its own severity filter. Emission is fire-and-forget and never blocks the proxy.

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

**Severity levels** (hardcoded per event type, not configurable):
- **critical:** kill switch deny, adaptive escalation to block
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

Ships with 8 built-in patterns covering reconnaissance, credential theft, data staging, and exfiltration chains.

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

When a budget limit is reached:

- **Request count and domain limits** are checked before the outbound request. Exceeding either returns `429 Too Many Requests`.
- **Byte limit (fetch proxy):** the response body read is capped at the remaining byte budget. If the response exceeds the limit, it is discarded and a `429` is returned.
- **Byte limit (CONNECT/WebSocket):** streaming connections track bytes after close. The byte budget is enforced on the next admission check, not mid-stream, because tunnel data cannot be recalled after transmission.

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

```yaml
license_key: "pipelock_lic_v1_eyJ..."
license_public_key: "a1b2c3d4..."  # hex-encoded Ed25519 public key
```

Multi-agent profiles (the `agents:` section) require a signed license token in `license_key`. The token is an Ed25519-signed JWT-like string issued by `pipelock license issue`. At startup, pipelock verifies the signature, checks expiration, and confirms the token includes the `agents` feature. If any check fails, agent profiles are disabled with a warning. All single-agent protection remains active.

Official release builds embed the signing public key at compile time via ldflags. The embedded key takes priority over `license_public_key` and cannot be overridden by config, preventing self-signing bypasses. The `license_public_key` config field is only used in development builds where no key is embedded.

Generate a keypair and issue licenses with:

```bash
pipelock license keygen              # generates ~/.config/pipelock/license.key + license.pub
pipelock license issue --email customer@company.com --expires 2027-03-07
pipelock license inspect TOKEN       # decode without verifying
```

A `_default` profile without any named agents does not require a license key.

## Validation Rules

The following are enforced at startup:

- Strict mode requires a non-empty `api_allowlist`
- All DLP and response patterns must compile as valid regex
- `secrets_file` must exist and not be world-readable (mode 0600 or stricter)
- MCP tool policy requires at least one rule if enabled
- Kill switch `api_listen` must differ from the main proxy listen address
- WebSocket `strip_compression` must be true when scanning is enabled
