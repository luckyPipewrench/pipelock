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
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `version` | int | `1` | Config schema version |
| `mode` | string | `"balanced"` | Operating mode (see [Modes](#modes)) |
| `enforce` | bool | `true` | When false, all blocks become warnings |

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
  redirect_websocket_hosts: []  # Redirect WS hosts to /ws proxy
```

| Field | Default | Restart? | Description |
|-------|---------|----------|-------------|
| `enabled` | `false` | **Yes** | Enable CONNECT tunnel proxy |
| `max_tunnel_seconds` | `300` | No | Max tunnel lifetime |
| `idle_timeout_seconds` | `120` | No | Kill idle tunnels |
| `redirect_websocket_hosts` | `[]` | No | Redirect matching hosts to /ws |

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

Scans URLs for secrets using regex patterns. Runs before DNS resolution to prevent secret exfiltration via DNS queries. Matching is always case-insensitive.

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
| `include_defaults` | `true` | Merge your patterns with the 35 built-in patterns |
| `patterns` | 35 built-in | DLP pattern list (22 credential + 13 injection) |

### Pattern Merging

When `include_defaults` is true (default), your patterns are merged with the built-in set by name. If you define a pattern with the same name as a built-in, yours overrides it. New built-in patterns added in future versions are automatically included.

Set `include_defaults: false` to use only your patterns.

### Built-in DLP Patterns (35)

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
| `api_token` | `""` | No | Bearer token for API endpoints |
| `api_listen` | `""` | **Yes** | Separate listen address for API |
| `allowlist_ips` | `[]` | No | IPs always allowed through |

**Port isolation:** When `api_listen` is set, the kill switch API runs on a dedicated port. The main proxy port has no API routes, preventing agents from deactivating their own kill switch.

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
```

All RFC 1918, RFC 4193, link-local, loopback, CGN (Tailscale/Carrier-Grade NAT), and cloud metadata ranges are blocked by default.

## Presets

Six starter configs in `configs/`:

| Preset | Mode | Response Action | MCP Policy | Best For |
|--------|------|----------------|------------|----------|
| `balanced.yaml` | balanced | warn | warn | General purpose |
| `strict.yaml` | strict | block | block | High-security |
| `audit.yaml` | audit | warn | warn | Log-only monitoring |
| `claude-code.yaml` | balanced | block | warn | Claude Code (unattended) |
| `cursor.yaml` | balanced | block | warn | Cursor IDE |
| `generic-agent.yaml` | balanced | warn | warn | New agents (tuning) |

Key differences between presets:

| Setting | Balanced | Strict | Claude Code |
|---------|----------|--------|-------------|
| Max URL Length | 2048 | 500 | 4096 |
| Entropy Threshold | 4.5 | 3.5 | 5.0 |
| Rate Limit | 60/min | 30/min | 120/min |
| API Allowlist | LLM + comms | LLM + comms | LLM + dev tools |

## Validation Rules

The following are enforced at startup:

- Strict mode requires a non-empty `api_allowlist`
- All DLP and response patterns must compile as valid regex
- `secrets_file` must exist and not be world-readable (mode 0600 or stricter)
- MCP tool policy requires at least one rule if enabled
- Kill switch `api_listen` must differ from the main proxy listen address
- WebSocket `strip_compression` must be true when scanning is enabled
