# Pipelock — SecureIQLab Validation Harness

Test harness for the [SecureIQLab AI Security CyberRisk Validation](https://www.secureiqlab.com/). This Docker Compose environment provides everything needed to test Pipelock against adversarial AI agent attack scenarios.

## Architecture

```
SOCx Platform (SecureIQLab)
       │
       ▼ HTTPS_PROXY=http://pipelock:8888
┌──────────────────┐     ┌──────────────┐
│  pipelock         │────▶│  mock-llm    │
│  :8888 proxy      │     │  :8080       │
│  :9999 MCP proxy  │     │  LLM backend │
│  :9100 metrics    │     └──────────────┘
│                   │
│  scanning:        │     ┌──────────────┐
│  • 11-layer URL   │◀──▶│  mock-mcp    │
│  • DLP (46 pat.)  │     │  :8081       │
│  • injection (19) │     │  MCP server  │
│  • MCP tool scan  │     └──────────────┘
│  • canary tokens  │
└────────┬──────────┘
         │ webhook
         ▼
┌──────────────────┐
│  log-collector    │
│  :9090            │
│  evidence store   │
└──────────────────┘
```

## Quick Start

```bash
# 1. Generate TLS certificates (first time only)
make init

# 2. Start all containers
make up

# 3. Verify everything works
make smoke

# 4. Run false positive tests
make fp-test
```

## Configuring SOCx Traffic

### Forward Proxy (HTTP/HTTPS)

Point SOCx agent traffic at Pipelock's forward proxy:

```bash
export HTTPS_PROXY=http://<harness-host>:8888
export HTTP_PROXY=http://<harness-host>:8888
```

All HTTP and HTTPS traffic flows through Pipelock's 11-layer scanner pipeline. TLS interception is enabled — Pipelock generates leaf certificates signed by the test CA.

### MCP Proxy

Send MCP JSON-RPC requests to the MCP proxy endpoint:

```bash
curl -X POST http://<harness-host>:9999 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

The MCP proxy scans all tool calls, tool definitions, and tool results bidirectionally.

## Verifying Detection Logging

Every detection produces a webhook event in the log collector. This is critical for scoring — products that block without logging are penalized.

```bash
# List all logged events
curl http://localhost:9090/events | jq .

# Count events
curl http://localhost:9090/events/count

# Filter by event type
curl "http://localhost:9090/events?type=dlp_violation" | jq .

# Summary by type
curl http://localhost:9090/events/summary | jq .

# Reset events (for fresh test runs)
curl -X DELETE http://localhost:9090/events
```

Each event includes: event type, severity, pattern name, match context, action taken, timestamp, and MITRE ATLAS technique ID (where applicable).

## Checking Metrics

Pipelock exposes Prometheus metrics on `:9100`:

```bash
# All pipelock metrics
curl http://localhost:9100/metrics | grep pipelock_

# Key metrics for validation:
# pipelock_requests_total{action="block|allow"}  — request counts by action
# pipelock_scanner_duration_seconds              — scanning latency
# pipelock_dlp_matches_total                     — DLP pattern hits
# pipelock_mcp_tool_scans_total                  — MCP tool scan counts
```

## Scanning Layers

Pipelock applies these scanning layers to all traffic:

| Layer | What it does | Applies to |
|-------|-------------|------------|
| **URL Scanner** | 11-layer pipeline: scheme, blocklist, DLP, path entropy, subdomain entropy, SSRF, rate limit, URL length, data budget | Forward proxy, fetch |
| **DLP** | 46 credential patterns with checksum validators (Luhn, Mod97, ABA, WIF). Env variable leak detection. Case-insensitive with `(?i)` prefix. | All transports |
| **Response Scanning** | 23 prompt injection / jailbreak patterns with 6-pass normalization (NFKC, invisible chars, leetspeak, optional whitespace, vowel folding, base64/hex decode) | Fetch responses, MCP tool results |
| **Request Body** | DLP + injection scanning on outbound request bodies and headers | Forward proxy, fetch |
| **Canary Tokens** | Synthetic secret detection — exact match, zero false positives by definition | All transports |
| **MCP Tool Scanning** | Poisoned tool description detection with recursive schema walking. Rug-pull drift detection between sessions. | MCP proxy |
| **MCP Input Scanning** | DLP + injection on tool call arguments | MCP proxy |
| **MCP Tool Policy** | Pre-execution allow/deny rules with shell obfuscation detection | MCP proxy |
| **Tool Chain Detection** | Subsequence matching on dangerous tool call sequences | MCP proxy |
| **Session Binding** | Tool inventory pinning per session — new tools after initialization are flagged | MCP proxy |
| **Cross-Request Detection** | Entropy budget + fragment reassembly across multiple requests | Forward proxy |
| **Seed Phrase Detection** | BIP-39 mnemonic phrase detection with checksum verification | All transports |
| **Adaptive Enforcement** | Behavioral escalation — repeated violations increase enforcement severity | All transports |

## Testing Modes

### Mock LLM Modes

Set via `MOCK_LLM_MODE` environment variable in `docker-compose.yaml`:

| Mode | Behavior |
|------|----------|
| `echo` (default) | Returns the input prompt as the response |
| `malicious` | Returns responses containing leaked credentials and injection payloads |
| `mixed` | Alternates between echo and malicious responses |

### Mock MCP Modes

Set via `MOCK_MCP_MODE` environment variable:

| Mode | Behavior |
|------|----------|
| `benign` (default) | Normal tool definitions |
| `poisoned` | Tool descriptions contain hidden injection payloads and exfiltration instructions |

To switch modes, edit `docker-compose.yaml` and restart:

```bash
# Edit the environment variable, then:
docker compose up -d mock-llm   # restart just the mock LLM
docker compose up -d mock-mcp   # restart just the mock MCP
```

## Known Limitations

- **Embedding-level attacks:** Pipelock operates at the transport layer. If a scenario involves poisoned vectors inside a vector database that never flow through HTTP/MCP, Pipelock cannot inspect them. However, if poisoned content flows through the proxy as a tool result or RAG response, it is scanned.
- **Factual accuracy:** Pipelock does not verify whether LLM outputs are factually correct. Hallucinated URLs or fabricated facts are not detected. Pipelock detects exfiltration and injection, not misinformation.
- **TLS interception CA:** Applications that pin certificates or use custom trust stores need the test CA (`configs/tls/ca.crt`) added to their trust store.
- **Documented example credentials:** Pipelock intentionally blocks strings matching real credential patterns even when they appear as documented examples (e.g., AWS example access key IDs, Stripe test keys). The proxy cannot distinguish a "documented placeholder" from a real credential. This is a deliberate fail-closed design choice — blocking a documented example is a minor inconvenience; allowing a real credential through is a breach.

## File Layout

```
test/secureiqlab/
├── docker-compose.yaml       # Container orchestration
├── Makefile                   # Convenience targets
├── README.md                  # This file
├── configs/
│   ├── validation.yaml        # Pipelock config (max security)
│   └── tls/                   # Generated TLS CA (not committed)
│       ├── ca.crt
│       └── ca.key
├── mock-llm/
│   ├── Dockerfile
│   ├── go.mod
│   └── main.go                # Mock LLM HTTP server
├── mock-mcp/
│   ├── Dockerfile
│   ├── go.mod
│   └── main.go                # Mock MCP HTTP server
├── log-collector/
│   ├── Dockerfile
│   ├── go.mod
│   └── main.go                # Webhook event collector
└── scripts/
    ├── smoke-test.sh           # Quick validation
    └── fp-test.sh              # False positive test suite (8 categories)
```
