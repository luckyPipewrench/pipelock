# Performance

Pipelock adds microseconds of overhead per request. The proxy is I/O bound (waiting for upstream responses), not CPU bound. At platform scale, CPU is never the bottleneck.

All numbers from Go benchmarks on AMD Ryzen 7 7800X3D (16 cores) / Go 1.24 / Linux. Run `make bench` to reproduce on your hardware. See [benchmarks.md](benchmarks.md) for raw ns/op data.

## Scanning Latency

### URL Scanning (fetch/forward proxy hot path)

9-layer pipeline: scheme, blocklist, DLP, path entropy, subdomain entropy, SSRF, rate limit, URL length, data budget.

| Operation | Latency | Throughput (1 core) | Throughput (16 cores) |
|-----------|---------|--------------------:|----------------------:|
| Full pipeline (allowed URL) | 38us | ~26,000/sec | ~416,000/sec |
| Blocklist block (early exit) | 440ns | ~2,300,000/sec | ~37,000,000/sec |
| DLP pattern match (22 patterns) | 11.5us | ~87,000/sec | ~1,400,000/sec |
| Entropy detection | 68us | ~14,700/sec | ~235,000/sec |
| Complex URL (ports, query params) | 53us | ~19,000/sec | ~300,000/sec |

### MCP Scanning (tool call/response inspection)

JSON-RPC parsing + text extraction + prompt injection pattern matching.

| Operation | Latency | Throughput (1 core) | Throughput (16 cores) |
|-----------|---------|--------------------:|----------------------:|
| Clean tool response | 107us | ~9,300/sec | ~149,000/sec |
| Injection detected (early exit) | 38us | ~26,000/sec | ~416,000/sec |
| Text extraction | 2.5us | ~400,000/sec | ~6,400,000/sec |

### Response Scanning (fetched content injection detection)

Pattern matching against 20 prompt injection patterns on fetched page content.

| Operation | Latency | Throughput (1 core) | Throughput (16 cores) |
|-----------|---------|--------------------:|----------------------:|
| Short clean text (~90B) | 122us | ~8,200/sec | ~131,000/sec |
| 10KB clean text | 16ms | ~63/sec | ~1,000/sec |
| Injection detected (early exit) | 47us | ~21,000/sec | ~336,000/sec |

The 10KB response scan is the current ceiling. It runs 6 sequential normalization passes (NFKC, confusable mapping, combining mark removal, zero-width removal, leetspeak expansion, vowel-fold) before pattern matching. Content size tiering (skipping passes 3-6 for large content) is planned and will reduce this to ~4ms.

## CPU Cost at Scale

How much CPU does scanning consume at various request rates? These numbers cover scanning overhead only, not network I/O.

| Request rate | CPU (URL scan) | CPU (MCP scan) |
|-------------|---------------:|---------------:|
| 100/sec | 0.4% of 1 core | 1.1% of 1 core |
| 1,000/sec | 3.8% of 1 core | 10.7% of 1 core |
| 10,000/sec | 38% of 1 core | 1.07 cores |
| 100,000/sec | 3.8 cores | 10.7 cores |

At 1,000 requests per second, pipelock uses less than 15% of a single CPU core for all scanning combined. Network latency (waiting for upstream HTTP responses) dominates total request time by orders of magnitude.

## Deployment Sizing

| Deployment | Expected load | CPU recommendation |
|------------|--------------|-------------------|
| Single developer (local proxy) | 1-10 req/sec | Any (negligible overhead) |
| Team sidecar (per-agent) | 10-100 req/sec | 0.1 CPU, 64MB RAM |
| Shared proxy (small org) | 100-1,000 req/sec | 0.5 CPU, 128MB RAM |
| Platform deployment | 10,000+ req/sec | 2+ CPU, 256MB RAM |

The binary is ~12MB static. Memory usage is dominated by the DLP regex compilation (~40MB RSS at idle with default patterns) and scales linearly with concurrent connections, not pattern count.

## Design Decisions That Affect Performance

**Early exit on block.** Blocked URLs short-circuit at the first failing layer. Blocklist hits resolve in ~440ns. DLP matches exit before DNS resolution.

**Layers 2-3 run before DNS.** DLP and blocklist checks execute before any network call. This prevents secret exfiltration via DNS queries and keeps the fast path fast.

**Fire-and-forget event emission.** Webhook events use an async buffered channel. Syslog is UDP. Neither blocks the scanning pipeline.

**Atomic config reload.** Hot-reload swaps the entire scanner via `atomic.Pointer`, so scanning never blocks on config changes.

## Reproducing These Numbers

```bash
# Full benchmark suite
make bench

# URL scanner only
go test -bench=BenchmarkScan -benchmem ./internal/scanner/

# MCP scanner only
go test -bench=BenchmarkMCP -benchmem ./internal/mcp/

# Response scanner only
go test -bench=BenchmarkResponse -benchmem ./internal/scanner/
```
