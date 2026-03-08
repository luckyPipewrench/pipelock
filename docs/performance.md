# Performance

Pipelock adds microseconds of overhead per request. The proxy is I/O bound (waiting for upstream responses), not CPU bound. For the request-side URL scanning hot path, CPU is never the bottleneck. Response scanning and MCP scanning on large payloads can use measurable CPU at high throughput (see tables below).

All numbers from Go benchmarks on AMD Ryzen 7 7800X3D (16 cores) / Go 1.24 / Linux. Run `make bench` to reproduce on your hardware. See [benchmarks.md](benchmarks.md) for raw ns/op data.

## Scanning Latency

### URL Scanning (fetch/forward proxy hot path)

9-layer pipeline: scheme, blocklist, DLP, path entropy, subdomain entropy, SSRF, rate limit, URL length, data budget.

| Operation | Latency | Throughput (1 core) | Throughput (16 cores) |
|-----------|---------|--------------------:|----------------------:|
| Full pipeline (allowed URL) | ~37us | ~27,000/sec | ~432,000/sec |
| Blocklist block (early exit) | ~400ns | ~2,500,000/sec | ~40,000,000/sec |
| DLP pattern match (22 patterns) | ~11us | ~91,000/sec | ~1,460,000/sec |
| Entropy detection | ~65us | ~15,400/sec | ~246,000/sec |
| Complex URL (ports, query params) | ~50us | ~20,000/sec | ~320,000/sec |

### MCP Scanning (tool call/response inspection)

JSON-RPC parsing + text extraction + prompt injection pattern matching.

| Operation | Latency | Throughput (1 core) | Throughput (16 cores) |
|-----------|---------|--------------------:|----------------------:|
| Clean tool response | ~104us | ~9,600/sec | ~154,000/sec |
| Injection detected (early exit) | ~36us | ~27,700/sec | ~443,000/sec |
| Text extraction | ~2.3us | ~435,000/sec | ~6,960,000/sec |

### Response Scanning (fetched content injection detection)

Pattern matching against 20 prompt injection patterns on fetched page content.

| Operation | Latency | Throughput (1 core) | Throughput (16 cores) |
|-----------|---------|--------------------:|----------------------:|
| Short clean text (~90B) | ~118us | ~8,500/sec | ~136,000/sec |
| 10KB clean text | ~15ms | ~65/sec | ~1,040/sec |
| Injection detected (early exit) | ~45us | ~22,000/sec | ~352,000/sec |

The 10KB response scan is the current ceiling. It runs 6 sequential normalization passes (NFKC, confusable mapping, combining mark removal, zero-width removal, leetspeak expansion, vowel-fold) before pattern matching. Content size tiering (skipping passes 3-6 for large content) is planned.

## CPU Cost at Scale

How much CPU does scanning consume at various request rates? These numbers cover scanning overhead only, not network I/O.

### Request-side scanning (URL + MCP)

| Request rate | CPU (URL scan) | CPU (MCP scan) |
|-------------|---------------:|---------------:|
| 100/sec | 0.4% of 1 core | 1.0% of 1 core |
| 1,000/sec | 3.7% of 1 core | 10.4% of 1 core |
| 10,000/sec | 37% of 1 core | 1.04 cores |
| 100,000/sec | 3.7 cores | 10.4 cores |

### Response-side scanning

| Request rate | CPU (short ~90B) | CPU (10KB content) |
|-------------|---------------:|---------------:|
| 100/sec | 1.2% of 1 core | 150% of 1 core (1.5 cores) |
| 1,000/sec | 12% of 1 core | 15 cores |

Response scanning is the most CPU-intensive path. At high throughput with large payloads, it dominates. For request-side scanning only, 1,000 requests per second uses less than 15% of a single CPU core. Network latency (waiting for upstream HTTP responses) dominates total request time by orders of magnitude.

## Deployment Sizing

| Deployment | Expected load | CPU recommendation |
|------------|--------------|-------------------|
| Single developer (local proxy) | 1-10 req/sec | Any (negligible overhead) |
| Team sidecar (per-agent) | 10-100 req/sec | 0.1 CPU, 64MB RAM |
| Shared proxy (small org) | 100-1,000 req/sec | 0.5 CPU, 128MB RAM |
| Platform deployment | 10,000+ req/sec | 2+ CPU, 256MB RAM |

The binary is ~12MB static. Memory usage is dominated by the DLP regex compilation (~40MB RSS at idle with default patterns) and scales linearly with concurrent connections, not pattern count.

## Design Decisions That Affect Performance

**Early exit on block.** Blocked URLs short-circuit at the first failing layer. Blocklist hits resolve in ~400ns. DLP matches exit before DNS resolution.

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
go test -bench=BenchmarkMCPScanResponse -benchmem ./internal/mcp/

# Response scanner only
go test -bench=BenchmarkScanResponse -benchmem ./internal/scanner/
```
