# Performance

Pipelock adds microseconds of overhead per request. The proxy is I/O bound (waiting for upstream responses), not CPU bound. For the request-side URL scanning hot path, CPU is never the bottleneck. Response scanning and MCP scanning on large payloads can use measurable CPU at high throughput (see tables below).

All numbers from Go benchmarks on AMD Ryzen 7 7800X3D (8 cores / 16 threads) / Go 1.25 / Linux. Run `make bench` to reproduce on your hardware. See [benchmarks.md](benchmarks.md) for raw ns/op data.

## Scanning Latency (single request)

### URL Scanning (fetch/forward proxy hot path)

11-layer pipeline: scheme, CRLF injection, path traversal, blocklist, DLP, path entropy, subdomain entropy, SSRF, rate limit, URL length, data budget.

| Operation | Latency | Throughput (1 core) |
|-----------|---------|--------------------:|
| Full pipeline (allowed URL) | ~21 μs | ~48,000/sec |
| Blocklist block (early exit) | ~1.9 μs | ~528,000/sec |
| DLP pattern match (36 patterns, pre-filtered) | ~6.7 μs | ~149,000/sec |
| DLP pre-filter only (clean text, zero alloc) | ~418 ns | ~2,390,000/sec |
| Entropy detection | ~41 μs | ~24,300/sec |
| Complex URL (ports, query params) | ~41 μs | ~24,700/sec |

### MCP Scanning (tool call/response inspection)

JSON-RPC parsing + text extraction + prompt injection pattern matching.

| Operation | Latency | Throughput (1 core) |
|-----------|---------|--------------------:|
| Clean tool response | ~110 μs | ~9,100/sec |
| Injection detected (early exit) | ~42 μs | ~23,800/sec |
| Text extraction | ~2.3 μs | ~430,000/sec |

### Response Scanning (fetched content injection detection)

Pattern matching against 20 prompt injection patterns on fetched page content.

| Operation | Latency | Throughput (1 core) |
|-----------|---------|--------------------:|
| Short clean text (~90B) | ~115 μs | ~8,700/sec |
| 10KB clean text | ~16 ms | ~61/sec |
| Injection detected (early exit) | ~45 μs | ~22,000/sec |

The 10KB response scan is the current ceiling. It runs 6 sequential normalization passes (NFKC, confusable mapping, combining mark removal, zero-width removal, leetspeak expansion, vowel-fold) before pattern matching. Content size tiering (skipping passes 3-6 for large content) is planned.

### Supporting Operations

| Operation | Latency |
|-----------|---------|
| Unicode normalization (DLP mode) | ~950 ns |
| Unicode normalization (matching mode) | ~1.3 μs |
| Unicode normalization (tool text mode) | ~2.0 μs |
| Shannon entropy calculation | ~2.2 μs |
| Domain matching (exact) | ~50 ns |
| Domain matching (wildcard) | ~53 ns |

## Concurrent Scaling

The scanner's core detection pipeline (scheme, blocklist, DLP, entropy, SSRF) is stateless per request with no shared mutable state. Config reads use atomic pointer swap. Rate limiting and data budget tracking use per-scanner mutexes, but these are low-contention (one lock acquisition per request). Benchmarks below are run with rate limiting and data budget disabled to isolate scanning throughput.

### Parallel throughput (`b.RunParallel`)

These benchmarks run across all available goroutines simultaneously, measuring total operations per second as parallelism increases.

**URL Scanning:**

| GOMAXPROCS | ns/op | Throughput | Scaling vs 1 |
|-----------:|------:|----------:|---------:|
| 1 | 51,246 | 19,500/sec | 1.0x |
| 2 | 26,568 | 37,600/sec | 1.9x |
| 4 | 13,885 | 72,000/sec | 3.7x |
| 8 | 8,843 | 113,100/sec | 5.8x |
| 16 | 7,955 | 125,700/sec | 6.4x |

**DLP Block (early exit):**

| GOMAXPROCS | ns/op | Throughput | Scaling vs 1 |
|-----------:|------:|----------:|---------:|
| 1 | 11,200 | 89,300/sec | 1.0x |
| 2 | 5,795 | 172,600/sec | 1.9x |
| 4 | 3,072 | 325,500/sec | 3.6x |
| 8 | 2,183 | 458,100/sec | 5.1x |
| 16 | 1,931 | 518,000/sec | 5.8x |

**Response Scanning (short content):**

| GOMAXPROCS | ns/op | Throughput | Scaling vs 1 |
|-----------:|------:|----------:|---------:|
| 1 | 120,230 | 8,300/sec | 1.0x |
| 2 | 62,053 | 16,100/sec | 1.9x |
| 4 | 31,510 | 31,700/sec | 3.8x |
| 8 | 18,007 | 55,500/sec | 6.7x |
| 16 | 15,441 | 64,800/sec | 7.8x |

**Response Scanning (10KB content):**

| GOMAXPROCS | ns/op | Throughput | Scaling vs 1 |
|-----------:|------:|----------:|---------:|
| 1 | 15,619,369 | 64/sec | 1.0x |
| 2 | 8,101,083 | 123/sec | 1.9x |
| 4 | 4,347,221 | 230/sec | 3.6x |
| 8 | 2,591,218 | 386/sec | 6.0x |
| 16 | 2,817,006 | 355/sec | 5.5x |

**MCP Scanning (clean response):**

| GOMAXPROCS | ns/op | Throughput | Scaling vs 1 |
|-----------:|------:|----------:|---------:|
| 1 | 104,674 | 9,600/sec | 1.0x |
| 4 | 27,076 | 36,900/sec | 3.9x |
| 8 | 15,509 | 64,500/sec | 6.7x |
| 16 | 13,633 | 73,400/sec | 7.7x |

**Blocklist (early exit):**

| GOMAXPROCS | ns/op | Throughput | Scaling vs 1 |
|-----------:|------:|----------:|---------:|
| 1 | 431 | 2,320,000/sec | 1.0x |
| 4 | 139 | 7,190,000/sec | 3.1x |
| 8 | 112 | 8,930,000/sec | 3.8x |
| 16 | 99 | 10,100,000/sec | 4.4x |

### Concurrent throughput scaling (goroutine ramp)

Sustained 2-second runs at increasing goroutine counts. Measures total operations completed, not per-goroutine latency.

**URL Scan:**

| Goroutines | Ops/sec | Scaling |
|-----------:|--------:|--------:|
| 1 | 19,466 | 1.0x |
| 2 | 37,122 | 1.9x |
| 4 | 67,722 | 3.5x |
| 8 | 106,321 | 5.5x |
| 16 | 121,337 | 6.2x |
| 32 | 115,875 | 6.0x |
| 64 | 123,959 | 6.4x |

**Response Scan:**

| Goroutines | Ops/sec | Scaling |
|-----------:|--------:|--------:|
| 1 | 8,284 | 1.0x |
| 2 | 16,135 | 1.9x |
| 4 | 31,417 | 3.8x |
| 8 | 52,405 | 6.3x |
| 16 | 62,776 | 7.6x |
| 32 | 66,575 | 8.0x |
| 64 | 65,470 | 7.9x |

**The pattern:** near-linear scaling up to physical core count (8), small gains from hyperthreading (16), then plateau. No degradation past core count. Adding more concurrent agents doesn't slow anything down, you just stop getting additional throughput once all cores are saturated.

### HTTP Proxy Overhead

Raw HTTP handler throughput measured with [hey](https://github.com/rakyll/hey) against the running proxy.

| Concurrency | Requests | Req/sec | P50 | P99 |
|------------:|--------:|--------:|----:|----:|
| 50 | 2,000 | 43,474 | 0.5 ms | 18.5 ms |
| 200 | 10,000 | 102,600 | 0.7 ms | 23.2 ms |
| 500 | 20,000 | 97,268 | 2.0 ms | 51.9 ms |

This measures HTTP accept/parse/route/respond overhead. Actual scanning latency adds the per-operation costs from the tables above.

## CPU Cost at Scale

How much CPU does scanning consume at various request rates? These numbers cover scanning overhead only, not network I/O.

### Request-side scanning (URL + MCP)

| Request rate | CPU (URL scan) | CPU (MCP scan) |
|-------------|---------------:|---------------:|
| 100/sec | 0.4% of 1 core | 1.1% of 1 core |
| 1,000/sec | 3.7% of 1 core | 10.8% of 1 core |
| 10,000/sec | 37% of 1 core | 1.1 cores |
| 100,000/sec | 3.7 cores | 10.8 cores |

### Response-side scanning

| Request rate | CPU (short ~90B) | CPU (10KB content) |
|-------------|---------------:|---------------:|
| 100/sec | 1.2% of 1 core | 1.6 cores |
| 1,000/sec | 12% of 1 core | 16 cores |

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

**Early exit on block.** Blocked URLs short-circuit at the first failing layer. Blocklist hits resolve in ~1.9μs. DLP matches exit before DNS resolution.

**Pre-DNS checks.** CRLF injection, path traversal, allowlist, blocklist, and DLP checks all execute before any network call. This prevents secret exfiltration via DNS queries and keeps the fast path fast.

**Stateless detection pipeline.** Each scan allocates its own working state. The core detection layers (scheme through SSRF) have no shared mutable state, enabling linear scaling with cores. Rate limiting and data budget use per-scanner mutexes but are low-contention.

**Fire-and-forget event emission.** Webhook events use an async buffered channel. Syslog is UDP. Neither blocks the scanning pipeline.

**Atomic config reload.** Hot-reload swaps the entire scanner via `atomic.Pointer`, so scanning never blocks on config changes.

## Reproducing These Numbers

```bash
# Full benchmark suite (sequential)
make bench

# Parallel scaling (URL scanner)
go test -bench=BenchmarkParallel -benchtime=3s -cpu=1,2,4,8,16 ./internal/scanner/

# Parallel scaling (MCP scanner)
go test -bench=BenchmarkParallel -benchtime=3s -cpu=1,4,8,16 ./internal/mcp/

# Concurrent throughput scaling test (~28s)
PIPELOCK_BENCH_SCALING=1 go test -v -run=TestConcurrentThroughputScaling ./internal/scanner/

# HTTP proxy overhead (requires running pipelock instance)
hey -n 10000 -c 200 http://localhost:8888/health
```
