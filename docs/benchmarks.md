# Pipelock Benchmarks

Raw benchmark data from Go's testing framework. For interpretation and deployment sizing, see [performance.md](performance.md).

## Methodology

Benchmarks measure the scanner pipeline only, not network I/O. This isolates pipelock's overhead from external fetch latency.

Configuration (balanced defaults):
- SSRF protection disabled (no DNS lookups in benchmarks)
- Rate limiting disabled (no time-dependent state)
- Response scanning: 20 prompt injection patterns
- DLP: 36 patterns

Run `make bench` to reproduce on your hardware.

## Scanner Pipeline (`Scanner.Scan()`)

Full 9-layer URL scanning: scheme, blocklist, DLP (pre-DNS), path entropy, subdomain entropy, SSRF (post-DNS), rate limit, URL length, data budget.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| AllowedURL | 36,711 | 1,412 | 26 |
| BlockedByBlocklist | 394 | 288 | 5 |
| BlockedByDLP | 10,873 | 2,260 | 41 |
| BlockedByEntropy | 64,932 | 4,303 | 50 |
| BlockedByURLLength | 6,228,301 | 69,998 | 52 |
| ComplexAllowedURL | 50,513 | 3,447 | 84 |

## Response Scanning (`ScanResponse()`)

Pattern matching for prompt injection on fetched content. 20 patterns.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean (~90B) | 122,042 | 500 | 7 |
| WithInjection (~100B) | 46,519 | 371 | 3 |
| LargeClean (~10KB) | 15,871,745 | 55,647 | 10 |

## MCP Response Scanning (`mcp.ScanResponse()`)

JSON-RPC 2.0 response parsing + text extraction + prompt injection scanning.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 108,138 | 1,398 | 28 |
| Injection | 39,725 | 1,449 | 25 |
| ExtractText (5 blocks) | 2,409 | 1,080 | 23 |

## Parallel Throughput (`b.RunParallel`, GOMAXPROCS=16)

True concurrent throughput across all available goroutines.

### Scanner

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Parallel_URLScan | 8,803 | 3,687 | 84 |
| Parallel_DLPBlock | 1,992 | 2,459 | 41 |
| Parallel_ResponseScan | 15,339 | 507 | 7 |
| Parallel_ResponseLarge | 2,837,123 | 92,857 | 40 |
| Parallel_Blocklist | 104 | 288 | 5 |
| Parallel_Entropy | 10,723 | 4,631 | 50 |

### MCP

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Parallel_MCPScanClean | 14,696 | 1,444 | 28 |
| Parallel_MCPScanInjection | 5,725 | 1,496 | 25 |
| Parallel_ExtractText | 613 | 1,080 | 23 |

## Normalization

Unicode normalization overhead per string.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| ForDLP | 953 | 1,336 | 10 |
| ForMatching | 1,262 | 864 | 7 |
| ForToolText | 1,982 | 1,776 | 12 |

## Other

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| ShannonEntropy | 2,285 | 2,120 | 7 |
| MatchDomain/exact | 50 | 48 | 1 |
| MatchDomain/wildcard | 54 | 48 | 1 |
| ColdStart (decide) | 1,298,678 | 1,775,685 | 10,469 |

## Key Takeaways

- **Full 9-layer scan on a typical URL: ~37 microseconds.** Well under 1ms.
- Blocked URLs short-circuit early: blocklist check is ~394ns.
- DLP regex matching (36 patterns) adds ~11 microseconds.
- Response scanning with 20 patterns on small content: ~122 microseconds. Large content (~10KB) takes ~16ms due to 6 normalization passes plus regex cost scaling with input size.
- MCP scanning (JSON parse + text extraction + pattern match): ~108 microseconds.
- **Parallel throughput scales linearly with cores** (benchmarks run with rate limiting and data budget disabled to isolate scanning overhead).
- The scanner pipeline adds **~0.037ms overhead for typical URL requests**. Network latency dominates.

## Hardware

AMD Ryzen 7 7800X3D (8 cores / 16 threads) / Go 1.24 / Linux 6.18 / Fedora 43

## Running Benchmarks

```bash
# Sequential (default)
make bench

# Parallel scaling
go test -bench=BenchmarkParallel -benchtime=3s -cpu=1,2,4,8,16 ./internal/scanner/
go test -bench=BenchmarkParallel -benchtime=3s -cpu=1,4,8,16 ./internal/mcp/

# Concurrent throughput scaling test (1-64 goroutines, ~28s)
PIPELOCK_BENCH_SCALING=1 go test -v -run=TestConcurrentThroughputScaling ./internal/scanner/
```
