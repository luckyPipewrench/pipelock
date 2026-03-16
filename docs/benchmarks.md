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

Full 11-layer URL scanning: scheme, CRLF injection, path traversal, blocklist, DLP (pre-DNS), path entropy, subdomain entropy, SSRF (post-DNS), rate limit, URL length, data budget.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| AllowedURL | 20,857 | 1,418 | 26 |
| BlockedByBlocklist | 1,893 | 288 | 5 |
| BlockedByDLP | 6,741 | 2,369 | 43 |
| BlockedByEntropy | 41,137 | 4,787 | 59 |
| BlockedByURLLength | 3,097,133 | 69,724 | 52 |
| ComplexAllowedURL | 40,520 | 3,485 | 85 |

## Response Scanning (`ScanResponse()`)

Pattern matching for prompt injection on fetched content. 20 patterns.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean (~90B) | 115,165 | 500 | 7 |
| WithInjection (~100B) | 45,460 | 371 | 3 |
| LargeClean (~10KB) | 16,498,471 | 55,112 | 10 |

## Text DLP Scanning (`ScanTextForDLP()`)

DLP pattern matching on arbitrary text (MCP arguments, request bodies). 36 patterns with Aho-Corasick pre-filter.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 25,092 | 855 | 10 |
| Match | 9,197 | 510 | 11 |

## DLP Pre-Filter

Aho-Corasick prefix automaton. Short-circuits clean text before regex evaluation. Zero allocations on miss.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| CleanText (no match) | 418 | 0 | 0 |
| WithPrefix (match) | 435 | 104 | 3 |

## MCP Response Scanning (`mcp.ScanResponse()`)

JSON-RPC 2.0 response parsing + text extraction + prompt injection scanning.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 110,027 | 1,397 | 28 |
| Injection | 41,784 | 1,454 | 25 |
| ExtractText (5 blocks) | 2,334 | 1,080 | 23 |

## Parallel Throughput (`b.RunParallel`, GOMAXPROCS=16)

True concurrent throughput across all available goroutines.

### Scanner

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Parallel_URLScan | 7,623 | 3,839 | 85 |
| Parallel_DLPBlock | 1,360 | 2,525 | 43 |
| Parallel_ResponseScan | 15,248 | 509 | 7 |
| Parallel_ResponseLarge | 2,695,906 | 75,509 | 30 |
| Parallel_Blocklist | 337 | 288 | 5 |
| Parallel_Entropy | 6,820 | 5,079 | 59 |

### MCP

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Parallel_MCPScanClean | 14,449 | 1,435 | 28 |
| Parallel_MCPScanInjection | 5,563 | 1,480 | 25 |
| Parallel_ExtractText | 608 | 1,080 | 23 |

## Other

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| ShannonEntropy | 2,295 | 2,120 | 7 |
| MatchDomain/exact | 50 | 48 | 1 |
| MatchDomain/wildcard | 55 | 48 | 1 |

## Key Takeaways

- **Full 11-layer scan on a typical URL: ~21 microseconds** (down from ~37μs in v1.2.0, thanks to DLP pre-filter). Well under 1ms.
- Blocked URLs short-circuit early: blocklist check is ~1.9μs.
- DLP regex matching (36 patterns) with pre-filter: ~6.7μs. Pre-filter alone: ~418ns with zero allocations on clean text.
- Response scanning with 20 patterns on small content: ~115μs. Large content (~10KB) takes ~16ms due to 6 normalization passes plus regex cost scaling with input size.
- MCP scanning (JSON parse + text extraction + pattern match): ~110μs.
- **Parallel throughput scales linearly with cores** (benchmarks run with rate limiting and data budget disabled to isolate scanning overhead).
- The scanner pipeline adds **~0.021ms overhead for typical URL requests**. Network latency dominates.

## Hardware

AMD Ryzen 7 7800X3D (8 cores / 16 threads) / Go 1.25 / Linux 6.18 / Fedora 43

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
