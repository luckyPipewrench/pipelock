# Pipelock Benchmarks

Raw benchmark data from Go's testing framework. For interpretation and deployment sizing, see [performance.md](performance.md).

## Methodology

Benchmarks measure the scanner pipeline only, not network I/O. This isolates pipelock's overhead from external fetch latency.

Configuration (balanced defaults):
- SSRF protection disabled (no DNS lookups in benchmarks)
- Rate limiting disabled (no time-dependent state)
- Response scanning: 20 prompt injection patterns
- DLP: 41 patterns

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
| Clean (~90B) | 81,261 | 622 | 10 |
| WithInjection (~100B) | 14,490 | 606 | 8 |
| LargeClean (~10KB) | 12,117,866 | 22,187 | 6 |

## Text DLP Scanning (`ScanTextForDLP()`)

DLP pattern matching on arbitrary text (MCP arguments, request bodies). 41 patterns with Aho-Corasick pre-filter.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 24,571 | 858 | 10 |
| Match | 9,378 | 510 | 11 |

## DLP Pre-Filter

Aho-Corasick prefix automaton. Short-circuits clean text before regex evaluation. Zero allocations on miss.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| CleanText (no match) | 405 | 0 | 0 |
| WithPrefix (match) | 427 | 104 | 3 |

## MCP Response Scanning (`mcp.ScanResponse()`)

JSON-RPC 2.0 response parsing + text extraction + prompt injection scanning.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 89,260 | 1,609 | 33 |
| Injection | 12,701 | 1,597 | 29 |
| ExtractText (5 blocks) | 2,496 | 1,080 | 23 |

## Parallel Throughput (`b.RunParallel`, GOMAXPROCS=16)

True concurrent throughput across all available goroutines.

### Scanner

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Parallel_URLScan | 6,500 | 3,724 | 85 |
| Parallel_DLPBlock | 1,184 | 2,464 | 43 |
| Parallel_ResponseScan | 12,900 | 634 | 10 |
| Parallel_ResponseLarge | 1,928,156 | 31,767 | 16 |
| Parallel_Blocklist | 364 | 288 | 5 |
| Parallel_Entropy | 6,367 | 5,026 | 59 |

### MCP

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Parallel_MCPScanClean | 11,510 | 1,642 | 33 |
| Parallel_MCPScanInjection | 1,828 | 1,640 | 29 |
| Parallel_ExtractText | 616 | 1,080 | 23 |

## Other

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| ShannonEntropy | 2,310 | 2,120 | 7 |
| MatchDomain/exact | 52 | 48 | 1 |
| MatchDomain/wildcard | 54 | 48 | 1 |

## Key Takeaways

- **Full 11-layer scan on a typical URL: ~21 microseconds** (down from ~37μs in v1.2.0, thanks to DLP pre-filter). Well under 1ms.
- Blocked URLs short-circuit early: blocklist check is ~1.9μs.
- DLP regex matching (41 patterns) with pre-filter: ~6.7μs. Pre-filter alone: ~405ns with zero allocations on clean text.
- Response scanning with 20 patterns on small content: ~81μs (29% faster with keyword pre-filter). Large content (~10KB): ~12ms (27% faster). Injection detected via early exit: ~14.5μs (3.1x faster).
- MCP scanning (JSON parse + text extraction + pattern match): ~89μs clean, ~12.7μs injection (3.3x faster with pre-filter).
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
