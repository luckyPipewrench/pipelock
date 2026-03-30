# Pipelock Benchmarks

Raw benchmark data from Go's testing framework. For interpretation and deployment sizing, see [performance.md](performance.md).

## Methodology

Benchmarks measure the scanner pipeline only, not network I/O. This isolates pipelock's overhead from external fetch latency.

Configuration (balanced defaults):
- SSRF protection disabled (no DNS lookups in benchmarks)
- Rate limiting disabled (no time-dependent state)
- Response scanning: 23 prompt injection patterns
- DLP: 46 patterns + BIP-39 seed phrase detection

Run `make bench` to reproduce on your hardware.

## Scanner Pipeline (`Scanner.Scan()`)

Full 11-layer URL scanning: scheme, CRLF injection, path traversal, blocklist, DLP (pre-DNS), path entropy, subdomain entropy, SSRF (post-DNS), rate limit, URL length, data budget.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| AllowedURL | 30,833 | 3,719 | 68 |
| BlockedByBlocklist | 1,949 | 288 | 5 |
| BlockedByDLP | 7,808 | 2,456 | 46 |
| BlockedByEntropy | 59,554 | 7,232 | 115 |
| BlockedByURLLength | 4,426,927 | 139,019 | 113 |
| ComplexAllowedURL | 57,294 | 7,426 | 173 |

## Response Scanning (`ScanResponse()`)

Pattern matching for prompt injection on fetched content. 23 patterns including 6 state/control patterns and 4 CJK-language override patterns.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean (~90B) | 75,718 | 2,021 | 29 |
| WithInjection (~100B) | 41,699 | 1,100 | 12 |
| LargeClean (~10KB) | 8,394,531 | 43,445 | 23 |
| StateControlClean | 133,650 | 2,434 | 29 |
| StateControlMatch | 42,841 | 2,138 | 17 |

## Text DLP Scanning (`ScanTextForDLP()`)

DLP pattern matching on arbitrary text (MCP arguments, request bodies). 46 patterns with Aho-Corasick pre-filter.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 40,657 | 3,554 | 40 |
| Match | 17,899 | 2,208 | 42 |

## DLP Pre-Filter

Aho-Corasick prefix automaton. Short-circuits clean text before regex evaluation. Zero allocations on miss.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| CleanText (no match) | 497 | 0 | 0 |
| WithPrefix (match) | 553 | 136 | 3 |

## Cross-Request Detection

Entropy budget tracking and fragment buffer for detecting secrets split across multiple requests.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| EntropyTracker_Record | 109,713 | 1,166 | 6 |
| EntropyTracker_RecordMultiSession | 14,913 | 1,126 | 6 |
| FragmentBuffer_Append | 83 | 200 | 1 |
| FragmentBuffer_AppendAndScan | 12,666,821 | 938,070 | 1,244 |

## MCP Response Scanning (`mcp.ScanResponse()`)

JSON-RPC 2.0 response parsing + text extraction + prompt injection scanning.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 76,398 | 2,934 | 51 |
| Injection | 32,723 | 2,156 | 34 |
| ExtractText (5 blocks) | 2,494 | 1,080 | 23 |

## Parallel Throughput (`b.RunParallel`, GOMAXPROCS=16)

True concurrent throughput across all available goroutines.

### Scanner

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Parallel_URLScan | 10,687 | 7,917 | 173 |
| Parallel_DLPBlock | 1,458 | 2,527 | 46 |
| Parallel_ResponseScan | 10,897 | 2,046 | 29 |
| Parallel_ResponseLarge | 1,548,417 | 63,055 | 33 |
| Parallel_Blocklist | 340 | 288 | 5 |
| Parallel_Entropy | 10,186 | 7,477 | 115 |

### MCP

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Parallel_MCPScanClean | 9,868 | 2,974 | 51 |
| Parallel_MCPScanInjection | 4,461 | 2,204 | 34 |
| Parallel_ExtractText | 599 | 1,080 | 23 |

## Other

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| ShannonEntropy | 2,385 | 2,120 | 7 |
| MatchDomain/exact | 53 | 48 | 1 |
| MatchDomain/wildcard | 55 | 48 | 1 |

## Key Takeaways

- **Full 11-layer scan on a typical URL: ~32 microseconds.** Slightly higher than v1.5.0 (~21μs) due to expanded DLP patterns and additional scanner layers. Well under 1ms.
- Blocked URLs short-circuit early: blocklist check is ~2μs.
- DLP regex matching (46 patterns) with pre-filter: ~8μs. Pre-filter alone: ~497ns with zero allocations on clean text.
- Response scanning with 23 patterns on small content: ~76μs. Large content (~10KB): ~8.4ms. State/control patterns add ~133μs on clean text. Injection detected via early exit: ~42μs.
- MCP scanning (JSON parse + text extraction + pattern match): ~76μs clean, ~33μs injection.
- Cross-request entropy tracking: ~110μs per record. Fragment buffer append: ~83ns (single alloc).
- **Parallel throughput scales linearly with cores** (benchmarks run with rate limiting and data budget disabled to isolate scanning overhead).
- The scanner pipeline adds **~0.032ms overhead for typical URL requests**. Network latency dominates.

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

# Seed phrase detection
go test -bench=BenchmarkSeed -benchmem ./internal/seedprotect/
```

## BIP-39 Seed Phrase Detection (`seedprotect.Detect()`)

Dedicated scanner for BIP-39 mnemonic seed phrases. Uses dictionary lookup + sliding window + SHA-256 checksum validation.

| Benchmark | ns/op | B/op | allocs/op | Description |
|-----------|-------|------|-----------|-------------|
| `SeedDetect_CleanText` | 2,229 | 1,803 | 20 | Short text with no BIP-39 words (fast bail) |
| `SeedDetect_ValidPhrase` | 2,926 | 1,756 | 18 | 12-word valid mnemonic (full pipeline + checksum) |
| `SeedDetect_LongText` | 2,853,140 | 858,447 | 6,368 | 1000-word text, all BIP-39 words (worst case) |
| `SeedChecksum` | 136 | 0 | 0 | Checksum validation in isolation |

Clean text bails in ~2μs. Valid phrase detection including checksum takes ~3μs. The 1000-word worst case (all BIP-39 words) is a pathological input that doesn't occur in real traffic. Checksum validation is 136ns with zero allocations.
