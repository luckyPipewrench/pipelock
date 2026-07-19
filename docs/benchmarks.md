# Pipelock Benchmarks

Raw benchmark data from Go's testing framework. For interpretation and deployment sizing, see [performance.md](performance.md).

## Methodology

Benchmarks measure the scanner pipeline only, not network I/O. This isolates pipelock's overhead from external fetch latency.

Configuration (balanced defaults):
- SSRF protection disabled (no DNS lookups in benchmarks)
- Rate limiting disabled (no time-dependent state)
- Response scanning: 32 prompt injection patterns
- DLP: 65 patterns + BIP-39 seed phrase detection

Run `make bench` to reproduce on your hardware. Numbers below are the median of three runs on the hardware listed at the bottom (v3.1.0).

## Scanner Pipeline (`Scanner.Scan()`)

URL scanning with DNS-based SSRF, rate limiting, and data budget checks disabled: scheme, CRLF injection, path traversal, blocklist, DLP (pre-DNS), path entropy, subdomain entropy, and URL length. DNS resolution, the post-DNS SSRF layer, rate limiting, and data budget enforcement are excluded from these measurements.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| AllowedURL | 38,656 | 5,722 | 99 |
| BlockedByBlocklist | 1,894 | 320 | 6 |
| BlockedByDLP | 7,204 | 4,272 | 109 |
| BlockedByEntropy | 59,432 | 11,589 | 194 |
| BlockedByURLLength | 142 | 64 | 3 |
| ComplexAllowedURL | 107,631 | 24,723 | 600 |

## Response Scanning (`ScanResponse()`)

Pattern matching for prompt injection on fetched content, across the multi-pass normalization cascade (normalized, invisible-spaced, leetspeak, optional-whitespace, vowel-fold, decode).

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean (~90B) | 387,450 | 6,727 | 68 |
| WithInjection (~100B) | 71,988 | 2,106 | 16 |
| LargeClean (~10KB) | 46,291,110 | 118,850 | 64 |
| StateControlClean | 667,271 | 7,964 | 68 |
| StateControlMatch | 537,802 | 8,121 | 72 |

## Text DLP Scanning (`ScanTextForDLP()`)

DLP pattern matching on arbitrary text (MCP arguments, request bodies). 65 patterns with Aho-Corasick pre-filter.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 82,425 | 5,805 | 80 |
| Match | 85,474 | 13,866 | 237 |

## DLP Pre-Filter

Aho-Corasick prefix automaton. Short-circuits clean text before regex evaluation. Zero allocations on miss.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| CleanText (no match) | 671 | 0 | 0 |
| WithPrefix (match) | 653 | 168 | 3 |

## Cross-Request Detection

Entropy budget tracking and fragment buffer for detecting secrets split across multiple requests.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| EntropyTracker_Record | 113,719 | 1,157 | 6 |
| EntropyTracker_RecordMultiSession | 18,018 | 1,129 | 6 |
| FragmentBuffer_Append | 76 | 200 | 1 |
| FragmentBuffer_AppendAndScan | 11,984,418 | 1,420,138 | 686 |

## MCP Response Scanning (`mcp.ScanResponse()`)

JSON-RPC 2.0 response parsing + text extraction + prompt injection scanning.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 351,475 | 12,283 | 186 |
| Injection | 61,047 | 6,145 | 130 |
| ExtractText (5 blocks) | 5,435 | 5,208 | 73 |

## Parallel Throughput (`b.RunParallel`, GOMAXPROCS=16)

True concurrent throughput across all available goroutines.

### Scanner

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Parallel_URLScan | 56,929 | 24,863 | 600 |
| Parallel_DLPBlock | 3,898 | 4,276 | 109 |
| Parallel_ResponseScan | 186,919 | 8,279 | 68 |
| Parallel_ResponseLarge | 22,611,580 | 370,125 | 134 |
| Parallel_Blocklist | 950 | 320 | 6 |
| Parallel_Entropy | 28,348 | 11,668 | 194 |

### MCP

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Parallel_MCPScanClean | 181,219 | 14,483 | 186 |
| Parallel_MCPScanInjection | 33,045 | 7,107 | 130 |
| Parallel_ExtractText | 3,363 | 5,208 | 73 |

## Other

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| ShannonEntropy | 2,201 | 2,120 | 7 |
| MatchDomain/exact | 49 | 48 | 1 |
| MatchDomain/wildcard | 52 | 48 | 1 |

## Key Takeaways

- **Typical URL scan with DNS-based SSRF, rate limiting, and data budget checks disabled: ~39 microseconds** (measured on v3.1.0). Well under 1ms; network latency dominates real requests.
- Blocked URLs short-circuit early: the blocklist check is ~2μs, and an over-length URL is rejected in ~142ns before any expensive layer runs.
- DLP regex matching (65 patterns) with pre-filter: ~7μs. Pre-filter alone: ~671ns with zero allocations on clean text.
- Response scanning runs the full multi-pass normalization cascade: ~387μs on small clean content, ~72μs when injection is detected via early exit. State/control patterns add cost on clean text (~667μs). Large content (~10KB) is the heavy case at ~46ms; a scanner + benchmark performance audit is planned for a future release.
- MCP scanning (JSON parse + text extraction + pattern match): ~351μs clean, ~61μs injection.
- Cross-request entropy tracking: ~114μs per record. Fragment buffer append: ~76ns (single alloc).
- **Parallel benchmark throughput was measured at GOMAXPROCS=16** (benchmarks run with rate limiting and data budget disabled to isolate scanning overhead; per-op time rises under SMT contention on this 8-core/16-thread part).

## Hardware

AMD Ryzen 7 7800X3D (8 cores / 16 threads) / Go 1.25 / Linux 6.x / Fedora 43

## Running Benchmarks

```bash
# Sequential (default)
make bench

# Advisory scanner/MCP regression guard against bench/scanner-baseline.txt
make bench-regression

# Regenerate the moving local baseline after an intentional benchmark refresh
make bench-baseline

# Parallel scaling
go test -bench=BenchmarkParallel -benchtime=3s -cpu=1,2,4,8,16 ./internal/scanner/
go test -bench=BenchmarkParallel -benchtime=3s -cpu=1,4,8,16 ./internal/mcp/

# Concurrent throughput scaling test (1-64 goroutines, ~28s)
PIPELOCK_BENCH_SCALING=1 go test -v -run=TestConcurrentThroughputScaling ./internal/scanner/

# Seed phrase detection
go test -bench=BenchmarkSeed -benchmem ./internal/seedprotect/
```

`make bench-regression` runs the scanner and MCP benchmarks with fixed `-count`
and `-benchtime`, then compares the fastest (min) `ns/op` per benchmark against
`bench/scanner-baseline.txt` straight from the raw `go test` output, and fails
when any benchmark regresses beyond `BENCH_REGRESSION_THRESHOLD_PCT` (default
`50`). The pass/fail decision does not depend on `benchstat`; if `benchstat` is
installed it is used only to print a readable summary. Set `BENCH_BASELINE` to
compare against a different baseline. This guard is an advisory maintainer/pre-tag
check, not a machine-independent CI gate, so it is intentionally not wired into
blocking CI.

## BIP-39 Seed Phrase Detection (`seedprotect.Detect()`)

Dedicated scanner for BIP-39 mnemonic seed phrases. Uses dictionary lookup + sliding window + SHA-256 checksum validation. Run `go test -bench=BenchmarkSeed -benchmem ./internal/seedprotect/` for current numbers on your hardware.

| Benchmark | ns/op | B/op | allocs/op | Description |
|-----------|-------|------|-----------|-------------|
| `SeedDetect_CleanText` | 2,229 | 1,803 | 20 | Short text with no BIP-39 words (fast bail) |
| `SeedDetect_ValidPhrase` | 2,926 | 1,756 | 18 | 12-word valid mnemonic (full pipeline + checksum) |
| `SeedDetect_LongText` | 2,853,140 | 858,447 | 6,368 | 1000-word text, all BIP-39 words (worst case) |
| `SeedChecksum` | 136 | 0 | 0 | Checksum validation in isolation |

Clean text bails in ~2μs. Valid phrase detection including checksum takes ~3μs. The 1000-word worst case (all BIP-39 words) is a pathological input that doesn't occur in real traffic. Checksum validation is 136ns with zero allocations.
