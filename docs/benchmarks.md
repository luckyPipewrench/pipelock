# Pipelock Benchmarks

Raw benchmark data from Go's testing framework. For interpretation and deployment sizing, see [performance.md](performance.md).

## Methodology

Benchmarks measure the scanner pipeline only, not network I/O. This isolates pipelock's overhead from external fetch latency.

Configuration (balanced defaults):
- SSRF protection disabled (no DNS lookups in benchmarks)
- Rate limiting disabled (no time-dependent state)
- Response scanning: 34 prompt-injection and state/control-poisoning patterns
- DLP: 65 patterns + BIP-39 seed phrase detection

Run `make bench` to reproduce on your hardware. Single-request numbers below are the median of three runs at pre-release commit `7283f25e7` for v3.6.0, with Go 1.26.0 on the hardware listed at the bottom and a process limit of four CPUs (`GOMAXPROCS=4`). Later changes in the release branch are not represented by that measurement. Response scanning evaluates its patterns in parallel, so its figures depend on the CPUs available and can be lower on a machine that gives the process more. The parallel throughput section is still from v3.1.0 with 16 CPUs and says so.

## Scanner Pipeline (`Scanner.Scan()`)

URL scanning with DNS-based SSRF, rate limiting, and data budget checks disabled: scheme, CRLF injection, path traversal, blocklist, DLP (pre-DNS), path entropy, subdomain entropy, and URL length. DNS resolution, the post-DNS SSRF layer, rate limiting, and data budget enforcement are excluded from these measurements.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| AllowedURL | 52,585 | 10,184 | 224 |
| BlockedByBlocklist | 2,817 | 760 | 21 |
| BlockedByDLP | 15,164 | 8,466 | 243 |
| BlockedByEntropy | 91,223 | 27,464 | 630 |
| BlockedByURLLength | 320 | 160 | 5 |
| ComplexAllowedURL | 255,189 | 85,535 | 2,001 |

## Response Scanning (`ScanResponse()`)

Pattern matching for prompt injection on fetched content, across the multi-pass normalization cascade (normalized, invisible-spaced, leetspeak, optional-whitespace, vowel-fold, decode).

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean (~90B) | 65,822 | 4,302 | 28 |
| WithInjection (~100B) | 66,689 | 2,108 | 11 |
| LargeClean (~10KB) | 5,545,968 | 86,399 | 14 |
| StateControlClean | 384,163 | 6,323 | 28 |
| StateControlMatch | 285,188 | 5,458 | 28 |

## Text DLP Scanning (`ScanTextForDLP()`)

DLP pattern matching on arbitrary text (MCP arguments, request bodies). 65 patterns with Aho-Corasick pre-filter.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 118,326 | 13,671 | 267 |
| Match | 159,391 | 37,176 | 791 |

## DLP Pre-Filter

Aho-Corasick prefix automaton. Short-circuits clean text before regex evaluation.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| CleanText (no match) | 1,115 | 104 | 2 |
| WithPrefix (match) | 926 | 104 | 2 |

## Cross-Request Detection

Entropy budget tracking and fragment buffer for detecting secrets split across multiple requests.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| EntropyTracker_Record | 110,469 | 1,169 | 6 |
| EntropyTracker_RecordMultiSession | 14,052 | 1,105 | 6 |
| FragmentBuffer_Append | 194 | 321 | 2 |
| FragmentBuffer_AppendAndScan | 10,387,231 | 1,658,632 | 5,301 |

## MCP Response Scanning (`mcp.ScanResponse()`)

JSON-RPC 2.0 response parsing + text extraction + prompt injection scanning.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 315,819 | 50,129 | 1,179 |
| Injection | 280,299 | 54,525 | 1,311 |
| ExtractText (5 blocks) | 9,475 | 9,840 | 131 |

## Parallel Throughput (`b.RunParallel`, GOMAXPROCS=16)

True concurrent throughput across all available goroutines. Measured on v3.1.0; these numbers have not been refreshed for v3.6.0.

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
| ShannonEntropy | 2,200 | 2,120 | 7 |
| MatchDomain/exact | 267 | 48 | 1 |
| MatchDomain/wildcard | 341 | 64 | 2 |

## Key Takeaways

- **Typical URL scan with DNS-based SSRF, rate limiting, and data budget checks disabled: ~53 microseconds** (pre-release v3.6.0 commit `7283f25e7`). Well under 1ms; network latency dominates real requests. It was ~39μs in v3.1.0.
- Blocked URLs short-circuit early: the blocklist check is ~3μs, and an over-length URL is rejected in ~320ns before any expensive layer runs.
- A DLP block on a URL takes ~15μs. The pre-filter alone takes ~1.1μs on clean text with two small allocations.
- Response scanning runs the full multi-pass normalization cascade: ~66μs on small clean content and ~67μs when injection is detected. State/control patterns add cost on clean text (~384μs). Large content (~10KB) takes ~5.5ms, down from ~46ms in v3.1.0.
- MCP scanning (JSON parse + text extraction + pattern match): ~316μs clean, ~280μs injection.
- Cross-request entropy tracking: ~110μs per record. Fragment buffer append: ~194ns.
- **Parallel throughput figures are from v3.1.0 at GOMAXPROCS=16** and were not re-measured for v3.6.0 (benchmarks run with rate limiting and data budget disabled to isolate scanning overhead; per-op time rises under SMT contention on this 8-core/16-thread part).

## Hardware

AMD Ryzen 7 7800X3D (8 cores / 16 threads) / Linux / Fedora 43. Single-request and seed-phrase tables: pre-release v3.6.0 commit `7283f25e7`, Go 1.26.0, `GOMAXPROCS=4`. Parallel tables: v3.1.0, Go 1.25, 16 CPUs.

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
| `SeedDetect_CleanText` | 2,073 | 528 | 3 | Short text with no BIP-39 words (fast bail) |
| `SeedDetect_ValidPhrase` | 2,832 | 688 | 4 | 12-word valid mnemonic (full pipeline + checksum) |
| `SeedDetect_LongText` | 2,472,856 | 796,784 | 5,366 | 1000-word text, all BIP-39 words (worst case) |
| `SeedChecksum` | 118 | 0 | 0 | Checksum validation in isolation |

Clean text bails in ~2μs. Valid phrase detection including checksum takes ~3μs. The 1000-word worst case (all BIP-39 words) is a pathological input that doesn't occur in real traffic. Checksum validation is ~118ns with zero allocations.
