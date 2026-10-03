# Pipelock Benchmarks

Raw benchmark data from Go's testing framework. For interpretation and deployment sizing, see [performance.md](performance.md).

## Methodology

Benchmarks measure the scanner pipeline only, not network I/O. This isolates pipelock's overhead from external fetch latency.

Configuration (balanced defaults):
- SSRF protection disabled (no DNS lookups in benchmarks)
- Rate limiting disabled (no time-dependent state)
- Response scanning: 34 prompt-injection and state/control-poisoning patterns
- DLP: 65 patterns + BIP-39 seed phrase detection

The scanner and MCP figures below are medians of three runs against the released v3.6.0 tag at commit `3e868ac5d`, using Go 1.26.8 on the hardware listed at the bottom with `GOMAXPROCS=4`. The standard `make bench` run used Go's default one-second benchmark target and `-count=3`. Large-body cases still have high variance: the 256KiB uniform-filler clean case completed only three iterations per sample, and the 20-query URL case completed five or six. These are local CPU costs, not network latency or production request-rate guarantees. Response scanning evaluates its patterns in parallel, so results depend on the CPUs available. Fixture-backed browser and saved JavaScript bundle benchmarks were skipped; they need generated input directories. The BIP-39 and historical parallel-scaling tables below weren't part of this scanner/MCP run.

## Scanner Pipeline (`Scanner.Scan()`)

URL scanning with DNS-based SSRF, rate limiting, and data budget checks disabled: scheme, CRLF injection, path traversal, blocklist, DLP (pre-DNS), path entropy, subdomain entropy, and URL length. DNS resolution, the post-DNS SSRF layer, rate limiting, and data budget enforcement are excluded from these measurements.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| AllowedURL | 24,989 | 8,451 | 116 |
| BlockedByBlocklist | 2,623 | 744 | 20 |
| BlockedByDLP | 12,206 | 7,321 | 143 |
| BlockedByEntropy | 46,189 | 19,591 | 226 |
| BlockedByURLLength | 140.3 | 64 | 3 |
| ComplexAllowedURL | 158,048 | 74,146 | 1,040 |

`BenchmarkScan_ManyQueryParamsAllowed` is a separate stress case: a clean allowed URL with 20 query parameters lets every DLP pass run to completion. It measured 206,022,910 ns/op, 43,546,905 B/op, and 841,560 allocs/op. This is a deliberately heavy input, not a typical URL scan.

## Response Scanning (`ScanResponse()`)

Pattern matching for prompt injection on fetched content, across the multi-pass normalization cascade (normalized, invisible-spaced, leetspeak, optional-whitespace, vowel-fold, decode).

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean (~90B) | 69,231 | 4,314 | 28 |
| WithInjection (~100B) | 72,577 | 1,875 | 16 |
| LargeClean (~10KB) | 3,996,104 | 106,643 | 59 |
| StateControlClean | 406,017 | 6,373 | 28 |
| StateControlMatch | 289,576 | 5,457 | 28 |

`BenchmarkScanResponse_Large` adds 64KiB and 256KiB bodies in JSON-like, natural-prose, and uniform-filler shapes. Injection cases place the marker near the start or end of the body.

| Benchmark case | ns/op | B/op | allocs/op |
|---------------|------:|-----:|----------:|
| JSON-like 64KiB clean | 27,261,818 | 2,547,904 | 121 |
| Natural prose 64KiB clean | 24,675,550 | 2,186,193 | 83 |
| Uniform filler 64KiB clean | 112,550,998 | 14,077,430 | 305 |
| JSON-like 64KiB injection early | 27,455,395 | 109,487 | 48 |
| JSON-like 64KiB injection late | 29,656,213 | 106,561 | 46 |
| Natural prose 64KiB injection early | 31,652,602 | 111,781 | 50 |
| Natural prose 64KiB injection late | 30,302,209 | 111,704 | 50 |
| Uniform filler 64KiB injection early | 17,586,189 | 109,255 | 46 |
| Uniform filler 64KiB injection late | 18,649,873 | 94,591 | 39 |
| JSON-like 256KiB clean | 106,071,467 | 3,272,900 | 92 |
| Natural prose 256KiB clean | 96,657,117 | 8,634,370 | 114 |
| Uniform filler 256KiB clean | 439,808,792 | 53,370,274 | 389 |
| JSON-like 256KiB injection early | 104,367,053 | 432,130 | 125 |
| JSON-like 256KiB injection late | 108,889,987 | 441,554 | 132 |
| Natural prose 256KiB injection early | 115,031,824 | 450,720 | 136 |
| Natural prose 256KiB injection late | 116,122,309 | 450,698 | 136 |
| Uniform filler 256KiB injection early | 66,018,966 | 357,436 | 80 |
| Uniform filler 256KiB injection late | 67,135,313 | 369,257 | 87 |

## Text DLP Scanning (`ScanTextForDLP()`)

DLP pattern matching on arbitrary text (MCP arguments, request bodies). 65 patterns with Aho-Corasick pre-filter.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 70,923 | 7,777 | 103 |
| Match | 94,564 | 23,489 | 315 |

## Canary Text Scanning

These cases keep one canary token configured and scan ordinary text or a payload that decodes through several nested layers.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean ordinary text | 20,947 | 9,328 | 220 |
| Nested encoded payload | 35,941 | 11,880 | 201 |

An earlier interleaved comparison measured the clean-text canary path about 54% slower than v3.5.0 in the release-candidate comparison. This tag run has no v3.5.0 control, so it reports the 3.6.0 cost but doesn't remeasure that percentage.

## DLP Pre-Filter

Aho-Corasick prefix automaton. Short-circuits clean text before regex evaluation.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| CleanText (no match) | 578.3 | 104 | 2 |
| WithPrefix (match) | 539.9 | 104 | 2 |

## Cross-Request Detection

Entropy budget tracking and fragment buffer for detecting secrets split across multiple requests.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| EntropyTracker_Record | 117,618 | 1,137 | 6 |
| EntropyTracker_RecordMultiSession | 14,424 | 1,103 | 6 |
| FragmentBuffer_Append | 152.5 | 48 | 1 |
| FragmentBuffer_AppendAndScan | 8,847,741 | 735,250 | 1,636 |
| FragmentBufferDeletePrefix | 5,345,191 | 0 | 0 |

## MCP Response Scanning (`mcp.ScanResponse()`)

JSON-RPC 2.0 response parsing + text extraction + prompt injection scanning.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 197,401 | 27,988 | 434 |
| Injection | 154,531 | 34,798 | 521 |
| ExtractText (5 blocks) | 6,568 | 6,053 | 74 |

## Parallel Samples (`b.RunParallel`, GOMAXPROCS=4)

These are the concurrent `b.RunParallel` cases in the tagged scanner/MCP run. They're single four-CPU measurements repeated three times, not a refreshed scaling curve.

### Scanner

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Parallel_URLScan | 48,851 | 74,090 | 1,040 |
| Parallel_DLPBlock | 4,201 | 7,314 | 143 |
| Parallel_ResponseScan | 20,363 | 4,253 | 28 |
| Parallel_ResponseLarge | 1,137,535 | 103,099 | 59 |
| Parallel_Blocklist | 859 | 744 | 20 |
| Parallel_Entropy | 21,758 | 19,578 | 226 |

### MCP

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Parallel_MCPScanClean | 53,527 | 27,509 | 434 |
| Parallel_MCPScanInjection | 42,064 | 34,307 | 521 |
| Parallel_ExtractText | 2,446 | 6,052 | 74 |

## Historical Parallel Throughput (`b.RunParallel`, GOMAXPROCS=16)

The following multi-core tables are historical v3.1.0 results and were not refreshed for v3.6.0.

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
| ShannonEntropy | 2,233 | 2,120 | 7 |
| MatchDomain/exact | 2.4 | 0 | 0 |
| MatchDomain/wildcard | 43 | 48 | 1 |

## Key Takeaways

- **Typical URL scan with DNS-based SSRF, rate limiting, and data budget checks disabled: ~25μs** at the released v3.6.0 tag.
- Blocklist, DLP, entropy, and URL-length blocks measured ~2.6μs, ~12μs, ~46μs, and ~140ns respectively.
- The clean-text canary path measured ~21μs with a canary configured. An earlier interleaved v3.5.0 comparison found it about 54% slower in the release-candidate comparison; this run doesn't repeat that comparison.
- Small response scans measured ~69μs on clean text and ~73μs with injection. The ~10KB clean case measured ~4.0ms. Larger-body costs vary sharply by content shape; the 256KiB uniform-filler clean case completed only three iterations per sample.
- MCP response scans measured ~197μs clean and ~155μs with injection. Text extraction measured ~6.6μs.
- The 20-query-parameter allowed-URL stress case measured ~206ms and 43.5MB allocated. This deliberately heavy workload is separate from the typical URL scan and completed only five or six iterations per sample.
- The multi-core v3.1.0 scaling curves below remain historical. The v3.6.0 run adds four-CPU parallel samples, not a new scaling study.

## Hardware

AMD Ryzen 7 7800X3D (8 cores / 16 threads) / Linux/amd64. Scanner and MCP tables: released v3.6.0 commit `3e868ac5d`, Go 1.26.8, `GOMAXPROCS=4`, standard `make bench` (`-count=3`, default one-second benchmark target); values are medians of three samples. BIP-39 seed-phrase tables: older results, not included in this run. Historical parallel-scaling tables: v3.1.0, Go 1.25, 16 CPUs.

## Running Benchmarks

```bash
# Released-tag scanner and MCP suite
GOMAXPROCS=4 make bench

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
