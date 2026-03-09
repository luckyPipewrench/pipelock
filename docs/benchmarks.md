# Pipelock Benchmarks

## Methodology

Benchmarks measure the scanner pipeline only, not network I/O. This isolates Pipelock's overhead from the external fetch latency.

Configuration used for these benchmarks (balanced defaults):
- SSRF protection disabled (no DNS lookups)
- Rate limiting disabled (no time-dependent state)
- Response scanning: 20 prompt injection patterns
- DLP: 22 patterns

> **Note:** Overhead scales linearly with pattern count. Typical URLs scan in ~37us. URLs exceeding the configured length limit take ~6ms (the `BlockedByURLLength` path runs earlier pipeline stages before the length check rejects). Run `make bench` with your config to measure.

Run `make bench` to reproduce on your hardware.

## Scanner Pipeline (`Scanner.Scan()`)

Full 9-layer URL scanning: scheme, blocklist, DLP (pre-DNS), path entropy, subdomain entropy, SSRF (post-DNS), rate limit, URL length, data budget.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| AllowedURL | 36,935 | 1,412 | 26 |
| BlockedByBlocklist | 404 | 288 | 5 |
| BlockedByDLP | 10,842 | 2,262 | 41 |
| BlockedByEntropy | 64,945 | 4,286 | 50 |
| BlockedByURLLength | 6,074,933 | 70,386 | 52 |
| ComplexAllowedURL | 49,894 | 3,456 | 84 |

## Response Scanning (`ScanResponse()`)

Pattern matching for prompt injection on fetched content. Benchmarked with 20 patterns.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean (~90B) | 117,775 | 504 | 7 |
| WithInjection (~100B) | 46,443 | 377 | 3 |
| LargeClean (~10KB) | 15,353,183 | 53,340 | 9 |

## MCP Response Scanning (`mcp.ScanResponse()`)

JSON-RPC 2.0 response parsing + text extraction + prompt injection scanning.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 103,641 | 1,408 | 28 |
| Injection | 36,130 | 1,457 | 25 |
| ExtractText (5 blocks) | 2,340 | 1,080 | 23 |

## Key Takeaways

- **Full 9-layer scan on a typical URL: ~37 microseconds.** Well under 1ms.
- Blocked URLs short-circuit early: blocklist check is ~400ns.
- DLP regex matching (22 patterns) adds ~11 microseconds.
- Response scanning with 20 patterns on small content: ~118 microseconds. Large content (~10KB) takes ~15ms due to 6 normalization passes plus regex cost scaling with input size.
- MCP scanning (JSON parse + text extraction + pattern match): ~104 microseconds.
- The scanner pipeline adds **~0.037ms overhead for typical URL requests**. Network latency dominates.
- Exception: `BlockedByURLLength` (~6ms) measures an over-limit URL rejected at the length check after earlier pipeline stages. This path only triggers when a URL exceeds the configured limit.

## Running Benchmarks

```bash
make bench
```

Numbers above from AMD Ryzen 7 7800X3D / Go 1.24 / Linux. Results vary by hardware.
