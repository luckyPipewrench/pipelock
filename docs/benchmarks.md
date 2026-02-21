# Pipelock Benchmarks

## Methodology

Benchmarks measure the scanner pipeline only, not network I/O. This isolates Pipelock's overhead from the external fetch latency.

Configuration used for these benchmarks (v0.2.5, balanced defaults):
- SSRF protection disabled (no DNS lookups)
- Rate limiting disabled (no time-dependent state)
- Response scanning: 20 prompt injection patterns
- DLP: 15 patterns

> **Note:** Overhead scales linearly with pattern count but stays well under 1ms even with custom patterns added. Run `make bench` with your config to measure.

Run `make bench` to reproduce on your hardware.

## Scanner Pipeline (`Scanner.Scan()`)

Full 9-layer URL scanning: scheme, blocklist, DLP (pre-DNS), path entropy, subdomain entropy, SSRF (post-DNS), rate limit, URL length, data budget.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| AllowedURL | 24,428 | 1,213 | 19 |
| BlockedByBlocklist | 378 | 288 | 5 |
| BlockedByDLP | 5,927 | 1,314 | 18 |
| BlockedByEntropy | 29,161 | 2,990 | 23 |
| BlockedByURLLength | 1,443,271 | 5,478 | 19 |
| ComplexAllowedURL | 29,473 | 2,693 | 42 |

## Response Scanning (`ScanResponse()`)

Pattern matching for prompt injection on fetched content. Benchmarked with 20 patterns.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean (~90B) | 44,211 | 1 | 0 |
| WithInjection (~100B) | 44,547 | 385 | 3 |
| LargeClean (~10KB) | 6,142,581 | 487 | 0 |

## MCP Response Scanning (`mcp.ScanResponse()`)

JSON-RPC 2.0 response parsing + text extraction + prompt injection scanning.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 42,231 | 985 | 21 |
| Injection | 39,570 | 1,462 | 25 |
| ExtractText (5 blocks) | 2,451 | 1,080 | 23 |

## Key Takeaways

- **Full 9-layer scan on a typical URL: ~25 microseconds.** Well under 1ms.
- Blocked URLs short-circuit early: blocklist check is ~378ns.
- DLP regex matching (15 patterns) adds ~6 microseconds.
- Response scanning with 20 patterns on small content: ~44 microseconds.
- MCP scanning (JSON parse + text extraction + pattern match): ~42 microseconds.
- The scanner pipeline adds **< 0.03ms overhead per request**. Network latency dominates.

## Running Benchmarks

```bash
make bench
```

Numbers above from AMD Ryzen 7 7800X3D / Go 1.24 / Linux. Results vary by hardware.
