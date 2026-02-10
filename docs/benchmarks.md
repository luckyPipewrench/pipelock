# Pipelock Benchmarks

## Methodology

Benchmarks measure the scanner pipeline only, not network I/O. This isolates Pipelock's overhead from the external fetch latency.

Configuration:
- SSRF protection disabled (no DNS lookups)
- Rate limiting disabled (no time-dependent state)
- Response scanning uses the 5 default prompt injection patterns
- DLP uses 8 default patterns (API keys, tokens, credentials)

Run `make bench` to reproduce on your hardware.

## Scanner Pipeline (`Scanner.Scan()`)

Full 7-layer URL scanning: scheme, SSRF, blocklist, rate limit, URL length, DLP, entropy.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| AllowedURL | 3,150 | 976 | 14 |
| BlockedByBlocklist | 367 | 288 | 5 |
| BlockedByDLP | 1,325 | 1,100 | 15 |
| BlockedByEntropy | 4,620 | 2,837 | 20 |
| BlockedByURLLength | 8,535 | 496 | 10 |
| ComplexAllowedURL | 4,745 | 1,822 | 24 |

## Response Scanning (`ScanResponse()`)

Pattern matching for prompt injection on fetched content. 5 regex patterns.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean (~90B) | 13,880 | 0 | 0 |
| WithInjection (~100B) | 14,400 | 369 | 3 |
| LargeClean (~10KB) | 1,880,000 | 88 | 0 |

## MCP Response Scanning (`mcp.ScanResponse()`)

JSON-RPC 2.0 response parsing + text extraction + prompt injection scanning.

| Benchmark | ns/op | B/op | allocs/op |
|-----------|------:|-----:|----------:|
| Clean | 13,285 | 601 | 15 |
| Injection | 13,085 | 1,069 | 19 |
| ExtractText (5 blocks) | 60 | 144 | 2 |

## Key Takeaways

- **Full 7-layer scan on a typical URL: ~3 microseconds.** Well under 1ms.
- Blocked URLs short-circuit early: blocklist check is ~370ns.
- DLP regex matching (8 patterns) adds ~1.3 microseconds.
- Response scanning with 5 patterns on small content: ~14 microseconds.
- MCP scanning (JSON parse + text extraction + pattern match): ~13 microseconds.
- The scanner pipeline adds **< 0.005ms overhead per request**. Network latency dominates.

## Running Benchmarks

```bash
make bench
```

Numbers above from AMD Ryzen 7 7800X3D / Go 1.24 / Linux. Results vary by hardware.
