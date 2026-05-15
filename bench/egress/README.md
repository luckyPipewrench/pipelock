# bench/egress — agent egress overhead benchmark

End-to-end latency, cold-start, and steady-state memory measurement for a running pipelock instance. Five transports: HTTP, SSE, tool-call chain, MCP stdio, WebSocket. All backends are deterministic in-repo mocks so numbers are reproducible without external API keys.

The goal is to answer **"how much does pipelock add to my agent's request path?"** with numbers a reader can re-run on their own machine. It is **not** a competitive benchmark and not a security correctness benchmark — see [`agent-egress-bench`](https://github.com/luckyPipewrench/agent-egress-bench) for accuracy.

## Quick start

```bash
# From the pipelock repo root:
make bench-egress          # quick mode, usually 1-3 minutes, no memory sampling
make bench-egress-long     # quick latency + 30 minute memory sampling
make bench-egress-release  # full iteration counts + memory (used for the public page)
```

Output is a single JSON document at `bench/egress/results.json` containing per-transport `direct` vs `proxied` percentiles, a cold-start table for three configs, and (if enabled) a memory time series.

## What gets measured

For each transport, the harness drives N requests directly against the mock and N requests through a running pipelock subprocess, in **adjacent pairs** so thermal and scheduler drift affect both measurements equally. Reported metrics:

| Transport | Workload | Direct & proxied stats | Streaming stats |
|---|---|---|---|
| `http` | Single GET, 1 KiB body | p50/p95/p99 round-trip | n/a |
| `sse` | 100-chunk text/event-stream | full-stream p50/p95/p99 | TTFB p50/p95/p99 |
| `toolchain` | N sequential `tool_use` POSTs to a Claude-shaped mock | per-iteration p50/p95/p99 | n/a |
| `mcp_stdio` | JSON-RPC `tools/call` over `pipelock mcp proxy --` stdio | per-call p50/p95/p99 | n/a |
| `websocket` | Connect + 100 text frames echo | per-iteration p50/p95/p99 | TTFB p50/p95/p99 |

**Cold-start** is measured three ways per config (minimal / default / full):

1. `process_started`: exec returned (always near zero, included for completeness).
2. `health_ready`: first 200 from `GET /health`.
3. `first_request_served`: first proxied HTTP request through pipelock succeeded.

The headline number is `first_request_served`. That's the only signal that means "pipelock is fully usable."

**Memory** samples `/proc/<pid>/status` (VmRSS, VmPeak) at a configurable interval (default 10s) for a configurable duration (default 30 minutes in `--release` mode). Each tick also scrapes pipelock's Prometheus `/metrics` endpoint for Go runtime collectors (`go_memstats_heap_alloc_bytes`, `go_memstats_heap_sys_bytes`, `go_memstats_heap_inuse_bytes`, `go_goroutines`) and the standard `process_resident_memory_bytes` gauge. Output is a per-sample time series plus mean / p99 / max for both RSS and heap.

## Configs

The cold-start measurement uses three configs that ship in this directory:

| File | Mode | What's enabled |
|---|---|---|
| `configs/minimal.yaml` | `audit` | No scanners, no patterns. Fastest startup. |
| `configs/default.yaml` | `balanced` | Default DLP patterns, MCP input/tool scanning. Used as the latency arm too. |
| `configs/full.yaml` | `strict` | Every scanner: adaptive enforcement, session profiling, address protection, seed-phrase detection, request-body scanning. |

All three set `ssrf.ip_allowlist: ["127.0.0.0/8"]` so the harness's localhost mocks are reachable. Real deployments do not exempt 127.0.0.0/8.

**Response scanning is OFF in every bench config.** Pipelock's response scanner reads the full body before forwarding, which converts streaming SSE into a one-shot round trip and breaks the TTFB measurement. Operators running pipelock with `response_scanning.enabled: true` should expect SSE numbers higher than this page reports. The cold-start configs preserve this trade-off so the three numbers are comparable.

## JSON schema

```jsonc
{
  "bench_version": "0.1.0",
  "started_at": "2026-05-15T15:10:27Z",
  "finished_at": "2026-05-15T15:11:17Z",
  "mode": "quick",                          // "quick" or "release"
  "host": {
    "os": "linux", "arch": "amd64",
    "num_cpu": 16, "gomaxprocs": 16,
    "go_version": "go1.25.x",
    "kernel": "Linux 6.x.y",
    "cpu_model": "...", "cpu_governor": "powersave",
    "mem_total_kb": 65461940
  },
  "pipelock": {
    "git_sha": "...", "git_dirty": false,
    "version": "pipelock version v2.5.0",
    "binary_path": "..."
  },
  "pipelock_listen": "127.0.0.1:PORT",
  "pipelock_metrics_listen": "127.0.0.1:PORT",
  "latency_config_name": "default",
  "latency_config_sha256": "...",
  "latency": {
    "http":      { "transport": "http",      "direct": Stats, "proxied": Stats, "elapsed_ns": N },
    "sse":       { "transport": "sse",       "direct": Stats, "proxied": Stats, "ttfb": { "direct": Stats, "proxied": Stats }, "elapsed_ns": N },
    "toolchain": { "transport": "toolchain", "direct": Stats, "proxied": Stats, "notes": "3 tool_use rounds per iteration", "elapsed_ns": N },
    "websocket": { "transport": "websocket", "direct": Stats, "proxied": Stats, "ttfb": { "direct": Stats, "proxied": Stats }, "notes": "100 frames per iteration", "elapsed_ns": N },
    "mcp_stdio": { "transport": "mcp_stdio", "direct": Stats, "proxied": Stats, "elapsed_ns": N }
  },
  "cold_start": [
    { "config": "minimal", "process_started": Stats, "health_ready": Stats, "first_request_served": Stats },
    { "config": "default", "process_started": Stats, "health_ready": Stats, "first_request_served": Stats },
    { "config": "full",    "process_started": Stats, "health_ready": Stats, "first_request_served": Stats }
  ],
  "memory": {
    "duration_ms": 1800000, "sample_interval_ms": 10000,
    "metrics_scraped": true,
    "samples": [
      { "offset_ms": N, "rss_kb": N, "vmpeak_kb": N, "vmsize_kb": N,
        "heap_alloc_bytes": N, "heap_sys_bytes": N, "heap_inuse_bytes": N,
        "goroutines": N, "process_rss_bytes": N },
      ...
    ],
    "mean_rss_kb": N, "p99_rss_kb": N, "max_rss_kb": N, "max_vmpeak_kb": N,
    "mean_heap_alloc_kb": N, "p99_heap_alloc_kb": N,
    "max_heap_sys_kb": N, "max_goroutines": N
  }
}
```

`Stats` is:
```jsonc
{ "n": 1000, "mean_ns": N, "p50_ns": N, "p95_ns": N, "p99_ns": N, "min_ns": N, "max_ns": N, "stddev_ns": N }
```

Percentiles use the nearest-rank method (NIST). For a sample of N values, p50 = sorted[ceil(0.5*N) - 1].

## Reproducibility

The bench is deterministic to a useful degree but not bit-for-bit. Run-to-run differences come from:

- Kernel scheduling and CPU frequency scaling (set `cpu_governor=performance` for tighter numbers).
- Other processes on the box (the bench does not pin to specific CPUs).
- Go runtime GC scheduling.

For the public `/learn/performance/` page we use `--release` mode on a quiet box, which raises iteration counts and adds the 30-minute memory window. Your numbers will differ. The repro command stays single-shot:

```bash
git clone https://github.com/luckyPipewrench/pipelock
cd pipelock
make bench-egress
cat bench/egress/results.json
```

## Known caveats

- **SSE proxied numbers depend on `response_scanning`.** With response scanning ON, pipelock buffers the body and the stream is no longer a stream. The bench configs disable response scanning. Document accordingly when quoting SSE numbers.
- **WebSocket loop is per-frame round-trip.** Each iteration is `send + read echo` × 100. Per-frame overhead is `total / 100`, not the headline number.
- **MCP stdio direct baseline includes process re-spawn cost across iterations? No** — the subprocess is started once and reused, so the per-call number is wire latency + JSON serialization, not fork/exec.
- **Cold-start is sensitive to `--listen` port reuse.** The harness picks a random free port per iteration; on a busy box this can occasionally race with another process. Re-run if a cold-start row shows an outlier in `max_ns`.
- **Bench writes a transient runtime config.** Pipelock's `run` subcommand does not expose a `--metrics-listen` flag. The bench reads `configs/default.yaml`, appends `metrics_listen: 127.0.0.1:<random-port>`, writes the result to a temp file, and points pipelock at the temp file. The temp file is removed at the end of the run.

## Layout

```
bench/egress/
  mocks/
    httpecho/        Canned 1 KiB body
    sse/             100-chunk text/event-stream
    toolchain/       Claude-shaped tool_use chain (chainLen configurable)
    wsfeed/          Minimal RFC 6455 echo server (raw frame impl, no deps)
    mcpstdio/        Binary: minimal MCP server (initialize + tools/list + tools/call)
  harness/
    stats.go         Percentiles + summary type
    latency.go       Five transport runners + paired-loop helper
    coldstart.go     Three-signal cold-start with /health polling
    memory.go        /proc/<pid>/status sampler
    probe.go         Health probe + free-port helper
  configs/
    minimal.yaml     Audit mode, no patterns
    default.yaml     Balanced + default patterns
    full.yaml        Strict + every scanner
  cmd/bench-egress/  Entry binary
  run-all.sh         Wrapper that builds pipelock + bench-egress + mcpstdio and runs
  README.md          (this file)
```

## CI

Not enabled. The bench takes minutes (or 30+ in `--release` mode), produces machine-dependent numbers, and is meant to be re-run by operators. Promoting it to CI would either slow PRs unacceptably or produce noisy numbers that don't compare across runners.

The bench code (mocks + harness + entry) is exercised by `go test -race ./bench/...` in the standard test pass.
