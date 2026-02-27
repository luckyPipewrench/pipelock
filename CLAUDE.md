# CLAUDE.md — Pipelock Development Guide

Pipelock is an agent firewall — a network proxy that sits between AI agents and the internet, scanning all HTTP/WebSocket/MCP traffic for secret exfiltration, prompt injection, SSRF, and tool poisoning.

## Hard Rules

These are non-negotiable. Violating any of them breaks the security model.

- **Never weaken capability separation.** The proxy runs in the unprivileged zone (no secrets, full network). The agent runs in the privileged zone (has secrets, no direct network). If pipelock ever needs access to agent secrets, the architecture is wrong.
- **Never bypass fail-closed defaults.** HITL timeout, non-terminal input, parse errors, context cancellation — all default to **block**. If in doubt, block.
- **Never add dependencies without justification.** 8 direct deps is intentional, not a limitation. Every dependency is attack surface. Propose additions in the PR description with rationale.
- **Never panic on runtime input.** All `panic()` calls in the codebase are post-validation programming errors caught at startup (invalid DLP regex, bad CIDR after config validation). User/agent input must never cause a panic.
- **DLP runs before DNS resolution.** Layers 2-3 (blocklist, DLP) execute before layer 6 (SSRF/DNS). Reordering them would allow secret exfiltration via DNS queries.

## Quick Reference

| Item | Value |
|------|-------|
| Module | `github.com/luckyPipewrench/pipelock` |
| Go | 1.24+ (CI tests 1.24 + 1.25 — code must compile on both) |
| License | Apache 2.0 |
| Binary | Single static binary, ~12MB |
| Deps | cobra, zerolog, go-readability, yaml.v3, prometheus, fsnotify, x/text, gobwas/ws |

## Build, Test, Lint

```bash
make build          # Compile with version ldflags
make test           # go test -race -count=1 ./...
make test-cover     # Coverage report → coverage.html
make lint           # golangci-lint (v2, 19 linters, gofumpt)
make bench          # Benchmarks for scanner + mcp
make fmt            # gofmt -s (CI enforces gofumpt — run `gofumpt -w .` locally)
make vet            # Static analysis
make tidy-check     # Verify go.mod/go.sum
make docker         # Docker image
```

Pre-commit (both must pass before pushing):
```bash
golangci-lint run --new-from-rev=HEAD ./...
go test -race -count=1 ./...
```

CI runs lint and tests on **all** code, not just changed files.

## Project Structure

```
cmd/pipelock/           Entry point
internal/
  cli/                  Cobra commands (20+ subcommands)
  proxy/                HTTP proxy: /fetch, CONNECT, /ws, /health, /metrics, /stats
  scanner/              9-layer URL scanning pipeline + response injection detection
  config/               YAML config, validation, hot-reload (fsnotify + SIGHUP)
  audit/                Structured JSON logging (zerolog) + event emission dispatch
  mcp/                  MCP proxy: bidirectional scanning, tool poisoning, input scanning
    chains/             Tool call chain detection (subsequence matching, 8 built-in patterns)
    jsonrpc/            JSON-RPC 2.0 types and text extraction
    policy/             Pre-execution tool call policy rules
    tools/              Tool description scanning + rug-pull (drift) detection
    transport/          Message framing (stdio newline-delimited, SSE, HTTP)
  killswitch/           Emergency deny-all (4 sources: config, API, SIGUSR1, sentinel file)
  emit/                 Event emission (webhook + syslog sinks, fire-and-forget)
  normalize/            Unicode normalization (NFKC, confusables, combining marks, leetspeak)
  hitl/                 Human-in-the-loop terminal approval
  integrity/            SHA256 file manifests
  signing/              Ed25519 key management
  gitprotect/           Git diff scanning for secrets
  metrics/              Prometheus counters/histograms/gauges + JSON /stats
  projectscan/          Project directory scanning for audit command
configs/                Presets: balanced, strict, audit, claude-code, cursor, generic-agent
docs/                   Guides, OWASP mapping, comparison
```

## Architecture

**Capability separation** — the agent (secrets, no network) talks to pipelock (no secrets, full network) which talks to the internet. Three proxy modes on the same port:

- **Fetch** (`/fetch?url=...`) — fetches URL, extracts text, scans response for injection
- **Forward** (CONNECT + absolute-URI) — standard HTTP proxy via `HTTPS_PROXY`, scans hostname through 9-layer pipeline
- **WebSocket** (`/ws?url=...`) — bidirectional frame scanning, DLP on headers, fragment reassembly

```
Agent (secrets, no network) → Pipelock (no secrets, full network) → Internet
```

### Scanner Pipeline

1. Scheme (http/https only) → 2. Domain blocklist → 3. DLP (15+ patterns, env leak detection, entropy) → 4. Path entropy → 5. Subdomain entropy → 6. SSRF (private IPs, metadata, DNS rebinding) → 7. Rate limiting → 8. URL length → 9. Data budget

Layers 2-3 run **before** DNS resolution. Layer 6 runs **after**. This ordering prevents DNS-based exfiltration.

### MCP Proxy

Wraps any MCP server with bidirectional scanning. Three transport modes:
- **Stdio** (`-- COMMAND`) — subprocess wrapping
- **Streamable HTTP** (`--upstream URL`) — stdio-to-HTTP bridge
- **HTTP reverse proxy** (`--listen ADDR --upstream URL`) — also available via `pipelock run --mcp-listen --mcp-upstream`

Scanning layers:
- **Response scanning** — prompt injection detection in tool results
- **Input scanning** — DLP + injection in tool arguments (`mcp_input_scanning`)
- **Tool scanning** — poisoned descriptions + rug-pull drift detection (`mcp_tool_scanning`)
- **Tool policy** — pre-execution allow/deny rules with shell obfuscation detection (`mcp_tool_policy`)
- **Chain detection** — subsequence matching on tool call sequences (`tool_chain_detection`)
- **Session binding** — tool inventory pinning per session (`mcp_session_binding`)

### Config System

YAML config loaded at startup. Hot-reload via fsnotify file watch + SIGHUP signal (100ms debounce). Reload atomically swaps config, scanner, and session manager via `atomic.Pointer[T]`. Kill switch state (all 4 sources) is preserved across reloads.

Top-level sections: `mode`, `enforce`, `api_allowlist`, `suppress`, `fetch_proxy`, `forward_proxy`, `websocket_proxy`, `dlp`, `response_scanning`, `mcp_input_scanning`, `mcp_tool_scanning`, `mcp_tool_policy`, `mcp_session_binding`, `session_profiling`, `adaptive_enforcement`, `kill_switch`, `emit`, `tool_chain_detection`, `git_protection`, `logging`, `internal`.

Action constants: `config.ActionBlock`, `ActionWarn`, `ActionAsk`, `ActionStrip`, `ActionForward`.

### Architectural Principles

- **Fail-closed everywhere.** Timeouts, parse errors, non-terminal HITL, context cancellation — all block.
- **OR-composed kill switch.** Four independent sources (config, API, SIGUSR1, sentinel file) tracked via atomic bools. Any one active = all traffic denied. Deactivating one doesn't affect others.
- **Fire-and-forget emission.** Webhook uses async buffered channel. Syslog is synchronous but UDP. Neither blocks the proxy. Queue overflow = drop + Prometheus counter.
- **Severity is not user-configurable.** Event severity is hardcoded per event type. Users control the emission *threshold* (`min_severity`), not the severity itself. This prevents misconfiguration hiding critical events.
- **Port isolation.** When `kill_switch.api_listen` is set, the API runs on a dedicated port. Main port gets no API route registration and no path exemption. Agent cannot self-deactivate.

### Implementation Gotchas

- `cfg.Internal = nil` disables SSRF checks (not empty slice). Used in tests to avoid DNS lookups.
- `Scanner.New()` panics on invalid DLP regex/CIDRs — these are programming errors after config validation, never runtime errors.
- `json.RawMessage("null")` is non-nil in Go. Must use `string(raw) == "null"`, not `raw == nil`. Checking nil would be a bypass vector.
- HITL uses a single reader goroutine that owns the `bufio.Reader`. Prevents data races on concurrent terminal reads.
- Tool baseline caps at 10,000 tools per session. Prevents unbounded memory from malicious MCP servers.
- DLP patterns are auto-prefixed with `(?i)` — agents can uppercase secrets, so matching is always case-insensitive.

## Testing

- **Race detector mandatory**: `-race -count=1` on all tests.
- **95% coverage target** on new code. See README for current count.
- Count test cases (including subtests): `go test -v ./... 2>&1 | grep -c -- '--- PASS:'`

### Patterns

```go
cfg := config.Defaults()
cfg.Internal = nil                    // Disable SSRF (no DNS in unit tests)
cmd.SetOut(&buf)                      // CLI output capture (never os.Pipe)
httptest.NewServer(handler)           // Proxy tests with SSRF disabled
prometheus.NewRegistry()              // Metrics isolation per test
net.ListenConfig{}.Listen(ctx, ...)   // Free port binding (noctx compliant)
```

### Linter Pitfalls

| Linter | Rule | Fix |
|--------|------|-----|
| errorlint | `err == ErrFoo` | `errors.Is(err, ErrFoo)` — even in tests |
| staticcheck | QF1012 | `fmt.Fprintf(w, ...)` not `w.WriteString(fmt.Sprintf(...))` |
| gosec | G101 | Build fake creds at runtime: `"AKIA" + "IOSFODNN7EXAMPLE"` |
| errcheck | ignored error | `_, _ = w.Write(b)` for intentional ignores |
| usestdlibvars | `"GET"` | `http.MethodGet` |
| goconst | repeated string | `//nolint:goconst // test value` |
| gosec | file perms | `0o600` not `0600` |
| noctx | bare listener | `net.ListenConfig{}.Listen(ctx, ...)` |
| unparam | unused param | `_` prefix |
| gofumpt | formatting | Stricter than gofmt — handles alignment + import grouping |

Re-stage `go.mod` after the tidy pre-commit hook runs.

## CI Pipeline

Three required checks on `main`:

1. **test** — Go 1.24 + 1.25 matrix, race detector, Codecov upload
2. **lint** — golangci-lint v2
3. **build** — compile binary, verify `--version`

Additional: CodeQL (security-and-quality), govulncheck.

**Release:** Tag push (`v*`) → GoReleaser v2 → multi-arch binaries + GHCR image + Homebrew formula.

## Common Development Tasks

### Adding a DLP pattern
1. Add regex to `internal/scanner/scanner.go` (DLP patterns section)
2. Add test cases in `scanner_test.go`
3. Update `configs/` presets if pattern should be on by default
4. Verify no false positives: `make test`

### Adding a scanner layer
1. Create check function in `internal/scanner/`
2. Wire into `Scanner.Scan()` pipeline
3. Add Prometheus counter in `internal/metrics/`
4. Add audit event type in `internal/audit/`

### Adding an emit sink
1. Implement the `Sink` interface in `internal/emit/` (Emit + Close)
2. Add config struct + fields in `internal/config/config.go`
3. Wire construction in `internal/cli/run.go` (follow webhook/syslog pattern)
4. Add validation in `config.Validate()`

### Adding a chain detection pattern
1. Add pattern to `builtinPatterns` in `internal/mcp/chains/matcher.go`
2. Define tool categories for any new tool names
3. Add test case in `matcher_test.go`

### Adding a finding suppression rule
1. Config: add `suppress` entry with `rule`, `path` (glob/exact/URL suffix), `reason`
2. Inline: add `// pipelock:ignore` comment to source file
3. Test: verify `config.IsSuppressed()` matches correctly

### Adding a CLI command
1. Create `internal/cli/<command>.go` with `<command>Cmd()` function
2. Register in `rootCmd()` in `root.go`
3. Use `cmd.OutOrStdout()` for output, `cmd.ErrOrStderr()` for diagnostics
4. Add tests in `internal/cli/<command>_test.go`

## Code Style

- **gofumpt** formatting (not gofmt)
- Error wrapping: `fmt.Errorf("context: %w", err)`
- Table-driven tests with `t.Run()`
- No stutter: `proxy.Option` not `proxy.ProxyOption`
- DRY: if two functions do the same work with different labels, extract a shared helper immediately

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide. PRs are squash-merged.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/luckyPipewrench/pipelock/security/advisories), not public issues.

## Documentation

| Resource | Location |
|----------|----------|
| OWASP Agentic Top 10 mapping | [docs/owasp-mapping.md](docs/owasp-mapping.md) |
| Competitive comparison | [docs/comparison.md](docs/comparison.md) |
| Integration guides | [docs/guides/](docs/guides/) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |
