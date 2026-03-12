# CLAUDE.md: Pipelock Development Guide

Pipelock is an agent firewall: a network proxy that sits between AI agents and the internet, scanning all HTTP/WebSocket/MCP traffic for secret exfiltration, prompt injection, SSRF, and tool poisoning.

## Hard Rules

These are non-negotiable. Violating any of them breaks the security model.

- **Never weaken capability separation.** The proxy holds no agent secrets by design; deployment must enforce separation. The agent runs in the privileged zone (has secrets, no direct network). If pipelock ever needs access to agent secrets, the architecture is wrong. Note: pipelock reads local environment variables for env leak scanning, but this is detection, not credential storage.
- **Never bypass fail-closed defaults.** HITL timeout, non-terminal input, parse errors, context cancellation: all default to **block**. If in doubt, block.
- **Never add dependencies without justification.** Minimal direct deps is intentional, not a limitation. Every dependency is attack surface. Propose additions in the PR description with rationale.
- **Never panic on runtime input.** All `panic()` calls in the codebase are post-validation programming errors caught at startup (invalid DLP regex, bad CIDR after config validation). User/agent input must never cause a panic.
- **DLP runs before DNS resolution.** Layers 2-3 (blocklist, DLP) execute before layer 6 (SSRF/DNS). Reordering them would allow secret exfiltration via DNS queries.

## Security Invariants

These must be proven by tests, not assumed from docs or deployment.

- **"Enforced" means the binary enforces it.** If a property depends on deployment, user separation, containers, or network policy, describe it as deployment guidance, not product enforcement.
- **Allowlist/suppression must not bypass content scanning.** Any allowlist, trusted-destination, or suppression logic must not skip DLP, header scanning, body scanning, or explicit secret detection unless the exception is deliberate, documented, and tested.
- **Security-sensitive config defaults must have one source of truth.** If docs say "default true," omitting the field from YAML must produce true. New security-sensitive boolean fields must be tested in 6 states: omitted, YAML null/blank, explicit false, explicit true, reload with change, reload without change.
- **Transport parity must be proven, not claimed.** If a scanning feature works on one surface, verify it works on all: fetch, forward proxy, CONNECT, WebSocket, MCP stdio, MCP HTTP/SSE. Don't claim parity in docs without tests.
- **Docs are security surface.** Don't claim "automatic escalation" if the code only scores or logs. Don't claim enforcement that only exists at the deployment layer. Review docs when changing behavior.
- **Hot reload must preserve security state.** Test: first load, first reload, second unrelated reload, downgrade/revocation, stale cached state. Kill switch state (all 4 sources) must survive reloads.

## Quick Reference

| Item | Value |
|------|-------|
| Module | `github.com/luckyPipewrench/pipelock` |
| Go | 1.24+ (CI tests 1.24 and 1.25) |
| License | Apache 2.0 (core), ELv2 (`enterprise/`) |
| Binary | Single static binary, ~12MB |
| Deps | cobra, zerolog, go-readability, yaml.v3, prometheus, fsnotify, x/text, x/net, gobwas/ws |

## Build, Test, Lint

```bash
make build          # Compile with version ldflags
make test           # go test -race -count=1 ./...
make test-cover     # Coverage report → coverage.html
make lint           # golangci-lint (v2, 19 linters, gofumpt)
make bench          # Benchmarks for scanner + mcp
make fmt            # gofumpt -w . (stricter than gofmt: handles alignment + import grouping)
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

## Architecture

**Capability separation:** the agent (secrets, no network) talks to pipelock (no agent secrets, full network) which talks to the internet. Three proxy modes on the same port:

- **Fetch** (`/fetch?url=...`): fetches URL, extracts text, scans response for injection
- **Forward** (CONNECT + absolute-URI): standard HTTP proxy via `HTTPS_PROXY`, scans hostname through 9-layer pipeline
- **WebSocket** (`/ws?url=...`): bidirectional frame scanning, DLP on headers, fragment reassembly

```text
Agent (secrets, no network) → Pipelock (no agent secrets, full network) → Internet
```

### Scanner Pipeline

1. Scheme (http/https only) → 2. Domain blocklist → 3. DLP (patterns, env leak detection, entropy) → 4. Path entropy → 5. Subdomain entropy → 6. SSRF (private IPs, metadata, DNS rebinding) → 7. Rate limiting → 8. URL length → 9. Data budget

Layers 2-3 run **before** DNS resolution. Layer 6 runs **after**. This ordering prevents DNS-based exfiltration.

### MCP Proxy

Wraps any MCP server with bidirectional scanning. Three transport modes:
- **Stdio** (`-- COMMAND`): subprocess wrapping
- **Streamable HTTP** (`--upstream URL`): stdio-to-HTTP bridge
- **HTTP reverse proxy** (`--listen ADDR --upstream URL`): also available via `pipelock run --mcp-listen --mcp-upstream`

Scanning layers:
- **Response scanning:** prompt injection detection in tool results
- **Input scanning:** DLP + injection in tool arguments (`mcp_input_scanning`)
- **Tool scanning:** poisoned descriptions + rug-pull drift detection (`mcp_tool_scanning`)
- **Tool policy:** pre-execution allow/deny rules with shell obfuscation detection (`mcp_tool_policy`)
- **Chain detection:** subsequence matching on tool call sequences (`tool_chain_detection`)
- **Session binding:** tool inventory pinning per session (`mcp_session_binding`)

### Config System

YAML config loaded at startup. Hot-reload via fsnotify file watch + SIGHUP signal (100ms debounce). Reload atomically swaps config, scanner, and session manager via `atomic.Pointer[T]`. Kill switch state (all 4 sources) is preserved across reloads.

Top-level sections: `mode`, `enforce`, `api_allowlist`, `suppress`, `fetch_proxy`, `forward_proxy`, `websocket_proxy`, `tls_interception`, `dlp`, `response_scanning`, `mcp_input_scanning`, `mcp_tool_scanning`, `mcp_tool_policy`, `mcp_session_binding`, `mcp_ws_listener`, `session_profiling`, `adaptive_enforcement`, `kill_switch`, `emit`, `tool_chain_detection`, `git_protection`, `logging`, `internal`.

Action constants: `config.ActionBlock`, `ActionWarn`, `ActionAsk`, `ActionStrip`, `ActionForward`.

### Architectural Principles

- **Fail-closed everywhere.** Timeouts, parse errors, non-terminal HITL, context cancellation: all block.
- **OR-composed kill switch.** Four independent sources (config, API, SIGUSR1, sentinel file) tracked via atomic bools. Any one active = all traffic denied. Deactivating one doesn't affect others.
- **Fire-and-forget emission.** Webhook uses async buffered channel. Syslog is synchronous but UDP. Neither blocks the proxy. Queue overflow = drop + Prometheus counter.
- **Severity is not user-configurable.** Event severity is hardcoded per event type. Users control the emission *threshold* (`min_severity`), not the severity itself. This prevents misconfiguration hiding critical events.
- **Port isolation.** When `kill_switch.api_listen` is set, the API runs on a dedicated port. Main port gets no API route registration and no path exemption. Agent cannot self-deactivate.

### Implementation Gotchas

- `cfg.Internal = nil` disables SSRF checks (not empty slice). Used in tests to avoid DNS lookups.
- `Scanner.New()` panics on invalid DLP regex/CIDRs. These are programming errors after config validation, never runtime errors.
- `json.RawMessage("null")` is non-nil in Go. Must use `string(raw) == "null"`, not `raw == nil`. Checking nil would be a bypass vector.
- HITL uses a single reader goroutine that owns the `bufio.Reader`. Prevents data races on concurrent terminal reads.
- Tool baseline caps at 10,000 tools per session. Prevents unbounded memory from malicious MCP servers.
- DLP patterns are auto-prefixed with `(?i)` because agents can uppercase secrets, so matching is always case-insensitive.

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
| errorlint | `err == ErrFoo` | `errors.Is(err, ErrFoo)` (even in tests) |
| staticcheck | QF1012 | `fmt.Fprintf(w, ...)` not `w.WriteString(fmt.Sprintf(...))` |
| gosec | G101 | Build fake creds at runtime: `"AKIA" + "IOSFODNN7EXAMPLE"` |
| errcheck | ignored error | `_, _ = w.Write(b)` for intentional ignores |
| errcheck | cleanup error | `_ = os.Remove(path)` in error-return cleanup paths |
| errcheck | fmt output | `_, _ = fmt.Fprintf(w, ...)` when writing to cmd output |
| usestdlibvars | `"GET"` | `http.MethodGet` |
| goconst | repeated string | Extract a `const`. Never use `//nolint:goconst`. |
| gosec | G301 dir perms | `0o750` not `0o755` for directories |
| gosec | G302/G306 file perms | `0o600` not `0o644` for files |
| gosec | G304 file inclusion | Use `filepath.Clean(path)` to satisfy G304 lint. For trust boundaries, also validate containment (EvalSymlinks + filepath.Rel). |
| noctx | bare listener | `net.ListenConfig{}.Listen(ctx, ...)` |
| unparam | unused param | `_` prefix |
| gofumpt | formatting | Stricter than gofmt. Run `gofumpt -w .` before committing |

**goconst:** always extract a named constant. Production code: package-level `const`. Test code: `const` block at file top. Check existing `config.Action*`, `config.Mode*`, `config.Severity*` before creating new ones. Re-stage `go.mod` after the tidy pre-commit hook runs.

## Non-Obvious Task Traps

These tasks have steps that are easy to miss:

- **Adding a DLP pattern:** URL tests (`scanner_test.go`), text tests (`text_dlp_test.go`), all preset YAML files in `configs/`, and docs if the default count changes.
- **Any transport or security change:** verify parity across all surfaces (fetch, forward, CONNECT, WebSocket, MCP stdio, MCP HTTP/SSE). Add exploit-style regression tests, not just happy paths.

## CI Pipeline

Six required checks on `main`:

1. **test:** Go 1.24 + 1.25 matrix, race detector, Codecov upload
2. **lint:** golangci-lint v2
3. **build:** compile binary, verify `--version`
4. **govulncheck:** known vulnerability scanning
5. **CodeQL:** security-and-quality static analysis
6. **pipelock:** self-scan (dogfooding the GitHub Action on every PR)

**Release:** Tag push (`v*`) → GoReleaser v2 → multi-arch binaries + GHCR image + Homebrew formula.

## Code Style

- **gofumpt** formatting (not gofmt). Run `gofumpt -w <file>` after creating/editing.
- Error wrapping: `fmt.Errorf("context: %w", err)`
- Table-driven tests with `t.Run()`
- No stutter: `proxy.Option` not `proxy.ProxyOption`
- DRY: if two functions do the same work with different labels, extract a shared helper immediately
- **File permissions:** always `0o600` for files, `0o750` for directories. Never `0o644`/`0o755`.
- **Error ignoring:** always `_ = fn()` in cleanup paths (not bare `fn()`). Always `_, _ = fmt.Fprintf(w, ...)` for output writes.
- **Lint before commit:** run `golangci-lint run ./...` on first draft, not after tests. Fix lint first, then test.
- **Prefer proper fixes over `//nolint`:** extract constants (goconst), use `filepath.Clean` (G304), split fake creds (G101). Only use `//nolint` when no clean fix exists.
- **Use existing constants:** check `config.Action*`, `config.Mode*`, `config.Severity*` before creating test-local constants for the same values.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide. PRs are squash-merged.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/luckyPipewrench/pipelock/security/advisories), not public issues.
