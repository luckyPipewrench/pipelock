# CLAUDE.md: Pipelock Development Guide

Pipelock is an agent firewall: a network and tool proxy that sits between AI agents and the internet, scanning the HTTP, WebSocket, and MCP traffic routed through it for secret exfiltration, prompt injection, SSRF, and tool poisoning. Coverage is for mediated traffic; blocking direct egress that bypasses the proxy is deployment guidance, not a binary-enforced property.

## Hard Rules

These are non-negotiable. Violating any of them breaks the security model.

- **Never weaken capability separation.** The proxy holds no agent secrets by design; deployment must enforce separation. The agent environment may hold secrets but should have no direct network egress; pipelock has network egress but must not hold agent secrets. If pipelock ever needs access to agent secrets, the architecture is wrong. Note: pipelock reads local environment variables for env leak scanning, but this is detection, not credential storage.
- **Never bypass fail-closed defaults.** HITL timeout, non-terminal input, parse errors, context cancellation: all default to **block**. If in doubt, block.
- **Never add dependencies without justification.** Minimal direct deps is intentional, not a limitation. Every dependency is attack surface. Propose additions in the PR description with rationale.
- **Never panic on runtime input.** All `panic()` calls in the codebase are post-validation programming errors caught at startup (invalid DLP regex, bad CIDR after config validation). User/agent input must never cause a panic.
- **DLP runs before DNS resolution.** Layers 2-3 (blocklist, DLP) execute before layer 6 (SSRF/DNS). Reordering them would allow secret exfiltration via DNS queries.

## Security Invariants

These must be proven by tests, not assumed from docs or deployment.

- **"Enforced" means the binary enforces it.** If a property depends on deployment, user separation, containers, or network policy, describe it as deployment guidance, not product enforcement.
- **Allowlist/suppression must not bypass content scanning.** Any allowlist, trusted-destination, or suppression logic must not skip DLP, header scanning, body scanning, or explicit secret detection unless the exception is deliberate, documented, and tested.
- **Security-sensitive config defaults must have one source of truth.** If docs say "default true," omitting the field from YAML must produce true. New security-sensitive boolean fields must be tested in 6 states: omitted, YAML null/blank, explicit false, explicit true, reload with change, reload without change.
- **Transport parity must be proven, not claimed.** If a scanning feature applies to multiple surfaces, verify it on each applicable one: fetch, forward proxy, CONNECT, WebSocket, MCP stdio, MCP HTTP/SSE. Not every feature applies to every transport (e.g., MCP stdio has no URL scanning path). Document exceptions explicitly and don't claim parity in docs without tests.
- **Docs are security surface.** Don't claim "automatic escalation" if the code only scores or logs. Don't claim enforcement that only exists at the deployment layer. Review docs when changing behavior.
- **Hot reload must preserve security state.** Test: first load, first reload, second unrelated reload, downgrade/revocation, stale cached state. Kill switch state (all 4 sources) must survive reloads.

## Quick Reference

| Item | Value |
|------|-------|
| Module | `github.com/luckyPipewrench/pipelock` |
| Go | 1.25+ (CI tests 1.25 and 1.26) |
| License | Apache 2.0 (core), ELv2 (`enterprise/`) |
| Binary | Single Go binary; size varies by OS, build tags, and release flags. |
| Deps | See `go.mod` for the current direct dependencies. Run `make stats` for the live count before citing it anywhere. Minimal direct deps is intentional. |

## Public Documentation Standards

- Keep public docs factual, product- and repo-focused. Do not add personal preferences, private infrastructure notes, unpublished roadmap, or ops-only workflow details.
- Use exact casing for **Pipelock**. Describe it as an **agent firewall** (or **open-source agent firewall**) only when the surrounding claim is supported by the README and the implementation.
- Distinguish binary-enforced controls from deployment guidance. If a property depends on sandboxing, containment, containers, user separation, or network policy, say so rather than implying the binary enforces it.
- Do not publish benchmark, corpus, pattern, preset, dependency, coverage, or release counts unless they were verified from the current source of truth in the same change.
- State what is enforced, where it is enforced, and what remains deployment-dependent. Avoid promotional framing in technical docs.

### Docs PR checklist

Before merging a README or docs PR that changes feature summaries, release notes, or security claims:

1. Compare every changed claim against the current code, `README.md`, and the relevant `docs/` pages.
2. Run `make stats` before citing pattern, preset, or dependency counts.
3. Verify external proof claims (such as benchmark corpus size) against the public benchmark repo or live public results before citing a hard number. If not verified, omit it.
4. Make sure screenshots, badges, and release claims still match the current release.
5. Confirm docs distinguish mediated traffic from direct egress, and binary-enforced controls from deployment-enforced controls.

## Build, Test, Lint

```bash
make build          # Compile with version ldflags
make test           # go test -race -count=1 ./...
make test-cover     # Coverage report → coverage.html
make lint           # go vet + golangci-lint v2 (config in .golangci.yml, gofumpt)
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

**Capability separation:** the agent environment (secrets, no direct egress) talks to pipelock (network egress, no agent secrets) which talks to the internet. Three proxy modes on the same port:

- **Fetch** (`/fetch?url=...`): fetches URL, extracts text, scans response for injection
- **Forward** (CONNECT + absolute-URI): standard HTTP proxy via `HTTPS_PROXY`, scans hostname through 11-layer pipeline
- **WebSocket** (`/ws?url=...`): bidirectional frame scanning, DLP on headers, fragment reassembly

```text
Agent environment (secrets, no direct egress) → Pipelock (network egress, no agent secrets) → Internet
```

### Scanner Pipeline

1. Scheme (http/https only) → 2. CRLF injection → 3. Path traversal → 4. Domain blocklist → 5. DLP (patterns, env leak detection, entropy) → 6. Path entropy → 7. Subdomain entropy → 8. SSRF (private IPs, metadata, DNS rebinding) → 9. Rate limiting → 10. URL length → 11. Data budget

Layers 4-5 run **before** DNS resolution. Layer 8 runs **after**. This ordering prevents DNS-based exfiltration.

### MCP Proxy

Wraps any MCP server with bidirectional scanning. Three transport modes:
- **Stdio** (`-- COMMAND`): subprocess wrapping
- **Streamable HTTP** (`--upstream URL`): stdio-to-HTTP bridge
- **HTTP reverse proxy** (`--listen ADDR --upstream URL`): also available via `pipelock run --mcp-listen --mcp-upstream`

Scanning layers:
- **Response scanning:** prompt injection detection in tool results
- **Input scanning:** DLP + injection in tool arguments (`mcp_input_scanning`)
- **Tool scanning:** poisoned descriptions + rug-pull drift detection (`mcp_tool_scanning`)
- **Tool policy:** pre-execution allow/deny/redirect rules with shell obfuscation detection (`mcp_tool_policy`). Redirect routes matched calls to audited handler programs with synthetic MCP response.
- **Chain detection:** subsequence matching on tool call sequences (`tool_chain_detection`)
- **Session binding:** tool inventory pinning per session (`mcp_session_binding`)

### Config System

YAML config loaded at startup. Hot-reload via fsnotify file watch + SIGHUP signal (100ms debounce). Reload atomically swaps config, scanner, and session manager via `atomic.Pointer[T]`. Kill switch state (all 4 sources) is preserved across reloads.

`internal/config/schema.go` is the authoritative list of top-level sections (`mode`, `enforce`, `fetch_proxy`, `forward_proxy`, `websocket_proxy`, `dlp`, `response_scanning`, the `mcp_*` sections, `adaptive_enforcement`, `kill_switch`, `emit`, `sandbox`, `agents`, and more). When adding a top-level section, update defaults, `Load()`, `Validate()`, the reload path, the preset YAML in `configs/`, docs, and tests together.

Action constants: `config.ActionBlock`, `ActionRedirect`, `ActionWarn`, `ActionAsk`, `ActionStrip`, `ActionForward`, `ActionAllow`.

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
- **Any transport or security change:** verify parity across all applicable surfaces (fetch, forward, CONNECT, WebSocket, MCP stdio, MCP HTTP/SSE). Document transport-specific exceptions and add exploit-style regression tests, not just happy paths.

## CI Pipeline

Public CI (see `.github/workflows/*.yaml` for the current job list; this file is not the source of truth for branch protection) includes:

- **test:** Go 1.25 + 1.26 matrix, race detector, Codecov upload
- **lint:** golangci-lint v2
- **build:** compile binary, verify `--version`
- **govulncheck:** known vulnerability scanning
- **CodeQL:** security-and-quality static analysis
- **pipelock:** self-scan (dogfooding the GitHub Action on every PR)

plus platform smoke tests and release/hardening checks.

**Release:** Tag push (`v*`) → GoReleaser v2 → multi-arch binaries + GHCR image + Homebrew formula.

## Code Style

- **gofumpt** formatting (not gofmt). Run `gofumpt -w <file>` after creating/editing.
- Error wrapping: `fmt.Errorf("context: %w", err)`
- Table-driven tests with `t.Run()`
- No stutter: `proxy.Option` not `proxy.ProxyOption`
- DRY: when two paths carry the same behavior or security meaning, extract a shared helper rather than duplicating it
- **File permissions:** always `0o600` for files, `0o750` for directories. Never `0o644`/`0o755`.
- **Error ignoring:** always `_ = fn()` in cleanup paths (not bare `fn()`). Always `_, _ = fmt.Fprintf(w, ...)` for output writes.
- **Lint before commit:** run `golangci-lint run ./...` on first draft, not after tests. Fix lint first, then test.
- **Prefer proper fixes over `//nolint`:** extract constants (goconst), use `filepath.Clean` (G304), split fake creds (G101). Only use `//nolint` when no clean fix exists.
- **Use existing constants:** check `config.Action*`, `config.Mode*`, `config.Severity*` before creating test-local constants for the same values.
- **Options structs over long parameter lists.** Functions with more than 6 parameters should take an options struct instead. Do not add parameters to existing long-signature functions (e.g. `ForwardScannedInput`, `scanHTTPInput`, `RunProxy`); new features should add fields to the relevant config/options struct, not append more params. Broader signature cleanup should be handled as an explicit refactor that groups related params into a struct and migrates callers.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide. PRs are squash-merged.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/luckyPipewrench/pipelock/security/advisories), not public issues.
