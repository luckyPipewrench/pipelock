# CLAUDE.md — Pipelock Development Guide

This file helps contributors (human and AI) work effectively on the Pipelock codebase.

## Quick Reference

| Item | Value |
|------|-------|
| Module | `github.com/luckyPipewrench/pipelock` |
| Go version | 1.24+ |
| License | Apache 2.0 |
| Binary | Single static binary, ~12MB |
| Dependencies | cobra, zerolog, go-readability, yaml.v3, prometheus, fsnotify, x/text |

## Build, Test, Lint

```bash
make build          # Compile binary with version ldflags
make test           # Run all tests with -race -count=1
make test-cover     # Generate coverage report (coverage.html)
make lint           # Run golangci-lint (requires golangci-lint installed)
make fmt            # Format with gofmt -s (CI enforces gofumpt — run `gofumpt -w .` locally)
make vet            # Static analysis
make tidy-check     # Verify go.mod/go.sum are tidy
make install        # Install to $GOPATH/bin
make docker         # Build Docker image
```

### Pre-commit workflow

```bash
golangci-lint run --new-from-rev=HEAD ./...   # Lint only changed code
go test -race -count=1 ./...                  # All tests with race detector
```

Both must pass before pushing. CI runs lint and tests on all code (not just changed).

## Project Structure

```
cmd/pipelock/          Entry point (main.go)
internal/
  cli/                 Cobra commands (audit, check, demo, generate, git, healthcheck, integrity, keygen, logs, mcp, run, sign, test, trust, verify, version)
  proxy/               HTTP proxy: fetch (/fetch), forward (CONNECT + absolute-URI), /health, /metrics, /stats
  scanner/             URL + response scanning pipeline (9 layers)
  config/              YAML config loading, validation, hot-reload (fsnotify + SIGHUP)
  audit/               Structured JSON logging (zerolog)
  mcp/                 MCP stdio proxy + JSON-RPC 2.0 response scanning + tool poisoning detection
  hitl/                Human-in-the-loop terminal approval (ask action)
  integrity/           SHA256 file manifests (init/check/update/diff)
  signing/             Ed25519 key management, signing, verification
  gitprotect/          Git diff scanning for secrets, branch validation
  metrics/             Prometheus metrics + JSON stats (custom registry)
configs/               Preset YAML configs (balanced, strict, audit, claude-code, cursor, generic-agent)
docs/                  Guides, OWASP mapping, comparison docs
examples/              CI workflow example, demo script
blog/                  GitHub Pages blog (Jekyll)
```

## Architecture

Pipelock uses **capability separation**: the agent process (which has secrets and API keys) cannot reach the internet directly. All HTTP traffic goes through Pipelock, which scans every request.

Two proxy modes on the same port:
- **Fetch proxy** (`/fetch?url=...`): fetches URL, extracts text, scans response for injection
- **Forward proxy** (CONNECT + absolute-URI): standard HTTP proxy, agents set `HTTPS_PROXY`. Scans target hostname through the 9-layer pipeline before opening the tunnel. Enabled via `forward_proxy.enabled: true`.

```
Agent (secrets, no network) → Pipelock Proxy (no secrets, full network) → Internet
```

### Scanner Pipeline (9 layers)

1. **Scheme** — Enforce http/https only.
2. **Domain blocklist** — Configurable deny/allow lists per mode. Runs before DNS resolution.
3. **DLP** — Regex patterns for API keys, tokens, credentials (15 built-in patterns, extensible via config). Includes env variable leak detection (raw + base64, Shannon entropy > 3.0). Runs before DNS resolution to prevent secret exfiltration via DNS queries.
4. **Path entropy** — Flag high-entropy URL path segments that may be exfiltrated data.
5. **Subdomain entropy** — Flag high-entropy subdomains used for DNS exfiltration.
6. **SSRF** — Block private IPs, link-local, metadata endpoints. DNS rebinding protection. Runs after DLP so secrets can't leak via DNS resolution.
7. **Rate limiting** — Per-domain sliding window.
8. **URL length** — Configurable max URL length.
9. **Data budget** — Per-domain byte limits prevent slow-drip exfiltration.

Response scanning adds prompt injection detection on fetched content.

### MCP Proxy

Wraps any MCP server with bidirectional scanning. Supports three transport modes: stdio subprocess (`-- COMMAND`), Streamable HTTP stdio-to-HTTP (`--upstream URL`), and HTTP reverse proxy (`--listen ADDR --upstream URL`). The HTTP reverse proxy mode is also available via `pipelock run --mcp-listen --mcp-upstream` for combined fetch/forward + MCP deployments. Server responses are scanned for prompt injection. Client requests are scanned for DLP leaks and injection in tool arguments (configurable via `mcp_input_scanning`). Tool descriptions are scanned for poisoned instructions and tracked for rug-pull changes (configurable via `mcp_tool_scanning`). All three scanning modes auto-enable in proxy mode unless explicitly configured.

### Key Design Decisions

- **Fail-closed**: HITL timeout, non-terminal input, context cancellation, and parse errors all default to **block**.
- **SSRF disabled when `cfg.Internal = nil`**: Not just empty slice — nil means no internal network protection (used in tests to avoid DNS lookups).
- **Scanner.New() panics on invalid DLP regex/CIDRs**: These are programming errors caught after config validation, not runtime errors.
- **HITL single reader goroutine**: One goroutine owns the bufio.Reader, sends lines to a channel. Prevents data races on concurrent terminal reads.
- **MCP scans bidirectionally**: Responses scanned for injection, requests scanned for DLP leaks + injection in tool arguments, tool descriptions scanned for poisoned instructions + rug-pull changes. `json.RawMessage("null")` is non-nil — checking for nil would be a bypass vector.

## CLI Commands

| Command | Purpose |
|---------|---------|
| `pipelock audit` | Scan a project directory and generate a tailored config |
| `pipelock run` | Start the proxy server (fetch + forward) |
| `pipelock check` | Validate a config file and optionally scan a URL |
| `pipelock test` | Run built-in scanner validation tests |
| `pipelock demo` | Run an interactive demo of scanner capabilities |
| `pipelock generate config` | Generate config from preset (--preset balanced/strict/audit). Agent configs in `configs/` for direct use with `--config`. |
| `pipelock generate docker-compose` | Generate a Docker Compose file for running the proxy |
| `pipelock mcp proxy` | MCP stdio proxy wrapping an MCP server |
| `pipelock mcp scan` | Scan MCP JSON-RPC responses |
| `pipelock integrity init/check/update` | Workspace file integrity monitoring |
| `pipelock git scan-diff` | Scan git diffs for leaked secrets |
| `pipelock keygen/sign/verify/trust` | Ed25519 signing and key management |
| `pipelock logs` | Tail structured audit logs |
| `pipelock version` | Version, build date, git commit |
| `pipelock healthcheck` | Health check for Docker/K8s liveness probes |

## Testing

### Requirements

- **Race detector mandatory**: All tests run with `-race -count=1`
- **95% coverage target** on new code, maintain 95%+ overall (currently 96.0%)
- **See README.md for current test count** (count with `go test -v ./... 2>&1 | grep -c -- '--- PASS:'`)

### Patterns

```go
// Test configs disable SSRF to avoid DNS in unit tests
func testConfig() *config.Config {
    cfg := config.Defaults()
    cfg.Internal = nil  // Disables SSRF checks
    return cfg
}

// CLI tests capture output via SetOut — never os.Pipe
var buf bytes.Buffer
cmd.SetOut(&buf)

// Proxy tests use httptest.Server with SSRF disabled
srv := httptest.NewServer(handler)  // Backend on 127.0.0.1

// Metrics tests use custom prometheus.Registry for isolation
reg := prometheus.NewRegistry()

// Integration tests use net.ListenConfig for free ports
ln, _ := net.ListenConfig{}.Listen(ctx, "tcp", "127.0.0.1:0")
```

### Updating test counts

When docs reference a test count, use the **total test cases** (including subtests), not the number of `func Test` definitions. Table-driven tests expand into many subtests via `t.Run()`.

```bash
# Correct way to count (includes subtests):
go test -v ./... 2>&1 | grep -c -- '--- PASS:'

# Wrong (only counts function definitions, misses subtests):
grep -r "func Test" internal/ | wc -l
```

After adding tests, update the count in `README.md` (the single canonical location). All other docs defer to README for current metrics. Verify with: `go test -v ./... 2>&1 | grep -c -- '--- PASS:'`

### Common pitfalls

- **errorlint**: Never compare errors with `==` / `!=`. Always use `errors.Is()` and `errors.As()` — even in tests, even for struct fields
- **staticcheck QF1012**: Use `fmt.Fprintf(w, ...)` not `w.WriteString(fmt.Sprintf(...))`
- **gosec G101**: Build fake credentials at runtime (`"AKIA" + "IOSFODNN7EXAMPLE"`) to avoid secret detection false positives
- **errcheck**: `_, _ =` to satisfy errcheck for intentionally-ignored errors
- **usestdlibvars**: `http.MethodGet` not `"GET"`
- **unparam**: `_` for unused function parameters
- **goconst**: `//nolint:goconst // test value` for repeated test strings
- **gosec**: File permissions: use `0o600` not `0600`
- **noctx**: `net.ListenConfig{}.Listen(ctx, ...)` not bare `net.Listen`
- Re-stage go.mod after the tidy pre-commit hook runs

## Linter Configuration

golangci-lint v2 with 19 enabled linters + gofumpt formatter. See `.golangci.yml`.

Key linters: errcheck, gosec, govet, staticcheck, bodyclose, errorlint, goconst, noctx, revive, unparam.

**gofumpt** is stricter than gofmt — handles alignment and import grouping.

## CI Pipeline

Three required status checks on `main` (branch protection):

1. **test** — Go 1.24 + 1.25 matrix, race detector, coverage upload to Codecov
2. **lint** — golangci-lint (latest)
3. **build** — Compile binary, verify `--version` output

Additional: CodeQL (security-and-quality) runs on push/PR/weekly.

### Release Process

Tag push (`v*`) triggers GoReleaser v2:
- Multi-arch binaries (linux/darwin × amd64/arm64)
- Docker image to GHCR (`ghcr.io/luckyPipewrench/pipelock:<tag>`)
- Homebrew formula auto-published to `luckyPipewrench/homebrew-tap`

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide. Summary:

1. Fork and create a feature branch
2. Write tests for new functionality (aim for 95%+ coverage)
3. Run `make lint && make test` — both must pass
4. Open a PR against `main` with a clear description
5. CI must pass (3 required checks). PRs are squash-merged.

### Code style

- **gofumpt** formatting (not just gofmt)
- Error wrapping: `fmt.Errorf("context: %w", err)`
- Table-driven tests where applicable
- Readability over cleverness
- No stutter: `proxy.Option` not `proxy.ProxyOption` (revive linter)
- **DRY enforcement**: When adding a new function that mirrors an existing one (same loop, same encoding checks, different inputs/outputs), extract a shared helper immediately — don't copy-paste and diverge. If you see parallel functions doing the same work with different labels, refactor first, then add the new variant as a thin wrapper.

### Security

- **Security bugs**: Report via [GitHub Security Advisories](https://github.com/luckyPipewrench/pipelock/security/advisories) — NOT public issues
- **Don't weaken capability separation** — the proxy must never have access to agent secrets
- **Don't add dependencies without justification** — 7 direct deps (cobra, zerolog, go-readability, yaml.v3, prometheus, fsnotify, x/text) is a feature, not a limitation
- **Don't bypass fail-closed defaults** — if in doubt, block

## Common Development Tasks

### Adding a new DLP pattern

1. Add regex to `internal/scanner/scanner.go` in the DLP patterns section
2. Add test cases in `internal/scanner/scanner_test.go`
3. Update `configs/` presets if the pattern should be on by default
4. Run `make test` — verify no false positives on existing tests

### Adding a new scanner layer

1. Create the check function in `internal/scanner/`
2. Wire it into the scanning pipeline in `Scanner.Scan()`
3. Add metrics counter in `internal/metrics/`
4. Add audit event type in `internal/audit/`
5. Add test coverage (aim for edge cases + bypass attempts)

### Adding a new CLI command

1. Create `internal/cli/<command>.go` with a `<command>Cmd()` function
2. Register in `rootCmd()` in `internal/cli/root.go`
3. Add CLI-level tests in `internal/cli/<command>_test.go`
4. `cmd.OutOrStdout()` for output, `cmd.ErrOrStderr()` for diagnostics (never raw `fmt.Print`)

## Documentation

| Resource | Location |
|----------|----------|
| OWASP Agentic Top 10 mapping | [docs/owasp-mapping.md](docs/owasp-mapping.md) |
| Competitive comparison | [docs/comparison.md](docs/comparison.md) |
| Claude Code integration guide | [docs/guides/claude-code.md](docs/guides/claude-code.md) |
| Blog | [pipelab.org/blog/](https://pipelab.org/blog/) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |
