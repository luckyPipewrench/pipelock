# AGENTS.md - Pipelock Contributor Guide

Pipelock is an agent firewall: a network and tool proxy that mediates AI-agent HTTP, WebSocket, and MCP traffic and scans it for secret exfiltration, prompt injection, SSRF, and tool poisoning. Direct egress controls are deployment guidance; binary-enforced coverage applies to mediated traffic.

## Quick Reference

| Item | Value |
|------|-------|
| Module | `github.com/luckyPipewrench/pipelock` |
| Go | 1.25+; CI tests Go 1.25 and 1.26 |
| License | Apache 2.0 core, ELv2 under `enterprise/` |
| Binary | Single Go binary; size varies by OS, build tags, and release flags |
| Dependencies | See `go.mod`. Run `make stats` before citing the current direct-dependency count. |

## Build, Test, Lint

```bash
make build          # Compile with version ldflags
make test           # go test -race -count=1 ./...
make test-cover     # Write coverage.html
make lint           # go vet + golangci-lint v2 + gofumpt check
make bench          # Scanner and MCP benchmarks
make fmt            # gofumpt -w .
make vet            # Static analysis
make tidy-check     # Verify go.mod/go.sum
make docker         # Docker image
make stats          # Canonical local stats for docs
```

Pre-commit parity for OSS and enterprise builds:

```bash
golangci-lint run --new-from-rev=HEAD ./...
golangci-lint run --build-tags enterprise --new-from-rev=HEAD ./...
go test -race -count=1 ./...
go test -tags enterprise -race -count=1 ./...
```

Full-repo CI-equivalent lint:

```bash
golangci-lint run ./...
golangci-lint run --build-tags enterprise ./...
```

## Architecture

Capability separation is part of the design: agent environments can hold secrets and route traffic through Pipelock; the proxy has network egress and does not store agent credentials. Pipelock reads local environment values for leak detection only.

Three proxy modes share the main listener:

- **Fetch** (`/fetch?url=...`): fetches a URL, extracts text, and scans responses for injection.
- **Forward proxy** (`CONNECT` and absolute-URI): standard HTTP proxy mode; hostnames enter the scanner pipeline.
- **WebSocket** (`/ws?url=...`): bidirectional frame scanning, header DLP, and fragment reassembly.

### Scanner Pipeline

`internal/scanner/scanner.go` is the source of truth. Max URL length is checked before parsing. After parsing and hostname canonicalization, URL scanning currently runs:

1. Scheme (`http`/`https`)
2. CRLF injection
3. Path traversal
4. Strict-mode allowlist
5. Domain blocklist
6. Core SSRF literal-IP floor, including private and metadata IP literals
7. SigV4 presigned-URL credential carve-out
8. Core DLP immutable floor
9. DLP (65 built-in credential patterns + checksum validators + env/file leak detection)
10. Path entropy analysis
11. Subdomain entropy analysis
12. SSRF / DNS resolution for private IPs, metadata, and rebinding
13. Rate limiting
14. Data budget
15. Final context check

Core and configured DLP run before DNS resolution; SSRF/DNS runs after them. `cfg.Internal = nil` disables DNS-based configured SSRF checks, not the literal-IP core SSRF floor.

### MCP Proxy

`pipelock mcp proxy` wraps MCP servers with bidirectional scanning. Runtime modes in `internal/cli/runtime/mcp.go` are:

- Subprocess stdio: `pipelock mcp proxy -- COMMAND`
- Stdio-to-HTTP upstream: `--upstream http://...` or `--upstream https://...`
- Stdio-to-WebSocket upstream: `--upstream ws://...` or `--upstream wss://...`
- HTTP reverse proxy: `--listen ADDR --upstream http://...`

MCP scanning layers include response scanning, input scanning (`mcp_input_scanning`), tool scanning (`mcp_tool_scanning`), tool policy (`mcp_tool_policy`), chain detection (`tool_chain_detection`), session binding (`mcp_session_binding`), binary integrity, provenance, media policy, taint, redaction, and contracts where configured.

### Config And Runtime

`internal/config/schema.go` is the authoritative list of top-level YAML fields and action constants. Config loads from YAML; hot reload uses fsnotify plus SIGHUP with atomic swaps of config, scanner, and session state. Kill switch runtime activation state persists across reloads.

The kill switch controller in `internal/killswitch/killswitch.go` OR-composes six activation sources: config, API, remote kill, stale bundle, SIGUSR1, and sentinel file. Any active source denies traffic, subject to endpoint and IP exemptions in the controller.

Emission is non-blocking for webhook output through an async buffer; syslog is synchronous UDP. Event severity is defined by event type, while configuration controls emission thresholds.

## Testing

- Race detector command: `go test -race -count=1 ./...`
- Coverage target for new code: 95%, including error paths.
- Test-count command: `go test -v ./... 2>&1 | grep -c -- '--- PASS:'`
- Synchronization uses channels or poll-with-deadline, not `time.Sleep`.
- Network tests bind `:0` and read back the selected address; fixed ports are checked by `scripts/check-test-stability.sh`.
- Security-sensitive boolean defaults need tests for omitted, YAML null/blank, explicit false, explicit true, reload with change, and reload without change.
- Transport claims need coverage for each applicable surface: fetch, forward proxy, CONNECT, WebSocket, MCP stdio, MCP HTTP/SSE. Document transport-specific exceptions.
- Hot-reload tests cover first load, first reload, unrelated reload, downgrade/revocation, stale cached state, and preservation of runtime security state.

### Test Patterns

```go
cfg := config.Defaults()
cfg.Internal = nil                    // avoids DNS SSRF in unit tests; core literal-IP floor remains
cmd.SetOut(&buf)                      // CLI output capture
httptest.NewServer(handler)           // proxy tests with configured SSRF disabled
prometheus.NewRegistry()              // metrics isolation per test
net.ListenConfig{}.Listen(ctx, ...)   // free port binding
```

## Linter Pitfalls

| Linter | Rule | Fix |
|--------|------|-----|
| errorlint | `err == ErrFoo` | `errors.Is(err, ErrFoo)` |
| staticcheck | QF1012 | `fmt.Fprintf(w, ...)` instead of `w.WriteString(fmt.Sprintf(...))` |
| gosec | G101 | Build fake credentials at runtime from split strings |
| errcheck | ignored error | `_ = fn()` or `_, _ = w.Write(b)` for intentional ignores |
| errcheck | fmt output | `_, _ = fmt.Fprintf(w, ...)` for command output |
| usestdlibvars | `"GET"` | `http.MethodGet` |
| goconst | repeated string | Extract a named `const` |
| gosec | G301 | `0o750` for directories |
| gosec | G302/G306 | `0o600` for files |
| gosec | G304 | `filepath.Clean(path)`; validate containment across trust boundaries |
| noctx | bare listener | `net.ListenConfig{}.Listen(ctx, ...)` |
| unparam | unused param | `_` prefix |
| gofumpt | formatting | `gofumpt -w <file>` |

## Non-Obvious Task Traps

- Adding a DLP pattern touches URL tests (`scanner_test.go`), text tests (`text_dlp_test.go`), preset YAML in `configs/`, and docs if default counts change.
- Transport or security behavior changes need parity tests across applicable surfaces and exploit-style regression cases.
- Example config snippets are executable claims; render and validate Helm/YAML examples instead of prose-checking them.
- Stateful security features need create, rotate, revoke, recover, and inspect/approve coverage.

## Code Style

- Format with gofumpt.
- Wrap errors as `fmt.Errorf("context: %w", err)`.
- Prefer table-driven tests with `t.Run`.
- Avoid stuttered exported names.
- Use shared helpers when duplicated paths have the same security meaning.
- File permissions are `0o600`; directory permissions are `0o750`.
- CLI output goes through `cmd.OutOrStdout()` / `cmd.SetOut(&buf)`.
- Prefer existing constants such as `config.Action*`, `config.Mode*`, and `config.Severity*`.
- Functions with more than six parameters use an options struct; new behavior should not extend long parameter lists.
- Public code, comments, tests, fixtures, and docs use neutral placeholder domains such as `api.vendor.example`.

## CI And Releases

Public CI includes test, lint, build, vulnerability scan, CodeQL, Pipelock self-scan, platform smoke tests, and release/hardening checks. Release tags (`v*`) run GoReleaser for binaries, container images, and package metadata.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide. PRs are squash-merged.

## Security

Report vulnerabilities through [GitHub Security Advisories](https://github.com/luckyPipewrench/pipelock/security/advisories), not public issues.
