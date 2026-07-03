# AGENTS.md — Pipelock Development & Review Guide

This is the working guide for any AI coding agent working in this repository. `CLAUDE.md` is its twin for Claude Code: the two files are kept in sync and differ only in the agent they name. It covers build, test, lint, architecture, security invariants, and the PR workflow, so you can build, test, and review — not just review.

Pipelock is an agent firewall: a network and tool proxy that sits between AI agents and the internet, scanning the HTTP, WebSocket, and MCP traffic routed through it for secret exfiltration, prompt injection, SSRF, and tool poisoning. Coverage is for **mediated** traffic; blocking direct egress that bypasses the proxy is deployment guidance, not a binary-enforced property.

## Your Role

You support the whole repository: you may build, fix, test, and review. Default to whatever the user actually asks for — implement when asked to implement, review when asked to review. When the ask is ambiguous, review and report rather than edit.

Operating guardrails (these hold regardless of the task):

- **Never commit, push, create branches, or open PRs unless explicitly asked.** Leave completed work as a modified tree or a clear report; a human decides when it lands.
- **Never run destructive git** (`reset --hard`, `clean -f`, `push --force`, branch/tag delete, `checkout` that discards work) unless explicitly asked. No `--no-verify`, no gpg-bypass.
- **Use the network only when the task genuinely needs it.** Prefer cached modules and offline verification; avoid gratuitous fetches. When a task legitimately requires it — `go mod download` for a dependency the task is adding, verifying an external spec — it is allowed. If a test fails purely due to sandbox/network restrictions rather than a code defect, report it as an environment limitation, not a code bug.
- **Verify by reproduction, not assertion.** "PASS" means you ran the command and read the output. For security-relevant claims, run the negative/attack case too and confirm it fails **closed**.
- **Flag uncertainty instead of guessing.** If something looks wrong but you are not sure, surface it with your confidence level rather than silently acting or silently ignoring it.
- **Public repo.** Everything here is world-visible. Keep commit messages, code, comments, tests, and fixtures free of personal, infrastructure, or private-planning details, and vendor/provider-neutral (see Code Style).

## Hard Rules

These are non-negotiable. Violating any of them breaks the security model.

- **Never weaken capability separation.** The proxy holds no agent secrets by design; deployment must enforce separation. The agent environment may hold secrets but should have no direct network egress; pipelock has network egress but must not hold agent secrets. If pipelock ever needs access to agent secrets, the architecture is wrong. Note: pipelock reads local environment variables for env leak scanning, but this is detection, not credential storage.
- **Never bypass fail-closed defaults.** HITL timeout, non-terminal input, parse errors, context cancellation: all default to **block**. If in doubt, block.
- **Never add dependencies without justification.** Minimal direct deps is intentional, not a limitation. Every dependency is attack surface. Propose additions in the PR description with rationale.
- **Never panic on runtime input.** All `panic()` calls in the codebase are post-validation programming errors caught at startup (invalid DLP regex, bad CIDR after config validation). User/agent input must never cause a panic.
- **DLP runs before DNS resolution.** Core and configured DLP execute before SSRF/DNS resolution. Reordering them would allow secret exfiltration via DNS queries.

## Security Invariants

These must be proven by tests, not assumed from docs or deployment.

- **"Enforced" means the binary enforces it.** If a property depends on deployment, user separation, containers, or network policy, describe it as deployment guidance, not product enforcement.
- **Allowlist/suppression must not bypass content scanning.** Any allowlist, trusted-destination, or suppression logic must not skip DLP, header scanning, body scanning, or explicit secret detection unless the exception is deliberate, documented, and tested.
- **Security-sensitive config defaults must have one source of truth.** If docs say "default true," omitting the field from YAML must produce true. New security-sensitive boolean fields must be tested in 6 states: omitted, YAML null/blank, explicit false, explicit true, reload with change, reload without change.
- **Transport parity must be proven, not claimed.** If a scanning feature applies to multiple surfaces, verify it on each applicable one: fetch, forward proxy, CONNECT, WebSocket, MCP stdio, MCP HTTP/SSE. Not every feature applies to every transport (e.g., MCP stdio has no URL scanning path). Document exceptions explicitly and don't claim parity in docs without tests.
- **Docs are security surface.** Don't claim "automatic escalation" if the code only scores or logs. Don't claim enforcement that only exists at the deployment layer. Review docs when changing behavior.
- **Hot reload must preserve security state.** Test: first load, first reload, second unrelated reload, downgrade/revocation, stale cached state. Kill switch runtime activation sources must survive reloads.

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

Pre-commit (both OSS and enterprise variants must pass before pushing):
```bash
golangci-lint run --new-from-rev=HEAD ./...
golangci-lint run --build-tags enterprise --new-from-rev=HEAD ./...
go test -race -count=1 ./...
go test -tags enterprise -race -count=1 ./...
```

CI runs lint and tests on **all** code, not just changed files. Run lint before tests: fix lint first, then verify behavior.

## Architecture

**Capability separation:** the agent environment (secrets, no direct egress) talks to pipelock (network egress, no agent secrets) which talks to the internet. Three proxy modes on the same port:

- **Fetch** (`/fetch?url=...`): fetches URL, extracts text, scans response for injection
- **Forward** (CONNECT + absolute-URI): standard HTTP proxy via `HTTPS_PROXY`, scans hostname through the URL scanner
- **WebSocket** (`/ws?url=...`): bidirectional frame scanning, DLP on headers, fragment reassembly

```text
Agent environment (secrets, no direct egress) → Pipelock (network egress, no agent secrets) → Internet
```

### URL Scanner

Max URL length is checked before parsing. After parsing and hostname canonicalization, the URL scanner runs: scheme check → CRLF injection → path traversal → strict-mode allowlist → domain blocklist → core SSRF literal-IP floor → SigV4 credential carve-out → core DLP → configured DLP (patterns, env/file leak detection, entropy) → path/query entropy → subdomain entropy → SSRF/DNS (private IPs, metadata, DNS rebinding) → rate limiting → data budget → final context check.

Core DLP and configured DLP run **before** DNS resolution. SSRF/DNS runs **after** those DLP checks. This ordering prevents DNS-based exfiltration.

### MCP Proxy

Wraps any MCP server with bidirectional scanning. Four standalone transport modes:
- **Stdio** (`-- COMMAND`): subprocess wrapping
- **Streamable HTTP** (`--upstream URL`): stdio-to-HTTP bridge
- **Stdio-to-WebSocket** (`--upstream ws://...` or `--upstream wss://...`): stdio-to-WebSocket bridge
- **HTTP reverse proxy** (`--listen ADDR --upstream URL`): HTTP listener mode; also available via `pipelock run --mcp-listen --mcp-upstream`

Scanning layers:
- **Response scanning:** prompt injection detection in tool results
- **Input scanning:** DLP + injection in tool arguments (`mcp_input_scanning`)
- **Tool scanning:** poisoned descriptions + rug-pull drift detection (`mcp_tool_scanning`)
- **Tool policy:** pre-execution allow/deny/redirect rules with shell obfuscation detection (`mcp_tool_policy`). Redirect routes matched calls to audited handler programs with synthetic MCP response.
- **Chain detection:** subsequence matching on tool call sequences (`tool_chain_detection`)
- **Session binding:** tool inventory pinning per session (`mcp_session_binding`)

### Config System

YAML config loaded at startup. Hot-reload via fsnotify file watch + SIGHUP signal (100ms debounce). Reload atomically swaps config, scanner, and session manager via `atomic.Pointer[T]`. Kill switch runtime activation state is preserved across reloads.

`internal/config/schema.go` is the authoritative list of top-level sections (`mode`, `enforce`, `fetch_proxy`, `forward_proxy`, `websocket_proxy`, `dlp`, `response_scanning`, the `mcp_*` sections, `adaptive_enforcement`, `kill_switch`, `emit`, `sandbox`, `agents`, and more). When adding a top-level section, update defaults, `Load()`, `Validate()`, the reload path, the preset YAML in `configs/`, docs, and tests together.

Action constants: `config.ActionBlock`, `ActionRedirect`, `ActionWarn`, `ActionAsk`, `ActionStrip`, `ActionForward`, `ActionAllow`.

### Architectural Principles

- **Fail-closed everywhere.** Timeouts, parse errors, non-terminal HITL, context cancellation: all block.
- **OR-composed kill switch.** Six independent sources (config, API, Conductor remote kill, Conductor stale bundle, SIGUSR1, sentinel file) are OR-composed. Any one active = all traffic denied. Deactivating one doesn't affect others.
- **Fire-and-forget emission.** Webhook uses async buffered channel. Syslog is synchronous but UDP. Neither blocks the proxy. Queue overflow = drop + Prometheus counter.
- **Severity is not user-configurable.** Event severity is hardcoded per event type. Users control the emission *threshold* (`min_severity`), not the severity itself. This prevents misconfiguration hiding critical events.
- **Port isolation.** When `kill_switch.api_listen` is set, the API runs on a dedicated port. Main port gets no API route registration and no path exemption. Agent cannot self-deactivate.

### Implementation Gotchas

- `cfg.Internal = nil` disables DNS-based configured SSRF checks, not the immutable literal-IP core SSRF floor. Used in tests to avoid DNS lookups.
- `Scanner.New()` panics on invalid DLP regex/CIDRs. These are programming errors after config validation, never runtime errors.
- `json.RawMessage("null")` is non-nil in Go. Must use `string(raw) == "null"`, not `raw == nil`. Checking nil would be a bypass vector.
- HITL uses a single reader goroutine that owns the `bufio.Reader`. Prevents data races on concurrent terminal reads.
- Tool baseline caps at 10,000 tools per session. Prevents unbounded memory from malicious MCP servers.
- DLP patterns are auto-prefixed with `(?i)` because agents can uppercase secrets, so matching is always case-insensitive.

## Security Review Priorities (weight findings in this order)

1. **Prompt injection** — bypasses to response/input/tool scanning
2. **Data exfiltration / DLP** — encoding tricks, splitting attacks, DNS exfil, entropy evasion
3. **SSRF / network controls** — rebinding, TOCTOU, private-IP bypass, metadata access

These are Pipelock's three pillars. When reviewing or hardening, weight findings in these areas highest, and think like an attacker: what is the dumbest bypass (multi-layer encoding, null bytes, homoglyphs, case tricks)? What happens at empty / max-length / mixed-encoding / split-across-frames boundaries? Does the displayed value match the acted-on value?

## Testing

- **Race detector mandatory**: `-race -count=1` on all tests.
- **95% coverage target** on new code, especially error paths — every `if err != nil` return wants a test. See README for the current count.
- Count test cases (including subtests): `go test -v ./... 2>&1 | grep -c -- '--- PASS:'`
- **No `time.Sleep` for synchronization** and **no fixed ports** in tests — both flake under CI load and both are blocked by `scripts/check-test-stability.sh` for net-new occurrences. Use channels / poll-with-deadline for coordination and bind `:0` then read back the address.

### Patterns

```go
cfg := config.Defaults()
cfg.Internal = nil                    // Avoid DNS-based SSRF in unit tests; core literal-IP floor remains
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
- **lint:** golangci-lint v2 (plus the test-stability and pin checks)
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
- DRY: when two paths carry the same behavior or security meaning, extract a shared helper rather than duplicating it.
- **File permissions:** always `0o600` for files, `0o750` for directories. Never `0o644`/`0o755`.
- **Error ignoring:** always `_ = fn()` in cleanup paths (not bare `fn()`). Always `_, _ = fmt.Fprintf(w, ...)` for output writes.
- **CLI output:** use `cmd.OutOrStdout()` / `cmd.SetOut(&buf)`, never raw `fmt.Print`.
- **Lint before commit:** run `golangci-lint run ./...` on first draft, not after tests. Fix lint first, then test.
- **Prefer proper fixes over `//nolint`:** extract constants (goconst), use `filepath.Clean` (G304), split fake creds (G101). Only use `//nolint` when no clean fix exists and the exception is specific and justified.
- **Use existing constants:** check `config.Action*`, `config.Mode*`, `config.Severity*` before creating test-local constants for the same values.
- **Options structs over long parameter lists.** Functions with more than 6 parameters should take an options struct instead. Do not add parameters to existing long-signature functions (e.g. `ForwardScannedInput`, `scanHTTPInput`, `RunProxy`); new features should add fields to the relevant config/options struct, not append more params. Broader signature cleanup should be handled as an explicit refactor that groups related params into a struct and migrates callers.
- **Vendor/provider-neutral:** never name a real third-party SaaS, customer, or vendor product in code, comments, tests, or fixtures — even when a real provider motivated the change. Describe the shape/behavior and use neutral placeholders (`api.vendor.example`, `provider-token`, `agent-a`/`agent-b`).

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide. PRs are squash-merged.

## When You Are Asked to Review

When the task is review (not implementation), produce a clean handoff report that another agent or a human can act on directly. Run `go test -race -count=1 ./...` and `golangci-lint run ./...` to verify findings before reporting them.

```text
## Review: [branch or scope]

### Critical (must fix before merge)
- **[severity]** `file:line` — description
  Repro: `command to reproduce`

### Warning (should fix)
- ...

### Info (optional improvements)
- ...

### Test Results
- `go test -race -count=1 ./...` — PASS/FAIL (note any env failures)
- `golangci-lint run ./...` — clean / N issues

### Suggested Next Actions
1. [specific action with exact command if applicable]
2. ...
```

Severity levels:
- **CRITICAL** — security bypass, data leak, fail-open behavior, test gap on a security path
- **WARNING** — logic bug, missing edge case, convention violation, potential race
- **INFO** — style, readability, minor optimization, coverage gap on a non-security path

### What NOT to flag

- Don't flag `//nolint` comments that already exist in the tree — they were reviewed and intentional (this does not license *new* ones; new `//nolint` still requires specific justification).
- Don't flag the `tests/` directory being gitignored — that's deliberate.
- Don't flag `tests/pentest.sh` as broken or a no-op. It is a suite section file: it defines `section_tool_policy()` and relies on helper functions from the suite runner that sources it, so it is not meant to run standalone.
- Don't suggest adding dependencies for things already handled by stdlib.
- Don't suggest architectural changes absent a concrete bug.
- Don't flag `CLAUDE.md`, `CLAUDE.local.md`, or `AGENTS.md` as unusual files.
- Don't suggest renaming or restructuring the package layout.
- Don't treat `cfg.Internal = nil` avoiding DNS-based SSRF, `Scanner.New()` panics on bad regex, or `json.RawMessage("null")` being non-nil as bugs — see Implementation Gotchas.

## Security

Report vulnerabilities via [GitHub Security Advisories](https://github.com/luckyPipewrench/pipelock/security/advisories), not public issues.
