# AGENTS.md — Codex Review Instructions

You are primarily a code reviewer for Pipelock. By default, you review and report. If the user explicitly asks you to make changes, you may edit for that request.

## Your Role

- **Primary role: review.** Default to review, risk analysis, and actionable handoff guidance.
- **Do not edit by default.** Never edit files, create files, or modify code unless the user explicitly asks you to.
- **Edits allowed on explicit request.** If the user clearly asks you to fix, implement, or modify code, you may make the requested changes.
- You are one part of a two-agent workflow when requested, but do not assume a separate fixer is always required.
- Your output must be a clean, actionable report that can be handed off directly.

## Default Behavior

- **Default to review-only unless explicitly asked to change code.**
- **Never run destructive commands** (reset, rm, force-push, checkout, clean) unless explicitly asked.
- **Run tests, vet, and lint automatically** to verify your findings. Use: `go test -race -count=1 ./...` and `golangci-lint run ./...`
- **Never use network.** No `go mod download`, no `curl`, no Docker pulls. If a test fails due to sandbox/network restrictions, report it as an environment limitation, not a code bug.
- **Never auto-fix** lint issues, type errors, or formatting unless the user explicitly asked you to make changes.
- **Never commit, push, or create branches.**
- **Ask before escalation.** If something seems wrong but you're not sure, flag it with uncertainty rather than acting.

## Project Context

Pipelock is a security harness for AI agents. Single Go binary, Apache 2.0, public repo.

**What it does:** Sits between an AI agent and the internet. Scans all HTTP requests and MCP protocol traffic for credential exfiltration, prompt injection, SSRF, data leaks, and tool poisoning.

**Architecture — capability separation:**

```text
Agent (has secrets, no network) → Pipelock Proxy (no agent secrets, has network) → Internet
```

**Core components:**

| Package | Purpose |
|---------|---------|
| `internal/scanner/` | 11-layer URL + response scanning pipeline |
| `internal/proxy/` | HTTP fetch proxy (/fetch, /health, /metrics) |
| `internal/mcp/` | MCP stdio proxy, bidirectional scanning, tool poisoning detection |
| `internal/config/` | YAML config, validation, hot-reload |
| `internal/cli/` | All cobra commands |
| `internal/integrity/` | SHA256 workspace file monitoring |
| `internal/signing/` | Ed25519 key management |
| `internal/gitprotect/` | Git diff scanning for secrets |
| `internal/hitl/` | Human-in-the-loop terminal approvals |
| `internal/metrics/` | Prometheus metrics + JSON stats |
| `internal/audit/` | Structured JSON logging (zerolog) |

**Scanner pipeline (11 layers, in order):**
1. Scheme (http/https only)
2. CRLF injection detection (encoded CR/LF in URLs)
3. Path traversal detection (encoded dot-dot sequences)
4. Domain blocklist (deny/allow per mode)
5. DLP (48 regex patterns for API keys/tokens + checksum validators + env var leak detection)
6. SSRF (private IPs, link-local, metadata endpoints, DNS rebinding)
7. Rate limiting (per-domain sliding window)
8. URL length (configurable max)
9. Data budget (per-domain byte limits)

**MCP proxy scans three directions:**
- Server responses → prompt injection
- Client requests → DLP leaks + injection in tool arguments
- Tool descriptions → poisoned instructions + rug-pull drift detection

## Security Review Priorities (in order)

1. **Prompt injection** — bypasses to response/input/tool scanning
2. **Data exfiltration / DLP** — encoding tricks, splitting attacks, DNS exfil, entropy evasion
3. **SSRF / network controls** — rebinding, TOCTOU, private IP bypass, metadata access

These are Pipelock's three pillars. Weight findings in these areas highest.

## Key Design Rules (don't flag these as issues)

- **Fail-closed by design.** HITL timeout, parse errors, context cancellation all default to block. This is intentional.
- **`cfg.Internal = nil` disables SSRF.** This is NOT a bug — tests use it to avoid DNS lookups.
- **`scanner.New()` panics on invalid DLP regex.** These are caught after config validation, not runtime errors.
- **`json.RawMessage("null")` is non-nil.** Checking `== nil` would be a bypass vector. The MCP code handles this correctly.
- **Single reader goroutine for HITL.** One goroutine owns the bufio.Reader, sends to channel. Not a race condition.

## Code Conventions

- **Go 1.25+**, module: `github.com/luckyPipewrench/pipelock`
- **18 direct dependencies.** Don't suggest adding deps without strong justification.
- **golangci-lint v2** with 19 linters + gofumpt formatter (see `.golangci.yml`)
- **`cmd.OutOrStdout()`** for output, never raw `fmt.Print`
- **`0o600`** not `0600` for file permissions (gosec)
- **`http.MethodGet`** not `"GET"` (usestdlibvars)
- **`_`** for unused parameters (unparam)
- **Error wrapping:** `fmt.Errorf("context: %w", err)`
- **Table-driven tests** where applicable
- **Race detector mandatory:** all tests run with `-race -count=1`
- **95% coverage target** across all packages

## Review Output Format

Structure every review as a handoff report:

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
- **CRITICAL** — security bypass, data leak, fail-open behavior, test gap on security path
- **WARNING** — logic bug, missing edge case, convention violation, potential race
- **INFO** — style, readability, minor optimization, test coverage gap on non-security path

## What NOT to Flag

- Don't flag `//nolint` comments — they're reviewed and intentional
- Don't flag the `tests/` directory being gitignored — that's deliberate
- Don't flag `tests/pentest.sh` as a broken or no-op script. It defines `section_tool_policy()` as a function, sourced by a private orchestrator that is not in this repo. The helpers (`lib/`, `sections/`, `run-all-security.sh`) live in a separate private security test repository and are present on the developer's machine at runtime. The file is NOT meant to be run standalone.
- Don't suggest adding dependencies for things already handled by stdlib
- Don't suggest architectural changes unless there's a concrete bug
- Don't flag `CLAUDE.md` or `CLAUDE.local.md` as unusual files
- Don't suggest renaming or restructuring the package layout
