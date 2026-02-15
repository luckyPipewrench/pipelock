# Changelog

All notable changes to Pipelock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- MCP tool description scanning: detects poisoned tool descriptions containing hidden instructions (`<IMPORTANT>` tags, file exfiltration directives, cross-tool manipulation)
- MCP tool rug-pull detection: SHA256 baseline tracks tool definitions per session, alerts when descriptions change mid-session
- `mcp_tool_scanning` config section (action: warn/block, detect_drift: true/false)
- Auto-enabled in `mcp proxy` mode unless explicitly configured
- `CODEOWNERS` file for automatic review assignment
- Cosign keyless signing for release checksums (Sigstore transparency log)
- Manual trigger (`workflow_dispatch`) for OpenSSF Scorecard workflow

### Changed
- Branch protection: squash-only merges, stale review dismissal

## [0.2.1] - 2026-02-15

### Added
- SLSA build provenance attestation for all release binaries and container images
- CycloneDX SBOM generated and attached to every release
- OpenSSF Scorecard workflow with results published to GitHub Security tab
- `govulncheck` CI job scanning Go dependencies for known vulnerabilities
- `go mod verify` step in CI and release pipelines
- OpenSSF Scorecard badge in README
- OpenSSF Best Practices passing badge in README
- Release verification instructions in README (`gh attestation verify`)

### Changed
- All GitHub Actions pinned to commit SHAs (supply chain hardening)
- Release workflow now includes `id-token` and `attestations` permissions for provenance signing
- Explicit top-level `permissions: contents: read` in CI workflow (least privilege)
- Release attestation steps use `continue-on-error` with final verification (prevents cascading failures)
- Container digest resolution uses `::warning` annotation instead of silent fallback
- `govulncheck`, `cyclonedx-gomod`, and `crane` pinned to specific versions (not `@latest`)
- Docker base images pinned by SHA256 digest (Scorecard Pinned-Dependencies)
- Write permissions moved from workflow-level to job-level (Scorecard Token-Permissions)
- Branch protection: added PR requirement, lint as required check, strict status policy, review thread resolution

### Fixed
- Fetch proxy DNS subdomain exfiltration: dot-collapse scanning now applied to hostnames in `checkDLP` (was only on MCP text scanning side)
- MCP content block split bypass: `ExtractText` now joins blocks with space separator (was `\n`, allowing between-word injection splits to evade detection)
- Git DLP case sensitivity: `CompileDLPPatterns` now applies `(?i)` prefix, matching URL scanner behavior
- Rate limiter subdomain rotation: `checkRateLimit` now uses `baseDomain()` normalization, preventing per-subdomain rate limit evasion
- Response scanning Unicode whitespace bypass: added `normalizeWhitespace()` for Ogham space (U+1680), Mongolian vowel separator (U+180E), and line/paragraph separators
- Agent name path traversal: `ValidateAgentName` now rejects names containing `..` or equal to `.`
- URL DLP NFKC normalization: applied `norm.NFKC.String()` before DLP pattern matching, consistent with response scanning

## [0.2.0] - 2026-02-13

### Added
- MCP input scanning: bidirectional proxy now scans client requests for DLP leaks and injection in tool arguments
- `mcp_input_scanning` config section (action: warn/block, on_parse_error: block/forward)
- Auto-enabled in `mcp proxy` mode unless explicitly configured
- Iterative URL decoding in text DLP (catches double/triple percent-encoding)
- Method name and request ID fields included in DLP scan coverage
- OPENSSH private key format added to Private Key Header DLP pattern
- Split-key concatenation scanning: detects secrets split across multiple JSON arguments
- DNS subdomain exfiltration detection: dot-collapse scanning catches secrets split across subdomains
- Case-insensitive DLP pattern matching: prevents evasion via `.toUpperCase()` or mixed-case secrets
- Null byte stripping in scanner pipeline: prevents regex-splitting bypass via `\x00` injection
- 55+ new tests for input scanning, text DLP, and config validation

### Changed
- CI workflow: removed redundant `go vet` and `go mod verify` steps, combined duplicate test runs, added job timeouts
- Audit preset `on_parse_error` changed from `block` to `forward` (consistent with observe-only philosophy)
- Config validation rejects `ask` action for input scanning (no terminal interaction on request path)
- CLI auto-enable checks both `enabled` and `action` fields (unconfigured = both at zero values)

## [0.1.8] - 2026-02-12

### Added
- Audit log sanitization: ANSI escapes and control characters stripped from all log fields (`internal/audit/logger.go`)
- Data budget enforcement per registrable domain (prevents subdomain variation bypass)
- Hex-encoded environment variable leak detection
- Container startup warning when running as root
- HITL channel drain before each prompt (prevents stale input from prior timeout)
- DLP patterns for `github_pat_` fine-grained PATs and Stripe keys (`[sr]k_(live|test)_`)
- Fuzz test for audit log sanitizer
- Integrity manifest path traversal protection
- 970+ tests passing with `-race`

### Security
- MCP proxy fail-closed: unparseable responses now blocked in all action modes (was forwarding in warn/strip/ask)
- MCP batch scanning fail-closed: parse errors on individual elements now propagate as dirty verdict
- MCP strip recursion depth limit (`maxStripDepth=4`) prevents stack overflow from nested JSON arrays

### Fixed
- DLP pattern overlap: OpenAI Service Key narrowed to `sk-svcacct-` (was `sk-(proj|svcacct)-`, overlapping with existing `sk-proj-` pattern)
- Redirect-to-SSRF: blocked flag now set on redirect hops (redirect to private IP was not caught)
- Rate limiter returns HTTP 429 Too Many Requests (was returning 403)
- io.Pipe resource leak in HITL tests

### Removed
- SKILL.md (ClawHub listing discontinued)

## [0.1.6] - 2026-02-11

### Added
- `--json` flag for `git scan-diff` command (CI/CD integration)
- Fuzz tests for 8 security-critical functions across 4 packages
- 660+ tests passing with `-race`

### Security
- IPv4-mapped IPv6 SSRF bypass: `::ffff:127.0.0.1` now normalized via `To4()` before CIDR matching
- MCP ToolResult schema bypass: result field uses `json.RawMessage` with recursive string extraction fallback
- MCP zero-width Unicode stripping applied to response content scanning
- DNS subdomain exfiltration: DLP/entropy checks now run on hostname before DNS resolution
- `--no-prefix` git diff bypass: parser accepts `+++ filename` without `b/` prefix
- MCP error messages (`error.message` and `error.data`) now scanned for injection
- Double URL encoding DLP bypass: iterative decode (max 3 rounds) on path segments
- Default SSRF CIDRs: added `0.0.0.0/8` and `100.64.0.0/10` (CGN/Tailscale)
- CRLF line ending normalization in git diff parsing
- `ReadHeaderTimeout` added to HTTP server (Slowloris protection)
- Non-text MCP content blocks now scanned (was skipping non-`text` types)

### Fixed
- Homebrew formula push: use `HOMEBREW_TAP_TOKEN` secret for cross-repo access

## [0.1.5] - 2026-02-10

### Added
- `pipelock audit` command: scans projects for security gaps, generates score (0-100) and suggested config (`internal/projectscan/`)
- `pipelock demo` command: 5 self-contained attack scenarios (DLP, injection, blocklist, entropy, MCP) using real scanner pipeline
- OWASP Agentic AI Top 15 threat mapping (`docs/owasp-agentic-top15-mapping.md`, 12/15 threats covered)
- 14 scanner pipeline benchmarks with `make bench` target (~3 microseconds per allowed URL)
- Grafana dashboard JSON (`configs/grafana-dashboard.json`, 7 panels, 3 rows)
- SVG logo
- Public contributor guide (`CLAUDE.md`)
- CONTRIBUTING.md expanded with detailed development workflow
- 756+ tests passing with `-race`

### Fixed
- Audit score: critical finding penalty (-5 per leaked secret found)
- DLP pattern compilation deduplication
- Follow mode context-aware shutdown in `logs` command
- Blog links updated from GitHub Pages to pipelab.org
- OWASP mapping updated to 2026 final category names

## [0.1.4] - 2026-02-09

### Added
- MCP stdio proxy mode: `pipelock mcp proxy -- <command>` wraps any MCP server, scanning responses in real-time (`internal/mcp/proxy.go`)
- Human-in-the-loop terminal approvals: `action: ask` prompts for y/N/s with configurable timeout (`internal/hitl/`)
- Agent-specific config presets: `configs/claude-code.yaml`, `configs/cursor.yaml`, `configs/generic-agent.yaml`
- Claude Code integration guide (`docs/guides/claude-code.md`)
- Homebrew formula in GoReleaser config
- Asciinema demo recording embedded in README

### Fixed
- Makefile VERSION fallback: `git describe` failure no longer produces empty version string
- OpenAI API key DLP regex: now matches keys containing `-` and `_` characters
- HITL approver data race: single reader goroutine pattern eliminates concurrent `bufio.Reader` access on timeout
- GoReleaser v2: `folder` renamed to `directory` in Homebrew brews config

## [0.1.3] - 2026-02-09

### Added
- File integrity monitoring for agent workspaces (`pipelock integrity init|check|update`)
- SHA256 manifest generation with glob exclusion patterns (`**` doublestar support)
- Integrity check reports: modified, added, and removed file detection
- JSON output mode for integrity checks (`--json` flag)
- Custom manifest path support (`--manifest` flag)
- Atomic manifest writes (temp file + rename) to prevent corruption
- Manifest version validation and nil-files guard on load
- Ed25519 signing for file and manifest verification (`pipelock keygen|sign|verify|trust`)
- Key storage under `~/.pipelock/` with versioned format headers
- Trusted key management for inter-agent signature verification
- Path traversal protection in keystore operations
- MCP JSON-RPC 2.0 response scanning for prompt injection (`pipelock mcp scan`)
- MCP scanning: text extraction from content blocks, split-injection detection via concatenation
- MCP scanning: `--json` output mode (one verdict per line) and `--config` flag
- Blog at pipelab.org/blog/
- 530+ tests passing with `-race`

### Fixed
- DLP bypass: secrets in URL hostnames/subdomains now scanned (full-URL DLP scan)
- DLP bypass: secrets split across query parameters now detected
- README: corrected signing CLI syntax, agent types, health version example
- GoReleaser: added missing BuildDate/GitCommit/GoVersion ldflags
- Blog: fixed hallucinated product name, removed stale "coming next" reference

### Security
- `json.RawMessage` null bypass prevention (MCP result always scanned regardless of error field)

### Removed
- Stale Phase 1.5 planning doc (planning docs live outside the repo)

## [0.1.2] - 2026-02-08

### Added
- CodeQL security scanning workflow
- Codecov coverage integration and badge
- Go Report Card badge

### Fixed
- All 53 golangci-lint warnings resolved (zero-warning CI baseline)
- 363 tests passing with `-race`

## [0.1.1] - 2026-02-08

### Changed
- CLI commands write to `cmd.OutOrStdout()` instead of `os.Stdout` (cobra-idiomatic)
- `run` command uses `cmd.Context()` as signal parent for testability

### Added
- Run command integration test (config loading, flag overrides, health check, graceful shutdown)
- Docker Compose YAML syntax validation test (all agent templates parsed via `yaml.Unmarshal`)
- Base64url environment variable leak detection test
- Rate limiter window rollover test
- Healthcheck command test against running server
- 363 tests passing with `-race`

## [0.1.0] - 2026-02-08

### Added
- Fetch proxy server with `/fetch`, `/health`, `/metrics`, and `/stats` endpoints
- URL scanning pipeline: scheme check, SSRF protection, domain blocklist, rate limiting, URL length, DLP regex, Shannon entropy
- SSRF protection with configurable CIDR ranges (IPv4 + IPv6), fail-closed DNS resolution, DNS rebinding prevention via pinned DialContext
- DLP pattern matching for API keys, tokens, secrets (Anthropic, OpenAI, GitHub, Slack, AWS, Discord, private keys, SSNs)
- Shannon entropy analysis for detecting encoded/encrypted data in URL segments
- Environment variable leak detection: scans URLs for high-entropy env var values (raw + base64-encoded)
- Domain blocklist with wildcard support (`*.pastebin.com`)
- Per-domain rate limiting with sliding window and configurable `max_requests_per_minute`
- Response scanning: fetched page content scanned for prompt injection patterns (block/strip/warn actions)
- Multi-agent support: `X-Pipelock-Agent` header identifies calling agents; agent name included in audit logs and fetch responses
- Agent name sanitization to prevent log injection
- Structured JSON audit logging via zerolog (allowed, blocked, error, anomaly, redirect events)
- YAML configuration with validation and sensible defaults
- Config hot-reload via fsnotify file watching and SIGHUP signal (when using `--config`)
- Hot-reload panic recovery: invalid config reloads are caught and logged without crashing the proxy
- Three operating modes: strict, balanced (default), audit
- CLI commands: `run`, `check`, `generate config`, `generate docker-compose`, `logs`, `git scan-diff`, `git install-hooks`, `version`, `healthcheck`
- Config presets: `configs/balanced.yaml`, `configs/strict.yaml`, `configs/audit.yaml`
- Docker Compose generation for network-isolated agent deployments (`pipelock generate docker-compose`)
- HTML content extraction via go-readability
- Redirect following with per-hop URL scanning (max 5 redirects)
- Graceful shutdown on SIGINT/SIGTERM
- Prometheus metrics: `pipelock_requests_total`, `pipelock_scanner_hits_total`, `pipelock_request_duration_seconds`
- JSON stats endpoint: top blocked domains, scanner hits, block rate, uptime
- Build metadata injection via ldflags (version, date, commit, Go version)
- Docker support: scratch-based image (~15MB), multi-arch (amd64/arm64), GHCR via GoReleaser
- GitHub Actions CI (Go 1.24 + 1.25, race detector, vet)
- 345 tests with `-race`
