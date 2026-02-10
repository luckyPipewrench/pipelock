# Changelog

All notable changes to Pipelock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
