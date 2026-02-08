# Changelog

All notable changes to Pipelock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
