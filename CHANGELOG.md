# Changelog

All notable changes to Pipelock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-02-08

### Added
- **Response scanning**: fetched page content is scanned for prompt injection patterns (block/strip/warn actions)
- **Git protection**: `pipelock git scan-diff` and `pipelock git install-hooks` commands for scanning diffs and pre-push hooks
- **Prometheus metrics**: `/metrics` endpoint with `pipelock_requests_total`, `pipelock_scanner_hits_total`, `pipelock_request_duration_seconds`
- **JSON stats**: `/stats` endpoint with top blocked domains, scanner hits, block rate, uptime
- **Multi-agent support**: `X-Pipelock-Agent` header identifies calling agents; agent name included in all audit logs and fetch responses
- **Config hot-reload**: file changes detected via fsnotify, manual reload via SIGHUP (when using `--config`)
- **Version subcommand**: `pipelock version` shows version, build date, git commit, Go version
- **Enhanced /health endpoint**: now includes `uptime_seconds`, `dlp_patterns`, `response_scan_enabled`, `git_protection_enabled`, `rate_limit_enabled`
- **Per-domain rate limiting**: sliding window rate limits with configurable `max_requests_per_minute`
- **Environment variable leak detection**: scans URLs for high-entropy env var values (raw + base64-encoded)
- **Build metadata**: Makefile injects build date, git commit, and Go version via ldflags

### Fixed
- Scanner resource cleanup: rate limiter goroutine is now properly stopped on shutdown

## [0.1.0] - 2026-02-07

### Added
- Fetch proxy server with `/fetch` and `/health` endpoints
- URL scanning pipeline: scheme check, SSRF protection, domain blocklist, URL length, DLP regex, Shannon entropy
- SSRF protection with configurable CIDR ranges (IPv4 + IPv6), fail-closed DNS resolution
- DLP pattern matching for API keys, tokens, secrets (Anthropic, OpenAI, GitHub, Slack, AWS, Discord, private keys, SSNs)
- Shannon entropy analysis for detecting encoded/encrypted data in URL segments
- Domain blocklist with wildcard support (`*.pastebin.com`)
- Structured JSON audit logging via zerolog (allowed, blocked, error, anomaly events)
- YAML configuration with validation and sensible defaults
- Three operating modes: strict, balanced (default), audit
- CLI commands: `run`, `check`, `generate config`, `logs`
- Config presets: `configs/balanced.yaml`, `configs/strict.yaml`, `configs/audit.yaml`
- HTML content extraction via go-readability
- Redirect following with per-hop URL scanning (max 5 redirects)
- Graceful shutdown on SIGINT/SIGTERM
- Docker support (scratch-based image, ~15MB)
- GitHub Actions CI (Go 1.23 + 1.24, race detector, vet)
- 165 tests with `-race`
