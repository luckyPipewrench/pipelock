# Changelog

All notable changes to Pipelock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
