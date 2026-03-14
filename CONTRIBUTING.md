# Contributing to Pipelock

Thanks for your interest in making AI agents more secure.

## Prerequisites

- Go 1.24+ (`go version`)
- [golangci-lint](https://golangci-lint.run/welcome/install/) v2
- [gofumpt](https://github.com/mvdan/gofumpt) (`go install mvdan.cc/gofumpt@latest`)

## Quick Start

```bash
git clone https://github.com/luckyPipewrench/pipelock.git
cd pipelock
make build
make test
make lint
```

## Development Workflow

1. Fork the repository on GitHub
2. Clone your fork and create a feature branch
3. Make changes with tests
4. Run the pre-commit checklist (below)
5. Open a PR against `main`

Branch naming:
- `feat/` for new features
- `fix/` for bug fixes
- `chore/` for maintenance
- `docs/` for documentation

### Pre-Commit Checklist

These match exactly what CI checks. Both must pass with zero issues.

```bash
golangci-lint run ./...          # Full lint (19 linters, see .golangci.yml)
go test -race -count=1 ./...     # All tests with race detector
```

## Pull Requests

1. Fill in a clear description of what changed and why
2. CI runs 3 required checks: **test** (Go 1.24 + 1.25 matrix), **lint**, **build**
3. Address reviewer feedback and bot comments (CodeRabbit reviews automatically)
4. PRs are squash-merged

## Testing

### Requirements

- All tests run with `-race -count=1`
- Target **95%+ coverage** on new code (`make test-cover` for local report)
- Table-driven tests where there are 3+ cases

### Patterns

Disable SSRF in unit tests to avoid DNS lookups:

```go
cfg := config.Defaults()
cfg.Internal = nil // disables SSRF checks
```

CLI tests capture output via `SetOut`, never `os.Pipe`:

```go
var buf strings.Builder
cmd.SetOut(&buf)
```

Build fake credentials at runtime to avoid gitleaks false positives:

```go
key := "sk-ant-" + "api03-" + "XXXXXXXXXXXX"
```

### Benchmarks

```bash
make bench
```

See [docs/benchmarks.md](docs/benchmarks.md) for methodology and results.

## Code Style

- **gofumpt** formatting, not just gofmt (CI enforces this)
- Error wrapping: `fmt.Errorf("context: %w", err)`
- No stutter: `proxy.Option` not `proxy.ProxyOption`
- `cmd.OutOrStdout()` for CLI output, `cmd.ErrOrStderr()` for diagnostics
- File permissions: `0o600` not `0600`
- HTTP methods: `http.MethodGet` not `"GET"`
- See [.golangci.yml](.golangci.yml) for all 19 enabled linters

## Building

```bash
make build    # Build with version metadata
make test     # Run tests
make lint     # Lint
make docker   # Build Docker image
```

## Project Structure

```text
cmd/pipelock/          CLI entry point
internal/
  cli/                 20+ Cobra commands (run, check, report, tls, mcp, audit, generate, ...)
  config/              YAML config loading, validation, defaults, hot-reload (fsnotify)
  scanner/             11-layer URL scanning pipeline + response injection detection
  audit/               Structured JSON audit logging (zerolog) + event emission dispatch
  proxy/               HTTP proxy: fetch, forward (CONNECT), WebSocket, TLS interception
  certgen/             ECDSA P-256 CA + leaf certificate generation, cache
  mcp/                 MCP proxy + bidirectional scanning + tool poisoning + chains
  report/              HTML/JSON audit report generation from JSONL event logs
  killswitch/          Emergency deny-all (4 sources) + port-isolated API
  emit/                Event emission (webhook + syslog sinks)
  metrics/             Prometheus metrics + JSON stats endpoint
  normalize/           Unicode normalization (NFKC, confusables, combining marks)
  hitl/                Human-in-the-loop terminal approval
  integrity/           File integrity monitoring (SHA256 manifests)
  signing/             Ed25519 key management, file signing, signature verification
  gitprotect/          Git diff scanning for secrets
  projectscan/         Project directory scanner for audit command
enterprise/            Multi-agent features (ELv2, see enterprise/LICENSE)
configs/               7 preset config files (balanced, strict, audit, claude-code, cursor, generic-agent, hostile-model)
docs/                  Guides, OWASP mapping, comparison
```

## Architecture

See [CLAUDE.md](CLAUDE.md) for the full architecture guide, including:

- Scanner pipeline (11 layers)
- MCP proxy design
- Config system and hot-reload
- Package structure and conventions

## Adding Features

### New CLI command

1. Create `internal/cli/<command>.go` with a `<command>Cmd()` function
2. Register in `rootCmd()` in `internal/cli/root.go`
3. Add tests in `internal/cli/<command>_test.go`

### New scanner layer

1. Add the check function in `internal/scanner/`
2. Wire into `Scanner.Scan()` pipeline
3. Add metrics counter in `internal/metrics/`
4. Add audit event in `internal/audit/`
5. Add benchmarks in `internal/scanner/scanner_bench_test.go`

### New DLP pattern

1. Add regex to `config.Defaults()` in `internal/config/config.go`
2. Add test cases in `internal/scanner/scanner_test.go`
3. Update preset configs in `configs/`

## Dependencies

Pipelock has 9 direct dependencies. This is intentional. Any new dependency must be justified in the PR description. We prefer the standard library.

## Security

- **Vulnerabilities**: Report via [GitHub Security Advisories](https://github.com/luckyPipewrench/pipelock/security/advisories), NOT public issues
- **Don't weaken capability separation:** the proxy must never access agent secrets
- **Don't bypass fail-closed defaults:** if in doubt, block
- See [SECURITY.md](SECURITY.md) for the full policy

## Reporting Issues

- **Security issues**: See [SECURITY.md](SECURITY.md)
- **Bugs**: Open a GitHub issue with steps to reproduce
- **Features**: Open a GitHub issue describing the use case
- **Scanner bypasses**: Use the security bypass issue template

## Contributor License Agreement

We use a [Contributor License Agreement](https://cla-assistant.io/luckyPipewrench/pipelock) (CLA) for all contributions. When you open your first PR, the CLA Assistant bot will ask you to sign electronically. This is a one-time process that takes about 30 seconds.

The CLA is based on the [Apache Individual Contributor License Agreement](https://www.apache.org/licenses/icla.pdf). It grants the project the right to use your contribution under the project's license terms while you retain ownership of your work.

## License

Pipelock uses two licenses:

- **Apache License 2.0** for the core (files without the `enterprise` build tag)
- **Elastic License 2.0 (ELv2)** for multi-agent enterprise features (files with the `//go:build enterprise` build tag, primarily in `enterprise/` with integration code in `cmd/` and `internal/`)

By contributing to the core, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE). Contributions to enterprise-licensed code are licensed under the [Elastic License 2.0](enterprise/LICENSE).

Each file's license is indicated by its header. When in doubt, check the file's build tag and license notice.
