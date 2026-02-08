# Contributing to Pipelock

Thanks for your interest in making AI agents more secure.

## Getting Started

```bash
git clone https://github.com/luckyPipewrench/pipelock.git
cd pipelock
make build
make test
```

## Development

- Go 1.24+
- Run `make fmt` before committing
- Run `make test` to verify all tests pass
- Run `make vet` for static analysis

## Pull Requests

1. Fork the repo and create a feature branch
2. Write tests for new functionality
3. Run `make test && make vet`
4. Open a PR with a clear description of the change

## Code Style

- Standard `gofmt` formatting
- Error wrapping with context: `fmt.Errorf("doing thing: %w", err)`
- Table-driven tests where applicable
- Clear variable names — readability over cleverness

## Reporting Issues

- **Security issues:** See [SECURITY.md](SECURITY.md) — do NOT open public issues
- **Bugs:** Open a GitHub issue with steps to reproduce
- **Features:** Open a GitHub issue describing the use case

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
