# Governance

## Project Leadership

Pipelock is maintained by Joshua Waldrep ([@luckyPipewrench](https://github.com/luckyPipewrench)).

## Decision-Making

This is a single-maintainer project. Joshua Waldrep makes final decisions on:

- Feature direction and roadmap priorities
- Release timing and versioning
- Dependency additions
- Security policy and vulnerability response
- Contribution acceptance

## Contributions

All contributions are welcome via pull request. See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, coding standards, and testing requirements.

Pull requests require:

- Passing CI (test, lint, build, CodeQL, govulncheck)
- At least one approving review
- All review threads resolved

## Releases

Releases follow [Semantic Versioning](https://semver.org/). Tags pushed to `main` trigger automated builds via GoReleaser, producing signed binaries, container images, and Homebrew formulae.

## Security

Vulnerabilities are reported through [GitHub Security Advisories](https://github.com/luckyPipewrench/pipelock/security/advisories/new) and handled per the timeline in [SECURITY.md](SECURITY.md).

## Continuity

Repository admin access is shared with at least one additional maintainer to ensure the project can continue accepting contributions, triaging issues, and cutting releases if the primary maintainer is unavailable.

## Contact

- **Security issues:** [GitHub Security Advisories](https://github.com/luckyPipewrench/pipelock/security/advisories/new)
- **Bugs and features:** [GitHub Issues](https://github.com/luckyPipewrench/pipelock/issues)
- **General questions:** [GitHub Discussions](https://github.com/luckyPipewrench/pipelock/discussions)
