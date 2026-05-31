# `pipelock scan`

`pipelock scan` inspects files for invisible-Unicode and bidi-control injection: zero-width, bidirectional-override, Unicode-tag, and control characters that hide instructions inside agent-context files (`CLAUDE.md`, `.cursorrules`, `AGENTS.md`, skill definitions) where a human reviewer cannot see them.

This is the local-file half of supply-chain prompt injection. The network proxy never sees files at rest, so this command surfaces that vector and exits non-zero so pre-commit hooks and CI can gate on it. Detection is free-tier and adds no dependencies; it reuses the same `normalize.InvisibleRanges` data the runtime scanner strips, so file detection never diverges from proxy detection.

```sh
pipelock scan                          # scan the current directory
pipelock scan CLAUDE.md .cursorrules
pipelock scan ~/.claude/skills --json
pipelock scan . --min-severity medium  # also gate on suspicious-but-contextual chars
pipelock scan . --fail-on-skip         # fail CI if anything went uninspected
pipelock scan . --include-deps         # also scan vendored/node_modules context
```

When no path is given, the current directory is scanned recursively.

## Flags

| Flag | Default | Description |
|---|---|---|
| `--json` | `false` | Emit findings as JSON instead of the human-readable report. |
| `--max-bytes` | `5 MiB` | Skip files larger than N bytes. `0` means the 5 MiB default. |
| `--exclude` | none | Additional directory names to skip (repeatable / comma-separated). |
| `--min-severity` | `high` | Minimum finding severity that causes a non-zero exit: `high`, `medium`, or `low`. Lower severities are still reported, just not gated. |
| `--include-deps` | `false` | Also scan dependency / VCS directories (`node_modules`, `vendor`, `.git`, ...) that are skipped by default. |
| `--fail-on-skip` | `false` | Exit 2 if any file was skipped (binary, symlink, or oversized). |

## Severity

Not every invisible character is equally suspicious in a file, so findings carry a severity and `--min-severity` controls what causes a non-zero exit (the default gates on `high` and reports the rest):

| Severity | Examples |
|---|---|
| `high` | Bidi embedding/override (U+202A–U+202E), bidi isolates (U+2066–U+2069), word joiner (U+2060), zero-width space (U+200B). |
| `medium` | Directional marks (U+200E/U+200F), BOM (U+FEFF), invisible math operators, Arabic letter mark. |
| `low` | Contextually legitimate characters: zero-width non-joiner/joiner (Persian/Arabic, emoji), soft hyphen, combining grapheme joiner. |

## Exit codes

| Exit code | Meaning |
|---|---|
| 0 | No findings at or above `--min-severity`. |
| 1 | One or more findings at or above `--min-severity`. |
| 2 | Scan / config error, an explicitly named file was skipped (binary, symlink, oversized), or `--fail-on-skip` was set and any file was skipped. |

The distinct exit codes let a CI wrapper tell "found hidden characters" (1) apart from "the scan itself broke" (2).

## CI / pre-commit use

```sh
# pre-commit hook: block commits that introduce hidden instructions in context files
pipelock scan CLAUDE.md AGENTS.md .cursorrules ~/.claude/skills || exit 1
```
