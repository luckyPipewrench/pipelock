# `pipelock scan`

`pipelock scan` recursively inspects readable regular text files for invisible-Unicode and bidi-control injection: zero-width, bidirectional-override, Unicode-tag, and control characters that hide instructions where a human reviewer cannot see them. The target is agent-context content such as `CLAUDE.md`, `AGENTS.md`, `.cursorrules` and skill definitions, but the scan does not decide which files are agent context: it reads every eligible text file, so a context file under a name nobody has heard of yet is still inspected.

Content is classified before it is read as text. A file that is text carrying one or a few NUL bytes is scanned, because a single NUL is not evidence that a document is binary. Ordinary binary assets and UTF-16 text are not scanned and are reported as skips.

The names matter in exactly one place. When a file the scanner cannot inspect carries a base name from the agent-context list, the result is a **refusal** rather than a skip, and the command exits 2 whether that file was named directly or found while walking a directory. The scanner will not report clean on the one file class this command exists to check. The built-in list is `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `SKILL.md`, `.cursorrules`, `.clinerules` and `.windsurfrules`, matched case-insensitively on the base name; it is not exhaustive and operators can extend it. Because the list only decides refusal-versus-skip and never decides what gets scanned, a name missing from it costs coverage only for content that is also undecodable.

This is the local-file half of supply-chain prompt injection. The network proxy never sees files at rest, so this command surfaces that vector and exits non-zero so pre-commit hooks and CI can gate on it. Detection is free-tier and adds no dependencies. It is seeded from the same `normalize.InvisibleRanges` data the runtime scanner strips, and then adds deceptive characters that set omits, so the file set is a superset of the proxy set rather than an exact copy of it.

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
| `--fail-on-skip` | `false` | Exit 2 if any file was skipped (binary, UTF-16, symlink, or oversized). |

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
| 2 | Scan / config error, an agent-context file could not be inspected so its content is unknown, an explicitly named file was skipped (binary, UTF-16, symlink, oversized), or `--fail-on-skip` was set and any file was skipped. |

The distinct exit codes let a CI wrapper tell "found hidden characters" (1) apart from "the scan itself broke" (2).

## CI / pre-commit use

```sh
# pre-commit hook: block commits that introduce hidden instructions in context files
pipelock scan CLAUDE.md AGENTS.md .cursorrules ~/.claude/skills || exit 1
```
