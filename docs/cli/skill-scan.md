# `pipelock skill-scan`

`pipelock skill-scan` inventories local agent skill files, compares them to an operator-owned lock file, and flags drift, hidden instructions, direct transfer patterns, and bounded source/sink co-occurrences with file and line evidence.

This command is static defense-in-depth for files at rest. Runtime network and tool enforcement remains Pipelock proper; a clean static scan is not a runtime allow.

```sh
pipelock skill-scan
pipelock skill-scan ~/.claude/skills ~/.codex/agents
pipelock skill-scan --baseline --lock-file ./pipelock-skill-lock.yaml ~/.claude/skills
pipelock skill-scan --lock-file ./pipelock-skill-lock.yaml ~/.claude/skills
pipelock skill-scan --lock-file ./pipelock-skill-lock.yaml --update ~/.claude/skills
pipelock skill-scan --json --min-severity low ~/.claude/skills
```

When no path is given, Pipelock scans existing local skill directories under `$XDG_CONFIG_HOME/claude/skills`, `~/.claude/skills`, `~/.claude/agents`, and `~/.codex/agents`.

## What it can and cannot prove

`skill-scan` is a lightweight static analyzer, not a data-flow engine. It does not prove that a source value actually reaches a sink (that needs taint tracking). Findings are therefore tiered by confidence, and combinations are named honestly:

| Class | Severity | What it means |
|---|---|---|
| Provable | `high` | Lock drift (content hash change), referenced-file tamper, unscanned oversize files, and **direct** transfers where the command shows an obvious source-to-network transfer (e.g. `cat ~/.aws/credentials \| curl ...`). |
| Advisory co-occurrence | `medium` / `low` | A source and sink appear in the **same code region within a few lines** but no direct transfer is shown. Named `*-cooccurrence`. Worth a look, not an assertion of exfiltration. |
| Inventory | none | Capability mentions (including in prose). Descriptive context, never a finding by itself. |

Hidden-Unicode findings inherit their severity from `pipelock scan`'s per-rune policy (a right-to-left override inside an instruction file is `high`; a leading BOM or emoji ZWJ in prose is `low`), so they are not always `high`. They are reported in normal scans plus `--baseline` and `--update`, so a hidden instruction can never be silently baselined. The explicit `--inventory-only` mode emits inventory only and skips all findings.

The default `--min-severity` is `high`, so a first run gates only on provable issues. Lower it to `medium` once you have curated co-occurrence findings (see Allowlist).

## Code-context scoping

Combination findings are generated only from **executable context**: fenced code blocks inside Markdown skill files and the full body of scanned script files. Prose, tables, headings, and blockquotes are never read as commands, so a Markdown table cell like `| CLAUDE.md |` or a blockquote `> note` is not mistaken for a guard-file target or a filesystem write. A source and sink must also co-occur in the **same region within 10 lines**; mentions farther apart, or in different code blocks, are not paired.

Scanned script files are those named by relative path in `SKILL.md` plus every file under the skill's `scripts/`, `bin/`, and `hooks/` directories (so an unreferenced script dropped into one of those directories is still scanned). Line endings are normalized (`\r\n` and bare `\r` to `\n`) before scanning, and any single file larger than 2 MiB is skipped with a high-severity `oversize` finding rather than read into memory.

Capability inventory still records mentions anywhere in the file (including prose) so the inventory stays complete.

## Mechanisms

| Mechanism | Behavior |
|---|---|
| M1 inventory | Records capability kinds, referenced files, hashes, modes, and `file:line` evidence. Descriptive; assigns no severity by itself. |
| M2 lock drift | Compares the current inventory to a lock file and flags new, changed, removed, widened, or mode-changed skills and referenced files. |
| M3 combinations | Flags source-and-sink combinations found in executable context, classified as direct (high) or co-occurrence (medium/low), each with a stable fingerprint. |
| Hidden instructions | Reuses `pipelock scan` file detection for zero-width, bidi, tag, and control characters on the same skill files. |

## Flags

| Flag | Default | Description |
|---|---|---|
| `--lock-file` | none | Compare against this lock file. |
| `--baseline` | `false` | Write the current inventory to `--lock-file`, or `./pipelock-skill-lock.yaml` when no lock path is given. |
| `--update` | `false` | Rewrite the lock file after operator review. |
| `--allowlist` | none | YAML file of exact combo fingerprints to suppress, each with a justification. |
| `--min-severity` | `high` | Minimum finding severity that causes a non-zero exit: `high`, `medium`, or `low`. |
| `--include-deps` | `false` | Include dependency install commands in the capability inventory. |
| `--json` | `false` | Emit inventory and findings as JSON. |
| `--inventory-only` | `false` | Emit M1 capability inventory only; skip all findings. |
| `--no-color` | `false` | Accepted for tooling compatibility; report output is not colorized. |

## Lock File

The lock file is stable YAML intended for an operator-controlled repo. It records skill and referenced-file hashes plus the combination fingerprints present at baseline time:

```yaml
schema_version: v1
baselined_at: "2026-05-25T12:00:00Z"
emitter_host: workstation
skills:
  example-skill:
    skill_path: /home/operator/.claude/skills/example-skill/SKILL.md
    skill_sha256: <hex>
    referenced_files:
      scripts/deploy.sh:
        sha256: <hex>
        mode: "0o600"
    capabilities_summary:
      - env_read
      - network_sink
    combos:
      - kind: credential-network-cooccurrence
        severity: medium
        region: scripts/deploy.sh#1
        fingerprint: 9028cbc10406a6a9d417d2c8f2c3aa73
```

After `--baseline`, only combinations whose fingerprint is **not** in the lock surface as findings, so an existing skill library does not turn red on day one while a newly introduced combination still alerts. This mirrors the baseline model used by secret scanners.

Drift severities:

| Drift | Severity |
|---|---|
| New skill | `high` |
| Skill content changed | `high` |
| Referenced-file content changed | `high` |
| Referenced-file mode changed | `medium` |
| Skill removed | `low` |
| Capability set widened | `medium` |

## Combinations

`skill-scan` flags these source-and-sink combinations. The direct variant is higher severity than the co-occurrence variant (same region, within the line window). For network transfers, "direct" is deliberately conservative: a same-line source and sink is promoted to a direct transfer only with syntax-level proof — a pipe into the network command, an upload/payload argument naming a credential file (`--data`/`-d`/`--form`/`-T`/`@file`, or a Python `requests` `data=`/`files=`/`json=`), or a command/process substitution that reads a credential file (`curl -d "$(cat ~/.aws/credentials)" ...`). Otherwise it stays co-occurrence.

| Combination | Direct | Co-occurrence |
|---|---|---|
| Credential source + outbound network sink | `high` `credential-exfil` | `medium` `credential-network-cooccurrence` |
| Guard file target + filesystem write | `high` `guard-file-write` | `medium` `guard-file-write-cooccurrence` |
| Shell startup file target + filesystem write | `medium` `shell-init-write` | `low` `shell-init-write-cooccurrence` |
| Scheduled task target + write or enable | `medium` `scheduled-task-write` | `low` `scheduled-task-write-cooccurrence` |
| Clipboard read + outbound network sink | `medium` `clipboard-network-transfer` | `low` `clipboard-network-cooccurrence` |

### Allowlist

Each finding prints a stable `fingerprint`. To accept an expected combination, allowlist that exact fingerprint with a required justification (and an optional review expiry):

```yaml
allow:
  - fingerprint: 9028cbc10406a6a9d417d2c8f2c3aa73
    reason: "deploy receipt upload reads kube config by design"
    expires: "2026-12-01"
```

An entry without a justification, or one past its expiry, does not suppress: the combination resurfaces for review (fail-closed). An allowlist entry that no longer matches any combination is reported as stale so dead exceptions get removed.

`expires` is a UTC date and is **inclusive** (the entry stays valid through the end of that day, UTC). A malformed date is treated as expired (fail-closed). The fingerprint binds the skill, the combo kind, the file, and the full normalized source and sink lines, so an allowlist entry cannot suppress a behaviorally different command that happens to share a matched keyword.

### Known limitations

- No data-flow proof. A co-occurrence is a heuristic, not evidence that the source reaches the sink.
- A transfer split across two separate code blocks, or expressed only in prose instructions, will not raise a combination finding (the capability inventory still lists both capabilities). Prose-based social engineering is the hidden-instruction and runtime injection scanners' job, not the capability detector's.
- The source and sink pattern set is deliberate and non-exhaustive. Covered sources include cloud-credential files, SSH / kube / gcloud config, `.env`, `.netrc`, Docker config, and common secret keywords; covered network sinks are `curl` / `wget` / `fetch` / HTTP-client calls to an `http(s)` URL. Other exfiltration channels (for example `nc`, `scp`, `rsync`, DNS tunnelling, `git push`) are not currently detected as combinations.

## Exit Codes

| Exit code | Meaning |
|---|---|
| 0 | No findings at or above `--min-severity`. |
| 1 | One or more findings at or above `--min-severity`. |
| 2 | Fatal scan, config, lock-file, path, or IO error. |
