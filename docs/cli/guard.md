# `pipelock guard`

`pipelock guard` provides read-only inspection of filesystem guard declarations
and the compiled validation floor.

> **Guard is not enforced in this build.** These commands describe what the
> configuration declares and what the compiled floor refuses, but no workload
> is constrained. Both human and JSON output carry this warning.

The commands deliberately separate two policy layers:

- **Compiled floor:** built into Pipelock and cannot be configured away. It
  refuses case-folded credential-directory components, whole homes and roots
  above all homes, home-relative and absolute credential shapes, renamed
  credential copies, and Pipelock credential/state locations. The write floor
  additionally refuses autostart and persistence locations, executable search
  paths, privilege paths, system libraries, boot artifacts, and runtime/socket
  roots.
- **Operator-declared grants:** exact file paths in `read_only` and
  `read_write`, plus explicit subtree grants in `read_only_directories` and
  `read_write_directories`. A profile makes a manifest effective by selecting
  it.

Plain `read_only` and `read_write` entries are file grants and match only the
declared path. The `_directories` lists are directory grants and cover the
declared path plus its subtree. The commands do not expand wildcards, infer a
type from the filesystem, or treat an unselected manifest as effective.

## Explain one path

```sh
pipelock guard explain --config pipelock.yaml /opt/app/config.yaml
pipelock guard explain --config pipelock.yaml --json /usr/bin/helper
```

`guard explain <absolute-path>` reports separate READ and WRITE declaration
verdicts across all declared profiles. For each operation it names the deciding
source and rule:

- `compiled_floor`: the floor refuses the operation. The report includes the
  specific rule, matched component/path shape/root, and a statement that the
  refusal cannot be configured away.
- `operator_declared`: at least one selected manifest contains an exact file
  grant or covering directory grant. The report names the manifest, declared
  type, scope, and selecting profiles.
- `none`: no selected manifest contains a covering grant. Matching declarations
  in orphaned manifests are listed but do not become effective.

The compiled floor wins over an operator declaration. For example, a selected
`read_write: [/usr/bin/helper]` entry is still reported as a WRITE floor refusal
because operator configuration cannot widen the compiled boundary.

Path-floor evaluation uses the same helper as config validation, including its
existing symlink-resolution behavior. The forbidden-component check applies to
the declared spelling as well as the resolved target, so a path declared as a
credential or key directory is refused even when the link resolves somewhere
innocuous. Grant matching is lexical: file grants
are exact and directory grants use path-component subtree boundaries. It never
probes the filesystem to infer a type.

## Show a profile

```sh
pipelock guard show --config pipelock.yaml worker
pipelock guard show --config pipelock.yaml --json worker
```

`guard show <profile>` resolves the profile's manifest references in declared
order. It prints every grant with its declared type (all four manifest lists),
scope (`file` or `directory`), original path, resolved path, and every
compiled-floor refusal that applies. Read-write grants are checked for both
read and write; read-only grants are checked for read.

Unlike normal config loading—which correctly refuses all non-empty guard
sections while enforcement is absent—these inspection commands retain a
floor-refused path long enough to explain the refusal. All other structural
validation still applies, including strict YAML fields, required and unique
names, absolute paths, valid manifest references, file-versus-directory
declarations, and case-folded conflicts across all four path lists.

## Flags

| Flag | Default | Purpose |
|---|---|---|
| `--config`, `-c` | built-in defaults | Config file to inspect. The file is parsed strictly without resolving unrelated runtime credential files. |
| `--json` | `false` | Emit the stable JSON shape described below. Available on both subcommands. |

Both commands are read-only. They do not write config or state, contact the
proxy, create filesystem entries, or alter enforcement.

## JSON shape

Both reports start with these stable fields:

```json
{
  "schema_version": "1",
  "command": "explain",
  "enforced": false,
  "enforcement_notice": "Guard is not enforced in this build. These results describe declarations and the compiled validation floor only; no workload is constrained.",
  "config_file": "pipelock.yaml"
}
```

`guard explain --json` adds:

- `scope`: currently `all_declared_profiles`.
- `path` and `resolved_path`.
- `read` and `write`, each containing `operation`, `would_be_allowed`,
  `source`, `rule`, `matched`, `reason`, `configurable`, and `grants`.
- Each `grants` entry contains `manifest`, `grant_type`, `scope`, `path`,
  `profiles`, and `effective`.

`guard show --json` adds:

- `profile`.
- `manifests`, each containing `name` and `grants`.
- Each grant contains `grant_type`, `scope`, `path`, `resolved_path`, and
  `floor_refusals`.
- Each floor refusal contains `operation`, `rule`, `matched`, and `reason`.

Array fields are always arrays (`[]` when empty), never `null`. Consumers should
key compatibility on `schema_version`.

## Exit behavior

A reported floor refusal or missing declaration is an explanation, so the
command exits 0 after producing the report. Invalid arguments, an unreadable or
malformed config, an invalid guard structure, or an unknown profile return a
configuration/usage error. Do not interpret exit 0 as evidence of enforcement;
check the mandatory `enforced` field, which is `false` in this build.
