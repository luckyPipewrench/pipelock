# Evidence commitment keys

> **Not active yet:** no evidence producer consumes these keys in this release.
> The lifecycle commands prepare durable key storage, but nothing is currently
> being committed with this keyring.

Evidence commitments use a dedicated symmetric keyring. They do not use
`flight_recorder.signing_key_path`, and the keyring cannot be loaded as a
receipt-signing key. Configure its operator-owned location separately:

```yaml
evidence_provenance:
  commitment_keyring_path: /var/lib/pipelock/evidence/commitment-keyring.json
logging:
  output: file
  file: /var/log/pipelock/audit.jsonl
```

The configured file is loaded at startup. A missing keyring, a symlink, a
non-regular file, malformed content, the wrong key purpose, or permissions
other than `0600` aborts startup. The path is restart-only.

Initialize and inspect the keyring:

```bash
pipelock commitment-key initialize --config /etc/pipelock/pipelock.yaml
pipelock commitment-key inspect --config /etc/pipelock/pipelock.yaml
```

Initialization creates 32 random bytes, an opaque key ID, and epoch 1. Inspect
prints metadata only; it never prints key material.

Rotate without breaking historical opening:

```bash
pipelock commitment-key rotate --config /etc/pipelock/pipelock.yaml
```

Rotation makes the previous key verify-only and creates the next monotonic
epoch. Old receipts remain openable by their key ID and epoch.

Retirement destroys a verify-only key. There is not yet an authoritative
retained-evidence inventory, so every retirement requires `--accept-loss`.
That explicit authorization permanently gives up opening any retained evidence
that uses the destroyed key.

```bash
pipelock commitment-key retire \
  --config /etc/pipelock/pipelock.yaml \
  --key-id ck_0123456789abcdef0123456789abcdef \
  --epoch 1 \
  --accept-loss
```

Backups and restores are validated, atomic, and written with `0600` mode. Both
destinations must be absent, preventing accidental overwrite:

```bash
pipelock commitment-key backup \
  --config /etc/pipelock/pipelock.yaml \
  --out /secure-backup/commitment-keyring.json

pipelock commitment-key restore \
  --config /etc/pipelock/pipelock.yaml \
  --from /secure-backup/commitment-keyring.json
```

`pipelock commitment-key test` recomputes the PR 3 `CommitView` contract for a
named key ID and epoch. The private transformed view is read from stdin by
default; use `--view-file` only with an owner-owned regular file whose parent
directories are not group/world-writable. The view is never accepted in argv
or written to lifecycle telemetry. Pass the receipt's typed recipe with `--recipe-json`;
omitting it selects the empty v1 recipe. Unknown recipe fields, unsupported
operations, trailing JSON, and commitment mismatches fail closed. Every
lifecycle storage operation emits a structured `commitment_key_lifecycle`
telemetry event to stderr.

## Lifecycle telemetry

This command opens the configured audit logger directly. It does not require a
running Pipelock server or flight recorder. It writes the lifecycle event to
the configured `logging.file`, rather than the flight-recorder directory, so it
does not compete with receipt evidence chains or their writer lock.

Every command that reaches its lifecycle handler emits exactly one
newline-delimited JSON `commitment_key_lifecycle` telemetry event to standard error after
the operation attempt: successful operations report `outcome: "succeeded"`;
refused or failed operations report `outcome: "denied"` and a reason. Missing
required lifecycle flags are handled inside that handler so they are recorded
as denials too. The event contains only the operation, outcome, key ID and
epoch when known, timestamp, a safe reason code, and the explicit loss
authorization when applicable. It never contains key material, the private
view supplied to `test`, or lifecycle file paths.

Standard error remains lifecycle telemetry but is not a retained record on its
own. Every mutating lifecycle command requires `--config` with
`logging.output: file` or `logging.output: both`, and the default
`logging.format: json`. `logging.file` is opened before the operation begins.
The command writes and fsyncs an `intent` record before it changes a keyring or
lifecycle artifact, then writes and fsyncs an `outcome` record after the
attempt. Both records share an `operation_id`; an intent without an outcome
means an operator must inspect the keyring before retrying. If either durable
write fails, the command returns an error. A failed intent denies the mutation;
a failed outcome reports the error after the key operation, with the durable
intent left for reconciliation. `logging.output: stdout` writes only to a
stream, including when the stream is a terminal, so it is not a durable
lifecycle audit sink and cannot authorize a mutation. Read-only `inspect` and
`test` commands warn and proceed when a durable sink is unavailable. When a
durable sink is available but its outcome record cannot be written, both
commands return that error rather than reporting a successful operation.

On Unix, Pipelock syncs the audit file's parent directory on every successful
sink open before a lifecycle mutation can proceed. That covers a newly created
file name and a name left behind by an earlier failed attempt.

The command verifies that the open file still names `logging.file` before and
after each durable record. It also rechecks every protected keyring, config,
backup, restore, and view path immediately before each record write, rejecting
an audit inode that currently aliases one of them. A deleted or rotated sink
makes the command fail instead of silently appending to an unlinked old file.
Each record is appended and synced as one write. Concurrent lifecycle commands
can interleave whole records without mixing them into one record; a failed
partial append is isolated from the next lifecycle record by a fresh line
boundary.

These are pathname checks, not a lock on a mutable filesystem namespace. An
actor able to replace names after a check can still race a later operation.
Keep the audit and lifecycle directories owned and writable only by the
Pipelock service account, and coordinate log rotation with lifecycle commands.

Pipelock opens the configured audit file in append mode and attempts a
filesystem sync after writing each lifecycle record. A newly created file uses
`0600` permissions. This is a local, file-backed operational record. It is not
tamper-evident evidence, a complete history, or rollback detection: anyone who
can modify the file can truncate, rewrite, delete, replace, or restore an
older copy without Pipelock detecting it. The lifecycle command does not write
to the signed receipt chain or anchor these records. Send the file and stderr
stream to an independently protected audit system when retention or
tamper-evidence matters.

On Unix, keyring, backup, restore, view, and lock paths are opened relative to
validated directory descriptors; final symlinks are refused. The lifecycle
audit sink's opened file and containing directories must be owned by root or
the effective user and not group/world-writable. Sticky directories owned by
root or the effective user, such as `/tmp`, remain usable when the audit file
itself is securely owned and mode-restricted.

Windows does not provide the no-follow, nonblocking descriptor binding used for
the required lifecycle audit sink. `initialize`, `rotate`, `retire`, `backup`,
and `restore` therefore fail closed on Windows. Read-only `inspect` and `test`
still run, but warn when a durable lifecycle sink cannot be opened. Use a Unix
host for lifecycle mutations. Other unsupported targets also fail closed.
