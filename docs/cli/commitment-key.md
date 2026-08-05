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
or written to audit output. Pass the receipt's typed recipe with `--recipe-json`;
omitting it selects the empty v1 recipe. Unknown recipe fields, unsupported
operations, trailing JSON, and commitment mismatches fail closed. Every
lifecycle storage operation emits a structured `commitment_key_lifecycle`
audit event to stderr.

On Unix, keyring, backup, restore, view, and lock paths are opened relative to
validated directory descriptors; final symlinks are refused, opened files must
be owned by the effective user with exact `0600` mode, and each parent must be
owned by root or the effective user and not group/world-writable. On Windows,
reparse-point checks cover existing parents and opened final files, but Unix
owner/mode rules have no direct ACL equivalent and parent replacement cannot be
pinned across the complete operation. Use an ACL-restricted directory owned by
the Pipelock service account.

Other operating-system targets fail closed because they do not provide the
filesystem primitives required for these storage guarantees.
