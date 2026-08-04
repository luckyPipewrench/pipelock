# Evidence commitment keys

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

Retirement destroys a verify-only key. Supply every retained receipt reference
as `KEY_ID:EPOCH`; a matching reference refuses the operation. If no reference
inventory is supplied, retirement also refuses. `--accept-loss` is the explicit
override and permanently gives up opening any retained receipt using that key.

```bash
pipelock commitment-key retire \
  --config /etc/pipelock/pipelock.yaml \
  --key-id ck_0123456789abcdef0123456789abcdef \
  --epoch 1 \
  --retained-reference ck_0123456789abcdef0123456789abcdef:1
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
named key ID and epoch. A mismatch fails closed. Every lifecycle attempt emits
a structured `commitment_key_lifecycle` audit event to stderr.
