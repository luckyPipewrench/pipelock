<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Conductor Backup And Restore

Conductor control-plane state lives under the `--storage-dir` passed to
`pipelock conductor serve`. Back up that directory as one unit while Conductor
is stopped, or from a crash-consistent volume snapshot mounted read-only.

Included:

- `policy-bundles/` records, stream heads, and rollback head markers
- `enrollments.json` follower enrollment and audit-key trust
- `emergency-controls/` remote-kill and rollback authorizations
- `audit.db` durable audit evidence, when the SQLite sink is used

Not included:

- TLS private keys
- operator signing keys
- license tokens
- Kubernetes Secrets, KMS keys, or HSM material

Those must stay in the deployment secret-management backup path.

## Create A Backup

```bash
pipelock conductor store backup \
  --storage-dir /var/lib/pipelock/conductor \
  --backup-dir /secure-backups/pipelock/conductor-20260622T120000Z
```

What this does: creates a manifest-wrapped copy at `--backup-dir` and refuses a
backup destination inside `--storage-dir`, so the backup cannot recursively copy
itself.

## Dry-Run A Restore

```bash
pipelock conductor store restore \
  --storage-dir /var/lib/pipelock/conductor \
  --backup-dir /secure-backups/pipelock/conductor-20260622T120000Z
```

What this does: validates the backup manifest and reports the restore action
without changing storage.

## Restore

Stop Conductor first, restore the secret/KMS material for TLS and signing keys,
then restore the storage directory:

```bash
pipelock conductor store restore \
  --storage-dir /var/lib/pipelock/conductor \
  --backup-dir /secure-backups/pipelock/conductor-20260622T120000Z \
  --confirm
```

If `--storage-dir` already exists as a directory, even an empty directory from a
freshly re-provisioned PVC, the restore command moves it aside to a sibling
`.pre-restore-<timestamp>` directory before installing the restored copy. A file
or symlink at `--storage-dir` is rejected.

## Post-Restore Checks

```bash
pipelock conductor store inspect-offline \
  --storage-dir /var/lib/pipelock/conductor
```

What this does: checks the restored policy-bundle store can be read and reports
stream heads and orphan records.

After starting Conductor, run:

```bash
pipelock conductor stream status \
  --org-id org-acme \
  --fleet-id prod \
  --server https://conductor.example.com:8895 \
  --ca-file /etc/pipelock/conductor/ca.crt \
  --client-cert /etc/pipelock/operator/tls.crt \
  --client-key /etc/pipelock/operator/tls.key \
  --token-file /etc/pipelock/operator/admin.token
```

What this does: confirms the restored stream heads and emergency controls are
visible through the live control-plane API.
