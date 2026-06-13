# `pipelock keys`

`pipelock keys status` prints a unified view of every signing-key purpose Pipelock recognises, in one place. Pipelock uses distinct Ed25519 keys for distinct jobs, and the information about where each key lives is otherwise spread across several config sections, deployment-level key files, and the trust roster. `keys status` collapses that into a single report so an operator can answer "are my signing keys set up correctly" without consulting each surface separately.

```sh
pipelock keys status
pipelock keys status --config /etc/pipelock/pipelock.yaml
pipelock keys status --json
```

The command makes no network requests and **never prints private key material**. For a present, valid key it prints the canonical `sha256:` fingerprint of the **public** key only.

## What It Reports

For each key purpose the report shows:

| Column | Meaning |
|---|---|
| `purpose` | The wire-format purpose string (or `license-verification` for the build/verify key). |
| `source_kind` | How the key reaches Pipelock (see the table below). This determines what `present` and `valid` can mean. |
| `source` | Human description of where the key is expected to come from: a config field, a default/operator path, the trust roster, or the build. |
| `path` | The resolved filesystem path, when the source locates one. |
| `present` | Whether a key file exists at `path` and is readable by the calling user. Meaningful only for file-backed sources. |
| `readable` | Whether the calling user can read the located material. For the license verify key, whether a key is available (embedded or override). |
| `valid` | Whether the located material parses as the expected key type (Ed25519). Only meaningful when `present` is true. |
| `key_type` | The parsed key type (`ed25519`) when valid. |
| `fingerprint` | The canonical `sha256:` public-key fingerprint when the public key is available and valid. Never reveals private material. |
| `status` | `ok`, `warn`, `info`, or `fail` — a one-word summary of the row. |
| `note` | Any caveat: an unlocatable source, a reserved purpose, a threshold requirement, embedded-vs-env precedence, or a parse failure (never key bytes). |

## Source Kinds

| `source_kind` | What it means | What `present`/`valid` can show |
|---|---|---|
| `config-private-key-file` | A private key located via a config field. | Present = file exists and is readable; valid = parses as an Ed25519 private key. |
| `deployment-key-file` | An operator-chosen file produced by `pipelock signing key generate --purpose <p> --out <path>`. The path is not recorded in a single config field, so `keys status` cannot locate it automatically. | Reported `info`; not auto-located. The public half is pinned in the trust roster. |
| `trust-roster-public-key` | A **public** key pinned in the deployment trust roster, chained from a pinned root fingerprint. The private signer lives off-host (the leader / an approver). | Present = roster file readable here; the pinned fingerprint is reported when set. |
| `bundled-public-key` | A **public** verification key configured inline (`rules.trusted_keys`) or shipped with the official rules bundle. | Present/valid = at least one configured trusted key parses. |
| `embedded-at-build-or-env` | The license verification **public** key, embedded at build time on official releases and overridable by config/env only on dev builds. | The embedded key wins; the override is consulted only when there is no embedded key. |

## Key Purposes

`keys status` enumerates these purposes (the list comes from the signing package's authoritative purpose enum, so it cannot drift from the rest of the product):

| Purpose | Expected source |
|---|---|
| `receipt-signing` | Private key at `flight_recorder.signing_key_path`. Signs runtime receipts and flight-recorder checkpoints. The mediation-envelope signer is a separate HTTP message-signing key and is not a receipt signer. |
| `contract-compile-signing` | Deployment-level key file from `pipelock signing key generate`. Signs compiled contract artifacts. |
| `contract-activation-signing` | Deployment-level key file from `pipelock signing key generate`. Authorizes contract promotion, rollback, rotation, and redaction. |
| `rules-official-signing` | Public verification keys in `rules.trusted_keys[]` plus the official rules bundle key. |
| `roster-root` | Deployment trust root pinned in the roster (`conductor.trust_roster_path` / pinned root fingerprint). Signs the key roster itself. |
| `recovery-root` | Deployment trust root pinned in the roster. Used for recovery operations (root transition, emergency rotation). |
| `policy-bundle-signing` | Conductor leader-side signer; the follower verifies via the trust roster. Signs policy bundles distributed to followers. |
| `policy-bundle-rollback` | Conductor threshold key; verified via the roster. Authorizes a one-shot rollback to a lower policy-bundle version. Deploy independent approver keys, not a single signer. |
| `remote-kill-signing` | Conductor threshold key; verified via the roster. Signs remote kill-switch state messages. |
| `trust-root-rotation` | Reserved Conductor threshold key; verified via the roster. No shipped operator workflow consumes it yet. |
| `audit-batch-signing` | Follower private key at `flight_recorder.signing_key_path`; `conductor.audit_signing_key_id` names the audit signer. The Conductor audit sink enrolls/trusts the public half and verifies Conductor-bound audit batch envelopes. |
| `enrollment-token-signing` | Reserved Conductor key; verified via the roster. No shipped operator workflow consumes it yet. |
| `license-verification` | Not a wire purpose. The license **verify** public key: embedded on official builds; `license_public_key` / `PIPELOCK_LICENSE_PUBLIC_KEY` only on dev builds. |

On a clean install most rows report `info` (absent) — that is expected, not an error. Rows turn `ok` once the corresponding key is present and valid, `warn` for a too-permissive private key or a dev-build license override, and `fail` for a present-but-corrupt key.

## Operator Notes

- Run without `sudo` when checking service-user file readability. When run as root, DAC checks are bypassed and any file the kernel can stat looks readable; the report prints a banner saying so. Re-run as the pipelock service user for an accurate readability report.
- A too-permissive private key (group- or other-accessible) is reported `warn` even though it is technically readable, mirroring the load-time permission gate.
- This command never reads a private key it does not need to, and never emits parsed private bytes. The only public-derived value it prints is the fingerprint.
