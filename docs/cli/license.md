<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# `pipelock license`

Manage the Pipelock license that unlocks paid features. Pipelock's detection,
enforcement, and verification are free and need no license; a license unlocks
the **Pro** (`agents`) and **Enterprise** (`fleet`) feature tiers.

The `license` command ships in official release builds. The paid features it
unlocks are gated at runtime by the license entitlement — installing a token
never weakens any free detection or enforcement.

| Subcommand | Who runs it | Purpose |
|---|---|---|
| [`install TOKEN`](#pipelock-license-install-token) | operator | Write a license token to disk for runtime use. |
| [`status`](#pipelock-license-status) | operator | Verify the configured license and show expiry/renewal status. |
| [`inspect TOKEN`](#pipelock-license-inspect-token) | anyone | Decode a token's claims (no signature verification). |
| [`keygen`](#pipelock-license-keygen) | issuer | Generate a license signing keypair. |
| [`issue`](#pipelock-license-issue) | issuer | Sign a license token from a private key. |
| [`intermediate issue`](#pipelock-license-intermediate-issue) | issuer | Mint a root-signed intermediate signing certificate (offline root). |

Most customers only run `install` and `status`: you receive a signed token,
install it, and confirm it is active. `keygen` and `issue` are for license
issuers and for self-managed or unofficial enterprise builds that mint their own
tokens.

## `pipelock license install TOKEN`

Validate a license token's format and write it to disk so the runtime can read
it. The write is atomic (temp file + rename).

```bash
pipelock license install pipelock_lic_v1_...
```

| Flag | Default | Description |
|---|---|---|
| `--path` | `~/.config/pipelock/license.token` | File path to write the token. |

After installing, point your config at the file (`license_file: <path>`) or set
`PIPELOCK_LICENSE_KEY`. The command prints the license ID, customer email,
expiry, the written path, and a sample config line.

## `pipelock license status`

Verify the configured license — full signature check, plus optional revocation
and intermediate-certificate checks — and report renewal/expiry status.

```bash
pipelock license status
pipelock license status --json
```

| Flag | Default | Description |
|---|---|---|
| `--config`, `-c` | discovered config or built-in defaults | Config file to read the license source from. |
| `--crl` | (none) | Signed CRL file override. |
| `--json` | `false` | Emit status as JSON. |

Text output reports the status (`valid` / `missing` / `invalid` / `expired` /
`revoked`), license ID, tier, subscription ID, expiry, renewal-band warning, CRL
expiry, whether an intermediate certificate is configured, and the reason on
failure. JSON output carries the same fields as machine-readable keys
(`status`, `license_id`, `tier`, `subscription_id`, `expires_at`,
`days_remaining`, `warning_band`, `severity`, `crl_configured`,
`crl_expires_at`, `crl_sha256`, `intermediate_configured`,
`require_intermediate`, `reason`).

When `license_require_intermediate` is on (config field or
`PIPELOCK_LICENSE_REQUIRE_INTERMEDIATE`), `status` enforces the full chain: a
configured intermediate is required, a missing or stale CRL is `invalid`, and a
token not signed through the intermediate fails. See the
[intermediate-signing migration runbook](../guides/license-intermediate-migration.md).

## `pipelock license inspect TOKEN`

Decode and print a token's claims **without verifying the signature**. Useful
for a quick look at what a token contains; it prints a warning that the
signature was not checked, so a token shown here may be forged. Use
[`status`](#pipelock-license-status) for a verified check.

```bash
pipelock license inspect pipelock_lic_v1_...
```

Prints the license ID, email, org, tier, subscription ID, issued and expiry
timestamps, and the feature list. No flags.

## `pipelock license keygen`

Generate an Ed25519 keypair for signing license tokens. Issuer-side: run this
once to create the signing key, then keep the private key offline.

```bash
pipelock license keygen --out ~/.config/pipelock
```

| Flag | Default | Description |
|---|---|---|
| `--out` | `~/.config/pipelock` | Output directory for the keypair. |

Writes `license.key` (private) and `license.pub` (public), and prints the hex
public key for embedding into a build. Unofficial enterprise builds verify
tokens against `PIPELOCK_LICENSE_PUBLIC_KEY`; official builds may embed the key.

## `pipelock license issue`

Sign a license token from a private key. Issuer-side.

```bash
# Free token (no paid feature) — allowed directly:
pipelock license issue --email customer@example.com --features "" \
  --expires 2027-01-01

# Paid token — minted by the license service in normal operation; the
# standalone CLI requires --break-glass + --export (see the issuance gate):
pipelock license issue --email customer@example.com --tier enterprise \
  --features fleet --features agents --expires 2027-01-01 \
  --break-glass --export break-glass-export.json
```

| Flag | Default | Description |
|---|---|---|
| `--key` | `~/.config/pipelock/license.key` | Path to the signing private key. |
| `--email` | (required) | Customer email. |
| `--org` | (none) | Organization name. |
| `--expires` | (none, perpetual) | Expiration date, `YYYY-MM-DD`. Omit for no expiration. |
| `--features` | `[agents]` | Feature list (repeat the flag for multiple). Pass `--features ""` for a featureless free token. |
| `--ledger` | alongside the private key | Ledger file path. |
| `--tier` | (none) | License tier (e.g. `pro`, `founding_pro`, `enterprise`). |
| `--subscription-id` | (none) | External billing subscription ID. |
| `--break-glass` | `false` | Override the issuance gate to mint a paid token offline (emergency only; requires `--export`). |
| `--export` | (none) | Write a signed issuance export to this path so the service can import the break-glass token. |

Prints the signed token and appends a truncated hash of it to the issuance
ledger. The `--features` you sign decide what the token unlocks: `agents` for
Pro, `fleet` for the Enterprise fleet control plane (see the
[tier-gating audit matrix](../security/tier-gating-audit-matrix.md)).

### Issuance gate (paid tokens must be revocable)

A paid license is a *revocable* credential: the license service tracks every
paid token it mints (in its database) so it can revoke a still-valid token via
the signed CRL. A token minted by the standalone CLI is invisible to the service
and therefore **cannot be revoked** — a popped signing host could mint perpetual
paid tokens with no way to pull them back.

To close that gap, `license issue` **refuses to mint a paid/revocable token**
unless `--break-glass` is set. The gate keys on the *capability itself*, not on a
label flag:

- any non-free feature (every shipped feature — `agents`, `assess`, `fleet` — is
  paid; the Free tier needs no license at all);
- a non-empty `--tier`;
- a non-empty `--subscription-id`;
- a no-expiry (perpetual) token that carries any feature.

Omitting `--tier`/`--subscription-id` does **not** slip a paid token past the
gate — the feature alone trips it.

A genuinely free token (no features, no tier, no subscription) is issued
directly, with or without an expiry.

### Break-glass (offline emergency signing)

`--break-glass` preserves the offline emergency-signing capability the
[key-custody runbook](../guides/license-intermediate-migration.md) depends on (e.g.
signing a replacement token directly from the offline root). To keep the token
revocable, a break-glass paid mint **requires `--export <path>`**: it writes a
**signed issuance export** that the license service imports into its durable
signed import table (keyed by license ID and the **full** token hash, with
replay and conflict rejection). The local issuance ledger stores only a
truncated, unsigned hash and **cannot** be the import source.

Import the export into the service after the emergency so the break-glass token
can be revoked like any other paid license — the service operator runs
`license-service import-issuance --export <file> --issuer-pubkey <key>` and can
review the import table with `license-service list-imported-issuances`. To
revoke it later, run
`license-service revoke-imported-license --license-id <license-id> --reason <reason>`;
the next signed CRL carries that license ID. See the full issue → export →
import → inspect → revoke flow in the
[intermediate-key migration guide](../guides/license-intermediate-migration.md#break-glass-tokens-issue-offline-then-import-so-they-stay-revocable).

## `pipelock license intermediate issue`

Mint a root-signed **intermediate signing certificate** from the OFFLINE root
key. Issuer-side; run it on the air-gapped host that holds the root key.

```bash
pipelock license intermediate issue \
  --root-key /path/to/offline/license.key \
  --serial im-2026-001 \
  --validity 2160h \
  --out ./out
```

| Flag | Default | Description |
|---|---|---|
| `--root-key` | `~/.config/pipelock/license.key` | Path to the OFFLINE root private key. Used to sign; never copied or logged. |
| `--serial` | (required) | Unique serial / key id for this intermediate — the CRL revocation key. |
| `--out` | current directory | Output directory for `intermediate.key` + `intermediate.json`. |
| `--validity` | `2160h` (90 days) | Validity window; capped by the library maximum (refused if too long). |

Generates a fresh intermediate keypair, signs the certificate over its public
half with the root key, and writes two `0600` files: `intermediate.key` (the
intermediate **private** key — deploy ONLY to the license service) and
`intermediate.json` (the root-signed certificate — distribute to consumers via
`license_intermediate_file`). It refuses to overwrite an existing
`intermediate.key`. This is the first step of the
[intermediate-signing migration runbook](../guides/license-intermediate-migration.md).

## `pipelock license crl`

Inspect and verify signed **certificate/license revocation lists** (CRLs). A CRL
lets the runtime reject licenses (and revoked intermediate signing certificates)
that have been pulled before their natural expiry.

CRLs are **issued (signed) by the cluster license-service**, which owns the
canonical revocation list. The CLI deliberately does **not** sign CRLs: a CRL is
a whole-list snapshot with no monotonic generation number, so an offline signer
that could mint a smaller list would be a revocation-rollback footgun. The CLI
provides only the read side.

### `pipelock license crl inspect FILE`

Decode a CRL and show what it revokes. Does **not** verify the signature.

```bash
pipelock license crl inspect crl.json
pipelock license crl inspect crl.json --json
```

### `pipelock license crl verify FILE`

Verify a CRL's Ed25519 signature and check it has not expired. Exit code `0` on
a valid, unexpired CRL; `1` otherwise.

```bash
pipelock license crl verify crl.json --public-key /path/to/license.pub
```

| Flag | Default | Description |
|---|---|---|
| `--public-key` | embedded key, then configured key | Public key as a file path or raw hex. |
| `--config` / `-c` | discovered config | Config file used to resolve the license public key when `--public-key` is omitted. |

The public key is resolved in order: `--public-key`, then the embedded build key
(if the binary was built with one), then the configured license public key
(config file or `PIPELOCK_LICENSE_PUBLIC_KEY`).

## Enterprise Eval

The time-boxed **Enterprise Eval** tier grants the full Enterprise feature set
(`agents` + `fleet`) for 60 days, non-renewing, one per customer email. It is
fulfilled as a hosted self-service flow: purchase the eval, receive a signed
token by email, then `pipelock license install TOKEN` and confirm with
`pipelock license status`. A refund revokes the eval through the signed
revocation list, and the runtime tears the paid features back down to free.

## See also

- [Intermediate-signing migration runbook](../guides/license-intermediate-migration.md)
  — move from direct root signing to root → intermediate → token and turn on
  `require_intermediate`.
- [Conductor](../guides/conductor.md) — the Enterprise fleet control plane the
  `fleet` feature unlocks.
- [Tier-gating audit matrix](../security/tier-gating-audit-matrix.md) — which
  feature gates which surface, with the deny cases.
