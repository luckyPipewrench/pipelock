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
`crl_expires_at`, `crl_sha256`, `intermediate_configured`, `reason`).

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
pipelock license issue --email customer@example.com --tier enterprise \
  --features fleet --features agents --expires 2027-01-01
```

| Flag | Default | Description |
|---|---|---|
| `--key` | `~/.config/pipelock/license.key` | Path to the signing private key. |
| `--email` | (required) | Customer email. |
| `--org` | (none) | Organization name. |
| `--expires` | (none, perpetual) | Expiration date, `YYYY-MM-DD`. Omit for no expiration. |
| `--features` | `[agents]` | Feature list (repeat the flag for multiple). |
| `--ledger` | alongside the private key | Ledger file path. |
| `--tier` | (none) | License tier (e.g. `pro`, `founding_pro`, `enterprise`). |
| `--subscription-id` | (none) | External billing subscription ID. |

Prints the signed token and appends a truncated hash of it to the issuance
ledger. The `--features` you sign decide what the token unlocks: `agents` for
Pro, `fleet` for the Enterprise fleet control plane (see the
[tier-gating audit matrix](../security/tier-gating-audit-matrix.md)).

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

- [Conductor](../guides/conductor.md) — the Enterprise fleet control plane the
  `fleet` feature unlocks.
- [Tier-gating audit matrix](../security/tier-gating-audit-matrix.md) — which
  feature gates which surface, with the deny cases.
