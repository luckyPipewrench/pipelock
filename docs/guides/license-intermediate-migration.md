<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# License intermediate-signing migration

This runbook moves Pipelock's license PKI from **direct root signing** to a
**root → intermediate → token** chain, then turns on `require_intermediate` so
consumers refuse any license that does not chain through a root-certified
intermediate.

## Why

Today the online license service can sign tokens directly with the root key. If
that host is compromised, an attacker mints licenses every consumer trusts, with
no recovery short of rotating the root everywhere. The fix is a textbook PKI
hierarchy:

- The **root key** stays **offline** (air-gapped / on a hardware token). It signs
  only short-lived **intermediate certificates**, never tokens directly.
- The **intermediate private key** is the only key the online license service
  holds. It signs the actual license tokens.
- A compromised service loses the **intermediate**, not the root. You **revoke**
  that intermediate's serial (it lands in the published CRL) and mint a new one.
  The root never leaves the safe.

`require_intermediate` is the enforcement switch: with it on, a token signed
directly by the root (legacy, or forged with a stolen root) is **rejected** — the
only accepted path is token → intermediate → root.

## Trust model recap

| Knob | Surface | Effect |
|---|---|---|
| `license_intermediate_file` | consumer | Path to the root-signed intermediate cert. Used to validate the chain. |
| `license_require_intermediate` (or `PIPELOCK_LICENSE_REQUIRE_INTERMEDIATE`) | consumer | When `true`, reject any token not validated through an intermediate. Requires a configured intermediate **and** a fresh signed CRL. |
| `license_crl_file` (or `PIPELOCK_LICENSE_CRL_FILE`) | consumer | Signed revocation list. Under require mode it is **mandatory** (the revocation floor) and must be fresh. |

Default (`license_require_intermediate` omitted/`false`) preserves today's
behaviour exactly: direct root-signed tokens still verify. Existing deployments
are unaffected until you flip the switch.

## Migration sequence

Do this in order. Each step is reversible until the final flip, and detection /
enforcement (the free single-agent path) is never gated by any of it.

### 1. Mint an intermediate from the offline root

On the air-gapped host that holds the root key:

```bash
pipelock license intermediate issue \
  --root-key /path/to/offline/license.key \
  --serial im-2026-001 \
  --validity 2160h \
  --out ./out
```

This generates a fresh intermediate keypair, signs the certificate with the root,
and writes (both `0600`):

- `out/intermediate.key` — the intermediate **private** key. Deploy ONLY to the
  license service.
- `out/intermediate.json` — the root-signed **certificate**. Distribute to every
  consumer.

The root private key is read, used to sign, and never copied or logged. Move the
two outputs off the host by hand; keep the root key offline. `--serial` is the
CRL revocation key — make it unique per intermediate.

### 2. Deploy the intermediate to the license service

Point the license service at the new intermediate signing key and certificate:

- token signing key → `out/intermediate.key`
- `IntermediateCert` / `--intermediate-cert` → `out/intermediate.json`

The service refuses to start if the certificate's public key does not match the
signing private key, so a mismatched pair fails fast. Restart the service. It now
signs **new** tokens with the intermediate; the root key is no longer online.

### 3. Take the root offline

With the intermediate live, the root key has no online role. Return it to the
safe / hardware token. From here on the root is touched only to mint or rotate an
intermediate.

### 4. Distribute the intermediate cert to consumers (dual-active overlap)

Ship `intermediate.json` to every consumer and set `license_intermediate_file`
(or `PIPELOCK_LICENSE_INTERMEDIATE_FILE`). Leave `license_require_intermediate`
**off** for now.

In this overlap window consumers accept **both** intermediate-signed (new) and
root-signed (legacy) tokens. Nothing breaks; you are staging trust. Make sure a
fresh signed CRL is also distributed (`license_crl_file`) — require mode will
demand it.

> **CRL cadence (required before you flip require on).** Under require mode the
> CRL is subject to a freshness check: a CRL whose signed issue time is older than
> the freshness window is rejected as stale and fails closed, even though its own
> signed validity window is longer. The window is **tunable** via
> `license_crl_max_age` (env `PIPELOCK_LICENSE_CRL_MAX_AGE`); the **default is
> 25h**, and a missing/malformed/non-positive value fails safe back to 25h (it can
> never disable the check). You **must** republish the CRL on a cadence shorter
> than `license_crl_max_age` while require mode is active. A weekly-expiry CRL
> published once is not enough — require-mode consumers will block once the last
> publish ages past the window. Wire CRL republishing into a job (default: daily,
> to stay under the 25h window) before step 6, and if you widen or narrow
> `license_crl_max_age`, adjust the republish cadence to match.

### 5. Re-issue live licenses under the intermediate

Roll customers/agents onto intermediate-signed tokens (re-issue on the normal
refresh cadence, or proactively). Confirm with:

```bash
pipelock license status --json   # intermediate_configured: true, status: valid
```

Wait until effectively all live tokens are intermediate-signed. Any token still
root-signed will stop verifying at the next step.

### 6. Flip `require_intermediate` on

Set on each consumer:

```yaml
license_require_intermediate: true
license_intermediate_file: /etc/pipelock/intermediate.json
license_crl_file: /etc/pipelock/crl.json
```

or via env:

```bash
PIPELOCK_LICENSE_REQUIRE_INTERMEDIATE=true
PIPELOCK_LICENSE_INTERMEDIATE_FILE=/etc/pipelock/intermediate.json
PIPELOCK_LICENSE_CRL_FILE=/etc/pipelock/crl.json
```

Now any token NOT validated through the intermediate is rejected, and a stale or
missing CRL fails closed. The free proxy never crashes on a misconfiguration: a
require-on-but-misconfigured license surfaces a startup **warning** and disables
paid features, while detection/enforcement stays up.

## Revoking a compromised intermediate

If the service (and thus the intermediate key) is compromised:

```bash
# On the license service host (offline admin subcommand):
license-service revoke-intermediate --serial im-2026-001 --reason compromise
```

The next published CRL carries the revoked serial. Consumers with a fresh CRL
then reject every token that intermediate signed (`ErrIntermediateRevoked`). Mint
a replacement intermediate (step 1), deploy it, and re-issue tokens. The root
never moved.

## Recovering the CRL generation high-water after a DB restore

The CRL carries a monotonic **generation** counter; consumers reject any CRL
below the highest generation they have accepted (rollback defense). If a database
restore rewinds the issuer's counter, re-seed it from the last published CRL
before serving a new one:

```bash
license-service recover-crl-generation --crl /path/to/last-published-crl.json
```

This verifies the CRL's signature and raises the counter to at least that CRL's
generation (it never lowers it). The next published CRL is then strictly higher,
so a consumer that accepted the old generation accepts the new one and the
restore cannot un-revoke anything.

## Rollback

Before step 6, rollback is just "set `license_require_intermediate` back to off /
remove the env var" — consumers return to accepting root-signed tokens. After
step 6, rollback means re-issuing root-signed tokens AND turning require off
again; prefer fixing forward (mint/deploy a valid intermediate) over reverting
the whole tier.
