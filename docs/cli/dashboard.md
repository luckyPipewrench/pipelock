<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# `pipelock dashboard`

Serve the read-only Evidence dashboard: a web view over the signed action
receipts in a flight-recorder evidence directory. It renders each recorder
session with a four-line scorecard — **Authentic**, **Untampered**,
**Anchored**, **Completeness** — where every line is an independent fact.
There is deliberately no aggregate "all clear": Completeness is always limited
to mediated traffic, Anchored is never green without an external inclusion
proof, and signers are only shown as trusted when the operator configured
their keys (never trust-on-first-use).

The command ships in official release builds (enterprise-tagged) and requires
a license that grants the `agents` feature (Pro or Enterprise); without one it
refuses to start. The dashboard is read-only: it renders evidence and never
mutates policy, receipts, or runtime state.

## `pipelock dashboard serve`

```bash
pipelock dashboard serve \
  --receipt-dir /var/lib/pipelock/evidence \
  --auth-token-file /etc/pipelock/dashboard.token \
  --trusted-signer 'file=/etc/pipelock/receipt-signing.pub,source=ops runbook'
```

Then open `http://127.0.0.1:8896/` in a browser (`https://` when
`--tls-cert`/`--tls-key` are set). The browser prompts for
credentials: enter any username and the token file's contents as the password.
Automation can send the same token as a bearer header:

```bash
curl -H "Authorization: Bearer $(cat /etc/pipelock/dashboard.token)" http://127.0.0.1:8896/
```

Create the token file once, readable only by the operator:

```bash
umask 077
openssl rand -hex 32 > /etc/pipelock/dashboard.token
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--receipt-dir` | (required) | Flight-recorder evidence directory holding action receipts (the runtime's `flight_recorder.dir`). |
| `--auth-token-file` | (required) | File containing the operator token required on every request. |
| `--listen` | `127.0.0.1:8896` | Dashboard listener address. Non-loopback addresses require `--tls-cert`/`--tls-key`. |
| `--trusted-signer` | none | Trusted receipt signing key: `(inline=HEX_OR_VERSIONED_PUBLIC_KEY\|file=/path)[,source=LABEL]`. Repeatable. `source` is shown in the UI as the reason the key is trusted. |
| `--license-crl-file` | none | Signed license revocation list; falls back to `PIPELOCK_LICENSE_CRL_FILE`. |
| `--tls-cert`, `--tls-key` | none | TLS server certificate and key. Both or neither. |

### License resolution

`dashboard serve` takes no config file. Like the other server commands, it
resolves the license token from `PIPELOCK_LICENSE_KEY` and verifies it against
the build-embedded public key (or `PIPELOCK_LICENSE_PUBLIC_KEY` on unofficial
builds). Verification fails closed before any listener binds, and the feature
entitlement is re-checked on every request, so a license that expires while
the server is running stops serving.

### Security model

- **Dedicated listener, never the proxy port.** The dashboard binds its own
  address, following the same port-isolation principle as
  `kill_switch.api_listen`: an agent routed through the proxy has no path to
  its own evidence view. Isolation from an agent running on the same host as
  a different user is deployment guidance (containment/network policy), not a
  property this command can enforce by itself — which is why the token is
  required even on loopback.
- **The license check is entitlement, not identity.** Every request must also
  carry the operator token (constant-time comparison), as a `Bearer` header or
  as the Basic-auth password. Requests without it get `401` and no evidence.
- **Cleartext refusal.** Without TLS the listener only accepts loopback
  addresses; serving a non-loopback address over plain HTTP is refused at
  startup because the operator token would transit in cleartext.
- **No trust-on-first-use.** Signer keys are trusted only via
  `--trusted-signer`. With no trusted keys configured the dashboard still
  serves, and the Authentic line honestly reports every signer as Unverified.
- **Sensitive by design.** The evidence view includes destinations, block
  reasons, signer fingerprints, and session IDs. Treat the listener like an
  admin API: keep it loopback or behind TLS on a network only operators reach.

### Verify it yourself

The dashboard is a lens, not the proof. Every session view includes the exact
offline `pipelock-verifier verify-run` command that re-verifies the same
receipts against the trusted key, so anything the dashboard claims can be
independently re-checked against the signed evidence — without trusting this
server.
