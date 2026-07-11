<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# `pipelock dashboard`

Serve the read-only operator dashboard. The Evidence view is a web view over
the signed action receipts in a flight-recorder evidence directory. It renders
each recorder session with a four-line scorecard — **Authentic**, **Untampered**,
**Anchored**, **Completeness** — where every line is an independent fact.
There is deliberately no aggregate "all clear": Completeness is always limited
to mediated traffic, Anchored is never green without an external inclusion
proof, and signers are only shown as trusted when the operator configured
their keys (never trust-on-first-use).

The Exemptions view is a read-only inventory over the loaded Pipelock config.
It lists configured exemption-like knobs and flags only the inert or
wrong-knob findings produced by the same config semantic analyzer used by
`pipelock doctor`. It does not create, renew, apply, remove, or hot-reload
exemptions, and it does not invent lifecycle telemetry: owner, expiry,
last-matched, and suppressed-count columns are shown as `not tracked`.

The command ships in official release builds (enterprise-tagged) and requires
a license that grants the `agents` feature (Pro or Enterprise); without one it
refuses to start. The dashboard is read-only: it renders evidence and never
mutates policy, receipts, or runtime state.

The Compliance console at `/compliance` is a source-grounded mapping view over
the same receipt scorecards, loaded config, optional live fleet coverage source,
and operator-authored legal-hold metadata. It renders Pipelock's mapping for
AARM R1-R9 and an illustrative generic SOC 2-style control set. It is not a
certification, an auditor opinion, or an endorsement by a framework body.
Coverage labels are LIMITED to mediated egress inside the declared Pipelock
boundary.

## `pipelock dashboard serve`

```bash
pipelock dashboard serve \
  --receipt-dir /var/lib/pipelock/evidence \
  --config /etc/pipelock/pipelock.yaml \
  --legal-hold-store /var/lib/pipelock/legal-holds.json \
  --auth-token-file /etc/pipelock/dashboard.token \
  --compliance-token-file /etc/pipelock/dashboard-auditor.token \
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
| `--config` | none | Optional Pipelock config file for the read-only Exemptions inventory. When omitted, `/exemptions` renders an explicit "no config loaded" state and the Evidence view still works. |
| `--auth-token-file` | (required) | File containing the operator token required on every request. Grants the redacted metadata view. |
| `--raw-token-file` | none | Optional second, higher-privilege token that unlocks raw destinations and signed payloads. Must differ from `--auth-token-file`. |
| `--compliance-token-file` | none | Optional distinct auditor token granting only `dashboard:compliance:read`; it cannot reach evidence, raw, fleet-control preparation, or signed-action routes. |
| `--legal-hold-store` | none | Optional atomic JSON legal-hold metadata store displayed read-only by `/compliance`. |
| `--listen` | `127.0.0.1:8896` | Dashboard listener address. Non-loopback addresses require `--tls-cert`/`--tls-key`. |
| `--trusted-signer` | none | Trusted receipt signing key: `(inline=HEX_OR_VERSIONED_PUBLIC_KEY\|file=/path)[,source=LABEL]`. Repeatable. `source` is shown in the UI as the reason the key is trusted. |
| `--license-crl-file` | none | Signed license revocation list; falls back to `PIPELOCK_LICENSE_CRL_FILE`. |
| `--tls-cert`, `--tls-key` | none | TLS server certificate and key. Both or neither. |

### License resolution

`dashboard serve` loads `--config` only when the flag is provided, using the
normal Pipelock config loader. The loaded config feeds the `/exemptions` view;
it does not grant the dashboard authority to mutate policy or reload runtime
state. If `--config` is omitted, the Exemptions view reports that no config was
loaded.

License resolution still follows the paid-surface gate: the command resolves
the license token from `PIPELOCK_LICENSE_KEY` and verifies it against the
build-embedded public key (or `PIPELOCK_LICENSE_PUBLIC_KEY` on unofficial
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
- **Redacted by default (least privilege).** The metadata token sees the
  scorecard, hashes, timeline verdicts/reasons/timestamps, and the offline
  verify command — but receipt destinations and full signed payloads are
  redacted, because a destination URL can carry a capability token and the raw
  payload is the largest exfil surface. Raw detail is shown only to a request
  that authenticates with `--raw-token-file`; with no raw token configured, raw
  is redacted for everyone (fail closed). Redaction happens before templating,
  so the raw bytes never reach a metadata-view response. The scorecard — the
  actual proof — does not depend on the raw fields.
- **Access is audited.** Every authenticated request is written to an access log
  on stderr (role `metadata` or `raw`, method, path, session, remote address).
  Viewing evidence is itself a recorded action.
- **Exemptions is inventory only.** `/exemptions` is GET-only and reads the
  already-loaded config snapshot. It has no POST route, no apply/remove/renew
  controls, no config write path, and no hot-reload hook.
- **Compliance is mapping only.** `/compliance` is GET-only. Its `covered`,
  `partial`, and `not-covered` labels report whether the declared backing
  evidence exists; they do not assert organizational compliance. With no live
  fleet source, it renders an unconfigured empty state rather than local data
  labeled as live fleet coverage.
- **Sensitive by design.** Even the metadata view exposes reasons, signer
  fingerprints, and session IDs. Treat the listener like an admin API: keep it
  loopback or behind TLS on a network only operators reach.

### Verify it yourself

The dashboard is a lens, not the proof. Every session view includes the exact
offline `pipelock-verifier verify-run` command that re-verifies the same
receipts against the trusted key, so anything the dashboard claims can be
independently re-checked against the signed evidence — without trusting this
server.

## Legal-hold metadata

The web dashboard never creates or releases a hold. An operator changes the
durable metadata store through the licensed CLI, then points `dashboard serve`
at the same file:

```bash
pipelock dashboard legal-hold add \
  --store /var/lib/pipelock/legal-holds.json \
  --id investigation-2026-07 \
  --scope agent-a \
  --reason 'preserve mediated-egress evidence for active review'

pipelock dashboard legal-hold release \
  --store /var/lib/pipelock/legal-holds.json \
  --id investigation-2026-07
```

The store contains only metadata that cannot be reconstructed from receipts:
ID, scope, reason, creation time, and optional release time. Writes are atomic;
the file is mode `0600` and its directory is created as `0750`. A corrupt store
fails closed at CLI or dashboard startup instead of silently showing no holds.

## Signed Action Workbench and Incident Cockpit (Enterprise fleet tier)

The dashboard adds two Enterprise fleet-tier pages, `/workbench` and
`/incident`. Both require a license that grants the `fleet` feature; a license
with only the `agents` feature gets `403` on these routes while the agent-tier
Evidence, Agents, and Exemptions views keep working. They are served by the same
`pipelock dashboard serve` command and reuse its authentication,
cleartext-refusal, audit-log, and redaction seams.

Both pages are **prepare / verify / replay only**. Neither can execute, submit,
or otherwise mutate fleet state:

- Every route is GET-only; a mutating HTTP method returns `405`.
- The only conductor seam these pages consume is read-only: it re-derives a
  decision (dry-run / replay) and never publishes, kills, resumes, or rolls back
  anything. There is no publish/kill/rollback method on that seam and no write
  path reachable from the dashboard.
- The operator prepares and submits an action with the shipped conductor CLI
  **outside** the dashboard. The workbench's job ends at "here is the predicted
  effect and the command template to run".

### Signed Action Workbench (`/workbench`)

The workbench has two parts. **Prepare and submit guidance** is a static,
per-request-identical list of the shipped conductor commands an operator runs
outside the dashboard: `pipelock conductor publish …`, `pipelock conductor kill …`
(and `resume`), and `pipelock conductor rollback …`. The dashboard only displays
these commands; it never runs them.

**Verify / replay a past decision**: with a conductor decision source wired,
supply `?org_id=<org>&fleet_id=<fleet>&artifact_hash=<hash>` to re-derive the
conductor authorization and effect decision for a past signed action under the
current fleet and policy state. The panel surfaces the re-derived verdict and a
loud **Divergence** flag when the re-derived decision no longer matches what was
recorded. Replay does not re-derive proxy content-scan verdicts, and does not
prove any action executed or was prevented outside the conductor decision. Until
the dashboard is wired to a conductor read source, the replay panel renders an
explicit "no conductor decision source configured" state; the prepare guidance
and the other views do not depend on that source.

### Incident Cockpit (`/incident`)

A read-only correlation lens. Supply
`?org_id=<org>&fleet_id=<fleet>&artifact_hash=<hash>` to correlate one conductor
decision with its **replay divergence** (from the read-only decision source) and
a bounded **fleet applied-state summary** — counts of enrolled followers by
applied-state source (verified / signed-but-unverified / unsigned / no report),
plus drift and apply-failed counts. The cockpit never kills an agent, publishes,
or mutates fleet state, and does not prove no bypass occurred outside Pipelock,
outside enrolled followers, or outside the report window.

### Redaction on these pages

Like the other views, these pages redact by default. In the metadata view
(`--auth-token-file`), decision artifact/result/recorded hashes, result
versions, and the free-text divergence reason are hidden; the computed status —
validity, the bounded conflict code, and the loud divergence flag — is always
shown. The fleet applied-state summary is counts only, carries no follower
identifiers, and is shown in full even in the metadata view. Raw detail is shown
only to a request that authenticates with `--raw-token-file`. There is
deliberately no aggregate "all clear".
