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

## Views and license tiers

All views use the same dedicated listener, authentication boundary, CSP, access
audit, and metadata-versus-raw redaction model.

| View | Route | License feature | Permission | What it proves |
|---|---|---|---|---|
| Overview | `/overview` | `agents` | `dashboard:evidence:read` | Ranked red/amber facts from the loaded evidence, fleet, governance, budget, and trust sources; no rolled-up green verdict. |
| Evidence | `/` and `/session/...` | `agents` | `dashboard:evidence:read` | Per-session receipt scorecard, timeline, and decision explanation from the configured recorder directory. |
| Exemptions | `/exemptions` | `agents` | `dashboard:exemptions:read` | Read-only exemption inventory from `--config`, with lifecycle metadata overlaid from `--exemption-store` when configured. |
| Agents | `/agents` and `/agent/...` | `agents` | `dashboard:agents:read` | Cross-session agent grouping and bounded scorecard rollups; absence means no loaded receipts, not proof the agent was idle. |
| Budgets | `/budgets` | `agents` | `dashboard:budgets:read` | Counts-only per-agent budget pressure from `--runtime-snapshot-file` or the default runtime snapshot. |
| Trust & Keys | `/trust-keys` | `agents` | `dashboard:trust_keys:read` | Trusted-key provenance, receipt blast radius, revocation status where verifiable, and local/Rekor anchor consistency. |
| Fleet | `/fleet` | `fleet` | `dashboard:fleet:read` | Enrolled follower runtime and signed applied-state status from the configured Conductor read source. |
| Workbench | `/workbench` | `fleet` | `dashboard:signed_action:read` | Prepare, dry-run, and replay guidance for signed Conductor actions; no write path. |
| Incident | `/incident` | `fleet` | `dashboard:incident:read` | Read-only correlation of a conductor decision, replay divergence, and fleet applied-state summary. |

Grant `dashboard:raw:read` only as an extra elevation. It is never enough by
itself to reach a route; the principal also needs that route's read permission.

## `pipelock dashboard serve`

```bash
pipelock dashboard serve \
  --receipt-dir /var/lib/pipelock/evidence \
  --config /etc/pipelock/pipelock.yaml \
  --legal-hold-store /var/lib/pipelock/dashboard/legal-holds.json \
  --exemption-store /var/lib/pipelock/dashboard/exemptions.json \
  --auth-token-file /etc/pipelock/dashboard.token \
  --trusted-signer 'file=/etc/pipelock/receipt-signing.pub,source=ops runbook' \
  --conductor-url https://127.0.0.1:8895 \
  --conductor-token-file /etc/pipelock/conductor-auditor.token \
  --conductor-tls-cert /etc/pipelock/dashboard-conductor-client.pem \
  --conductor-tls-key /etc/pipelock/dashboard-conductor-client.key \
  --conductor-server-ca /etc/pipelock/conductor-server-ca.pem \
  --conductor-org org-main \
  --conductor-fleet prod
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

### Authentication modes

The dashboard requires at least one of three authenticators, and each is a
complete authenticator on its own — none depends on the others:

- **Operator token** (`--auth-token-file`): a bearer token, optionally paired
  with a higher-privilege `--raw-token-file`.
- **OIDC** (`--oidc-issuer` plus its required options): a verified bearer token
  whose mapped claim grants bounded permissions.
- **Mutual TLS** (`--require-client-cert` plus the three mTLS file flags): a
  verified client certificate authorized through the role map.

You may combine token and OIDC, but mutual TLS is exclusive: when
`--require-client-cert` is set the verified certificate is authoritative and
supplies both route and raw-view permissions, so `--auth-token-file` and OIDC
are neither required nor consulted. Starting with none of the three is a
startup error.

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--receipt-dir` | (required) | Flight-recorder evidence directory holding action receipts (the runtime's `flight_recorder.dir`). |
| `--config` | none | Optional Pipelock config file for the read-only Exemptions inventory. When omitted, `/exemptions` renders an explicit "no config loaded" state and the Evidence view still works. |
| `--auth-token-file` | none | File containing the operator token for token-authenticated requests. Required unless OIDC or `--require-client-cert` is configured. Grants the redacted metadata view. |
| `--raw-token-file` | none | Optional second, higher-privilege token that unlocks raw destinations and signed payloads. Must differ from `--auth-token-file`. |
| `--legal-hold-store` | none | Optional atomic JSON legal-hold metadata store displayed read-only by the governance sections. |
| `--exemption-store` | none | Optional exemption lifecycle store. Overlays owner, reason, expiry, and last-match metadata onto the read-only Exemptions inventory. |
| `--delivery-inbox` | none | Optional alert delivery inbox file for read-only delivery-health and dead-letter status. |
| `--read-model-index` | none | Optional rebuilt dashboard read-model index file for freshness/source-hash status. Rebuild with `pipelock dashboard rebuild-read-model`. |
| `--runtime-snapshot-file` | `<receipt-dir>/dashboard/runtime-snapshot.json` | Counts-only proxy runtime snapshot used by the Budgets view. |
| `--listen` | `127.0.0.1:8896` | Dashboard listener address. Non-loopback addresses require `--tls-cert`/`--tls-key`. |
| `--trusted-signer` | none | Trusted receipt signing key: `(inline=HEX_OR_VERSIONED_PUBLIC_KEY\|file=/path)[,source=LABEL]`. Repeatable. `source` is shown in the UI as the reason the key is trusted. |
| `--anchor-expected` | `false` | Treat a session with no anchor-state marker as an anchor audit failure in Trust & Keys. |
| `--anchor-local-log` | none | Local anchor log used to verify anchor bundles produced with the local backend. |
| `--rekor-log-key` | none | Pinned Rekor log public key for verifying Rekor SET, checkpoint, and inclusion proof. Repeat for rotations. |
| `--license-crl-file` | none | Signed license revocation list; falls back to `PIPELOCK_LICENSE_CRL_FILE`. |
| `--tls-cert`, `--tls-key` | none | TLS server certificate and key. Both or neither. |
| `--oidc-issuer` | none | OIDC issuer URL used for discovery and exact issuer validation. |
| `--oidc-audience` | none | Expected OIDC audience. Required with `--oidc-issuer` unless `--oidc-client-id` is set. |
| `--oidc-client-id` | none | Alias for `--oidc-audience`; both values must match when both are set. |
| `--oidc-role-claim` | none | Verified token claim containing role or group values. Required with `--oidc-issuer`. |
| `--oidc-role-map` | none | JSON mapping of verified claim values to bounded dashboard permissions. Required with `--oidc-issuer`. |
| `--require-client-cert` | `false` | Require a verified client certificate on every TLS connection and authorize it through the role map. Requires all three mTLS file flags below. |
| `--client-ca-file` | none | PEM bundle of trust anchors used by TLS to verify client certificates. |
| `--client-cert-role-map` | none | YAML file mapping client-certificate SPKI SHA-256 fingerprints to roles and bounded dashboard permissions. |
| `--conductor-url` | none | Optional Conductor HTTPS base URL for read-only live fleet status. When omitted, live fleet panels render the explicit "no conductor source configured" state. |
| `--conductor-token-file` | none | File containing the Conductor read bearer token. Required with `--conductor-url`; must authorize the configured org/fleet read. |
| `--conductor-tls-cert`, `--conductor-tls-key` | none | Client certificate and key used for Conductor mutual TLS. Both are required with `--conductor-url`. |
| `--conductor-server-ca` | none | PEM CA bundle that signed the Conductor server certificate. Required with `--conductor-url`; the dashboard never falls back to plaintext or insecure TLS. |
| `--conductor-org`, `--conductor-fleet` | none | The single org/fleet scope this dashboard is allowed to read from the Conductor. Required with `--conductor-url`; requests for any other scope are denied before the Conductor is queried. |

### Mutual TLS client authentication

Mutual TLS is a complete authenticator on its own: enable it with all of
`--require-client-cert`, `--client-ca-file`, and `--client-cert-role-map` (plus
server TLS via `--tls-cert`/`--tls-key`), with or without an operator token or
OIDC. When enabled, the verified client certificate is authoritative: TLS
requires a certificate on every connection, and the certificate's mapped role
supplies both route and raw-view permissions and takes precedence over any
token or OIDC principal. An absent, wrong-CA, or unmapped certificate is denied
(the TLS layer rejects the first two; the fingerprint role map rejects the
third), so a server-wiring or ordering bug cannot silently fall back to token
access.

The role map uses the SHA-256 fingerprint of the leaf certificate's DER-encoded
SubjectPublicKeyInfo (SPKI). This identity remains stable when a certificate is
renewed with the same key. Role permissions must come from the dashboard's
bounded permission vocabulary. Grant `dashboard:raw:read` only to roles that
may view raw destinations and signed payloads.

<!-- dashboard-mtls-role-map-start -->
```yaml
version: 1
roles:
  metadata:
    permissions:
      - dashboard:evidence:read
      - dashboard:exemptions:read
      - dashboard:agents:read
      - dashboard:budgets:read
      - dashboard:trust_keys:read
  raw:
    permissions:
      - dashboard:evidence:read
      - dashboard:exemptions:read
      - dashboard:agents:read
      - dashboard:budgets:read
      - dashboard:trust_keys:read
      - dashboard:raw:read
  fleet-auditor:
    permissions:
      - dashboard:evidence:read
      - dashboard:fleet:read
      - dashboard:signed_action:read
      - dashboard:incident:read
certificates:
  0000000000000000000000000000000000000000000000000000000000000000: metadata
```
<!-- dashboard-mtls-role-map-end -->

Replace the all-zero example key with the client certificate's SPKI SHA-256
fingerprint. The map also accepts colon-separated hexadecimal and an optional
`sha256:` prefix. Unknown permissions, roles, fields, or fingerprints are hard
startup errors; an empty certificate map is never treated as allow-all.

Start the dashboard with client-certificate verification as the sole
authenticator (no `--auth-token-file`; add one only if you also want token
access to non-mTLS paths, though the certificate role stays authoritative):

```bash
pipelock dashboard serve \
  --receipt-dir /var/lib/pipelock/evidence \
  --tls-cert /etc/pipelock/dashboard-server.pem \
  --tls-key /etc/pipelock/dashboard-server.key \
  --require-client-cert \
  --client-ca-file /etc/pipelock/dashboard-client-ca.pem \
  --client-cert-role-map /etc/pipelock/dashboard-client-roles.yaml
```

The standard library verifies the chain, validity period, and client-auth key
usage before HTTP handling. Pipelock then maps only the verified leaf SPKI. A
missing, expired, wrong-CA, or unmapped certificate is denied. If a request
also carries a token, its certificate role remains authoritative for route and
raw-view permissions; a metadata certificate cannot use a raw token to
escalate.

### OIDC identity-provider setup

In OIDC mode the dashboard validates every bearer token against the configured
issuer and audience before authorizing it. Three claim checks are relevant when
wiring an identity provider:

- `iss` must exactly equal `--oidc-issuer`.
- `aud` must contain `--oidc-audience` (aliased by `--oidc-client-id`).
- `azp`, when present, must equal that same audience; a token with multiple
  audiences and no `azp` is rejected.

The common setup failure is the `aud` check. Many providers do not put the
client ID in the access token's audience by default, so the token is rejected
even though sign-in succeeds. Keycloak, for example, issues access tokens with
`aud: "account"` unless you add an audience mapper. To use the dashboard with
Keycloak, add an **Audience** protocol mapper to the client (or to a client
scope it uses) whose included client audience is the dashboard client ID, then
set `--oidc-audience` to that same client ID. The issued token then includes
the client ID in its `aud` claim (alongside any audiences the provider already
sets, such as `account`), so the "aud contains `--oidc-audience`" check passes.
A token that then carries multiple audiences must also set `azp` to the client
ID, which Keycloak does for the client that obtained the token; the dashboard
requires that `azp` match when more than one audience is present.

Pick a role source with `--oidc-role-claim` and map it to bounded dashboard
permissions with `--oidc-role-map`. The role claim can be `azp` (the client ID,
useful for a single-client deployment) or a groups/roles claim your provider
adds to the token. As with the mTLS role map, permissions must come from the
dashboard's bounded vocabulary and an unmapped principal is denied.

Example OIDC role map:

```json
{
  "claim_values": {
    "pipelock-dashboard-auditor": "auditor"
  },
  "roles": {
    "auditor": [
      "dashboard:evidence:read",
      "dashboard:exemptions:read",
      "dashboard:agents:read",
      "dashboard:budgets:read",
      "dashboard:trust_keys:read"
    ]
  }
}
```

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
  property this command can enforce by itself — which is why authentication is
  required even on loopback.
- **The license check is entitlement, not identity.** Token-only mode requires
  the operator token (constant-time comparison), as a `Bearer` header or as the
  Basic-auth password. OIDC mode requires a verified bearer token whose mapped
  roles grant bounded dashboard permissions. With mutual TLS enabled, every
  connection must present a verified certificate mapped to a role. Missing or
  invalid authentication gets no evidence.
- **Embedded handlers fail closed without an auth boundary.** The
  `pipelock dashboard serve` command wires its configured token, OIDC, or mTLS
  auth boundary into the dashboard handler. Go embedders that construct the
  dashboard handler directly and authenticate in an outer router must explicitly
  set `TrustedOuterAuth`; otherwise, leaving both authorization callbacks nil
  returns `403` for every route instead of serving unauthenticated.
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
  payload is the largest exfil surface. Token-authenticated requests receive
  raw detail only with `--raw-token-file`; OIDC and client-certificate requests
  receive it only when their mapped permissions include `dashboard:raw:read`
  (fail closed).
  Redaction happens before templating, so the raw bytes never reach a
  metadata-view response. The scorecard — the actual proof — does not depend
  on the raw fields.
- **Access is audited.** Every authenticated request is written to an access log
  on stderr (role `metadata` or `raw`, method, path, session, remote address).
  Viewing evidence is itself a recorded action.
- **Exemptions is inventory only.** `/exemptions` is GET-only and reads the
  already-loaded config snapshot. It has no POST route, no apply/remove/renew
  controls, no config write path, and no hot-reload hook.
- **Conductor reads are scoped and read-only.** When `--conductor-url` is set,
  the dashboard uses mutual TLS plus a bearer token to issue GET requests to
  the Conductor followers roster read endpoint, enriched with runtime status,
  for the configured
  `--conductor-org` / `--conductor-fleet`. It never holds a signing key and has
  no publish, kill, resume, rollback, enroll, revoke, or delete method.
- **Sensitive by design.** Even the metadata view exposes reasons, signer
  fingerprints, and session IDs. Treat the listener like an admin API: keep it
  loopback or behind TLS on a network only operators reach.

### Verify it yourself

The dashboard is a lens, not the proof. Every session view includes the exact
offline `pipelock-verifier verify-run` command that re-verifies the same
receipts against the trusted key, so anything the dashboard claims can be
independently re-checked against the signed evidence — without trusting this
server.

## Free single-session evidence server

`pipelock evidence serve` is the no-license, single-agent counterpart to the
Pro dashboard Evidence view. It binds exactly one session at startup and has no
route or query parameter that can switch to another session.

```bash
pipelock evidence serve \
  --receipt-dir /var/lib/pipelock/evidence \
  --session agent-a \
  --listen 127.0.0.1:8897
```

If the receipt directory contains only one session, `--session` can be omitted.
If it contains multiple sessions, `--session` is required so the free viewer
cannot enumerate other agents.

## Exemption lifecycle store

The Exemptions page reads config state; lifecycle mutation stays in the CLI.
Create and maintain lifecycle records with the `dashboard exemption` command
family, then point `dashboard serve` at the same store:

```bash
pipelock dashboard exemption add \
  --store /var/lib/pipelock/exemptions.json \
  --scope response_scanning.exempt_domains:api.vendor.example \
  --owner security-team \
  --reason "vendor docs include benign instruction-like examples" \
  --expiry 2026-10-01T00:00:00Z

pipelock dashboard exemption list --store /var/lib/pipelock/exemptions.json
pipelock dashboard exemption renew --store /var/lib/pipelock/exemptions.json --id exm_0123456789abcdef --expiry 2026-12-01T00:00:00Z
pipelock dashboard exemption expire --store /var/lib/pipelock/exemptions.json --id exm_0123456789abcdef
```

`add`, `renew`, `expire`, `touch`, `remove`, and `list` are the mutation and
inspection surface. Use the `exm_...` ID printed by `add` or `list` when
renewing or expiring a record. The HTTP dashboard overlays
owner/reason/expiry/status read-only and redacts owner/reason unless the
request has raw access.

## Coverage certificates

A coverage certificate is a signed statement about one agent over a time window.
It summarizes mediated-egress receipt integrity and completeness for that agent
only; it does not claim all agent activity or no bypass outside Pipelock.

Generate requires the Pro `agents` feature:

```bash
pipelock dashboard coverage-cert generate \
  --receipt-dir /var/lib/pipelock/evidence \
  --agent agent-a \
  --window-start 2026-07-01T00:00:00Z \
  --window-end 2026-07-12T00:00:00Z \
  --trusted-receipt-signer file=/etc/pipelock/keys/receipt-signing.pub,source=security-team \
  --signing-key /etc/pipelock/keys/coverage-cert.key \
  --out agent-a-coverage.json
```

When `--trusted-receipt-signer` is supplied, generation verifies each session's
receipt chain against that trusted signer set. Its CLI output says
`receipt chains: verified against trusted signer set`. Without it, generation
uses self-consistency checks and prints `receipt chains: self-consistent only`.

Verify is free and offline:

```bash
pipelock evidence verify-cert \
  --cert agent-a-coverage.json \
  --trusted-signer file=/etc/pipelock/keys/coverage-cert.pub,source=security-team
```

Verification exits zero only when the certificate signer is in the
`--trusted-signer` set. With no trusted signer, verification fails closed by
default. Pass `--allow-unpinned` only for an explicit structural-only
check; that output is labeled `STRUCTURAL ONLY` and does not report the signer
as trusted.

## Backup, restore, and read-model rebuild

Dashboard durable stores are the JSON files that cannot be reconstructed from
receipts, such as exemption lifecycle state, legal holds, and delivery inbox
state. Keep those stores under one state directory and back up that directory:

```bash
pipelock dashboard backup \
  --state-dir /var/lib/pipelock/dashboard \
  --legal-hold-store /var/lib/pipelock/dashboard/legal-holds.json \
  --exemption-store /var/lib/pipelock/dashboard/exemptions.json \
  --output /var/backups/pipelock-dashboard-state.tar

pipelock dashboard restore \
  --state-dir /var/lib/pipelock/dashboard \
  --legal-hold-store /var/lib/pipelock/dashboard/legal-holds.json \
  --exemption-store /var/lib/pipelock/dashboard/exemptions.json \
  --input /var/backups/pipelock-dashboard-state.tar
```

Restore validates the archive and writes each file atomically with best-effort
whole-set rollback. It is not a cross-file transaction; if a process crashes
between file writes, re-run restore to converge.

The read model is disposable and should be rebuilt from recorder evidence, not
backed up as authority:

```bash
pipelock dashboard rebuild-read-model \
  --receipt-dir /var/lib/pipelock/evidence \
  --output /var/lib/pipelock/dashboard/read-model-index.json
```

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
the dashboard can resolve the supplied artifact hash to the signed artifact the
Conductor replay endpoint requires, the replay panel renders an explicit "no
conductor decision source configured" state; the prepare guidance and the other
views do not depend on that source.

### Incident Cockpit (`/incident`)

A read-only correlation lens. Supply
`?org_id=<org>&fleet_id=<fleet>&artifact_hash=<hash>` to correlate one conductor
decision with its **replay divergence** (from the read-only decision source) and
a bounded **fleet applied-state summary** — counts of enrolled followers by
applied-state source (verified / signed-but-unverified / unsigned / no report),
plus drift and apply-failed counts. The cockpit never kills an agent, publishes,
or mutates fleet state, and does not prove no bypass occurred outside Pipelock,
outside enrolled followers, or outside the report window.

With `--conductor-url` configured, the fleet applied-state summary reads the
configured Conductor follower roster and runtime/applied-state status for the
single configured org/fleet. Decision replay remains unavailable until the
dashboard has a read source for the signed artifact behind an artifact hash.

### Redaction on these pages

Like the other views, these pages redact by default. In the metadata view
(`--auth-token-file`), decision artifact/result/recorded hashes, result
versions, and the free-text divergence reason are hidden; the computed status —
validity, the bounded conflict code, and the loud divergence flag — is always
shown. The fleet applied-state summary is counts only, carries no follower
identifiers, and is shown in full even in the metadata view. Raw detail is shown
only to a request that authenticates with `--raw-token-file`, or whose verified
OIDC or client-certificate mapping contains `dashboard:raw:read`. There is
deliberately no aggregate "all clear".
