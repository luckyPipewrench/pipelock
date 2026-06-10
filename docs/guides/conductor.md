<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Conductor: the Pipelock fleet control plane

Conductor is Pipelock's Enterprise control plane for a fleet of Pipelock
instances. It distributes signed policy bundles to follower instances, ingests
and stores their signed evidence for audit, and coordinates fleet-wide
operations — enrollment, remote kill, and policy rollback. It is **General
Availability as of v2.7**.

Conductor preserves Pipelock's capability separation. Followers enforce policy
locally and stay fail-closed on their own; Conductor coordinates distribution,
evidence, and visibility but **holds no agent secrets and does not scan traffic
on behalf of followers**. If a follower loses contact with Conductor it keeps
enforcing the policy it already has — Conductor is not inline for enforcement.

Conductor is Enterprise-tier and only exists in an enterprise build
(`-tags enterprise`). Every Conductor command verifies an Enterprise license
that grants the `fleet` feature and **fails closed before binding a listener or
writing a file** if the entitlement is missing.

> **Scope.** This guide covers what Conductor is, how the planes fit together,
> and how to run each component. For a hands-on local walkthrough (one
> Conductor, one follower, one signed batch, verified offline) see the
> [Conductor operator runbook](conductor-operator-runbook.md). For the full
> protocol and storage design see the
> [Conductor & audit sink design](../specs/pipelock-conductor-audit-sink.md).

## When to use Conductor

Reach for Conductor when you run **more than one** Pipelock instance and need to:

- push one signed policy across the fleet instead of editing each host;
- collect every instance's signed decision evidence into one audit store you can
  query and verify offline;
- hit a fleet-wide kill switch or roll a bad policy bundle back, with a signed,
  time-bounded authorization rather than an ad-hoc SSH loop.

A single Pipelock instance needs none of this — all detection, enforcement, the
kill switch, and the flight recorder are free and work standalone. Conductor
sells **coordination across instances**, not detection.

## Architecture: three planes

Conductor runs three logical planes over one mutually-authenticated (mTLS)
follower API:

| Plane | What it does |
|-------|--------------|
| **Control** | Distributes signed policy bundles to followers; followers verify the signature and pin against a trust roster before applying. |
| **Audit sink** | Ingests signed evidence batches from followers, DLP-scans them before storage, detects sequence forks, and stores them append-only in a per-follower namespace. |
| **Coordination** | Manages follower enrollment, fleet-wide remote-kill state, and policy-bundle rollback authorization. |

A **follower** is an ordinary Pipelock deployment configured with a `conductor:`
block (see [Follower configuration](#follower-configuration)). It authenticates
to Conductor with a client certificate; its identity is derived from the
certificate's SPIFFE URI SAN, **not** from any request field, so a follower
cannot claim to be another.

Every fleet object is namespaced by the tuple **org / fleet / instance**. An
audit signing key is bound to its `org` so a key from one org cannot
authenticate batches for another.

## Licensing and gating

Conductor and the fleet control plane are gated by the `fleet` feature, which
the **Enterprise** tier grants (the time-boxed **Enterprise Eval** tier grants
the same `fleet` feature for 60 days). The gate is binary-enforced and
fail-closed: `pipelock conductor serve`, `pipelock conductor bootstrap`,
`pipelock fleet-sink`, and `pipelock run` with `conductor.enabled: true` all call
the fleet license check at startup and refuse to proceed without a valid
Enterprise license.

Provide the license through the standard sources:

- `PIPELOCK_LICENSE_KEY` — the signed license token (or install it with
  [`pipelock license install`](../cli/license.md));
- `PIPELOCK_LICENSE_PUBLIC_KEY` — required on unofficial/local enterprise builds
  that do not embed the public key;
- `PIPELOCK_LICENSE_CRL_FILE` (or `--license-crl-file`) — an optional signed
  revocation list. Server commands check it at startup. Follower runtimes also
  watch configured license revocation/expiry state: a proven loss tears down the
  Conductor fan-out while free detection keeps running, and config reload cannot
  re-activate Conductor once it is down (restart-only).

See the [tier-gating audit matrix](../security/tier-gating-audit-matrix.md) for
the full entitlement map and the negative (deny) cases.

## Running Conductor (`pipelock conductor serve`)

`conductor serve` binds the follower-facing HTTPS API (TLS 1.3, mandatory client
certificates) plus an optional plain-HTTP probe listener for health, readiness,
and Prometheus metrics.

```bash
pipelock conductor serve \
  --storage-dir /var/lib/pipelock/conductor \
  --tls-cert conductor.crt --tls-key conductor.key \
  --client-ca followers-ca.pem \
  --publisher-token-file publisher.token \
  --auditor-token-file auditor.token \
  --admin-token-file admin.token \
  --trusted-audit-key 'id=follower-1,org=org-acme,file=/keys/follower-1.pub'
```

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `127.0.0.1:8895` | Address for the Conductor HTTPS follower API. |
| `--probe-listen` | `127.0.0.1:9092` | Plain-HTTP address for health/readiness/metrics probes; empty disables it. |
| `--storage-dir` | (required) | Directory for policy bundles and the audit store. |
| `--conductor-id` | `conductor` | Conductor ID advertised in capabilities. |
| `--follower-trust-domain` | `pipelock.local` | SPIFFE trust domain for follower mTLS identities. |
| `--publisher-token-file` | (required) | File holding the bearer token required to publish policy bundles. |
| `--auditor-token-file` | (required) | File holding the bearer token required to query audit metadata. |
| `--admin-token-file` | (required) | File holding the bearer token required for Conductor admin requests. |
| `--audit-retention` | `0` (keep forever) | Duration to keep audit evidence; older batches are pruned at startup. |
| `--trusted-audit-key` | (repeatable) | Trusted follower audit signing key: `id=ID,(inline=BASE64\|file=/path),org=ORG[,fleet=FLEET][,instance=INSTANCE]`. `org=` is required. |
| `--trusted-control-key` | (repeatable) | Trusted emergency control key: `id=ID,purpose=(remote-kill-signing\|policy-bundle-rollback),(inline=BASE64\|file=/path)`. |
| `--remote-kill-max-validity` | `72h` | Maximum validity window for published remote-kill messages. |
| `--rollback-max-validity` | `24h` | Maximum validity window for published rollback authorizations. |
| `--license-crl-file` | (optional) | Signed license revocation list; falls back to `PIPELOCK_LICENSE_CRL_FILE`. |
| `--tls-cert` | (required) | TLS server certificate. |
| `--tls-key` | (required) | TLS server private key. |
| `--client-ca` | (required) | Client CA bundle for follower mTLS. |

Operator bearer tokens are read **from files**, never passed as command-line
arguments, so they do not leak into process listings or shell history.

The `--storage-dir` holds the policy-bundle store, the SQLite audit database,
the enrollment roster, and the emergency-controls store. Keep it on durable
storage with restrictive permissions.

## The audit sink (`pipelock fleet-sink`)

The audit sink ingests and stores signed evidence batches. It is the audit-sink
plane of Conductor and can also run as a standalone sink for operators who want
to collect evidence separately from the control plane.

```bash
pipelock fleet-sink \
  --storage-dir /var/lib/pipelock/fleet-sink \
  --trusted-audit-key 'id=follower-1,org=org-acme,file=/keys/follower-1.pub' \
  --tls-cert sink.crt --tls-key sink.key --client-ca followers-ca.pem
```

| Flag | Default | Description |
|------|---------|-------------|
| `--listen` | `127.0.0.1:8894` | Address for the fleet-sink HTTP listener. |
| `--probe-listen` | (empty = disabled) | Plain-HTTP address for health probes; empty disables it. |
| `--storage-dir` | (required) | Directory for the fleet-sink SQLite store. |
| `--trusted-audit-key` | (repeatable) | Trusted follower audit signing key: `id=ID,(inline=BASE64\|file=/path)[,org=ORG][,fleet=FLEET][,instance=INSTANCE]`. |
| `--max-skew` | `60s` | Maximum allowed clock skew on an audit batch. |
| `--tls-cert` | (optional) | TLS server certificate. |
| `--tls-key` | (optional) | TLS server private key. |
| `--client-ca` | (optional) | Client CA bundle for mTLS. |
| `--reader-token-file` | (optional) | Bearer token required for GET requests; required for a non-loopback bind without `--client-ca`. |
| `--license-crl-file` | (optional) | Signed license revocation list; falls back to `PIPELOCK_LICENSE_CRL_FILE`. |

On ingest, the sink validates the batch schema, the follower signature against a
trusted audit key, and the clock skew; **DLP-scans the batch before it touches
disk**; detects sequence forks (a replay or a forked chain for the same
follower); and stores accepted batches append-only, isolated per
org/fleet/instance. Ingest is idempotent per `batch_id`, so a retried delivery
is recorded once.

Audit reads require the full `org`/`fleet`/`instance` namespace tuple and an
auditor (reader) token. The query API, including the per-batch endpoint, returns
metadata-only summaries and deliberately does **not** export raw stored payload
bytes. The local SQLite store is the raw-evidence escrow boundary; treat
`--storage-dir` as sensitive operator-controlled evidence storage.

## Trying it locally (`pipelock conductor bootstrap`)

`conductor bootstrap` stands up a complete local dev fleet end to end: it
generates a CA, server and client certificates (with SPIFFE URI SANs), audit
keys, a trust roster, a license, and operator tokens; runs one Conductor and one
follower in-process; enrolls the follower over mTLS; has it sign one audit
batch; ingests and queries it back; and verifies it offline.

```bash
pipelock conductor bootstrap --dir /var/lib/pipelock/dev-fleet
```

| Flag | Default | Description |
|------|---------|-------------|
| `--dir` | (required) | Directory to write the dev-fleet material into. |
| `--trust-domain` | `pipelock.local` | SPIFFE trust domain for fleet identities. |
| `--org` | `org-local` | Fleet org ID. |
| `--fleet` | `dev` | Fleet ID. |
| `--instance` | `follower-1` | Follower instance ID. |
| `--env` | `dev` | Follower environment. |
| `--conductor-id` | `conductor-local` | Conductor ID. |
| `--listen-host` | `127.0.0.1` | Loopback host for the listener and certificate SAN. |
| `--conductor-port` | `8895` | Conductor port baked into the follower config. |
| `--validity` | `90 days` | Validity window for the generated CA, certificates, and license. |
| `--force` | `false` | Regenerate material even if a complete prior bootstrap is present. |
| `--skip-proof` | `false` | Generate material without running the live round-trip proof. |
| `--license-crl-file` | (optional) | Signed license revocation list; falls back to `PIPELOCK_LICENSE_CRL_FILE`. |

Bootstrap is for evaluation and local validation, not production. Use a private
directory under a non-world-writable parent — follower config validation rejects
world-writable ancestors, so avoid a shared `/tmp` path. The
[operator runbook](conductor-operator-runbook.md) walks the full sequence.

## Follower configuration

A follower is a standard Pipelock instance with a `conductor:` block. Pipelock
parses the block in any build but **refuses to run with `conductor.enabled: true`
unless it is an enterprise build with the `fleet` entitlement**.

```yaml
conductor:
  enabled: true
  conductor_url: https://conductor.internal:8895
  org_id: org-acme
  fleet_id: prod
  instance_id: edge-01
  trust_roster_path: /etc/pipelock/trust-roster.json
  trust_roster_root_fingerprint: <sha256-of-trust-root>
  server_ca_file: /etc/pipelock/conductor-ca.pem
  client_cert_path: /etc/pipelock/follower.crt
  client_key_path: /etc/pipelock/follower.key
  bundle_cache_dir: /var/lib/pipelock/bundles
  durable_audit_queue_dir: /var/lib/pipelock/audit-queue
  audit_signing_key_id: edge-01-audit
  recorder_key_id: edge-01-recorder
  poll_interval: 30s
  honor_remote_kill_switch: true
```

When `conductor.enabled: true`, validation requires:

- the **flight recorder enabled and signing checkpoints** with a configured
  `signing_key_path` — a follower must produce signed evidence to participate;
- a non-empty `trust_roster_root_fingerprint`;
- all identity fields (`org_id`, `fleet_id`, `instance_id`, `audit_signing_key_id`,
  `recorder_key_id`) matching the canonical identifier pattern;
- all file paths absolute.

`honor_remote_kill_switch` (default `true`) opts the follower into the
fleet-wide kill signal. A few fields (`created_skew_seconds`,
`max_min_version_*_skew`, `max_capability_threshold`, `emergency_stream`,
`stale_policy`) are validated at startup but reserved — the follower runtime
does not enforce them yet. See the
[configuration reference](../configuration.md#conductor-follower-v27-enterprise)
for the full field list.

## PKI and trust model

Conductor's trust is rooted in deployment-provided PKI, not in the binary:

- **Follower mTLS.** Followers present a client certificate signed by the
  `--client-ca` bundle; their fleet identity is the certificate's SPIFFE URI SAN
  under the `--follower-trust-domain`. Conductor requires TLS 1.3 and verifies
  the client certificate on every request.
- **Audit signing keys** (`--trusted-audit-key`) verify the signature on each
  evidence batch. The `org=` binding stops a key from one org authenticating
  batches for another.
- **Emergency control keys** (`--trusted-control-key`) are purpose-scoped
  (`remote-kill-signing` or `policy-bundle-rollback`); a key signed for one
  purpose is rejected for the other.
- **Operator tokens** (publisher/auditor/admin/reader) authorize the
  human-driven HTTP roles and are read from files.

Pipelock enforces the verification and the fail-closed gates; **you** supply and
protect the certificates, keys, and tokens. Treat the CA keys, audit/control
signing keys, and operator tokens as deployment secrets.

## Emergency controls

Conductor can publish two kinds of signed, time-bounded authorization to the
fleet:

- **Remote kill** — a fleet-wide stop signal. Followers that set
  `honor_remote_kill_switch: true` act on it. Conductor rejects a remote-kill
  message whose validity window exceeds `--remote-kill-max-validity`
  (default `72h`).
- **Policy-bundle rollback** — authorization to revert to a prior signed bundle.
  Conductor rejects a rollback whose window exceeds `--rollback-max-validity`
  (default `24h`).

Both are signed with a purpose-scoped control key, so an operator cannot reuse a
rollback key to issue a kill (or vice versa).

## Evidence and verification

Every follower emits Ed25519-signed, hash-chained evidence (the
[flight recorder](flight-recorder.md)) and ships it to the audit sink in signed
batches. Because the batches are signed by the follower and verified against a
pinned key, an operator with the raw evidence — the follower's own recorder
output, or the sink's operator-controlled escrow at `--storage-dir` — can verify
it **offline** with [`pipelock verify-receipt`](receipt-verification.md) or the
standalone `pipelock-verifier`, without trusting Conductor, the follower, or the
storage layer. The audit query API surfaces metadata only; the raw evidence
stays in the escrow. Retention is bounded by `--audit-retention`; older batches
are pruned at startup.

## Deployment notes

- **Binary-enforced vs deployment-provided.** Pipelock enforces the license
  gate, mTLS client-cert verification, signature and skew checks, fork
  detection, fail-closed validation, and the validity-window caps. The PKI
  (CAs, certificates, SPIFFE identities), the network reachability between
  followers and Conductor, and the protection of keys and tokens are yours to
  provide and operate.
- **Followers enforce locally.** Conductor distributes and collects; it is not
  in the data path. A follower keeps enforcing the policy it already has if
  Conductor is unreachable; a bundle's validity window is checked when the
  bundle is verified and applied, so an expired bundle never applies. (The
  `stale_policy` block is reserved for finer-grained staleness handling and is
  not enforced yet.)
- **Capability separation holds.** Conductor never receives agent secrets and
  never scans traffic for a follower.

## See also

- [Conductor operator runbook](conductor-operator-runbook.md) — hands-on local
  fleet walkthrough and verification.
- [Conductor & audit sink design](../specs/pipelock-conductor-audit-sink.md) —
  protocol, storage, and threat model.
- [`pipelock license`](../cli/license.md) — install and check the Enterprise
  license that unlocks the fleet feature.
- [Tier-gating audit matrix](../security/tier-gating-audit-matrix.md) — the full
  entitlement map and deny cases.
- [Receipt verification](receipt-verification.md) — verify follower evidence
  offline.
