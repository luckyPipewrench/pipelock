<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Conductor Production Operator Runbook

This runbook walks the **full production lifecycle** of a [Conductor](conductor.md)
fleet with shipped Pipelock CLIs and a documented bring-your-own-PKI recipe — no
custom Go and no hand-rolled OpenSSL beyond the PKI choice you make. It is the
day-2 counterpart to the [local dev walkthrough](conductor-operator-runbook.md)
(which proves the round trip in-process with `conductor bootstrap`) and the
[Kubernetes deployment guide](kubernetes-enterprise-deployment.md) (which covers
the Helm topology). Read those first for context; this guide is the operator
*workflow* around a real fleet.

Everything here is Enterprise-tier. Every server command verifies a license
granting the `fleet` feature and **fails closed** before binding a listener or
writing a file. See [`pipelock license`](../cli/license.md).

> **Build note.** Conductor exists only in an enterprise build (`-tags
> enterprise`). The commands below assume a `pipelock` binary built with that
> tag. On an unofficial/local enterprise build, also set
> `PIPELOCK_LICENSE_PUBLIC_KEY` so license verification can run.

## Lifecycle at a glance

| Stage | Command(s) | Status |
|-------|-----------|--------|
| 1. Generate fleet keys | `pipelock signing key generate --purpose …` | **Shipped** |
| 2. Build the trust roster | `pipelock signing roster build` | **Shipped** |
| 3. Provision PKI (BYO) | cert-manager recipe (below) | **Shipped (recipe)** |
| 4. Deploy Conductor + sink | `pipelock conductor serve` / `pipelock fleet-sink` + Helm | **Shipped** |
| 5. Enroll followers | follower `conductor:` config + mTLS auto-enroll | **Shipped** |
| 6. Publish a policy | `pipelock conductor publish` | **Shipped** |
| 7. Kill / resume the fleet | `pipelock conductor kill` / `resume` | **Shipped** |
| 8. Roll back a bad bundle | `pipelock conductor rollback` | **Shipped** |
| 9. Mint enrollment tokens | `pipelock conductor enrollment-token mint` | **Shipped** |
| 10. Fleet status / followers | `pipelock conductor fleet status` / `followers` | **Shipped** |
| 11. Query the audit sink | `pipelock conductor audit query` | **Shipped** |
| 12. Rotate certs and keys | cert-manager + `signing key generate` | **Shipped** |

Every stage uses a shipped CLI; the full lifecycle runs without hand-rolled Go or
OpenSSL beyond the documented bring-your-own-PKI choice. For the on-wire request
shapes behind each command, see the
[audit-sink design](../specs/pipelock-conductor-audit-sink.md).

## 0. License gate

Provision the Enterprise license first; every later command needs it.

```bash
# Install the signed Enterprise license token where pipelock reads it at startup.
# The token is the positional argument; --path is where it is written.
pipelock license install "$PIPELOCK_LICENSE_KEY" --path /etc/pipelock/license/license.token

# Confirm it verifies and grants the fleet feature.
pipelock license status
```

`pipelock license status` prints the tier, the granted features (look for
`fleet`), and the expiry. If the fleet feature is absent, the server commands
below refuse to start.

## 1. Generate the fleet keys

Conductor has five signing-key roles plus a per-follower recorder key. Generate
each with `pipelock signing key generate`, which writes a `0600` JSON keypair
file and prints the canonical sha256 fingerprint you pin downstream.

```bash
mkdir -p /etc/pipelock/fleet-keys && chmod 700 /etc/pipelock/fleet-keys

# Deployment-local trust root — signs the roster that followers pin.
pipelock signing key generate --purpose roster-root \
  --out /etc/pipelock/fleet-keys/fleet-root.json --id fleet-root

# Policy-bundle signing — signs every published policy bundle.
pipelock signing key generate --purpose policy-bundle-signing \
  --out /etc/pipelock/fleet-keys/policy-signing.json --id policy-primary

# Remote-kill signing — signs fleet-wide kill messages. THRESHOLD key.
pipelock signing key generate --purpose remote-kill-signing \
  --out /etc/pipelock/fleet-keys/kill-approver-1.json --id kill-approver-1

# Policy-bundle rollback — signs rollback authorizations. THRESHOLD key.
pipelock signing key generate --purpose policy-bundle-rollback \
  --out /etc/pipelock/fleet-keys/rollback-approver-1.json --id rollback-approver-1
```

**Threshold keys.** Rollback, remote-kill, and trust-root-rotation are
*threshold* roles: an authorization should require M independent approvers, not
one. Generate one key file **per approver** on **separate operator machines** and
configure the Conductor control plane to require the fleet threshold. Never
deploy a single rollback or kill key as a one-signer authority. (The keygen
command prints a `threshold: required` advisory line for these purposes on a
build that carries the conductor-keygen help update.)

> **Reserved purposes.** `trust-root-rotation` and `enrollment-token-signing`
> are wire-stable purpose bindings, but no shipped operator workflow consumes
> them yet. You can generate them, but nothing reads them until the trust-root
> rotation and enrollment-token features ship.

Each follower also needs an Ed25519 recorder key to sign its evidence:

```bash
# Per-follower recorder key, written into the pipelock keystore.
pipelock keygen edge-01-recorder
# Public key path is printed; mount the private key into the follower pod and
# point flight_recorder.signing_key_path at it.
```

## 2. Build the signed trust roster

Followers pin a **trust roster** — a signed list of which public keys are
trusted for which purpose — by its root fingerprint. Build it from the root key
and the public halves of the signing keys:

```bash
pipelock signing roster build \
  --root /etc/pipelock/fleet-keys/fleet-root.json \
  --include id=policy-primary,key=/etc/pipelock/fleet-keys/policy-signing.json,purpose=policy-bundle-signing,role=publisher \
  --include id=kill-approver-1,key=/etc/pipelock/fleet-keys/kill-approver-1.json,purpose=remote-kill-signing,role=kill-approver \
  --include id=rollback-approver-1,key=/etc/pipelock/fleet-keys/rollback-approver-1.json,purpose=policy-bundle-rollback,role=rollback-approver \
  --data-class internal \
  --out /etc/pipelock/fleet-keys/trust-roster.json

# Confirm the roster signature and capture the root fingerprint to pin.
pipelock signing roster verify \
  --path /etc/pipelock/fleet-keys/trust-roster.json \
  --root-fingerprint sha256:<root-fingerprint-from-step-1>
```

`roster build` accepts either the JSON keypair file or a public-key file for each
`--include`; it reads only the public half. Distribute `trust-roster.json` plus
the **root fingerprint** to every follower (`conductor.trust_roster_path` and
`conductor.trust_roster_root_fingerprint`). The fingerprint pin is what makes a
swapped roster fail closed.

## 3. Provision PKI (bring-your-own, cert-manager recipe)

Conductor's mTLS is rooted in **deployment-provided PKI**, not the binary. The
fleet CA signs two kinds of certificate:

- the **Conductor server cert** (DNS + IP SANs the followers reach it on);
- a **per-follower client cert** whose **SPIFFE URI SAN is the follower's fleet
  identity** — Conductor derives org/fleet/instance/environment from that URI,
  never from a request field, so a follower cannot impersonate another.

The proven recipe uses cert-manager with a CA `ClusterIssuer`. Generate the CA
keypair once with your PKI tooling, store it in a Secret in the cert-manager
namespace, and reference it:

```yaml
# Fleet CA issuer. Signs BOTH the server cert and every follower client cert.
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: conductor-fleet-ca
spec:
  ca:
    secretName: conductor-fleet-ca   # CA keypair Secret (cert-manager namespace)
```

```yaml
# Conductor server cert, auto-renewed. SANs cover the in-cluster Service DNS and
# every node IP a follower might reach the leader on (e.g. via NodePort).
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: conductor-server
  namespace: pipelock-control
spec:
  secretName: conductor-server-tls   # tls.crt / tls.key
  duration: 2160h                     # 90d
  renewBefore: 360h                   # 15d — renews well before expiry
  privateKey:
    algorithm: ECDSA
    size: 256
  usages:
    - server auth
  dnsNames:
    - conductor.pipelock-control.svc.cluster.local
    - conductor.pipelock-control.svc
  ipAddresses:
    - 127.0.0.1
    # - <node IPs here if followers reach the leader off-cluster via NodePort>
  issuerRef:
    name: conductor-fleet-ca
    kind: ClusterIssuer
    group: cert-manager.io
```

```yaml
# Per-follower client cert. The SPIFFE URI SAN IS the follower's fleet identity.
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: follower-edge-01-client
  namespace: pipelock
spec:
  secretName: follower-edge-01-client   # tls.crt / tls.key
  duration: 2160h
  renewBefore: 360h
  privateKey:
    algorithm: ECDSA
    size: 256
  usages:
    - client auth
  uris:
    - spiffe://pipelock.local/orgs/org-acme/fleets/prod/instances/edge-01/environments/prod
  issuerRef:
    name: conductor-fleet-ca
    kind: ClusterIssuer
    group: cert-manager.io
```

Issue one client `Certificate` per follower with a distinct SPIFFE URI. The
`--follower-trust-domain` on `conductor serve` (default `pipelock.local`) must
match the trust domain in these URIs. cert-manager handles **auto-renewal**
mid-flight: `renewBefore` rotates the cert before it expires and the workload
picks up the new Secret without a restart.

> **Off-cluster followers.** A follower running outside Kubernetes (a bare-metal
> host) reaches the leader via a NodePort Service with
> `externalTrafficPolicy: Local`; add the node IPs it dials to the server cert
> `ipAddresses`. Its client cert is issued the same way — a `Certificate` with
> its own SPIFFE URI — and mounted on the host.

Don't want cert-manager? Any PKI that produces a CA, a server cert with the
right SANs, and per-follower client certs with SPIFFE URI SANs works. The binary
verifies the chain and the SPIFFE identity; **you** own the CA keys and renewal.

## 4. Deploy Conductor and the audit sink

Run the control plane. Operator bearer tokens are read **from files** (never
flags), so they never land in process listings or shell history.

```bash
pipelock conductor serve \
  --listen 0.0.0.0:8895 \
  --probe-listen 0.0.0.0:9092 \
  --storage-dir /var/lib/pipelock/conductor \
  --conductor-id conductor-prod \
  --follower-trust-domain pipelock.local \
  --tls-cert /etc/pipelock/conductor/tls/server/tls.crt \
  --tls-key /etc/pipelock/conductor/tls/server/tls.key \
  --client-ca /etc/pipelock/conductor/tls/client-ca/ca.crt \
  --publisher-token-file /etc/pipelock/conductor/tokens/publisher/token \
  --auditor-token-file /etc/pipelock/conductor/tokens/auditor/token \
  --admin-token-file /etc/pipelock/conductor/tokens/admin/token \
  --trusted-audit-key "id=edge-01-audit,org=org-acme,inline=$(jq -r .public /etc/pipelock/fleet-keys/edge-01-audit.json)" \
  --trusted-control-key "id=kill-approver-1,purpose=remote-kill-signing,inline=$(jq -r .public /etc/pipelock/fleet-keys/kill-approver-1.json)" \
  --trusted-control-key "id=rollback-approver-1,purpose=policy-bundle-rollback,inline=$(jq -r .public /etc/pipelock/fleet-keys/rollback-approver-1.json)" \
  --remote-kill-max-validity 72h \
  --rollback-max-validity 24h
```

> **Trusted-key format (a current rough edge).** `--trusted-audit-key` and
> `--trusted-control-key` take the public key either `inline=` (a raw 64-hex
> Ed25519 public key) or `file=` (a public-key file in the versioned
> `pipelock-ed25519-public-v1` format). `pipelock signing key generate` writes
> the public half as the `public` hex field inside its JSON keypair, so the
> simplest shipped path is `inline=$(jq -r .public <keypair>.json)` as shown
> above. There is no shipped command that emits a versioned `.pub` file for
> these conductor purposes yet, so prefer `inline=`. (The trust **roster**
> `--include key=` path is different — it reads the JSON keypair file directly.)

On Kubernetes, the Helm chart renders this from
[`values-enterprise-conductor.yaml`](../../charts/pipelock/examples/values-enterprise-conductor.yaml):

```bash
helm install pipelock-conductor ./charts/pipelock \
  -f charts/pipelock/examples/values-enterprise-conductor.yaml
```

Optionally run the standalone audit sink (or co-locate it with the control
plane):

```bash
pipelock fleet-sink \
  --listen 0.0.0.0:8894 \
  --storage-dir /var/lib/pipelock/fleet-sink \
  --trusted-audit-key 'id=edge-01-audit,org=org-acme,file=/etc/pipelock/fleet-sink/audit-keys/edge-01.pub' \
  --tls-cert /etc/pipelock/fleet-sink/tls/tls.crt \
  --tls-key /etc/pipelock/fleet-sink/tls/tls.key \
  --client-ca /etc/pipelock/fleet-sink/tls/client-ca/ca.crt
```

Health, readiness, and Prometheus metrics live on the separate plain-HTTP probe
listener (`--probe-listen`), never on the mTLS follower API.

## 5. Enroll followers

A follower is an ordinary Pipelock proxy with a `conductor:` block. It
authenticates with its client cert; its identity is the cert's SPIFFE URI SAN.
On first contact over mTLS the follower **auto-enrolls** from that identity — no
pre-shared token in the default model.

```yaml
conductor:
  enabled: true
  conductor_url: https://conductor.pipelock-control.svc.cluster.local:8895
  org_id: org-acme
  fleet_id: prod
  instance_id: edge-01
  trust_roster_path: /etc/pipelock/trust-roster.json
  trust_roster_root_fingerprint: sha256:<root-fingerprint-from-step-1>
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

A follower **must produce signed evidence** to participate: config validation
rejects `conductor.enabled: true` unless the flight recorder is enabled with
signing checkpoints and a `signing_key_path`. On Kubernetes, use
[`values-enterprise-follower.yaml`](../../charts/pipelock/examples/values-enterprise-follower.yaml):

```bash
helm install pipelock-follower ./charts/pipelock \
  -f charts/pipelock/examples/values-enterprise-follower.yaml
```

Once running, the follower polls Conductor on `poll_interval` for the latest
policy bundle and for remote-kill state, and ships signed audit batches to the
sink. These three loops are what Conductor coordinates — the follower still
enforces locally and stays fail-closed if Conductor is unreachable.

## 6. Publish a policy bundle

`pipelock conductor publish` builds, signs, and POSTs a policy bundle from a
follower config. The bundle is signed with a policy-bundle-signing key and
authorized by the publisher token; followers verify the signature against the
pinned roster and apply only bundles addressed to their org/fleet/environment/
audience.

```bash
pipelock conductor publish \
  --conductor-url https://conductor.pipelock-control.svc.cluster.local:8895 \
  --config /etc/pipelock/fleet-policy.yaml \
  --bundle-id prod-2026-06-11 \
  --org org-acme --fleet prod --env prod \
  --validity 720h \
  --min-pipelock-version 2.7.0 \
  --signing-key /etc/pipelock/fleet-keys/policy-signing.json \
  --publisher-token-file /etc/pipelock/conductor/tokens/publisher/token \
  --tls-cert /etc/pipelock/operator.crt \
  --tls-key /etc/pipelock/operator.key \
  --server-ca /etc/pipelock/conductor-ca.pem
```

The command computes the canonical `policy_hash` / `payload_sha256`, stamps the
validity window from `--validity`, and assigns a monotonic version server-side.
Add `--rule-bundle <path>` (repeatable) to ship signed rule bundles alongside the
config, `--audience` to narrow the addressed followers, and
`--previous-bundle-hash <hex>` to pin continuity against the prior bundle (the
publish is rejected if the server's current bundle does not match). For a
loopback dev conductor without TLS, `--allow-plaintext-loopback` permits an
`http://127.0.0.1` URL.

**Prove on apply:** after publishing, confirm followers picked up the new version
(watch the follower logs for the bundle-apply line, or `pipelock conductor fleet
status`) before treating the rollout as complete.

## 7. Kill and resume the fleet

`pipelock conductor kill` pushes a signed, time-bounded fleet-wide kill;
`pipelock conductor resume` clears it. Followers with
`honor_remote_kill_switch: true` fail closed within one poll and recover on
resume.

```bash
# Push a signed, time-bounded fleet-wide kill (threshold-signed).
pipelock conductor kill \
  --conductor-url https://conductor.pipelock-control.svc.cluster.local:8895 \
  --org org-acme --fleet prod --instance '*' \
  --signing-key /etc/pipelock/fleet-keys/kill-approver-1.json \
  --signing-key /etc/pipelock/fleet-keys/kill-approver-2.json \
  --ttl 1h \
  --admin-token-file /etc/pipelock/conductor/tokens/admin/token \
  --tls-cert /etc/pipelock/operator.crt \
  --tls-key /etc/pipelock/operator.key \
  --server-ca /etc/pipelock/conductor-ca.pem

# Clear it once the incident is resolved.
pipelock conductor resume \
  --conductor-url https://conductor.pipelock-control.svc.cluster.local:8895 \
  --org org-acme --fleet prod --instance '*' \
  --signing-key /etc/pipelock/fleet-keys/kill-approver-1.json \
  --signing-key /etc/pipelock/fleet-keys/kill-approver-2.json \
  --admin-token-file /etc/pipelock/conductor/tokens/admin/token \
  --tls-cert /etc/pipelock/operator.crt \
  --tls-key /etc/pipelock/operator.key \
  --server-ca /etc/pipelock/conductor-ca.pem
```

Conductor rejects a kill whose validity window exceeds
`--remote-kill-max-validity` (default `72h`). Followers honoring the kill switch
fail closed within one `poll_interval`; clearing it lets them recover on the
next poll.

## 8. Roll back a bad bundle

`pipelock conductor rollback` authorizes a signed revert to a prior bundle
version:

```bash
pipelock conductor rollback \
  --conductor-url https://conductor.pipelock-control.svc.cluster.local:8895 \
  --org org-acme --fleet prod --instance '*' \
  --current-bundle-id bundle-v2 --current-version 2 \
  --target-bundle-id bundle-v1 --target-version 1 \
  --signing-key /etc/pipelock/fleet-keys/rollback-approver-1.json \
  --signing-key /etc/pipelock/fleet-keys/rollback-approver-2.json \
  --ttl 1h \
  --admin-token-file /etc/pipelock/conductor/tokens/admin/token \
  --tls-cert /etc/pipelock/operator.crt \
  --tls-key /etc/pipelock/operator.key \
  --server-ca /etc/pipelock/conductor-ca.pem
```

Signed with the policy-bundle-rollback (threshold) key. Conductor rejects a
rollback whose window exceeds `--rollback-max-validity` (default `24h`). Because
kill and rollback keys are purpose-scoped, a rollback key cannot issue a kill or
vice versa.

## 9. Mint enrollment tokens

The default enrollment model auto-registers a follower from its mTLS SPIFFE
identity, so no token is required to enroll. For an approval-gated join,
`pipelock conductor enrollment-token mint` issues a single-use token scoped to
one follower identity:

```bash
pipelock conductor enrollment-token mint \
  --conductor-url https://conductor.pipelock-control.svc.cluster.local:8895 \
  --org org-acme --fleet prod --instance edge-02 \
  --admin-token-file /etc/pipelock/conductor/tokens/admin/token \
  --tls-cert /etc/pipelock/operator.crt \
  --tls-key /etc/pipelock/operator.key \
  --server-ca /etc/pipelock/conductor-ca.pem
```

## 10. Fleet status and followers

`pipelock conductor fleet status` and `pipelock conductor fleet followers` list
enrolled instances — identity, audit key id, active state, and enrollment time —
read over mTLS with an org-scoped operator token against the audience-scoped
`/followers` endpoint.

```bash
pipelock conductor fleet status \
  --server https://conductor.pipelock-control.svc.cluster.local:8895 \
  --org-id org-acme --fleet-id prod \
  --token-file /etc/pipelock/conductor/tokens/auditor/token \
  --client-cert /etc/pipelock/operator.crt \
  --client-key /etc/pipelock/operator.key \
  --ca-file /etc/pipelock/conductor-ca.pem
```

## 11. Query the audit sink

`pipelock conductor audit query` queries the audit sink's stored evidence
metadata for one org/fleet/instance, read over mTLS with an auditor token:

```bash
pipelock conductor audit query \
  --server https://conductor.pipelock-control.svc.cluster.local:8895 \
  --org-id org-acme --fleet-id prod --instance-id edge-01 \
  --token-file /etc/pipelock/conductor/tokens/auditor/token \
  --client-cert /etc/pipelock/operator.crt \
  --client-key /etc/pipelock/operator.key \
  --ca-file /etc/pipelock/conductor-ca.pem
```

The audit query API returns **metadata only** — it never exports raw stored
payload bytes. The sink's `--storage-dir` is the raw-evidence escrow boundary;
treat it as sensitive operator-controlled storage.

## Verify follower evidence offline

Every follower emits Ed25519-signed, hash-chained evidence and ships it to the
sink in signed batches. An operator with the raw evidence — the follower's own
recorder output, or the sink's escrow — verifies it offline against a pinned key,
with no trust in Conductor, the follower, or the storage layer:

```bash
# Verify a follower's receipt chain against the pinned recorder public key.
# --chain takes the evidence DIRECTORY; --key is a hex key or a key-file path
# (repeat --key across a signing-key rotation, one per trusted segment key).
pipelock verify-receipt --chain /var/lib/pipelock/recorder/evidence \
  --key /etc/pipelock/keys/edge-01-recorder.pub
```

Without `--key`, verification is **structural-only** and exits non-zero unless
you pass `--allow-unpinned` — pin the trusted signer key to get a meaningful
`CHAIN VALID`. See [receipt verification](receipt-verification.md).

## 12. Rotate certs and keys

The operator-lifecycle rule for every piece of fleet state: prove you can
**rotate, revoke, and recover** it, not just create it.

- **TLS certificates (server + follower).** cert-manager rotates automatically
  via `renewBefore`; the workload picks up the new Secret without a restart. To
  force a rotation, delete the cert Secret and let cert-manager reissue. The CA
  stays stable, so no roster change is needed.
- **The fleet CA.** Rotating the CA is a bigger event: issue the new CA, add it
  to followers' `server_ca_file` trust bundle (and the Conductor `--client-ca`
  bundle) **before** cutting over so both old and new chains validate during the
  overlap, then reissue leaf certs from the new CA and retire the old one.
- **Policy-bundle signing key.** Generate a new `policy-bundle-signing` key,
  rebuild the roster (`signing roster build`) including the new key (mark the old
  one `status=revoked` to retire it), re-sign and redistribute the roster, then
  publish future bundles with the new key. Followers pin the roster by root
  fingerprint, so the **roster root** is the long-lived anchor — keep it offline.
- **Threshold keys (kill / rollback).** Rotate per approver: generate a fresh
  approver key, update the roster and the Conductor `--trusted-control-key`
  flags, revoke the old one. The threshold means losing one approver key does not
  compromise the authority.
- **Recorder keys.** A signing-key rotation **does not brick the receipt
  chain** — the emitter opens a new, linked chain segment anchored to the prior
  tail with a key-transition marker, and `verify-receipt --chain` is
  segment-aware. Generate the new recorder key, update the follower config, and
  the chain stays offline-verifiable across the boundary.
- **Operator tokens.** Tokens are file-mounted. Rotate by writing a new token to
  the Secret and restarting the consuming server; there is no in-flight token
  refresh.

## Stale-policy fail-closed enforcement

Under `stale_policy.strict_deny_all` (the default), a follower re-evaluates its
active bundle each poll interval and, once that bundle is missing, unreadable, or
past its grace window, engages the independent `conductor_stale` kill-switch
source — denying **all traffic across every transport** (forward, CONNECT,
WebSocket, MCP) until a fresh in-grace bundle applies. The `conductor_stale`
source is OR-composed and independent of the remote-kill source: clearing
remote-kill does not clear stale denial, and clearing stale does not clear
remote-kill.

On proven license revocation or expiry the follower tears down its Conductor
pollers and keeps only free local detection running (re-activatable by restart).
Under a strict stale policy, teardown engages the `conductor_stale` source
**before** the enforcer's ticker stops, so the deny is in place even though no
later tick will re-evaluate the bundle — this closes the teardown fail-open
window. Under `continue_last_known_good` the flag is not set and the follower
keeps serving its last applied bundle.

## Known limitations (be honest about these)

- **Several follower `conductor:` fields are reserved.**
  `created_skew_seconds`, `max_min_version_*_skew`, `max_capability_threshold`,
  and `emergency_stream` validate but are not enforced by the follower runtime
  yet.
- **`trust-root-rotation` and `enrollment-token-signing` keys** are wire-stable
  purpose bindings with no consuming workflow yet.

## See also

- [Conductor guide](conductor.md) — architecture, planes, licensing, flags
- [Conductor dev runbook](conductor-operator-runbook.md) — local round-trip walkthrough
- [Kubernetes enterprise deployment](kubernetes-enterprise-deployment.md) — Helm topology
- [Conductor & audit sink design](../specs/pipelock-conductor-audit-sink.md) — protocol + storage
- [Helm chart README](../../charts/pipelock/README.md) — full values reference
- [Configuration reference: Conductor follower](../configuration.md#conductor-follower-v27-enterprise)
- [Receipt verification](receipt-verification.md) — verify follower evidence offline
- [`pipelock license`](../cli/license.md) — install and check the fleet license
