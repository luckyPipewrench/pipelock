# Pipelock Conductor and Audit Sink Design

**Status:** Draft, pre-implementation gate
**Version:** 0.1.0
**Date:** 2026-05-23

This document defines the hardened design target for Pipelock Conductor, the
enterprise control plane for Pipelock fleets. It covers the conductor plane
that distributes signed policy bundles to follower instances and the audit sink
plane that ingests signed evidence from those instances.

The architecture shape is:

```text
Conductor control plane
  -> signed policy / emergency control messages
Pipelock follower instances
  -> local enforcement, local recorder, local receipts
  -> signed audit batches
Conductor audit sink
  -> verification, DLP scanning, append-only ingest, indexed search
```

Conductor is not a scanner and must not become an inline dependency for enforcement.
Followers continue to enforce locally. Conductor coordinates policy distribution,
evidence operations, fleet visibility, and auditor workflows.

## Goals

- Distribute signed, audience-bound policy bundles to follower instances.
- Preserve Pipelock capability separation: Conductor must not hold agent secrets or
  scan on behalf of followers.
- Keep follower enforcement local and fail-closed.
- Make bundle signing, enrollment, rollback, remote kill, and audit ingest
  explicit security protocols, not implicit HTTP APIs.
- Provide a central audit sink that verifies source, schema, chain continuity,
  and content safety before indexing.
- Dogfood Pro value through fleet coordination, per-agent budgets, source CIDR
  binding, central audit search, and auditor export.

## Non-Goals

- No new scanner pipeline.
- No replacement for local flight recorder or receipt verification.
- No hosted dependency for local allow/block decisions.
- No license metadata inside policy bundles in the MVP.
- No bearer-only follower-to-Conductor transport.
- No single online signing key that can silently compromise the whole fleet.

## Hard MVP Gates

No implementation should start until these are accepted as product/security
requirements:

1. Bundle signing uses KMS/HSM-backed keys and never stores signing private keys
   on Conductor disk.
2. Every signed bundle hash is written to an append-only transparency log.
3. Catastrophic messages require threshold approval and a separate key purpose.
4. Enrollment is concrete: one-shot token exchange for per-instance mTLS
   identity and per-instance signing material.
5. Bundle signed preimages include `org_id`, `fleet_id`, environment, and
   audience selectors.
6. Rollback is a first-class signed operation with its own key purpose.
7. Remote kill switch state is not ordinary bundle state.
8. License metadata is excluded from policy bundles.
9. Audit payloads are treated as hostile input even after signature validation.
10. Follower-to-Conductor transport is mTLS.

## Trust Model

### Principals

- `conductor-admin`: manages Conductor configuration and users.
- `policy-publisher`: can create policy bundle candidates.
- `policy-approver`: can countersign catastrophic operations.
- `follower-instance`: a registered Pipelock deployment.
- `auditor`: can query and export accepted evidence without changing policy.

### Key Purposes

Each signing key has one purpose. Verifiers reject signatures made with the
wrong purpose.

| Purpose | Used for | Threshold required |
|---|---|---|
| `policy-bundle-signing` | ordinary policy bundle publication | no |
| `policy-bundle-rollback` | one-shot rollback authorization | yes |
| `remote-kill-signing` | remote kill switch toggle | yes |
| `trust-root-rotation` | Conductor/fleet trust root changes | yes |
| `audit-batch-signing` | follower audit batch signatures | no |
| `receipt-signing` | local follower action receipts/checkpoints | no |
| `enrollment-token-signing` | one-shot enrollment token minting | no |

Wire form is lowercase-hyphenated. See `internal/signing/key_purpose.go` for the
canonical KeyPurpose constants and `internal/conductor/messages.go` for use.

Threshold means m-of-n approval with m >= 2. The MVP may implement this as two
independent Ed25519 signatures over the same canonical preimage, but the schema
must allow more signatures later.

### Signing Key Lifecycle

Conductor signing keys must be backed by KMS/HSM or equivalent external signing
service. Private key material must not be exportable to Conductor process storage.

Requirements:

- Every key has `key_id`, `purpose`, `created_at`, `not_before`, `not_after`,
  and `revoked_at`.
- Follower trust rosters pin public keys and accepted purposes.
- Key rotation is published as a signed trust-root or intermediate update.
- Followers reject unknown key IDs, wrong-purpose signatures, expired keys, and
  revoked keys.
- CRL/trust roster age is exposed as a metric on both Conductor and followers.

## Enrollment Protocol

Enrollment bootstraps follower identity. It is not optional.

### Recommended MVP

1. Operator creates a one-shot enrollment token in Conductor.
2. Token includes `org_id`, `fleet_id`, `instance_id`, allowed environment,
   allowed IP/CIDR hint, expiry, nonce, and token ID.
3. Token is signed by `enrollment-token-signing`.
4. Follower starts with the token and Conductor trust root.
5. Follower generates local private keys:
   - mTLS leaf key
   - audit batch signing key
   - optional local receipt signing key if not already configured
6. Follower calls `POST /api/v1/enroll` over TLS.
7. Conductor verifies token, checks token unused, validates singleton
   `instance_id`, and issues an mTLS leaf certificate.
8. Conductor stores the follower audit public key and expected instance metadata.
9. Token is marked consumed permanently.
10. All future follower calls derive identity from the mTLS certificate, not
    from request fields.

### Singleton Rule

Conductor must prevent silent instance cloning. A second enrollment for an active
`instance_id` fails unless an admin revokes or rotates the prior identity.

### Rotation

Follower certificates and audit keys rotate through a signed re-enrollment flow:

- Existing mTLS identity authenticates the rotation request.
- Conductor issues a new cert/key binding.
- Old identity remains accepted for a short overlap window.
- Both old and new identities are visible in audit logs.

## Transport Surfaces

Conductor uses separate listeners:

| Listener | Auth | Purpose |
|---|---|---|
| Follower API | mTLS per instance | poll, audit ingest, capabilities, emergency stream |
| Operator Admin API | bearer/session auth plus IP allowlist | human/admin control |
| Public Artifact API | public or CDN-gated | public verification keys and transparency artifacts |

Listener addresses are restart-only. This mirrors the existing Pipelock pattern
for scan API, kill switch API, and metrics listeners.

All HTTP servers must set read header timeouts, read timeouts, write timeouts,
connection limits, request body caps, and per-instance rate limits.

## Capability Handshake

Follower starts each Conductor session with:

```http
GET /api/v1/conductor/capabilities
```

Conductor returns supported schema ranges:

```json
{
  "schema_version": 1,
  "conductor_id": "conductor-us-1",
  "required_mtls": true,
  "conductor_bundle": {"min": 1, "max": 1},
  "remote_kill": {"min": 1, "max": 1},
  "rollback_authorization": {"min": 1, "max": 1},
  "audit_batch": {"min": 1, "max": 1},
  "receipt_entry_versions": [2],
  "max_created_skew_seconds": 60,
  "emergency_stream": true,
  "remote_kill_threshold": 2,
  "rollback_threshold": 2,
  "trust_rotation_threshold": 2
}
```

Follower selects the highest supported intersection. If no audit schema
intersection exists, audit emission hard-fails locally and emits evidence. It
must not silently drop Conductor-bound audit.

## Policy Bundle

Policy bundles distribute policy content only. License fields are forbidden.

MVP server endpoints:

```http
PUT /api/v1/conductor/policy-bundles
POST /api/v1/conductor/policy-bundles
GET /api/v1/conductor/policy/latest
```

`PUT` and `POST` publish signed bundle envelopes through the operator/admin
surface. `GET /api/v1/conductor/policy/latest` is a follower API endpoint: the
server derives follower identity from the authenticated transport and returns
the newest currently valid bundle whose org, fleet, environment, and audience
match that follower, or `204 No Content` when no bundle applies.

### Bundle Envelope

```json
{
  "schema_version": 1,
  "bundle_id": "uuidv7",
  "org_id": "org_...",
  "fleet_id": "fleet_...",
  "environment": "prod",
  "audience": {"labels": {"ring": "canary"}},
  "version": 42,
  "previous_bundle_hash": "hex",
  "created_at": "2026-05-23T17:00:00Z",
  "not_before": "2026-05-23T17:00:00Z",
  "expires_at": "2026-05-23T18:00:00Z",
  "min_pipelock_version": "2.6.0",
  "policy_hash": "canonical-policy-hash",
  "payload_sha256": "hex",
  "payload": {
    "config_yaml": "...",
    "rule_bundles": []
  },
  "signatures": []
}
```

### Validation Rules

Follower rejects a bundle if:

- Signature is missing or wrong-purpose.
- Transparency log inclusion proof is missing or invalid.
- `org_id`, `fleet_id`, environment, or audience do not match local enrollment.
- Bundle is expired or not yet valid.
- Version is lower than local freshness state and no rollback authorization is
  present.
- `previous_bundle_hash` does not match local freshness state, except for
  initial enrollment or authorized rollback.
- `payload_sha256` does not match the canonicalized `payload`.
- `policy_hash` does not match the canonicalized policy representation.
- `min_pipelock_version` exceeds follower version by more than the configured
  sanity window.
- Payload contains forbidden fields, including license metadata.
- Config validation fails.
- Reload would violate restart-only constraints.

### Min Version Sanity

Follower config includes:

```yaml
conductor:
  max_min_version_major_skew: 0
  max_min_version_minor_skew: 1
```

If a bundle demands a version outside this window, the follower rejects it and
continues last-known-good. This prevents a signed but mistaken bundle from
bricking the fleet.

## Remote Kill Switch Message

Remote kill is separate from policy bundles.

```json
{
  "schema_version": 1,
  "message_id": "uuidv7",
  "org_id": "org_...",
  "fleet_id": "fleet_...",
  "audience": {"labels": {"ring": "all"}},
  "state": "active",
  "reason": "operator emergency stop",
  "created_at": "2026-05-23T17:05:00Z",
  "not_before": "2026-05-23T17:05:00Z",
  "expires_at": "2026-05-23T17:20:00Z",
  "counter": 18,
  "signatures": []
}
```

`state` is `"active"` or `"inactive"` (see `KillSwitchState` in
`internal/conductor/messages.go`). `reason` is capped at `MaxReasonBytes` and
must not contain control characters.

Follower behavior:

- Default `conductor.honor_remote_kill_switch` is false unless a managed-fleet
  preset explicitly enables it.
- When disabled, followers reject remote kill messages, emit local evidence, and
  report the rejection to Conductor.
- When enabled, remote kill messages require `remote-kill-signing` threshold
  signatures.
- Accepted remote kill state is OR-composed as a separate kill source.
- Every accepted, rejected, expired, and superseded remote kill message is
  written to local recorder evidence with the full signed envelope.

## Emergency Stream

Pure polling is insufficient for emergency state. Followers maintain an
SSE/long-poll connection on the follower mTLS listener:

```http
GET /api/v1/conductor/emergency-stream
```

Only high-urgency message kinds flow through this stream:

- remote kill toggle
- rollback authorization
- trust root revocation notice

If the stream disconnects, follower falls back to pull. Pull remains the source
of truth for ordinary policy bundles.

## Rollback Authorization

Rollback is an explicit operation, not a version exception.

```json
{
  "schema_version": 1,
  "authorization_id": "uuidv7",
  "org_id": "org_...",
  "fleet_id": "fleet_...",
  "audience": {"labels": {"ring": "all"}},
  "current_bundle_id": "bundle-current",
  "current_version": 42,
  "target_bundle_id": "bundle-target",
  "target_version": 41,
  "counter": 7,
  "reason": "bad policy bundle",
  "created_at": "2026-05-23T17:10:00Z",
  "expires_at": "2026-05-23T17:25:00Z",
  "signatures": []
}
```

Field names match the `RollbackAuthorization` Go struct. `counter` is the
single-use authorization counter. `target_version` must be strictly less than
`current_version` (enforced by `Validate`).

Follower accepts it once, then pins the lower bundle as the new freshness
baseline. Reuse is rejected and logged as a security event.

## Bundle Apply Pipeline

Follower apply is all-or-nothing:

1. Download bundle to memory under body cap.
2. Verify canonical signature and transparency inclusion proof.
3. Validate audience, freshness, TTL, version, and key purpose.
4. Validate payload does not include forbidden sections.
5. Write bundle to cache using temp file, fsync, and rename.
6. Cache directory mode: `0o700`.
7. Bundle file mode: `0o600`.
8. Re-read staged bundle from disk.
9. Re-run signature and payload hash verification.
10. Write staged config candidate atomically.
11. Run existing config validation and runtime resolve pipeline.
12. Call the same reload path used by local config reload.
13. Surface scanner construction panics and reload failures exactly like
    file-driven reload.
14. Record local evidence for accept or reject.

Conductor-driven reload must share the same dedup/reload guard as file-driven reload
to avoid fsnotify and conductor races.

## Stale Bundle Policy

Fail-closed is the default.

Follower config:

```yaml
conductor:
  stale_policy:
    grace_multiplier: 1
    after_grace: strict_deny_all
```

Default behavior:

- Before expiry: run active bundle.
- Expired but within `1x bundle TTL` grace: continue last-known-good and page.
- After grace: switch to strict fail-closed behavior for conductor-managed
  policy gaps.

Operators can override this, but overrides must warn at validation time and emit
local evidence.

## Audit Batcher

Conductor-bound audit cannot be a normal `emit.Sink`. The existing emitter ignores
sink errors by design; a Conductor audit transport needs durable retry state and
explicit drop accounting.

Implement a peer package:

```text
internal/conductor/auditbatcher
```

Responsibilities:

- Observe recorder v2 entries after they are durably flushed.
- Persist batches to a local durable queue.
- Sign each batch with the follower audit key at recorder checkpoint boundaries.
- Send over follower mTLS transport.
- Retry with bounded backoff.
- Track drop reasons explicitly.
- Never block enforcement decisions.

Local audit batcher failures produce local recorder evidence and metrics.

## Audit Ingest

MVP server endpoint:

```http
POST /api/v1/conductor/audit/batches
```

The server derives follower identity from the authenticated transport, validates
the signed audit batch envelope and payload together, verifies the follower
audit-batch signature against the enrolled audit key for that identity, and only
then hands the accepted batch to the configured audit sink. Durable central
storage, DLP-before-indexing, search indexing, fork response workflow, and
dashboard views are later slices.

## Audit Batch Schema

Conductor-bound batches require recorder v2 entries. v1 entries are not accepted for
Conductor-bound ingestion because v2 binds `event_kind` into the chain hash.

```json
{
  "schema_version": 1,
  "batch_id": "uuidv7",
  "org_id": "org_...",
  "fleet_id": "fleet_...",
  "instance_id": "pl-prod-1",
  "audit_schema_version": 2,
  "emitted_at": "2026-05-23T17:12:01Z",
  "seq_start": 1000,
  "seq_end": 1200,
  "event_count": 201,
  "payload_sha256": "hex",
  "payload_bytes": 32768,
  "dropped": {
    "count": 3,
    "reasons": [
      {"reason": "queue_full", "count": 2},
      {"reason": "payload_too_large", "count": 1}
    ]
  },
  "chain": {
    "entry_version": 2,
    "segment_id": "segment-2026-q2",
    "seq_start": 1000,
    "seq_end": 1200,
    "previous_segment_tail": "hex",
    "segment_head_hash": "hex",
    "segment_tail_hash": "hex",
    "checkpoint_seq": 1199,
    "checkpoint_hash": "hex",
    "checkpoint_signature": "ed25519:hex",
    "checkpoint_signer_key_id": "receipt-key-2026-q2",
    "follower_recorder_key_id": "instance-recorder-1",
    "follower_recorder_public_key_hex": "hex"
  },
  "signatures": []
}
```

Field names match the `AuditBatchEnvelope` Go struct. `payload_bytes` is capped
at `MaxAuditPayloadBytes` (1 MiB). Conductor enforces `|now - emitted_at|` against a
configured skew via `ValidateForConductor` — see `DefaultAuditMaxSkew` (60s) and
`MaxAllowedAuditSkew` (300s). Ingest handlers must validate the envelope and
payload together with `ValidateForConductorWithPayload` before DLP scanning,
storage, or indexing.

`dropped` is part of the signed envelope so evidence gaps are captured
cryptographically rather than inferred from Conductor-side metrics. When `count` is
zero, `reasons` must be empty. When `count` is non-zero, reason counts must sum
exactly to `count`.

### Conductor Verification

Conductor must:

- Authenticate follower identity from mTLS.
- Verify batch signature with enrolled follower audit key.
- Verify `len(payload) == payload_bytes` and `sha256(payload) == payload_sha256`.
- Count only cryptographically verified distinct signer keys toward thresholds.
- Reject instance ID mismatches between cert and payload.
- Enforce created skew: default 60s, configurable max 300s with warning.
- Verify schema version intersection.
- Verify sequence range monotonicity.
- Detect overlapping sequence ranges with different hashes as a compromise
  indicator.
- Verify v2 recorder entry hashes.
- Verify checkpoint signature with enrolled receipt/checkpoint public key.
- Stitch segment rotation using previous segment tail and current segment head.
- DLP-scan payload contents before indexing.
- Apply per-follower rate, size, and reputation limits.
- Store raw accepted batch in per-follower namespace.
- Index only redacted/safe fields into cross-fleet search.

Fork detection is critical severity, not a soft reject.

## Audit Sink as Hostile Input

A compromised follower can produce signed malicious audit batches. Signatures
prove source, not truth. Conductor must treat every field as attacker-controlled.

Controls:

- Strict JSON decoding and unknown-field rejection.
- Request body caps.
- Batch entry count caps.
- Per-follower namespace isolation.
- DLP and prompt-injection scanning before indexing.
- Escaping and query-safe indexing for all strings.
- No cross-fleet query expansion from untrusted event fields.
- Reputation scoring for malformed, oversized, forked, or DLP-positive batches.

Audit batches are also potential exfiltration channels. Conductor must scan for
secrets before storing or indexing.

## Privacy and Storage

Default storage is redacted. Raw evidence escrow is separate and opt-in.

Storage classes:

- Accepted batch envelope: append-only, per follower.
- Search index: redacted fields only.
- Raw escrow: optional encrypted object storage, separate access controls.
- Transparency log artifacts: public or auditor-visible hashes, no payloads.

App-level append-only is not WORM. Production compliance deployments should use
WORM-capable storage such as object lock. If unavailable, the system must report
that immutability is app-enforced only.

## License Boundary

Policy bundles must not carry:

- `license_key`
- `license_file`
- `license_public_key`
- `license_crl_file`
- runtime-derived license status fields

Reason: current Pipelock canonical policy hashes intentionally exclude license
metadata, and reload preserves license inputs until restart. Bundling license
changes would create silent divergence.

A future `LicenseBundle` requires:

- separate schema
- separate key purpose
- explicit restart orchestration
- follower report of pending restart
- clear operator UX that license behavior has not changed until restart

## Follower Configuration

Draft YAML shape:

```yaml
conductor:
  enabled: true
  conductor_url: "https://conductor.example.internal"
  org_id: "org_main"
  fleet_id: "prod"
  instance_id: "pl-prod-1"
  trust_roster_path: "/etc/pipelock/conductor/trust-roster.json"
  server_ca_file: "/etc/pipelock/conductor/boss-ca.pem"
  client_cert_path: "/etc/pipelock/conductor/client.crt"
  client_key_path: "/etc/pipelock/conductor/client.key"
  bundle_cache_dir: "/var/lib/pipelock/conductor/bundles"
  durable_audit_queue_dir: "/var/lib/pipelock/conductor/audit-queue"
  audit_signing_key_id: "instance-audit-1"
  recorder_key_id: "instance-recorder-1"
  poll_interval: "30s"
  honor_remote_kill_switch: false
  created_skew_seconds: 60
  max_min_version_major_skew: 0
  max_min_version_minor_skew: 1
  stale_policy:
    grace_multiplier: 1
    after_grace: strict_deny_all

flight_recorder:
  enabled: true
  dir: "/var/lib/pipelock/recorder"
  sign_checkpoints: true
  signing_key_path: "/etc/pipelock/recorder.key"
```

When `conductor.enabled` is true, the flight recorder must be enabled with
signed checkpoints and a configured signing key. `audit_signing_key_id` and
`recorder_key_id` default to `instance_id` when omitted.

Config validation must reject:

- missing mTLS paths when enabled
- missing Boss server CA bundle when enabled
- non-absolute cache paths
- cache directory paths under world-writable parents
- `created_skew_seconds > 300`
- remote kill enabled without trust roster support for threshold signatures

## Conductor RBAC

MVP roles:

| Role | Capabilities |
|---|---|
| `admin` | manage users, fleets, trust, storage, and listeners |
| `publisher` | create and stage bundle candidates |
| `approver` | countersign catastrophic operations |
| `viewer` | view fleet state and non-sensitive metrics |
| `auditor` | query/export accepted evidence |

Catastrophic actions require approval by at least two distinct principals:

- remote kill activation/deactivation
- trust root rotation
- rollback authorization
- audit deletion or retention override
- policy downgrade authorization

## Observability

Conductor metrics:

- `conductor_fleet_drift{policy_hash}`
- `conductor_bundle_apply_latency_seconds`
- `conductor_audit_lag_seconds`
- `conductor_signature_verification_failures_total{kind}`
- `conductor_crl_age_seconds`
- `conductor_trust_roster_age_seconds`
- `conductor_poll_last_success_seconds_ago`
- `conductor_audit_drop_total{reason}`
- `conductor_audit_fork_detected_total`
- `conductor_enrollment_failures_total{reason}`
- `conductor_remote_kill_messages_total{result}`

Follower metrics:

- `pipelock_conductor_active_bundle_age_seconds`
- `pipelock_conductor_last_successful_poll_seconds_ago`
- `pipelock_conductor_bundle_apply_total{result,reason}`
- `pipelock_conductor_remote_kill_total{result}`
- `pipelock_conductor_audit_queue_depth`
- `pipelock_conductor_audit_durable_queue_bytes`
- `pipelock_conductor_audit_drop_total{reason}`
- `pipelock_conductor_emergency_stream_connected`

Paging defaults:

- follower poll stale beyond one poll interval plus jitter
- active bundle expired
- active bundle beyond grace
- any signature verification failure
- any audit fork detection
- audit queue depth above threshold
- CRL/trust roster too old

## Regionalization

Conductor deployments are regional. Default design is no cross-region replication.

- `Conductor-US` handles US fleets and US evidence.
- `Conductor-EU` handles EU fleets and EU evidence.
- Cross-region export requires explicit operator/auditor action.
- Policy bundles include region/environment audience claims.

## FIPS and Crypto Policy

Default crypto is Ed25519, matching current Pipelock signing primitives. Some
regulated environments require FIPS 140-3 acceptable algorithms. The MVP must
document this limitation. A future FIPS build may add ECDSA-P256 key purposes
and dual-algorithm trust rosters.

## Conductor Supply Chain

Conductor is the highest-value target in the product line. Its release provenance
must be stronger than ordinary follower deployment:

- signed container images
- transparency log entry per release
- SLSA L3 target
- reproducible build story
- SBOM
- pinned dependencies
- release attestation verified by deployment tooling

## Implementation Phases

### Phase 0: Spec and Schema

- Define bundle, rollback, remote kill, enrollment, and audit batch schemas.
- Add canonical preimage tests and golden vectors.
- Add key-purpose validation.
- Add explicit license-field rejection tests.
- Add threat model docs.

### Phase 1: Follower Skeleton

- Add follower config schema and validation.
- Implement capability handshake.
- Implement bundle polling and verification without applying.
- Implement local evidence for accepted/rejected messages.
- Add metrics.

### Phase 2: Atomic Apply

- Add durable bundle cache.
- Wire verified bundle payload into existing reload path.
- Add stale bundle state machine.
- Add rollback authorization support.

### Phase 3: Conductor Server MVP

- Add follower mTLS listener.
- Add admin listener with RBAC skeleton.
- Add enrollment endpoint.
- Add bundle publication and latest-bundle endpoint.
- Add transparency log integration or local append-only transparency prototype.

### Phase 4: Audit Batcher and Sink

- Add durable follower audit batcher.
- Add Conductor audit ingest endpoint.
- Add DLP-before-indexing.
- Add fork detection.
- Add per-follower storage namespace.

### Phase 5: Emergency Stream and Catastrophic Actions

- Add SSE/long-poll emergency stream.
- Add threshold signatures for remote kill and rollback.
- Add two-person approval workflow.

## Test Matrix

Required test coverage:

- Wrong-purpose signatures are rejected.
- Expired keys are rejected.
- Revoked keys are rejected.
- Bundle for staging is rejected by prod follower.
- Bundle with license fields is rejected.
- Rollback without authorization is rejected.
- Rollback authorization is single-use.
- Remote kill is rejected when `honor_remote_kill_switch` is false.
- Remote kill without threshold signatures is rejected.
- Remote kill and rollback reasons reject control characters.
- Bundle apply is atomic under partial write.
- Bundle apply uses existing reload panic handling.
- Conductor audit ingest rejects v1 recorder entries.
- Conductor audit ingest detects sequence forks.
- Conductor audit ingest verifies checkpoint signatures.
- Conductor audit ingest DLP-scans payload before indexing.
- Follower identity is derived from mTLS, not payload `instance_id`.
- Enrollment token reuse fails.
- Duplicate active `instance_id` enrollment fails.
- Audit schema mismatch hard-fails.
- Canonical preimage is byte-identical across producer timezones.
- Canonical preimage changes when any policy-semantic field changes.
- Policy bundles reject `policy_hash` and `payload_sha256` mismatches.
- Nested license fields under any submap are rejected with a path-tagged error.
- `MinPipelockVersion` is required and must be `major.minor.patch`.
- `ValidateAtTime` rejects bundles outside `[NotBefore, ExpiresAt]`.
- `ValidateForConductor` rejects audit batches outside `±DefaultAuditMaxSkew`.
- `ValidateForConductorWithPayload` rejects payload length/hash mismatches.
- `Audience` rejects `"*"` mixed with explicit instance IDs.
- `Audience` rejects mixed `instance_ids` and `labels`.
- Capability handshake advertises all message schema ranges, mTLS requirement,
  v2 receipt entries, skew ceiling, and catastrophic thresholds.
- Audit batch dropped accounting is signed and internally consistent.
- Signature verification rejects tampered preimages, wrong roster purposes, and
  missing threshold signers.
- Signed-message identifiers are bounded and restricted to a safe wire charset.

## Open Decisions

- Transparency log implementation: external Rekor-style service, embedded
  append-only log, or both.
- KMS/HSM provider abstraction and minimum supported provider.
- Exact trust roster file format.
- Whether local follower receipt signing key is reused for checkpoints or a
  separate checkpoint key is required.
- Whether FIPS support is a documented limitation or a near-term build target.
- WORM storage backend for first enterprise deployment.
