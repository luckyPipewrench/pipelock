# Conductor Operator Runbook

This runbook walks through a local Conductor dev fleet: one Conductor, one follower, one signed audit batch, and offline verification of that batch.

Conductor is Enterprise-tier and only exists in an enterprise build. The `conductor bootstrap`, `conductor serve`, and `fleet-sink` commands all fail closed on license verification before writing files or binding listeners. In this validation session, the live bootstrap attempt stopped at that entitlement gate in `0.00s`; the full live `<10 min` validation is pending an operator Enterprise license.

Commands marked "source-verified" come from `--help` output or the enterprise source named in this guide. Commands marked "live-run" were run during this documentation pass.

## Prerequisites

- Enterprise build of Pipelock (`-tags enterprise`).
- Enterprise license with the `fleet` feature available to the operator command:
  - official enterprise builds may embed the license public key;
  - unofficial/local enterprise builds also need `PIPELOCK_LICENSE_PUBLIC_KEY`;
  - all builds need a valid `PIPELOCK_LICENSE_KEY` unless your deployment uses another supported license source.
- A private bootstrap directory under a non-world-writable parent. Avoid shared `/tmp` for the fleet material path because follower config validation rejects world-writable ancestors.

Build the enterprise binary (live-run):

```bash
go build -tags enterprise -o /tmp/pipelock-ent ./cmd/pipelock
```

Confirm the Enterprise commands are present (live-run):

```bash
/tmp/pipelock-ent conductor --help
/tmp/pipelock-ent conductor bootstrap --help
/tmp/pipelock-ent conductor serve --help
/tmp/pipelock-ent fleet-sink --help
```

The verified subcommands are:

```text
pipelock conductor bootstrap   Stand up and verify a local Conductor dev fleet end to end
pipelock conductor serve       Serve Conductor policy and audit ingest endpoints
pipelock fleet-sink            Run a Conductor audit batch sink
```

## License Gate

This command was run live without an operator fleet license:

```bash
/tmp/pipelock-ent conductor bootstrap --dir <tmpdir>
```

Actual output, sanitized:

```text
fleet control plane (Conductor) requires an Enterprise license that grants the "fleet" feature; set PIPELOCK_LICENSE_KEY (and PIPELOCK_LICENSE_PUBLIC_KEY on unofficial builds) or contact your administrator
real 0.00
user 0.00
sys 0.00
```

Bootstrap also mints a separate dev license token for the spawned Conductor and follower. That generated token is not the same thing as the operator Enterprise entitlement that lets `conductor bootstrap` start.

## Bootstrap A Dev Fleet

Create a private fleet directory:

```bash
export FLEET_DIR="$HOME/.local/share/pipelock-conductor-dev"
mkdir -p "$FLEET_DIR"
chmod 750 "$FLEET_DIR"
```

Run bootstrap after the operator license environment is present (source-verified from `conductor bootstrap --help`):

```bash
/tmp/pipelock-ent conductor bootstrap --dir "$FLEET_DIR"
```

Useful optional flags, all verified from help:

```text
--trust-domain string       SPIFFE trust domain for fleet identities (default pipelock.local)
--org string                fleet org id (default org-local)
--fleet string              fleet id (default dev)
--instance string           follower instance id (default follower-1)
--env string                follower environment (default dev)
--conductor-id string       Conductor id (default conductor-local)
--listen-host string        loopback host for the Conductor listener and certificate SAN (default 127.0.0.1)
--conductor-port int        Conductor port baked into the follower config (default 8895)
--validity duration         validity window for generated CA, certificates, and license (default 90 days)
--force                     regenerate material even if a complete prior bootstrap is present
--skip-proof                generate material without running the live round-trip proof
--license-crl-file string   signed license revocation list file; falls back to PIPELOCK_LICENSE_CRL_FILE
```

A successful bootstrap generates material, starts one Conductor and one follower in-process, enrolls the follower over mTLS, produces one signed audit batch, ingests it through Conductor, queries it back through the auditor API, and verifies it offline with the existing verifier. The bootstrap quickstart output intentionally prints secret file paths, not token or key bytes.

## Generated Layout

Bootstrap writes this layout under `$FLEET_DIR` (source-verified from `enterprise/conductor/bootstrap/layout.go`):

```text
$FLEET_DIR/
  bootstrap-manifest.json
  audit-batch.json
  ca/
    ca.crt
    ca.key
  conductor/
    server.crt
    server.key
    storage/
    publisher.token
    auditor.token
    admin.token
  follower/
    client.crt
    client.key
    audit-signing.key
    audit-signing.pub
    follower.yaml
    bundles/
    audit-queue/
    recorder/
  trust/
    trust-roster.json
    roster-root.key
    roster-root.pub
    remote-kill.key
    remote-kill.pub
    rollback.key
    rollback.pub
  license/
    license.key
    license.pub
    license.token
```

Files carrying keys, tokens, manifests, config, and the proof batch are written with `0o600`; directories are created with `0o750`.

## PKI And Trust Model

Bootstrap creates local dev material for speed:

- A local CA signs the Conductor TLS server certificate and the follower mTLS client certificate.
- The follower certificate carries a SPIFFE URI SAN:

```text
spiffe://<trust-domain>/orgs/<org>/fleets/<fleet>/instances/<instance>/environments/<env>
```

- The follower pins `trust/trust-roster.json` and the roster root fingerprint in `follower/follower.yaml`.
- The roster pins Conductor control keys for `remote-kill-signing` and `policy-bundle-rollback`.
- The follower audit key is used for audit-batch signing and recorder checkpoint signing in the generated dev fleet.

This is dev material. Production keeps signing keys in KMS/HSM or equivalent external signing systems and off Conductor disk.

## Run The Real Dev Fleet

After bootstrap succeeds, export the generated dev fleet license for the spawned Conductor and follower. This is source-verified from bootstrap quickstart output:

```bash
export PIPELOCK_LICENSE_KEY="$(cat "$FLEET_DIR/license/license.token")"
export PIPELOCK_LICENSE_PUBLIC_KEY="<hex printed by bootstrap>"
```

Start Conductor (source-verified from bootstrap quickstart and `conductor serve --help`):

```bash
/tmp/pipelock-ent conductor serve \
  --listen 127.0.0.1:8895 \
  --conductor-id conductor-local \
  --follower-trust-domain pipelock.local \
  --storage-dir "$FLEET_DIR/conductor/storage" \
  --tls-cert "$FLEET_DIR/conductor/server.crt" \
  --tls-key "$FLEET_DIR/conductor/server.key" \
  --client-ca "$FLEET_DIR/ca/ca.crt" \
  --publisher-token-file "$FLEET_DIR/conductor/publisher.token" \
  --auditor-token-file "$FLEET_DIR/conductor/auditor.token" \
  --admin-token-file "$FLEET_DIR/conductor/admin.token" \
  --trusted-control-key id=conductor-remote-kill-1,purpose=remote-kill-signing,file="$FLEET_DIR/trust/remote-kill.pub" \
  --trusted-control-key id=conductor-rollback-1,purpose=policy-bundle-rollback,file="$FLEET_DIR/trust/rollback.pub" \
  --probe-listen 127.0.0.1:9092
```

### Emergency-control signature verification (defense in depth)

The `--trusted-control-key` set is the leader's static, restart-stable list of
keys that may sign remote-kill messages and rollback authorizations. The leader
verifies an emergency-control signature against this set at **publish ingress**
and **again at every read** (startup reconcile, the follower latest-bundle
rollback ceiling, remote-kill / rollback lookups, and the stream-status
overview). A stored emergency-control record that does not verify is
**quarantined**: it is dropped from every read path so it can neither move nor
suppress the served stream head, and a high-severity audit event is emitted
(`conductor_rollback_reconcile_quarantined_unverified`,
`conductor_remote_kill_quarantined_unverified`, with the
`conductor_emergency_quarantine_total{control,reason}` metric). The leader does
**not** crash on an unverifiable record — only raw on-disk corruption is fatal.

**Key rotation caution.** If you rotate a control key out of
`--trusted-control-key`, any emergency-control record still on disk that was
signed only by the rotated-out key will quarantine after the next leader
restart. This is correct (the leader will not honor a record it can no longer
verify), but it can **silently remove emergency state** that you still rely on.
The rotation case is logged distinctly
(`conductor_rollback_quarantined_rotated_key` /
`conductor_remote_kill_quarantined_rotated_key`, reason
`untrusted_or_rotated_signer`). When rotating control keys, re-issue and
re-publish any still-active remote-kill or rollback authorization under a key
that remains in the trusted set, and confirm via `conductor kill status` /
`conductor stream` after the restart that the expected emergency controls are
still served.

Start the follower in a second shell with the same generated dev license environment:

```bash
/tmp/pipelock-ent run -c "$FLEET_DIR/follower/follower.yaml"
```

The generated follower config enables:

- `conductor.enabled: true`
- `flight_recorder.enabled: true`
- signed flight-recorder checkpoints
- Conductor bundle cache and durable audit queue directories
- mTLS client certificate and Conductor server CA paths
- `stale_policy.after_grace: strict_deny_all`

## Follower Enrollment

The live bootstrap proof performs enrollment in-process:

1. Conductor starts with mTLS required.
2. The follower performs `GET /api/v1/conductor/capabilities`.
3. Conductor creates a one-shot enrollment token.
4. The follower calls `POST /api/v1/conductor/enroll` with that token, its audit key ID, and its audit public key.
5. Conductor records the active follower identity and enrolled audit key.
6. Future follower calls derive identity from the mTLS certificate, not request fields.

The operator does not have to run separate enrollment commands for the generated dev fleet; bootstrap proves that path before writing its quickstart.

### Enrollment-token lifecycle (mint, list, status, revoke)

For a real fleet you mint enrollment tokens out of band and hand each one to a
starting follower. The `enrollment-token` subcommands manage that lifecycle. All
of them are admin-authorized: they use the same mTLS client material plus the
admin bearer token as the other operator reads.

Mint a one-shot token for a follower identity. The token (the secret) is printed
to stdout; the summary goes to stderr, so `> token.txt` captures only the token:

```bash
/tmp/pipelock-ent conductor enrollment-token mint \
  --conductor-url https://127.0.0.1:8895 \
  --admin-token-file "$FLEET_DIR/conductor/admin.token" \
  --server-ca "$FLEET_DIR/ca/ca.crt" \
  --tls-cert "$FLEET_DIR/follower/client.crt" \
  --tls-key "$FLEET_DIR/follower/client.key" \
  --token-id enroll-pl-prod-1 \
  --org org-local --fleet dev --instance pl-prod-1 --env dev \
  --ttl 1h
```

The server rejects an over-long `--ttl`. The maximum is set on `conductor serve`
with `--enrollment-token-max-validity` (default 24h); a token requested past the
ceiling is rejected before it is minted, so a leaked-but-unused token cannot have
a multi-week exposure window.

List, inspect, and revoke tokens by their stable `token_id`. These reads return
lifecycle metadata only (`pending` / `consumed` / `revoked` / `expired`); the
token secret is shown only once, at mint, and is never returned again:

```bash
# List all tokens (or filter by --org-id/--fleet-id/--instance-id/--environment).
/tmp/pipelock-ent conductor enrollment-token list \
  --server https://127.0.0.1:8895 \
  --ca-file "$FLEET_DIR/ca/ca.crt" \
  --client-cert "$FLEET_DIR/follower/client.crt" \
  --client-key "$FLEET_DIR/follower/client.key" \
  --token-file "$FLEET_DIR/conductor/admin.token"

# Inspect one token's state.
/tmp/pipelock-ent conductor enrollment-token status \
  --server https://127.0.0.1:8895 \
  --ca-file "$FLEET_DIR/ca/ca.crt" \
  --client-cert "$FLEET_DIR/follower/client.crt" \
  --client-key "$FLEET_DIR/follower/client.key" \
  --token-file "$FLEET_DIR/conductor/admin.token" \
  --token-id enroll-pl-prod-1

# Revoke a still-pending token so it can no longer enroll a follower.
/tmp/pipelock-ent conductor enrollment-token revoke \
  --server https://127.0.0.1:8895 \
  --ca-file "$FLEET_DIR/ca/ca.crt" \
  --client-cert "$FLEET_DIR/follower/client.crt" \
  --client-key "$FLEET_DIR/follower/client.key" \
  --token-file "$FLEET_DIR/conductor/admin.token" \
  --token-id enroll-pl-prod-1
```

Revoke only succeeds for a still-pending token. A consumed, already-revoked, or
expired token is rejected (the enrollment already happened, or the token is
already dead), and a revoked token fails closed if a leaked copy is later
presented to `POST /api/v1/conductor/enroll`. The revocation is durable across a
Conductor restart.

Note the connection flags differ between `mint` and the read commands. `mint`
takes `--conductor-url`, `--admin-token-file`, `--server-ca`, `--tls-cert`, and
`--tls-key`; `list`, `status`, and `revoke` take `--server`, `--token-file`,
`--ca-file`, `--client-cert`, and `--client-key`. The read commands share the
common operator-client flags used across all read endpoints (`fleet status`,
`audit query`), while `mint` is a dedicated write operation with its own options.
Use each command's flag names as written above rather than copying them across.

## Operator Bearer Tokens (generation and rotation)

The publisher, auditor, and admin bearer tokens are read from files on
`conductor serve` (`--publisher-token-file`, `--auditor-token-file`,
`--admin-token-file`). They are opaque shared secrets the Conductor compares in
constant time; Pipelock does not mint or rotate them for you, so generate and
rotate them out of band.

Generate a high-entropy token (256 bits, URL-safe), written `0o600`:

```bash
umask 077
openssl rand -base64 32 | tr -d '\n' > "$FLEET_DIR/conductor/admin.token"
```

`bootstrap` writes dev tokens into the generated layout for you; the command
above is the production path where you control the secret store. To rotate a
token: write the new value to the token file (or your secret store), then restart
`conductor serve` so it reloads the file, and distribute the new value to the
operators or automation that present it. Because the tokens are independent
files, you can rotate one role without disturbing the others.

## Policy Publish

Policy publication is an HTTP API surface, not a standalone CLI command in the current help output. The source-verified endpoint is:

```http
PUT /api/v1/conductor/policy-bundles
POST /api/v1/conductor/policy-bundles
```

The request body shape is source-verified from `enterprise/conductor/controlplane/handler.go`:

```json
{
  "bundle": {
    "schema_version": 1,
    "bundle_id": "bundle-1",
    "org_id": "org-local",
    "fleet_id": "dev",
    "environment": "dev",
    "audience": {},
    "version": 1,
    "created_at": "2026-05-25T12:00:00Z",
    "not_before": "2026-05-25T12:00:00Z",
    "expires_at": "2026-05-26T12:00:00Z",
    "min_pipelock_version": "2.7.0",
    "policy_hash": "<hex>",
    "payload_sha256": "<hex>",
    "payload": {
      "config_yaml": "mode: balanced\n",
      "rule_bundles": []
    },
    "signatures": []
  }
}
```

The server authorizes the request with the publisher token file configured on `conductor serve`, verifies the signed bundle, rejects forbidden config sections such as license and local trust-boundary fields, and stores accepted bundles under the Conductor storage directory. Followers poll `GET /api/v1/conductor/policy/latest` over mTLS and apply only bundles addressed to their org, fleet, environment, and audience.

This runbook does not include a one-line policy signing helper because none exists in the verified CLI help. Use the signed bundle producer in your operator workflow, then publish through the API above.

### Publish conflicts (HTTP 409)

A forward publish can be rejected with `409 Conflict` for three operationally distinct reasons. The control plane carries a machine-readable `code` in the JSON error body so the publisher can tell them apart instead of treating every conflict as a stale version:

| `code` | Meaning | What to do |
| --- | --- | --- |
| `rollback_attempt` | The supplied `version` is below the current (rolled-back) stream head. A publish cannot roll back. | Use the rollback authorization flow, not a publish. |
| `version_below_stream_max` | The `version` is not greater than the stream's **highest-ever** published version. After a rollback the head sits at `vN` while `vN+1..vM` still exist, so a forward publish needs a version greater than `M`, not merely greater than the current head `N`. | Publish a `version` above the stream **max**. Query the stream head/max version through your Conductor status workflow before retrying. |
| `previous_hash_mismatch` | `previous_bundle_hash` does not match the current stream head hash (typically a stale or copy-pasted hash). | Set `previous_bundle_hash` to the hash printed by the most recent successful publish for this stream. |

The `pipelock conductor publish` CLI maps each `code` to a distinct, errors-comparable error with an actionable message, so an operator recovering from a rollback is told to publish above the stream max rather than seeing a misleading "version is stale".

## Signed Audit Batch And Offline Verification

Bootstrap proves the signed audit path end to end unless `--skip-proof` is set:

1. The follower writes a real flight-recorder checkpoint.
2. The audit batcher signs one batch with the follower audit key.
3. The follower posts the batch to `POST /api/v1/conductor/audit/batches` over mTLS.
4. Conductor verifies the batch envelope and payload together.
5. Conductor verifies the audit-batch signature against the enrolled follower audit key.
6. Conductor accepts the batch with HTTP `202`.
7. Bootstrap queries it back through the auditor API.
8. Bootstrap verifies the batch offline with `AuditBatchEnvelope.VerifySignaturesAt`.
9. The signed batch is written to:

```text
$FLEET_DIR/audit-batch.json
```

The source proof records batch id, envelope hash, sequence start/end, event count, ingest status, query-back status, offline verification status, and batch path.

## Fleet Sink

`fleet-sink` is a separate Conductor audit batch sink. It is Enterprise-gated and fails closed on license verification before listener bind or disk IO.

Start a loopback dev sink with one trusted audit key (source-verified from `fleet-sink --help`):

```bash
/tmp/pipelock-ent fleet-sink \
  --listen 127.0.0.1:8894 \
  --storage-dir "$FLEET_DIR/fleet-sink" \
  --trusted-audit-key id=follower-audit-1,file="$FLEET_DIR/follower/audit-signing.pub",org=org-local,fleet=dev,instance=follower-1 \
  --probe-listen 127.0.0.1:9094
```

For non-loopback binds without mTLS, `fleet-sink --help` requires `--reader-token-file` for GET requests. For mTLS, provide:

```text
--tls-cert <path>
--tls-key <path>
--client-ca <path>
```

`fleet-sink` stores accepted batches in a SQLite database under `--storage-dir` and verifies signatures using the configured `--trusted-audit-key` values. Optional tenant bindings (`org=`, `fleet=`, `instance=`) constrain which batches a trusted key can authenticate.

## What This Proves

With a valid operator Enterprise license, bootstrap proves:

- the generated PKI and SPIFFE identity are usable;
- follower enrollment works over mTLS;
- the follower can sign a real audit batch;
- Conductor accepts that batch over mTLS;
- the auditor API can query the accepted batch metadata;
- offline signature verification succeeds with no running Conductor.

It does not prove mediation completeness. The agent reaching the network only through Pipelock remains deployment-enforced through capability separation, container/network policy, or per-UID firewalling.

## Recovery Operations

After a rollback or during incident recovery, additional operator commands are
available. See [`docs/cli/conductor-recovery.md`](../cli/conductor-recovery.md)
for full details.

| Command | Purpose |
|---|---|
| `conductor publish --previous-bundle-hash auto` | Publish forward after a rollback without manually copying the stream head hash. |
| `conductor rollback clear --authorization-id <id> --confirm` | Remove a single active rollback authorization (unblock forward publishes before TTL expiry). |
| `conductor stream reset --org-id <org> --fleet-id <fleet> --confirm` | Clear all active rollback authorizations for an org/fleet scope. |
| `conductor kill status --org-id <org>` | Show active remote-kill messages (read-only). |
| `conductor store dump --org-id <org>` | Dump the stream-status JSON response for support. |

All guarded commands require `--confirm`; they refuse to run without it.

## Validation Status For This Doc

Live-run commands completed in this documentation pass:

```text
go build -tags enterprise -o /tmp/pipelock-ent ./cmd/pipelock
/tmp/pipelock-ent conductor --help
/tmp/pipelock-ent conductor bootstrap --help
/tmp/pipelock-ent conductor serve --help
/tmp/pipelock-ent fleet-sink --help
/tmp/pipelock-ent conductor bootstrap --dir <tmpdir>
```

The bootstrap run stopped at the Enterprise entitlement gate in `0.00s`; no fleet files were written and no production token was searched for. The full under-10-minute live proof should be rerun by an operator with a valid fleet license.
