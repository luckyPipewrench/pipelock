# Key rotation runbook

Operational procedure for rotating Pipelock's deployment-level Ed25519 signing keys without breaking the live-lock roster or stranding existing signed artifacts. Audience: a security engineer with `pipelock signing` available and access to the production key material.

This runbook covers the four wire purposes that operators rotate during normal operation: `roster-root`, `contract-activation-signing`, `contract-compile-signing`, and `receipt-signing`. The `recovery-root` purpose is rotated under break-glass procedures, which are out of scope here.

## When to rotate

Rotation has two kinds of trigger. The first is scheduled cadence drawn from `docs/guides/learn-and-lock.md`: ninety days for `receipt-signing`, roughly yearly for `contract-compile-signing`. `contract-activation-signing` and `roster-root` are not on a fixed cadence; the deployment's key-management policy sets them. The second is event-driven rotation, triggered by operator custody changes or any suspected compromise. Compromise collapses the soak window to zero.

Rotating without one of these triggers is not free. Every rotation is a window where two keys are valid, and that window costs verifier complexity. Rotate on a cadence, not on instinct.

## Pre-flight check

Confirm the live roster matches the operator's expectation. Read the current roster file and pretty-print it.

```bash
pipelock signing roster show \
  --path /etc/pipelock/roster.json \
  --root-fingerprint sha256:CURRENTROOTFINGERPRINT
```

The output lists the root, each included entry, and the signing key ID. If the entries do not match the operator's record of the production roster, fix that divergence before rotating. Rotating from an unknown baseline is how rosters get orphaned.

Capture the current pinned root fingerprint that the live-lock loader binds against. The runtime configuration field is `learn_lock.pinned_root_fingerprint`. Use that value for every roster verification command in this procedure; `roster verify` confirms the roster chains to the pinned root and fails closed on mismatch.

```bash
pipelock signing roster verify \
  --path /etc/pipelock/roster.json \
  --root-fingerprint sha256:CURRENTROOTFINGERPRINT
```

If verification fails, stop. The remediation path for a broken roster is not rotation; it is recovery, which uses `pipelock signing recovery verify` and is documented separately.

## Generate the new key

Generate the new keypair bound to the wire purpose being rotated. Use an absolute output path on a 0o700 directory and confirm the file lands with 0o600 mode.

```bash
pipelock signing key generate \
  --purpose contract-activation-signing \
  --id activation-YYYYMM \
  --out /etc/pipelock/keys/activation-YYYYMM.json
```

The command prints the canonical SHA-256 fingerprint of the public half on success. Record that fingerprint in the rotation change record alongside the operator name and the wire purpose. The private half stays on disk at the path passed to `--out`; it never leaves the host that generated it.

For `roster-root` rotation, the procedure is the same with `--purpose roster-root`. The new root key produces a new pinned root fingerprint, which means the live-lock configuration must be updated in lockstep with the new roster. See "Rotating the root" below.

## Build the dual-trust roster

Build a new roster that includes the old key as `status=active` and the new key also as `status=active`. The roster's root entry is auto-included from `--root`; do not pass the root via `--include`.

The `key=` value may point at the generated deployment key JSON file. The roster builder reads the public half and the declared purpose from that file, verifies that the private half derives the same public key, and writes only public key material into the roster output.

```bash
pipelock signing roster build \
  --root /etc/pipelock/keys/fleet-root.json \
  --include id=activation-PRIOR,key=/etc/pipelock/keys/activation-PRIOR.json,purpose=contract-activation-signing,status=active,role=operator \
  --include id=activation-YYYYMM,key=/etc/pipelock/keys/activation-YYYYMM.json,purpose=contract-activation-signing,status=active,role=operator \
  --data-class internal \
  --out /etc/pipelock/roster-YYYYMM.json
```

Verify the new roster against the unchanged pinned root fingerprint, then distribute it to every Pipelock instance. The distribution mechanism is integrator-specific. Common patterns are file-based rollout through a configuration management tool, or fetching from a signed remote location and verifying it with `pipelock signing roster verify --path PATH --root-fingerprint sha256:CURRENTROOTFINGERPRINT` before activation.

Until every instance has the new roster, the live-lock loader on un-updated instances will accept the old key and reject artifacts signed by the new key. Production cutover happens after distribution completes.

## Verify chain continuity

Sign at least one test artifact with the new key and confirm the live-lock loader on a representative instance accepts it. For receipt signing, this means a session that emits a receipt under the new key and runs through `pipelock-verifier chain PATH --key NEWPUB`. For contract activation, this means a contract promotion that the runtime loader accepts.

If the test artifact is rejected, do not proceed to sunset. Roll back to the prior roster by re-distributing the pre-rotation file. The dual-trust roster is the safety net; the rollback is to remove the new key, not to remove the old.

## Soak window

Hold the dual-trust roster live for a soak period before sunsetting the old key. Recommended windows: thirty days for `roster-root` and `contract-activation-signing`, fourteen days for `contract-compile-signing`, and seven days for `receipt-signing`.

The soak exists so that any artifact signed by the old key in the last hours before cutover is still verifiable from the live roster. Shortening the soak under time pressure is a known way to strand pending verifications.

## Sunset the old key

After the soak window, build a subsequent roster that includes the new key as `status=active` and the old key as `status=revoked`. The roster build command accepts `status=revoked` on an `--include` entry.

```bash
pipelock signing roster build \
  --root /etc/pipelock/keys/fleet-root.json \
  --include id=activation-PRIOR,key=/etc/pipelock/keys/activation-PRIOR.json,purpose=contract-activation-signing,status=revoked \
  --include id=activation-YYYYMM,key=/etc/pipelock/keys/activation-YYYYMM.json,purpose=contract-activation-signing,status=active,role=operator \
  --data-class internal \
  --out /etc/pipelock/roster-YYYYMM-postsunset.json
```

Verify and distribute. The old key remains in the roster for transparency and so that historical verifications by parties who already have the old public key on file continue to resolve. Live signing operations under the old key now fail.

The old key's private material can be destroyed at this point. Coordinate destruction with whatever secure-destruction policy applies to the host that holds it.

## Compromise response

If a key is suspected compromised, the dual-trust window collapses to zero. Issue a roster that marks the compromised key `status=revoked` and includes the replacement as `status=active`, then distribute immediately. Once a Pipelock instance has received the revoking roster, the live-lock loader rejects all signatures from the revoked key regardless of when the artifact was produced. The rejection is enforced by the roster state, not by a trusted clock.

Pre-revocation artifacts remain verifiable by parties who already trusted the compromised public key and retained a copy. Pipelock does not retroactively un-sign anything; that property is not possible with detached Ed25519 signatures. Communicate the compromise timeline and affected window to relying parties through the coordinated-disclosure channel documented in [coordinated-disclosure.md](coordinated-disclosure.md).

## Rotating the root

`roster-root` rotation changes the pinned root fingerprint that every Pipelock instance binds against in its live-lock configuration. The transition is signed by both the old and the new root and is verified with `pipelock signing transition verify`. Procedure: generate the new root, build a root transition document signed by both roots, distribute the transition document and the new roster, update `learn_lock.pinned_root_fingerprint` in the runtime configuration on every instance, then verify with `pipelock signing transition verify` and `pipelock signing roster verify --path NEWROSTER --root-fingerprint sha256:NEWROOTFINGERPRINT`.

Root rotation is the highest-risk procedure in this runbook. Schedule it during a maintenance window, not on a calendar trigger. Test the transition document on a non-production instance before distributing.

## Verification checklist

The operator confirms before considering the rotation complete:

- [ ] New key generated with the correct `--purpose`
- [ ] Output file is mode 0o600 on a directory mode 0o700
- [ ] Public-key SHA-256 fingerprint recorded in the change ticket
- [ ] Dual-trust roster built and verified against the pinned root fingerprint
- [ ] New roster distributed to every Pipelock instance
- [ ] Test artifact signed under the new key passes live verification
- [ ] Soak window scheduled in the operator's calendar
- [ ] Audit log entry written for the rotation, including operator name, key ID, purpose, and timestamp

## See also

- [coordinated-disclosure.md](coordinated-disclosure.md): communicating compromise timelines
- [per-deployment-ca-threat-model.md](per-deployment-ca-threat-model.md): CA rotation, which has a different procedure
- [SECURITY.md](../../SECURITY.md): reporting channel for key-handling vulnerabilities
