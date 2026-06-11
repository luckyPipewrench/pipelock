# PR B — Conductor emergency control: deferred live-proof sequence

This PR ships the operator producer-side CLIs for Conductor emergency control:

- `pipelock conductor kill` / `pipelock conductor resume` → signed remote-kill →
  `POST /api/v1/conductor/remote-kill` (purpose `remote-kill-signing`, 2-of-N).
- `pipelock conductor rollback` → signed rollback authorization →
  `POST /api/v1/conductor/rollback-authorizations` (purpose `policy-bundle-rollback`, 2-of-N).
- `pipelock conductor enrollment-token mint` → one-shot enrollment token →
  `POST /api/v1/conductor/enrollment-tokens` (admin bearer token).

All three are gated on the `fleet` Enterprise license and refuse to run unlicensed.

## What is proven in-repo (unit, `-race`, in this PR)

Full producer→server round-trips drive the REAL control-plane handler over an
`httptest` server (mTLS is a transport concern; the producer logic — message
construction, M-of-N signing, and the server's acceptance — is what these
exercise):

- kill → server accepts (`state=active`); resume with a higher counter → accepts (`state=inactive`).
- rollback (target_version < current_version) → server accepts.
- enrollment-token mint → server issues a `pl_enroll_…` token (to stdout; summary to stderr).
- **M-of-N enforced both sides:** one signer → rejected at the CLI boundary
  (`ErrThresholdRequired`, no network call); the same keyfile supplied twice
  (same embedded `key_id`) → rejected at the CLI; a roster key held under the
  WRONG purpose → rejected by the server (distinct-public-key threshold).
- **Purpose binding at load:** `--signing-key` reads the keygen JSON keyfile and
  rejects a keyfile whose embedded purpose ≠ the action's required purpose (a
  rollback keyfile handed to `kill` fails locally), plus a strict integrity gate
  (0600/0640-only, strict JSON, schema, key sizes, private→public derivation).
- **TTL ceiling:** a window exceeding the server's configured max validity → rejected.
- **Replay:** a stale (`<= max`) counter → rejected.
- **Auth:** a wrong admin bearer token → 403; a missing token file → required error.
- **Fail-closed transport:** with no injected transport and no TLS flags, the
  production mTLS client build fails (`--tls-cert is required`) before any request.
- **No license → no action:** each command returns `ErrFleetLicenseRequired` unlicensed.

Coverage on the package is ~90% (new run functions 93–100%).

## What is DEFERRED (live, against the dogfood/test followers)

The live fleet proof needs ≥2 keys per catastrophic purpose for the 2-of-N
demonstration. The bootstrap fleet at `~/.local/share/v27-prod-fleet/trust/`
ships ONE `remote-kill.key` and ONE `rollback.key`. Generating the SECOND key per
purpose is **PR #736's keygen** (`signing key generate` accepting the conductor
purposes). #736 is NOT on this branch, so the live proof is deferred until this
branch is rebased onto a main that includes #736. The bar forbids undocumented
key material (no `openssl`), so the second key must come from the shipped CLI.

### Exact live-proof sequence (run after rebasing onto main with #736 merged)

Fleet material (already on this host): `~/.local/share/v27-prod-fleet/`
(CA at `ca/ca.crt`, conductor server at `conductor/`, admin token at
`conductor/admin.token`, operator client cert reusable from `follower/client.crt`
+ `follower/client.key`, first control keys at `trust/remote-kill.key` and
`trust/rollback.key`). Conductor URL: `https://127.0.0.1:8895`.

`--signing-key` takes a PATH to a JSON keypair file produced by
`pipelock signing key generate` (the file carries its own `key_id` and
`purpose`; the CLI reads them and validates the purpose matches the action — no
`id=`/`file=` sub-fields, no inline keys). The existing bootstrap keys at
`trust/remote-kill.key` are in the OLD `pipelock-ed25519-private-v1` format and
are NOT directly consumable; regenerate both signers per purpose with #736's
keygen, which emits the JSON keyfile format.

```bash
FLEET=~/.local/share/v27-prod-fleet
CU=https://127.0.0.1:8895
KD=$FLEET/control-keys; mkdir -p "$KD"

# 0. Generate TWO signers per purpose with #736's keygen (sanctioned key
#    material; --out writes a single JSON keypair file).
pipelock signing key generate --purpose remote-kill-signing --id remote-kill-1 --out "$KD/remote-kill-1.json"
pipelock signing key generate --purpose remote-kill-signing --id remote-kill-2 --out "$KD/remote-kill-2.json"
pipelock signing key generate --purpose policy-bundle-rollback --id rollback-1  --out "$KD/rollback-1.json"
pipelock signing key generate --purpose policy-bundle-rollback --id rollback-2  --out "$KD/rollback-2.json"
# Roster/serve the Conductor so it TRUSTS both signer ids per purpose. The
# conductor `--trusted-control-key` flag is repeatable and takes the PUBLIC key
# (extract `public` hex from each keyfile, or use the matching .pub the keygen
# wrote alongside it):
#   --trusted-control-key id=remote-kill-1,purpose=remote-kill-signing,inline=<pubhex>
#   --trusted-control-key id=remote-kill-2,purpose=remote-kill-signing,inline=<pubhex>
#   --trusted-control-key id=rollback-1,purpose=policy-bundle-rollback,inline=<pubhex>
#   --trusted-control-key id=rollback-2,purpose=policy-bundle-rollback,inline=<pubhex>

# 1. KILL: both followers must fail CLOSED (deny all traffic).
pipelock conductor kill \
  --conductor-url "$CU" \
  --admin-token-file "$FLEET/conductor/admin.token" \
  --signing-key "$KD/remote-kill-1.json" \
  --signing-key "$KD/remote-kill-2.json" \
  --org pipelab --fleet prod --instance '*' \
  --reason "live emergency-stop proof" \
  --tls-cert "$FLEET/follower/client.crt" --tls-key "$FLEET/follower/client.key" \
  --server-ca "$FLEET/ca/ca.crt" --server-name 127.0.0.1
# OBSERVE: both followers poll, apply the remote-kill, and deny all egress.
#   Confirm on each follower: a probe request returns the fail-closed block, and
#   the follower's remote-kill-state.json records state="active".

# 2. RESUME: both followers recover (counter is auto-derived from the clock, so
#    a resume issued after the kill always supersedes it).
pipelock conductor resume \
  --conductor-url "$CU" \
  --admin-token-file "$FLEET/conductor/admin.token" \
  --signing-key "$KD/remote-kill-1.json" \
  --signing-key "$KD/remote-kill-2.json" \
  --org pipelab --fleet prod --instance '*' \
  --tls-cert "$FLEET/follower/client.crt" --tls-key "$FLEET/follower/client.key" \
  --server-ca "$FLEET/ca/ca.crt" --server-name 127.0.0.1
# OBSERVE: both followers return to normal enforcement; state="inactive".

# 3. ROLLBACK: publish bundle v2 (via PR A's `conductor publish`, or the publish
#    HTTP path directly), confirm followers apply v2, then roll back to v1.
pipelock conductor rollback \
  --conductor-url "$CU" \
  --admin-token-file "$FLEET/conductor/admin.token" \
  --signing-key "$KD/rollback-1.json" \
  --signing-key "$KD/rollback-2.json" \
  --org pipelab --fleet prod --instance '*' \
  --current-bundle-id <v2-bundle-id> --current-version 2 \
  --target-bundle-id  <v1-bundle-id> --target-version 1 \
  --reason "live rollback proof" \
  --tls-cert "$FLEET/follower/client.crt" --tls-key "$FLEET/follower/client.key" \
  --server-ca "$FLEET/ca/ca.crt" --server-name 127.0.0.1
# OBSERVE: both followers restore the PRIOR bundle; applied version goes 2 -> 1.

# 4. UNDER-THRESHOLD rejected: one signer short -> the CLI refuses BEFORE any
#    network call.
pipelock conductor kill \
  --conductor-url "$CU" \
  --admin-token-file "$FLEET/conductor/admin.token" \
  --signing-key "$KD/remote-kill-1.json" \
  --org pipelab --fleet prod --instance '*' \
  --tls-cert "$FLEET/follower/client.crt" --tls-key "$FLEET/follower/client.key" \
  --server-ca "$FLEET/ca/ca.crt" --server-name 127.0.0.1
# OBSERVE: "requires 2 distinct signers, got 1" with no request sent.
#   (Supplying the same keyfile twice is also rejected at the CLI — same key_id —
#    and a key the roster holds under the wrong purpose is rejected by the server.
#    Both are covered by unit tests.)
```

## Notes / scope

- **`enrollment-token` ships `mint` only.** The control plane has no token-LIST
  read endpoint today (the only new fleet read endpoint in this epic is PR C's
  follower-list). `enrollment-token` is a parent command so a `list` subcommand
  can be added later without breaking the surface; this PR does not invent a
  server endpoint to back a `list`.
- **Private signing keys are file-only** (`--signing-key /path/to/keypair.json`,
  the keygen JSON format). Inline key values are not accepted, so signing
  material never lands in shell history or the process table. The keyfile's
  embedded `key_id` is used (operator does not retype it) and its `purpose` is
  validated against the action.
- The minted enrollment token goes to **stdout**, the human summary to **stderr**,
  so `... mint > token.txt` captures only the credential.
- One-line CHANGELOG stub belongs in PR D (consolidated docs/CHANGELOG per the
  parallel-coordination plan); this PR keeps its docs to this file.
