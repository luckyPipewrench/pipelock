# PR A: `conductor publish` — notes

## What shipped
`pipelock conductor publish` — a producer CLI that builds a `PolicyBundle` from a
pipelock config (+ optional rule-bundle refs), signs it with a
`policy-bundle-signing` key, and PUTs it to a running Conductor's publish
endpoint (`PUT /api/v1/conductor/policy-bundles`) over mutual TLS with a
publisher bearer token. Followers then pull and apply it on their next poll.

- New file: `enterprise/cli/conductor/publish.go` (+ `publish_test.go`).
- One-line registration in `enterprise/cli/conductor/cmd.go` (`cmd.AddCommand(publishCmd())`).
- License gate: `license.VerifyFleet` (fleet entitlement), fail-closed before any
  key read or network call, mirroring `serveCmd` / `bootstrapCmd`.

## Proven by unit test (not live)
- Full build → sign → PUT accepted by the REAL `controlplane.Handler` over
  `httptest` (real `PolicyBundle.Validate` + real file-store monotonic/chain logic).
- Monotonic version: forward publish chained via `--previous-bundle-hash` accepted;
  unchained forward and lower version both rejected (409 → `ErrStalePolicyVersion`).
- First-bundle-with-previous-hash rejected.
- Bad publisher token → "not authorized"; wrong-purpose / unknown-purpose /
  tampered / too-permissive signing key all rejected; forbidden config section and
  license field rejected at local `Validate` before any network call.
- mTLS required for https; `--allow-plaintext-loopback` restricted to a true
  loopback host (userinfo trick, look-alike subdomain, 0.0.0.0, link-local all
  rejected; `[::1]` allowed). Signature verifies against the signer public key.
- publish.go statement coverage: ~92%.

## DEFERRED — live follower proof (run after #736 lands and a rebase)
`#736` adds the `policy-bundle-signing` purpose to `pipelock signing key generate`.
It is NOT on this branch. Once it merges, `git rebase origin/main` and run:

```bash
# 0. Fleet material already exists at ~/.local/share/v27-prod-fleet/ (CA, roster,
#    publisher token, follower client cert/key). Confirm the leader + both
#    followers are up first.

# 1. Generate a policy-bundle-signing key with the SHIPPED CLI (no openssl).
pipelock signing key generate \
  --purpose policy-bundle-signing \
  --out ~/.local/share/v27-prod-fleet/policy-signing.json

#    Add its PUBLIC key to the Conductor's trusted policy-bundle-signing roster
#    so followers verify the signature (roster wiring is the serve side; if the
#    running leader's roster does not yet trust this key, add it and restart the
#    leader, OR sign with a key already in the roster).

# 2. Publish v1 with a visible config change (e.g. flip a mode / add a suppress).
pipelock conductor publish \
  --conductor-url https://<leader-host>:8895 \
  --config /path/to/changed-policy.yaml \
  --org <org> --fleet <fleet> --env <env> \
  --audience '*' \
  --version <N+1> \
  --signing-key ~/.local/share/v27-prod-fleet/policy-signing.json \
  --publisher-token-file ~/.local/share/v27-prod-fleet/publisher.token \
  --tls-cert ~/.local/share/v27-prod-fleet/follower-client.crt \
  --tls-key  ~/.local/share/v27-prod-fleet/follower-client.key \
  --server-ca ~/.local/share/v27-prod-fleet/ca.pem
#    -> prints: published policy bundle <id> version <N+1> (hash <H>, created=true) ...

# 3. OBSERVE BOTH followers apply it:
#    - in-cluster dogfood follower(s) and the fedora-host follower at
#      ~/.local/share/v27-fedora-follower/ should advance their applied version
#      to <N+1> and reflect the config change on their next poll.
#    - check follower logs / applied-version metric for each.

# 4. Re-publish a LOWER version -> MUST be rejected as stale:
pipelock conductor publish ... --version <N>     # (same flags)
#    -> exits non-zero: "policy bundle version is stale ..."

# 5. Forward publish v<N+2> chained to the prior head hash <H>:
pipelock conductor publish ... --version <N+2> --previous-bundle-hash <H>
#    -> accepted; followers advance to <N+2>.
```

Done-state for the live proof: both followers visibly apply the new config and
their applied version advances; a lower version is rejected; the chained forward
is accepted.

## External review hardening (2026-06-11, commit 2)

Codex adversarial review found no critical breaks but three WARNINGs, all fixed
in-PR with mutation-proven regression tests:

1. **Untrusted server body → log forging / token echo.** `serverErrorDetail` now
   redacts the publisher token if reflected, collapses every control/non-printable
   rune (CR/LF/tab/NUL/ESC, BOM, U+2028/29) to a single space, and rune-caps AFTER
   sanitization. Test `TestServerErrorDetail_LogForgingAndTokenEcho` (+
   `TestSanitizeServerDetail_TokenSubstringRedaction`).
2. **Private key not zeroized on every error path.** `buildSignedBundle` now
   validates ALL non-key inputs before reading the key, then `defer`s a conditional
   wipe that fires on every error path; success hands off and the caller `defer`s
   its own wipe. Tests `TestBuildSignedBundle_InputsValidatedBeforeKeyRead` (ordering)
   and `TestBuildSignedBundle_NoKeyEscapesOnPostLoadError`.
3. **Symlink rejection comment was false.** `ReadKeyFileBytes` now `os.Lstat`s
   first and rejects `os.ModeSymlink` before `os.Open` (which follows symlinks),
   then fd-stats. Test `TestReadSigningKeyBytes_SymlinkRejected`.

Each fix was mutation-verified: reverting it makes the matching test fail with the
exact security symptom (token leak / key read before input validation / symlink
followed).

## Known boundaries (honest)
- The publisher does NOT auto-discover the current stream head. Forward publishes
  need `--previous-bundle-hash <H>` where `<H>` is the hash printed by the prior
  publish. (Auto-fetch would require follower mTLS identity on the publish path,
  which the publisher role does not carry; the `LatestPolicyBundlePath` GET is
  follower-identity gated, not publisher-token gated.)
- Roster trust for the new signing key is a serve-side concern (operator adds the
  public key to the Conductor's trusted policy-bundle-signing set). This PR is the
  producer/client only.
