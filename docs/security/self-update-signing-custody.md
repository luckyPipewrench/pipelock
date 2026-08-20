# Self-Update Signing Key Custody

Pipelock self-update verification requires a native signed `release.json`
manifest before any downloaded binary is installed. That preserves offline
Ed25519 verification on the client. The remaining release-risk decision is
where the `release.json` private signing key lives.

## Decision

Option A is chosen and implemented for v2.8: CI builds artifacts and publishes
an unsigned `release.json`; the release owner signs that exact manifest offline
and uploads `release.json.sig` as a release asset.

`RELEASE_KEYRING_HEX` remains in CI because it is the public Ed25519 verification
keyring embedded into release binaries. The private manifest signing key is not
referenced by the release workflow.

## Current Signing Custody

The private manifest signing key is kept off persistent host storage and loaded
only for the signing operation. This limits persistence but is not an air gap:
a compromised signing host could still access key material while it is in use.
A non-exportable hardware-backed key is the preferred next hardening step; the
current signer can read key material from standard input so it does not appear
in the process argument list.

## Signing Runbook

1. Download `release.json` from the draft GitHub release. If signing happens on
   a separate offline machine, transfer the manifest there. Only public bytes
   need to cross the boundary: `release.json` in and `release.json.sig` out.

2. Load the release signing key using the designated custody procedure. Remove
   access to it as soon as signing finishes.

3. Sign the manifest:

   ```bash
   read -rsp 'release Ed25519 seed/private key hex: ' PIPELOCK_RELEASE_PRIVATE_KEY_HEX
   echo
   printf '%s\n' "$PIPELOCK_RELEASE_PRIVATE_KEY_HEX" | \
     go run ./cmd/pipelock-release-manifest \
       -sign-only \
       -manifest ./release.json \
       -private-key-stdin
   unset PIPELOCK_RELEASE_PRIVATE_KEY_HEX
   ```

4. If signing happened on a separate offline machine, transfer the generated
   `release.json.sig` off it on removable media. Upload the signature from a
   networked machine to the same release assets as `release.json`.

5. Confirm the release contains both files:

   ```bash
   gh release view v3.4.0 --json assets --jq '.assets[].name' | sort
   ```

The client verification path is unchanged: `pipelock update` downloads
`release.json` and `release.json.sig`, verifies the Ed25519 signature against
the embedded public keyring, then checks the archive hash pinned inside the
signed manifest. A release without `release.json.sig` fails closed.
