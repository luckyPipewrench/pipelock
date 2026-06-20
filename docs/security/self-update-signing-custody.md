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

## Offline Signing Runbook

1. On a networked machine, download `release.json` from the draft GitHub release,
   then transfer it to the offline signing machine on removable media. The signing
   machine stays air-gapped and never connects to the network.

2. Unlock the offline release signing key from USB `PIPELOCK-KEYS2`, using the
   same custody handling as the license signer.

3. Sign the manifest:

```bash
read -rsp 'release Ed25519 seed/private key hex: ' PIPELOCK_RELEASE_PRIVATE_KEY_HEX
echo
go run ./cmd/pipelock-release-manifest \
  -sign-only \
  -manifest ./release.json \
  -private-key-hex "$PIPELOCK_RELEASE_PRIVATE_KEY_HEX"
unset PIPELOCK_RELEASE_PRIVATE_KEY_HEX
```

4. Transfer the generated `release.json.sig` off the signing machine on removable
   media, then from a networked machine upload it to the same release assets as
   `release.json`.

5. Confirm the release contains both files:

```bash
gh release view v2.8.1 --json assets --jq '.assets[].name' | sort
```

The client verification path is unchanged: `pipelock update` downloads
`release.json` and `release.json.sig`, verifies the Ed25519 signature against
the embedded public keyring, then checks the archive hash pinned inside the
signed manifest. A release without `release.json.sig` fails closed.
