# `pipelock update`

Update Pipelock to the latest verified release (alias: `pipelock upgrade`).

`pipelock update` checks GitHub Releases for a newer build, downloads the
archive for the current OS/architecture, verifies it, and atomically replaces
the running binary in place. The previous binary is saved next to the new one
as `<binary>.bak` so a bad update can be rolled back.

The command is **fail-closed**: any failure in the verification chain aborts
the update and leaves the installed binary untouched.

## Usage

```bash
pipelock update              # interactive update to the latest release
pipelock update --check      # report current vs latest; change nothing
pipelock update --yes        # update without the confirmation prompt
pipelock update --version v2.7.0   # install a specific release tag
pipelock update --rollback   # restore the previous binary from <binary>.bak
pipelock update --json       # machine-readable status
pipelock update --insecure-skip-signature   # checksum-only fallback if cosign is unavailable
```

## Flags

| Flag | Description |
|------|-------------|
| `--check` | Report the current and latest versions and whether an update is available. Makes no changes. Exits 0. |
| `--version <vX.Y.Z>` | Target a specific release tag instead of the latest. |
| `--yes`, `-y` | Skip the interactive confirmation prompt. |
| `--rollback` | Restore the previous binary from the `.bak` backup saved by a prior update. |
| `--json` | Emit machine-readable JSON status (consistent with `doctor` / `keys`). |
| `--insecure-skip-signature` | Allow checksum-only update when `cosign` is unavailable. Publisher identity is not verified; use only for explicit recovery. |

## Verification chain

Every step below must succeed; **any failure aborts the update with the
installed binary unchanged**:

1. **Resolve the release.** Fetch `releases/latest` (or `releases/tags/<tag>`
   with `--version`) from the GitHub API for `luckyPipewrench/pipelock`. The
   HTTP client honors `HTTPS_PROXY` / `HTTP_PROXY` from the environment, so the
   updater works inside a contained Pipelock deployment.
2. **Publisher authenticity.** Download `checksums.txt` plus its
   keyless cosign signature (`checksums.txt.sig`) and certificate
   (`checksums.txt.pem`).
   - If a `cosign` binary is on `PATH`, run `cosign verify-blob` pinned to the
     GitHub Actions OIDC issuer (`https://token.actions.githubusercontent.com`)
     and the `luckyPipewrench/pipelock` release workflow identity for the
     target tag. If it fails, the update **aborts**.
   - If `cosign` is **not** on `PATH`, the update **aborts** by default before
     any binary replacement. Passing `--insecure-skip-signature` changes this to
     checksum-only mode and prints a warning. See the caveat below.
3. **Integrity.** Download the release archive
   (`pipelock_<version>_<os>_<arch>.tar.gz`, or `.zip` on Windows), compute its
   SHA256, and require an **exact match** to the entry in `checksums.txt`. A
   mismatch aborts the update.
4. **Extract.** Extract only the `pipelock` binary from the archive into a temp
   file in the **same directory** as the target binary (so the final rename is
   atomic on one filesystem). Archive entries are validated: any entry with a
   `..` traversal segment or an absolute path is rejected (zip-slip /
   tar-traversal protection).
5. **Version check.** Run `<new binary> --version` and confirm it reports the
   expected target version. A mismatch aborts and deletes the temp file.
6. **Install.** Back up the current binary to `<binary>.bak` (overwriting any
   prior backup), then atomically rename the verified temp binary into place.
   On Linux, renaming over a running executable is allowed. If the rename fails,
   the binary is restored from the backup.

### Authenticity caveat (cosign)

Publisher-signature verification depends on a `cosign` binary being present on
`PATH`. When it is absent, the updater fails closed by default. If you pass
`--insecure-skip-signature`, the updater still enforces the SHA256 checksum
match (integrity) but **cannot prove publisher identity**. Use that fallback
only for an explicit recovery flow, or verify the release artifacts manually.

## Rollback

`pipelock update --rollback` restores `<binary>.bak` over the current binary
using the same atomic rename. If no backup exists, it reports a clear error.

## Privileged install paths

Before making any change, the updater checks that the target binary **and its
directory** are writable by the current user. If Pipelock is installed to a
root-owned location (for example `/usr/local/bin`), the update aborts early with
a message to re-run with appropriate privileges (for example via `sudo`). The
update is never partially applied.

## Unsupported platforms

If there is no published archive for the current OS/architecture, the command
reports a clear error and makes no changes. Supported targets follow the release
matrix (Linux and macOS on amd64/arm64; Windows archives are `.zip`).
