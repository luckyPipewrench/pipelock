# Reproducible Builds

Pipelock tests that the open-source `pipelock` binary builds byte-for-byte
identically when the source tree, dependencies, Go toolchain, target, and build
metadata are held constant.

Run the check from the repository root:

```bash
make reproducible-build-check
```

The check builds `./cmd/pipelock` twice in separate output paths and compares
the resulting files with `cmp`. It uses:

- `CGO_ENABLED=0`;
- `-trimpath` to remove local source paths;
- `-buildvcs=false` to avoid embedding checkout-specific VCS metadata;
- the current commit timestamp instead of the wall clock;
- fixed version, commit, and Go-version linker values.

Success prints the shared SHA-256 digest:

```text
reproducible-build: OK sha256:<digest>
```

CI runs this check on pull requests, and the release workflow runs it again
before GoReleaser publishes artifacts. GoReleaser uses the same stable build
inputs and normalizes archive member timestamps to the source commit time.
Release CI pins the Go toolchain version.

## Scope

This check proves repeatability for the open-source `pipelock` binary on the
current CI target. Reproducing an official release artifact also requires the
same tagged source, dependency graph, Go version, target OS and architecture,
build tags, and public linker inputs. Signatures and attestations are separate
artifacts and are not expected to have identical bytes.

The Enterprise build embeds deployment-independent public verification keys
provided by release CI. Reproducing that binary requires the same public linker
inputs; private signing material is never embedded in the binary.

See [`scripts/check-reproducible-build.sh`](../scripts/check-reproducible-build.sh)
and [`.goreleaser.yaml`](../.goreleaser.yaml) for the executable build contract.
