# Publishing a permanently verifiable playground replay

A live playground session and a published replay have different lifecycles.
The live session uses a short-lived delegated signing key. Its root-signed
delegation expires so that a copied live signing credential stops being useful.
That expiry is a required live-session control: normal `verify-run` continues to
reject an expired delegation.

A published replay is different. It is a sealed, public record, not a signing
credential. A replay that cannot be re-verified after its live delegation
expires does not provide durable evidence.

## Decision

Published replay archives use an explicit, root-signed replay archive
authorization. It binds the published root identity, run nonce, immutable image
digest, signed launch-manifest hash, and hash of the exact delegation artifact.
Archive verification authenticates every one of those bindings and the
delegation signature, but deliberately does not evaluate the delegation's live
time window. The verifier prints that it used archive semantics.

The authorization is separate from the delegation. It grants no signing power,
cannot start a session, cannot extend a delegation, and cannot turn an ordinary
live bundle into an archive by adding a field. The durable root must sign the
authorization after the run is sealed. The verifier's `--archive` invocation is
necessary but not sufficient: without a valid authorization for the exact
artifacts it fails closed.

This rejects the other available shapes:

- A bare archive switch would let a verifier ignore expiry for any live bundle.
- A long-lived delegation would create a long-lived signing credential.
- A direct-root manifest would restore the legacy key-distribution shape that
  delegated signing removed.
- Removing downloadable replays would discard the durable, offline evidence
  visitors need to inspect independently.

## Produce the replay

Start with a sealed run directory. Verify it normally before its delegation
expires; that confirms the live-session path. Then use the trusted publisher
environment, where the durable root is already protected, to create a new
archive and optional operating-system kits:

```bash
go run ./cmd/pipelock-playground-broker archive-replay \
  --run-dir /path/to/sealed-run \
  --output /path/to/replay-bundle.tar.gz \
  --orchestrator-key-file /path/to/protected-root \
  --kit-output-dir /path/to/verify-kits \
  --linux-verifier /path/to/pipelock-verifier-linux \
  --macos-verifier /path/to/pipelock-verifier-macos \
  --windows-verifier /path/to/pipelock-verifier-windows.exe
```

The root is read only by the publisher. The command never writes it into the
bundle or prints it. It refuses to overwrite output paths, verifies the archive
before writing it, and creates kits only when all three verifier binaries are
supplied. The generated archive contains
`replay-archive-authorization.json`; the generated kits include that file and
use archive verification visibly in their scripts.

Do not use `archive-replay` for an ordinary visitor download. Live downloads
must continue to use `ArchiveRunForDownload` and strict `verify-run` semantics.

## The browser verifier decides for itself, and why that is safe

The published bundle has two consumers, not one. The downloadable kits run the
command-line verifier, where `--archive` is an explicit choice. The viewer's
"Verify in your browser" button runs the WebAssembly verifier, which has no
flags and serves both a live session bundle and the published archive from the
same entry point.

So that path selects on whether a replay archive authorization is present, and
verifies it in full when it is. A bundle without one takes the strict path and an
expired delegation still fails closed there.

That is not a bundle choosing its own leniency. The authorization is a root
signature over this run's exact manifest hash, delegation bytes, run nonce and
image digest, so only the holder of the published root can produce one, and an
authorization lifted from another run fails its binding check. An attacker
cannot mint leniency; at most they can present a genuine root-authorized run,
which is what the archive is for. Keep both surfaces in step: a change that
teaches one of them archive semantics and not the other leaves a visitor with a
kit that passes and a button that fails on a single artifact.

## Verify before publishing

Extract the proposed archive and run the public verifier against the pinned
published root:

```bash
tar xzf replay-bundle.tar.gz
go run ./cmd/pipelock-verifier verify-run pipelock-session \
  --orchestrator-key <published-public-key> \
  --archive
```

Success prints `archive mode: root-authorized permanent replay; delegation time
window intentionally not evaluated` before `result: VALID`. That line is part
of the evidence: a reader must be able to distinguish archive semantics from a
currently live session.

Also run the same command **without** `--archive`. Once the delegation has
expired it must fail at `orchestrator-delegation`; that proves the live path has
not been weakened. Finally, remove or alter
`replay-archive-authorization.json` in a disposable copy and rerun with
`--archive`; it must fail at `replay-archive-authorization`.

The published public key is the only trust root. Never accept a root key from a
replay bundle, a kit, or an archive authorization.
