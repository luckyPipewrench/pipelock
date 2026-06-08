# Publishing the reference verifiers

The TypeScript and Rust reference verifiers under `sdk/verifiers/` are published
so third parties can install a Pipelock receipt verifier with one command:

| Language   | Registry  | Package                  | Install                              |
| ---------- | --------- | ------------------------ | ------------------------------------ |
| TypeScript | npm       | `@pipelock/verifier-ts`  | `npm install -g @pipelock/verifier-ts` |
| Rust       | crates.io | `pipelock-verifier-rs`   | `cargo install --locked pipelock-verifier-rs` |
| Python     | PyPI      | `pipelock-verify`        | `pip install pipelock-verify` (separate repo) |
| Go         | —         | `cmd/pipelock-verifier`  | built from this repo / release binaries |

**Target: publish automatically when a release is tagged.** The goal is that
cutting a Pipelock release also ships the verifiers, with no passwords stored in
the repository (GitHub OIDC "trusted publishing" to both registries). Until that
is wired, and to claim each package name the first time, use the one-time manual
steps below.

> Why automate: the Python verifier (`pipelock-verify`) was published once by
> hand and then fell behind the receipt format because nobody re-ran the manual
> step each release. Auto-publish-on-tag removes that drift risk.

## One-time account setup

You only do this once per registry.

### npm (`@pipelock/verifier-ts`)

1. Create / sign in to an npm account at <https://www.npmjs.com>.
2. Create the **`pipelock` organization** (the `@pipelock` scope) at
   <https://www.npmjs.com/org/create>. The first publish under the scope needs
   the org to exist and you to be a member. (Scoped packages publish as
   **public** because `publishConfig.access` is set to `public` in
   `package.json` — without that, scoped publishes default to private/paid.)
3. On the machine you publish from: `npm login`.

### crates.io (`pipelock-verifier-rs`)

1. Sign in to <https://crates.io> with GitHub.
2. Go to <https://crates.io/me>, create an API token, then run
   `cargo login <token>` once on your machine.
3. The **first** `cargo publish` claims the crate name `pipelock-verifier-rs` for
   your account. There is nothing to pre-reserve.

## Before every publish

1. **Version alignment.** Bump the package version to track the receipt schema
   it verifies. Both packages currently verify Audit Packet v0 + ActionReceipt
   v1 + EvidenceReceipt v2 (spanned). Keep `package.json` `version` and
   `Cargo.toml` `version` in lockstep with each other and with the receipt
   format they support; do not publish a verifier that cannot verify the current
   receipts.
2. **Conformance must be green.** The cross-language conformance gate
   (`.github/workflows/verifiers.yaml`) must pass on the commit you publish from.
   The published source must be the in-repo verifier — always publish from a
   clean checkout via the build/publish commands below; never hand-edit a package
   after building. (Note: registries don't pin a consumer's transitive deps for
   you — npm `install` ignores `package-lock.json`, and `cargo install` only uses
   the packaged `Cargo.lock` with `--locked`, which the install docs use.)
3. **Rust schema drift guard.** `sdk/verifiers/rust/audit-packet-v0.json` is a
   vendored copy of `sdk/audit-packet/v0.json` (the crate must be self-contained
   for `cargo publish`). If the canonical schema changed, re-vendor and commit:
   ```bash
   cp sdk/audit-packet/v0.json sdk/verifiers/rust/audit-packet-v0.json
   ```
   The `Schema vendor drift guard` CI step fails the build if these diverge.

## Publish: TypeScript → npm

```bash
cd sdk/verifiers/ts
npm ci
npm test                     # build + run the full suite
npm publish --dry-run        # inspect tarball contents; confirm dist/ + v0.schema.json present
npm publish                  # the real publish (prepack rebuilds; publishes as public)
```

Verify: `npm view @pipelock/verifier-ts version` shows the new version, and
`npm install -g @pipelock/verifier-ts@<version>` then
`pipelock-verifier-ts receipt <file> --key <hex>` works.

## Publish: Rust → crates.io

```bash
cd sdk/verifiers/rust
cargo test --release
cargo package --list         # confirm audit-packet-v0.json is in the package
cargo publish --dry-run      # builds the packaged crate in isolation
cargo publish                # the real publish
```

Verify: the crate appears at <https://crates.io/crates/pipelock-verifier-rs>, and
`cargo install --locked pipelock-verifier-rs` builds and runs offline.

## Ordering note

The README install lines (`npm install -g …` / `cargo install …`) only become
true once the publish succeeds. Publish first, then merge / release the docs that
point at the published packages, so the public docs are never ahead of reality.

## Auto-publish on release tag

`.github/workflows/publish-verifiers.yaml` publishes both verifiers automatically
when a `verifier-v*` tag is pushed (e.g. `verifier-v0.1.1`). The verifiers version
independently of pipelock, so a pipelock `v*` release tag does NOT trigger it.
Authentication is OIDC trusted publishing on both registries: no npm or crates.io
tokens are stored in the repository. `workflow_dispatch` runs the build/verify path
only (a dry run) by default. Real publishes always require an immutable
`verifier-v*` tag: pushing the tag publishes, and a manual dispatch only publishes
when it is run from a `verifier-v*` tag with "Dry run" unchecked (a dispatch from a
branch only ever runs the build/verify job).

### One-time setup

Do this once, after the first manual publish. A trusted publisher can only be
configured on a package/crate that already exists.

GitHub environment (gates real publishes behind a human approval): repo Settings,
Environments, create `verifier-release`, add yourself as a Required reviewer. The
two publish jobs already declare `environment: verifier-release`, so each real
publish waits for your approval. Without a reviewer the environment exists but does
not gate.

npm (`@pipelock/verifier-ts`): package page, Settings, Trusted Publisher, add a
GitHub Actions publisher with:

- Organization or user: `luckyPipewrench`
- Repository: `pipelock`
- Workflow filename: `publish-verifiers.yaml` (filename only, not a path)
- Environment: `verifier-release`
- Allowed actions: `npm publish`

crates.io (`pipelock-verifier-rs`): crate page, Settings, Trusted Publishing, add
a GitHub publisher with:

- Repository owner: `luckyPipewrench`
- Repository name: `pipelock`
- Workflow filename: `publish-verifiers.yaml`
- Environment: `verifier-release`

### Cutting a release

1. Bump the version in `sdk/verifiers/ts/package.json` and `sdk/verifiers/rust/Cargo.toml` (keep them in lockstep; re-vendor the schema if the canonical one changed) and merge it.
2. Tag and push: `git tag verifier-v0.1.1 && git push origin verifier-v0.1.1`.
3. The `build` job runs the tests and verification builds, then the two publish jobs wait for your environment approval and publish both packages. No tokens.

Try it first with the `workflow_dispatch` dry run (Actions, Publish verifiers, Run
workflow, leave "Dry run" checked): it runs only the unprivileged `build` job (tests
plus `npm pack` and `cargo package`), so the path is exercised without publishing or
minting any registry credential.

### Hardening (built into the workflow)

- OIDC only; no `CARGO_REGISTRY_TOKEN` / `NODE_AUTH_TOKEN` stored. npm emits build provenance where supported for a public repo + public package.
- All third-party code (dependency install scripts, test suites, the TS build, the Rust verification build) runs in the unprivileged `build` job, which has no `id-token` and cannot mint a publish credential. The `id-token: write` publish jobs run no dependency or build code: `publish-npm` uploads the tarball already packed by `build` (no `npm ci`, no prepack), and `publish-crates` uses `cargo publish --no-verify` (no dependency or build-script compilation).
- Both publish jobs run in the `verifier-release` environment, so a required reviewer gates every real publish.
- The crates publish job re-checks schema drift before publishing.
- Recommended: restrict who can push `verifier-v*` tags (protected tags / ruleset). The tag is the trigger.

## Related: GitHub Action `verify` mode

Documenting a `verify` mode on the existing security-scan Action (so a consumer's
CI can gate on a verifying receipt) is a **separate follow-up** — it does not add
a new Action, and it is not part of the distribution work above.
