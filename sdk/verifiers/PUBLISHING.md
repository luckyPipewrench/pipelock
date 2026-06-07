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

## Automating publish on release tag (recommended next step)

Once both names exist (from the first manual publish above), wire publishing into
the release flow so a version tag ships the verifiers automatically:

- **crates.io:** configure Trusted Publishing for `pipelock-verifier-rs` (GitHub
  OIDC) so a release workflow with `id-token: write` publishes with no stored
  token.
- **npm:** configure the trusted publisher for `@pipelock/verifier-ts` and
  publish with `npm publish --provenance` (signed provenance, no stored token).

Gate the publish job on the `Verifiers` conformance workflow being green for the
tagged commit. This keeps "tag a release → verifiers ship" hands-off and
secret-free.

**Release hardening (do this when wiring the workflow):**

- Bind the trusted publisher to the **exact** repo + workflow file + ref pattern
  (`refs/tags/v*`); don't trust the whole repo or arbitrary branches.
- Grant `permissions: id-token: write` **only** on the publish job, not workflow-wide.
- Restrict who can push `v*` tags (protected tags / ruleset) — a tag is the trigger.
- Use a GitHub **Environment** with a required reviewer for the publish job, at
  least for the first few releases, so a tag can't auto-ship unreviewed.
- npm: publish with `--provenance` so each release carries a signed build
  attestation tied to the workflow.

## Related: GitHub Action `verify` mode

Documenting a `verify` mode on the existing security-scan Action (so a consumer's
CI can gate on a verifying receipt) is a **separate follow-up** — it does not add
a new Action, and it is not part of the distribution work above.
