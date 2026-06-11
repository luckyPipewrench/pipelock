# Changelog

All notable changes to Pipelock will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.7.0] - 2026-06-10

### Highlights

The arc of v2.7 is **receipts you can actually rely on, on by default**. The flight recorder is now enabled out of the box, so a stock install produces signed, verifiable evidence instead of nothing; receipt verification is **safe by default** (an unpinned `verify-receipt` is structural-only and exits non-zero unless you pass `--allow-unpinned`); a signing-key rotation no longer bricks the chain (it opens a linked, offline-verifiable segment); every receipt is bound to its process run by a signed `run_nonce` to defeat replay; A2A block paths emit receipts for transport parity; and `flight_recorder.require_receipts` lets an operator make an allow-path receipt a fail-closed precondition for egress.

The second headline is **Conductor reaches GA**: the enterprise fleet control plane (signed policy-bundle distribution, a per-org/fleet/instance signed-evidence audit sink, and fleet-wide enrollment / remote kill / policy rollback over mTLS + SPIFFE) ships with the operator command surface and documentation to run the whole lifecycle with shipped tooling — generate the fleet keys, build a signed trust roster, provision PKI, deploy, enroll followers, **publish a signed policy, push and clear a fleet-wide kill, roll back a bad bundle, list followers, query the audit sink**, and verify evidence offline. Stale-policy fail-closed now enforces at runtime: a follower that loses contact with Conductor past the grace window under `strict_deny_all` denies all traffic via an independent kill-switch source. Followers enforce locally and stay fail-closed; Conductor holds no agent secrets and never scans on their behalf, and every fleet command fails closed without an Enterprise license granting the `fleet` feature.

### ⚠️ Breaking Changes / Upgrade Notes

- **`verify-receipt` without `--key` now exits non-zero.** Unpinned verification is structural-only and no longer reads as success — this applies to `pipelock verify-receipt`, the standalone `pipelock-verifier`, and every language SDK verifier. **Migration:** any script or CI step that calls a verifier without pinning a key must either pass the trusted signer key with `--key` (preferred — that is what makes the verification mean something) or pass `--allow-unpinned` to explicitly accept the structural-only check. (#726)
- **Flight recorder defaults to enabled.** Existing configs are unaffected (recording stays inert until a `dir` and signing key exist), but a fresh `pipelock init` now provisions both, so new installs produce signed evidence on disk by default. Set `flight_recorder.enabled: false` to opt out. (#728)
- **Key-free capture is DLP-redacted by default.** `pipelock run --capture-output` and `pipelock mcp proxy --capture-output` now honor `flight_recorder.redact` and redact by default before writing key-free evidence. **Migration:** if you intentionally consume raw capture payloads, set `flight_recorder.redact: false` and protect the capture directory as raw evidence. (#696)
- **Receipts now carry a `run_nonce`.** The field is additive: receipts emitted before this release (no `run_nonce`) still verify. (#729)
- **`conductor serve` now requires `--auditor-org` and `--admin-org`.** Operator read tokens are now scoped to an org (optionally a fleet via `--auditor-fleet` / `--admin-fleet`): an unscoped auditor or admin token could read audit evidence and the follower roster across *every* org, a cross-tenant read bypass on the `/audit` and new `/followers` endpoints. Scope is now mandatory and a deployment that omits it **fails closed at startup** rather than serving cross-org reads. **Migration:** add `--auditor-org <org>` and `--admin-org <org>` (plus an optional `--auditor-fleet` / `--admin-fleet`) for each configured read token on every `conductor serve` invocation. (#740)

### New Features

- **Conductor — the enterprise fleet control plane — is GA.** Conductor was an enterprise preview in v2.6; v2.7 promotes it to General Availability with the full operator command surface and user documentation. It distributes signed policy bundles to follower instances, ingests and stores their signed evidence in a per-org/fleet/instance audit sink (`pipelock fleet-sink`), and coordinates fleet-wide enrollment, remote kill, and policy rollback over mutually-authenticated (mTLS, SPIFFE-identified) connections. Followers enforce locally and stay fail-closed; Conductor holds no agent secrets and never scans on their behalf. Every fleet server command (`conductor serve`, `conductor bootstrap`, `fleet-sink`) verifies an Enterprise license granting the `fleet` feature and fails closed before binding a listener or writing a file; follower runtimes also tear down Conductor fan-out on proven license revocation or expiry while free detection keeps running (restart-only re-activation). New [Conductor guide](docs/guides/conductor.md), [production runbook](docs/guides/conductor-production-runbook.md), [`pipelock license` reference](docs/cli/license.md), and the [audit-sink design](docs/specs/pipelock-conductor-audit-sink.md) cover the GA surface.
- **Conductor operator command surface — publish, emergency control, and observability.** v2.7 ships the day-2 management CLIs that turn the control plane into a manageable fleet, all Enterprise-gated and driven over mTLS with file-mounted operator tokens:
  - **`pipelock conductor publish`** builds, signs, and POSTs a policy bundle from a follower config (`--config`), with a monotonic `--validity` window, `--org`/`--fleet`/`--env`/`--audience` addressing, an optional `--previous-bundle-hash` continuity pin, and a policy-bundle-signing `--signing-key`, authorized by `--publisher-token-file`. (#738)
  - **`pipelock conductor kill` / `resume`** push and clear a signed, time-bounded (`--ttl`, capped by the server's `--remote-kill-max-validity`) fleet-wide kill, addressed by `--org`/`--fleet`/`--instance` and signed by a remote-kill key; followers honoring the kill switch fail closed within one poll and recover on resume. **`pipelock conductor rollback`** authorizes a signed revert from `--current-bundle-id`/`--target-bundle-id` under the rollback key. **`pipelock conductor enrollment-token mint`** issues a single-use enrollment token for an approval-gated follower join. (this PR)
  - **`pipelock conductor fleet status` / `fleet followers`** list enrolled instances (identity, audit key, active state, enrollment time) and **`pipelock conductor audit query`** queries the audit sink's metadata, both org/fleet-scoped via the new audience-scoped `/followers` read endpoint and an org-scoped operator read token. (#740)
  - **Stale-policy fail-closed now enforces at runtime.** A follower with Conductor enabled re-evaluates its active bundle each poll interval and, under `strict_deny_all`, engages an independent `conductor_stale` kill-switch source — denying ALL traffic across every transport (forward, CONNECT, WebSocket, MCP) — once the bundle is missing, unreadable, or past its grace window, recovering only when a fresh in-grace bundle applies. The `conductor_stale` source is OR-composed and independent of the remote-kill source: clearing one does not clear the other. On proven license revocation or expiry, teardown under a strict policy engages the same fail-closed source *before* the enforcer's ticker stops, closing the teardown fail-open window; under `continue_last_known_good` the follower keeps serving its last applied bundle. This closes the gap the runbook previously described as pending. (this PR)
- **Conductor operator workflow — keys, provisioning, and the production lifecycle.** Release readiness is the deploy *and* the day-2 manage. The fleet's signing-key roles (`policy-bundle-signing`, `remote-kill-signing`, `policy-bundle-rollback`, `audit-batch-signing`, plus the reserved `trust-root-rotation` / `enrollment-token-signing`) are generated with `pipelock signing key generate --purpose <role>`, composed into a signed trust roster with `pipelock signing roster build` (which a follower pins by root fingerprint), and the public halves are wired into `conductor serve` as `inline=` trusted keys. Rollback, remote-kill, and trust-root-rotation are flagged as threshold roles. A documented **bring-your-own-PKI recipe** (cert-manager CA `ClusterIssuer` issuing the auto-renewing Conductor server cert and per-follower client certs whose SPIFFE URI SAN is the fleet identity) provisions production mTLS without hand-rolled OpenSSL. The new [Conductor production runbook](docs/guides/conductor-production-runbook.md) walks the lifecycle end to end with filled-in shipped commands (generate → provision → deploy → enroll → publish → kill/rollback → fleet status → audit query → rotate → verify offline) and documents the stale-policy fail-closed enforcement and its license-teardown behavior.
- **`pipelock baseline` operator ratification surface.** Adds a free-tier live admin API and CLI for behavioral-baseline profiles: `list` shows profile states and pending ratifications, `show <agent>` displays learned per-dimension ranges plus retained/observed/trimmed session counts, `ratify <agent>` transitions a pending profile to `locked` and enforcement starts immediately in the running manager, and `forget <agent>` deletes the persisted profile and returns the agent to observe/relearn. The baseline endpoints use the existing authenticated admin API token and are mounted only on the dedicated admin API listener, not the agent-facing proxy port, so an agent cannot self-ratify a poisoned baseline.
- **Recorder signing public-key export.** `pipelock signing pubkey` prints the
  64-hex Ed25519 public key for the configured flight-recorder signing key
  (`--config`, with normal config discovery) or a direct private key file
  (`--key-file`), and `--out` writes the public key sidecar with 0640
  permissions. `pipelock init` and `pipelock contain install` now create or
  refresh `<flight_recorder.signing_key_path>.pub` without rotating the private
  key, so operators have a clean key-handoff path for external receipt
  verification.
- **`pipelock contain` runtime contract + `pipelock contain doctor`.** `install` now provisions a complete, proxy-correct runtime contract for the contained agent so common tooling works out of the box instead of dying with a generic network error: the full proxy + CA environment matrix (upper- and lower-case `*_PROXY`, `NO_PROXY` including IPv6 `::1`, and per-ecosystem CA trust — `SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` / `CURL_CA_BUNDLE` / `GIT_SSL_CAINFO` / `CARGO_HTTP_CAINFO` / `PIP_CERT` / `NODE_EXTRA_CA_CERTS`) injected across every contained-agent exec path (`plk-launch`, an agent-scoped `/etc/profile.d` login-shell script, and the wrappers); a node undici proxy shim loaded via `NODE_OPTIONS=--require` so node's built-in `fetch()` honors `HTTPS_PROXY`; known-good `pipelock-curl` / `pipelock-python` / `pipelock-node` wrappers on the agent PATH that force the contract even when the caller's environment is incomplete; and per-tool proxy + CA config for `git` / `npm` / `pip` / `cargo` written into the agent home so config-reading tools are correct on every invocation. The new `pipelock contain doctor` runs live checks — gateway health, curl/python/node through the proxy, clean DNS-failure behavior, and a raw direct-egress diagnostic — and reports per-check remediation tagged with one of four block classes (`policy`, `proxy-compat`, `local-context`, `infra`) so a proxy-incompatible tool reads as "use a wrapper," not "the agent is broken." This makes compatible tooling work without widening egress; direct proxy-bypassing connections from the agent stay blocked by the nftables owner-match rule.
- **Enterprise Eval self-service fulfillment (license service).** The license service mints a 60-day, non-renewing Enterprise Eval license on a *paid* order webhook — after re-fetching the order from the billing provider and validating paid state, a product allowlist, and the exact expected amount and currency — and never on the unpaid order-created event. A full or partial refund revokes the eval through the signed CRL; a refund that arrives before payment records a pending revocation and blocks any later (stale) mint. Webhook deliveries are de-duplicated by provider message id with safe retry, and a failed delivery email resends the *same* token rather than re-minting or restarting the evaluation window. One active eval per customer email (matched on a single canonical email normalization). The Enterprise Eval is a distinct tier carrying the same fleet capability as Enterprise, time-boxed to the evaluation window; the delivery email is rendered from an auto-escaping HTML template.
- **EvidenceReceipt v2 source-span verification across languages.** TypeScript, Rust, and Python verifiers now accept `proxy_decision_with_spans` EvidenceReceipt v2 receipts with RFC 8785/JCS preimages, Ed25519 verification against a pinned key, strict unknown-field rejection, versioned `pipelock-transform-vN` transform profiles, and source-span validation for HMAC commitments. The shared spanned receipt fixture covers valid verification, tamper rejection, unknown-field rejection, and the no-offline-oracle commitment boundary.
- **`pipelock-verifier` verifies EvidenceReceipt v2 chains.** The standalone verifier now verifies EvidenceReceipt v2 evidence (learn-and-lock `shadow_delta`, `proxy_decision`, and contract-lifecycle receipts), so an auditor or SIEM can verify shadow-rollout evidence offline without the source tree. The `receipt` and `chain` subcommands version-detect v1 ActionReceipts from v2 EvidenceReceipts by `record_type`, and `evidence` aliases `chain`. v2 chain verification recomputes the hash chain (`chain_seq` monotonicity, genesis root, `chain_prev_hash` linkage) and verifies every signature against a pinned `--key`; without `--key` it confirms structure, signer-id consistency, and hash linkage only and reports `signatures_verified: false`, because a detached signature cannot prove provenance without an out-of-band key. `--expect-signer-id`, `--expect-contract`, `--expect-manifest`, and `--expect-payload-kind` bind a chain to known values on every receipt. v1 paths now report `signatures_verified` consistently (true only when a key is pinned and verification passed). v2 receipt parsing rejects duplicate JSON keys to prevent parser-differential smuggling.
- **Key-free MCP evidence capture (`pipelock mcp proxy --capture-output`).** The MCP proxy accepts `--capture-output DIR` (and `--capture-escrow-public-key` for payload-sidecar encryption), mirroring `pipelock run --capture-output`. It writes `evidence-*.jsonl` for DLP, injection, tool-policy, and CEE verdicts **without a signing key**, across every MCP transport (stdio, sandbox-stdio, streamable-HTTP, HTTP-reverse, WS-listener). Previously MCP evidence flowed only through the signed receipt emitter, which is nil unless a signing key loads, so with the recorder on and no key the evidence directory stayed empty on every OS. The async capture writer is drained on shutdown (the standalone proxy has no server-cleanup hook, so it closes the writer on exit). (#696)
- **`pipelock skill-scan` static skill review.** Adds a free-tier command that inventories local agent skill files, writes and compares a diffable skill lock, and delegates hidden-Unicode detection to `pipelock scan`. Source-to-sink combinations are scoped to executable context only (fenced code blocks and scanned script files; prose, tables, and blockquotes are never read as commands) and require the source and sink to co-occur in the same region within a small line window, so causally unrelated mentions are not paired. Findings are tiered by what the scanner can prove: HIGH for provable drift, referenced-file tamper, unscanned oversize files, and direct single-command transfers with an obvious pipe or upload/payload argument; MEDIUM/LOW and honestly named (`*-cooccurrence`) for advisory co-occurrence; hidden-Unicode findings inherit their severity from `pipelock scan` and are reported in normal scans plus baseline/update so a hidden instruction is never silently baselined. The default `--min-severity` is `high`, so a first run gates only on provable issues. Combos carry a stable 128-bit fingerprint; an operator-owned lock baselines existing combinations (only newly introduced ones surface) and an allowlist suppresses exact fingerprints with a required justification and optional expiry, reporting stale entries. `file:line` evidence on every finding.
- **Per-run nonce binds every receipt to one process run (replay defense).** Each action receipt now carries a `run_nonce` generated once per process start and folded into the signed preimage, so a receipt cannot be lifted from one run and replayed as evidence of another — the nonce is part of what the signature commits to. The nonce is canonicalized identically across the Go reference and the TypeScript, Rust, and Python verifiers, and the cross-language conformance corpus gains a run-nonce-bound golden plus a tampered-nonce malicious vector so a verifier that ignores the field fails the release. Receipts emitted before this change (no `run_nonce`) still verify, so the field is additive. (#729)
- **`flight_recorder.require_receipts` makes allow-path receipts fail-closed.** Receipt emission is best-effort by default (evidence, not enforcement). Set `require_receipts: true` to make an allow-path receipt a precondition for forwarding: pipelock emits the allow receipt **before** the request leaves the proxy, and if that emission fails it blocks with `receipt_emission_failed` instead of egressing — enforced on every egress transport (forward, CONNECT, WebSocket, `/fetch`, MCP stdio, MCP HTTP). Block-path receipts stay best-effort because the action is already denied. The knob needs a live signed recorder (`enabled` + `dir` + `signing_key_path`); `pipelock run` and `pipelock mcp proxy` refuse to start with `require_receipts` on and no recorder rather than serve an all-blocked proxy, and enabling it via hot-reload without a recorder only warns (the recorder is built once at startup). (#730)

### Changed

- **Flight recorder is enabled by default.** `flight_recorder.enabled` now defaults to `true`, so a stock install produces signed, verifiable evidence ("verify the boundary") instead of nothing. The flip is inert on its own: recording still requires a `dir` and a signing key, so `enabled: true` with no `dir` writes nothing and is a startup notice rather than an error, and no existing config breaks. `pipelock init` now provisions a recorder directory and an Ed25519 signing key and writes them into the generated config so receipts are live out of the box; an existing key is reused, never regenerated, so re-running `init` does not orphan the chain. All shipped presets carry a matching `flight_recorder` block, and the default-on footguns are bounded by defaults (rotation at `max_entries_per_file`, `redact: true`). On a clean shutdown the recorder now seals the chain with a `transcript_root` completeness anchor — emitted after in-flight receipts drain — so `verify-receipt --chain` can tell a chain that reached its sealed end from one silently truncated at the tail; a `SIGKILL` or power loss still truncates without a seal and needs an external anchor. (#728)
- **Receipt verification is safe by default.** `pipelock verify-receipt` (and the standalone verifier and every language SDK verifier) no longer reports an unpinned receipt or chain as a plain success. Without `--key`, verification is structural-only — it proves hash linkage and signature self-consistency but not signer provenance — so it prints a loud `UNPINNED` / `CHAIN UNPINNED` banner and **exits non-zero** unless you pass `--allow-unpinned` to acknowledge the reduced guarantee. Pin one or more trusted keys with `--key` (repeatable) to get `OK` / `CHAIN VALID` and exit 0. This closes a footgun where a script treated an unpinned exit-0 as "verified against a trusted signer." (#726)
- **Shadow candidate receipts omit `active_manifest_hash`.** `pipelock learn shadow` no longer stamps the candidate contract hash into `active_manifest_hash`; shadow-delta receipts are bound via `contract_hash` only, because a candidate contract is not yet an active manifest.
- **Key-free capture is DLP-redacted by default, on both HTTP and MCP.** `--capture-output` now plumbs the DLP redactor into the capture writer, gated on `flight_recorder.redact` (default `true`), so captured tool arguments and bodies are scrubbed before they reach disk. Previously the HTTP `pipelock run --capture-output` path passed no redactor and wrote raw payloads regardless of the `redact` knob; set `flight_recorder.redact: false` to opt into raw capture.

### Fixed

- **Receipt chains survive a signing-key rotation instead of bricking.** The v1 action-receipt emitter resumed an on-disk chain by hard-verifying the tail against the *current* signing key, so any legitimate operator key rotation orphaned the chain and failed every subsequent emit. The resume path now distinguishes three cases: a tail signed by the current key resumes the same segment; a tail signed by a different key but self-valid under its own embedded key is treated as a rotation — a **new chain segment** opens, anchored to the prior tail hash with a `KeyTransition` marker so the boundary is provable; a tail whose own signature is invalid still fails closed. Chain verification is now segment-aware (`VerifyChainTrusted` accepts a trusted key per segment), so a rotated chain stays offline-verifiable, and the verifier names the per-segment signer keys for the operator to confirm. A new `pipelock_receipt_emit_failures_total` metric (labeled by reason) and a one-time startup log surface a chain that cannot resume. Re-running `pipelock contain install` now recovers an existing valid signing key before generating a fresh one, so it no longer churns the key and orphans the chain. The same change grants the resolved operator a minimal user-scoped POSIX ACL (read+traverse) on the containment evidence directories so they can verify the receipt chain offline **without sudo** — deliberately not a group ACL, since the contained agent shares the operator's group and must never gain read access to the detection/block evidence policing it; it fails closed (skips with a logged reason) if the operator cannot be resolved. (#725)
- **A2A block paths now emit decision receipts (transport parity).** Two agent-to-agent decision points blocked traffic without recording a receipt, leaving a blocked A2A action with no evidence while every other transport (forward / CONNECT / WebSocket / MCP tools-call) recorded one: the MCP HTTP listener's A2A-Extensions header block, and A2A method body blocks (whose deferred emitter skipped on the empty `ActionID` that A2A methods never set). Both now emit a policy-hash-bearing block receipt — transport stays `mcp_http_listener`, with A2A attribution in the `mcp_a2a_scanning` layer and method — and the body path mints a synthetic action ID only when the request is actually blocked, so clean/allowed A2A and ordinary tools/call behavior are unchanged. (#727)
- **Recorder signing key, license, secrets, CA key, salt, and `--header-file` now load on native Windows (#695).** The fail-closed file-permission gate rejected modes failing a Unix bitmask (`& 0o037`, `& 0o077`, `& 0o137`, `& 0o002`). On Windows, Go derives `FileMode` from the read-only attribute and never reflects the NTFS ACL, so it reports `0666`/`0444` and the gate could never pass — a recorder signing key could not load at all. A new `internal/secperm` package centralizes the check with an OS split: Unix behavior is byte-for-byte unchanged (loose modes still rejected, including the k8s fsGroup `0o040` group-read allowance), and Windows skips the unenforceable mode check. Windows access control must be enforced via NTFS ACLs at deployment time, which Pipelock does not inspect; no `chmod` remediation text surfaces on Windows. A `windows-latest` CI lane now guards the load paths.
- **MCP tool-policy verdicts are captured on the HTTP transport.** The streamable-HTTP MCP input path enforced `mcp_tool_policy` rules but never recorded the verdict to evidence, while the stdio path did — a transport-parity gap surfaced by the key-free capture work. The HTTP path now emits an `mcp_tool_policy` capture entry on a policy match, matching stdio.
- **Response-injection scanner no longer false-positives on security-standards and documentation prose.** The "Hidden Instruction" and "Credential Solicitation" response-injection patterns matched text that *describes* prompt-injection and credential-handling attacks rather than performing them, so fetching a page that merely discusses these attacks (a standards doc, a security guide) could trip an injection block. The patterns now require the directive/marker form (`hidden instruction:` rather than the bare noun) and drop the weak `include` verb that described configuration; a real credential-path directive ("include the .aws/credentials") stays caught. Detection of the actual attack forms is preserved and regression-tested. The same change fixes a seccomp CI test that could hang by adding a per-child timeout. (#737)

## [2.6.0] - 2026-05-30

### Highlights

The headline is **operation-level egress control**. `request_policy` is a new allow-by-default deny/warn safety rail that matches outbound HTTP API *operations* (not just hostnames or DLP content) and blocks the dangerous ones. Operators write rules that match on route (host / effective method / normalized path / content-type) plus the operation extracted from the request body, such as a GraphQL mutation root field. It enforces across every HTTP agent-egress transport (forward, CONNECT, TLS-interception, reverse, fetch, redirect-hop) and per WebSocket text frame, with the upgrade handshake gating route-only rules, recurses into JSON `$batch` envelopes, and fails closed on unparseable or opaque bodies. It composes with the learn-and-lock contract gate and runs before it, so a contract allow can never suppress an operation-policy block. The section is allow-by-default and has no `default_action` knob, so it can never be configured into a default-deny posture by accident.

The second arc is **Hermes**: Pipelock bridges Hermes Agent hook events into the scanner pipeline so a Hermes deployment routes agent activity through Pipelock enforcement. `pipelock hermes install / verify / rollback` plus a `hook` subcommand manage the integration, and `--mode full | mcp-only` selects how much of the agent's surface is wrapped.

Rounding out the release: `pipelock scan` catches invisible-Unicode / bidi prompt injection hidden in agent-context files at rest (the supply-chain half the network proxy never sees); NSA MCP CSI follow-ups add context-leak parameter detection, lethal-trifecta awareness, per-message signing, and replay defense; two new compliance frameworks (NIST AI RMF + HIPAA) bring `pipelock assess` to seven; `dns.host_overrides` adds hostname-scoped static routing; a constrained `reverse_proxy.profile: submit` listener ships with an SSRF-safe dial path; `file_sentry` gains a block-action mode; enterprise license expiry warnings and signed-CRL enforcement are hardened; and CVE-driven `golang.org/x/crypto` (13 SSH fixes) and `golang.org/x/net` (5 HTML-parser fixes) bumps land.

Conductor remains an enterprise preview in v2.6, not a GA feature. User-facing Conductor documentation is deferred to v2.7.

### New Features

- **`request_policy` operation-rails.** An allow-by-default deny/warn safety rail over outbound HTTP API operations, independent of `request_body_scanning` and composing with the learn-lock contract gate (it is neither a DLP scanner nor a behavioral allowlist). Rules match on route (host / effective method / normalized path / content-type, with method-override headers resolved and both base and overridden methods evaluated so a tunneled verb cannot dodge a method-scoped rule) and, optionally, on an extracted **GraphQL** operation predicate matching operation type and resolved root-field names (alias- and fragment-resolved, with every operation in a document or batch evaluated, never just the first). `on_parse_error` and `on_opaque_operation` (each `block` (default) / `warn` / `allow`) drive fail-closed handling: an unparseable body or an opaque request (for example a GraphQL APQ hash with no inline query) is blocked by default rather than silently allowed. Enforced across forward absolute-URI, CONNECT, TLS-interception, reverse, fetch, and redirect-hop, including GraphQL-over-GET query parameters and multipart bodies. WebSocket is enforced per text frame: the upgrade handshake gates route-only rules and each reassembled UTF-8 frame payload is evaluated as an operation body against the live matcher, so a hot-reloaded rule applies to open sockets. JSON `$batch` envelopes are unwrapped and every sub-request is evaluated against the full rule set with the strictest decision winning. Blocks emit a dedicated `request_policy_deny` reason on `X-Pipelock-Block-Reason` with an optional correlated receipt id. (#627, #628, #630, #631, #632, #633)
- **`request_policy` JSON discriminator rules.** An optional discriminator predicate matches a top-level JSON body field against RE2 value patterns with strict fail-closed semantics: invalid JSON applies `on_parse_error`; an absent field is no match; a string value is matched against `value_patterns`; a non-string value, a non-object top-level body, or a duplicated target field is treated as opaque and applies `on_opaque_operation`. It composes with the GraphQL predicate, so a rule carrying both requires both to match, and folds into the canonical policy hash. Evaluated on every HTTP transport (forward, CONNECT, TLS-interception, reverse, fetch, redirect-hop) and per WebSocket text frame. (#634)
- **Hermes Agent integration.** `pipelock hermes` bridges Hermes Agent hook events into the Pipelock scanner pipeline. `install` / `verify` / `rollback` manage the integration idempotently, a `hook` subcommand handles individual hook events, and `--mode full | mcp-only` selects whether the full agent surface or only its MCP traffic is wrapped. Full mode loads, enables, and blocks under a real Hermes runtime. (#605, #607, #610, #629)
- **`pipelock demo` signed action receipts.** The self-contained `pipelock demo` attack walkthrough now emits an Ed25519-signed action receipt for every mediated scenario, binding the detection layer, pattern, and verdict, and verifies each one inline against the demo signing key. `--receipts-dir` writes each receipt plus the public key to disk so a third party can verify them offline with `pipelock-verifier`. The scenario set was refreshed to replace the high-entropy data smuggling scenario with a cloud-metadata SSRF probe (`169.254.169.254`) blocked by the core SSRF layer.
- **`pipelock scan` invisible-Unicode / bidi file injection detection.** New `pipelock scan [paths]` detects hidden Unicode embedded in files at rest: zero-width, bidi-control, tag, and C0/C1 control characters used to inject instructions into agent-context files (CLAUDE.md, .cursorrules, AGENTS.md, skill definitions) that a human reviewer cannot see. This is the local-file half of supply-chain prompt injection; the network proxy never sees files at rest. Detection seeds from the same invisible-character set the scanner strips at runtime, applies a per-rune severity/category policy (a leading BOM or emoji ZWJ in prose is low; a right-to-left override or tag character inside an instruction file is high), and exits non-zero for pre-commit / CI gating. New `internal/filescan` package. (#612)
- **NSA MCP CSI follow-ups.** Five hardening surfaces driven by the May 2026 NSA MCP Cybersecurity Information mapping: context-leak parameter-name detection on MCP tool definitions, lethal-trifecta awareness, per-message signing, and replay defense. (#579)
- **NIST AI RMF + HIPAA compliance frameworks.** `pipelock assess` adds two built-in compliance frameworks (now seven total) plus a public procurement-oriented mapping document buyers and audit reviewers can attach to a security questionnaire. (#576)
- **`pipelock assess` evidence-trust hardening + schema v2.** Closes evidence-trust gaps in the assessment bundle and bumps the assess schema to v2, aligning the audit/sim coverage with the current feature set. (#575)
- **`dns.host_overrides` hostname routing.** A hostname-scoped static resolver layer maps configured hostnames to fixed IPs without touching `/etc/hosts`, while everything else delegates to the default resolver. IP-literal lookups bypass the override entirely so an attacker cannot smuggle an SSRF exemption through an IP-shaped key. Built once at load, normalized and defensively copied. (#589)
- **`query_entropy_exclusions` per-host query-string entropy bypass.** A new per-host exclusion list disables the URL query-string entropy gate for configured hosts, for endpoints whose query parameters carry legitimately high-entropy opaque values (signed tokens, session blobs). Subdomain entropy and path entropy stay enforced for those hosts unless separately excluded, so the carve-out is scoped to the query string only. (#639)
- **Hostname/DNS subdomain exfiltration detection.** Structural hostname checks now detect long hex/base32 subdomain labels and chunked DNS-tunneling shapes that evade Shannon-entropy thresholds, while honoring existing `subdomain_entropy_exclusions`. The signal runs on the shared URL scanner (fetch, forward absolute-URI, CONNECT, WebSocket) and on URLs embedded in MCP/A2A text and tool arguments, hard-blocking hostname-exfil matches even when generic DLP is in warn mode. (#642)
- **`reverse_proxy.profile: submit` + per-listener `trusted_upstream`.** A constrained reverse-proxy listener mode for narrow internal-egress POST submissions: `trusted_upstream` must exact-match the parsed upstream host+port (no IP literals), `allowed_paths` are required and canonical, `allowed_methods` are restricted to well-known verbs, and `max_body_bytes` / `request_timeout_seconds` must be positive. The empty (default) profile preserves the generic reverse proxy unchanged, and submit-profile fields are rejected when the profile is empty so a typoed selector cannot silently drop semantics. Submit-profile dials route through the same SSRF-safe `DialContext` as the fetch and forward proxies, closing the DNS-rebinding / TOCTOU window. (#622, #624)
- **`file_sentry` block-action mode + per-path `required`.** `file_sentry.action: warn | block`; in block mode the first agent-attributed DLP finding cancels the proxy context once and terminates the MCP child (the file reaches disk before the scan completes, so block prevents the agent from continuing to act on the leak, not from writing it). A per-path `required:` flag opts individual watch paths into must-exist enforcement, and `pipelock doctor --check-ports` flags listener port collisions. (#603, #620)
- **WebSocket `verify-install` check.** `pipelock verify-install` gains a WebSocket scan probe, closing the transport-parity gap in the previous 14-check suite (which proved fetch, forward CONNECT, MCP, and containment but never WebSocket). The suite now has 15 named checks. (#600)

### Internal Refactors / Tech Debt

- **Audit logger options structs.** Five long-parameter logger functions migrated to options structs (37 caller sites), plus three TODO close-outs including `posture.RenderProofMarkdown`. (#597)
- **`server.go` / `proxy_http.go` per-concern split.** `server.go` 1592 → 462 lines plus five sibling files; `proxy_http.go` 1901 → 208 lines plus four sibling files; five in-scope review findings folded in. (#598)
- **Compliance framework ID + feature-name constants extracted.** (#591)
- **`sessionKeyFor` session-key helper.** The per-session adaptive-enforcement key (agent-namespaced client IP, falling back to client IP for anonymous agents) was rebuilt inline across the fetch, forward, CONNECT, WebSocket, TLS-interception, CEE, and admin/session paths; all sites now route through one helper so escalation, de-escalation, and audit correlation share a single source of truth.
- **Adaptive-upgrade audit/metric helper.** The adaptive-enforcement audit log line and its matching Prometheus counter were emitted as a duplicated pair at 28 proxy call sites; they now route through one `recordAdaptiveUpgrade` helper fed by a single value, so the audit trail and the metric cannot drift apart on a future edit. No change to deny-path behavior.

### Changed

- **`reverse_proxy.profile`** selector added; the empty default preserves prior generic reverse-proxy behavior. (#622)
- **`request_policy` WebSocket policy is now enforced per frame.** Previously a body-predicate rule on a WebSocket host blocked the upgrade outright on the empty handshake body, so the frames it was meant to inspect were never seen. The handshake now gates route-only rules and each reassembled text frame is evaluated as an operation body against the live matcher (GraphQL and discriminator predicates), so the frames the rule targets are actually inspected and hot-reloaded rules apply to open sockets. (#634)
- **Local Dockerfile builds with `-tags enterprise`,** matching CI and GoReleaser, so docker-built images no longer silently compile out enterprise hooks (`agents:` config previously stripped at startup with no error). (#600)

### Fixed

- **Configured-upstream egress no longer honors an ambient `HTTP_PROXY`/`HTTPS_PROXY`.** The reverse-proxy, MCP HTTP client (`--upstream`), and MCP HTTP listener (`--mcp-listen`) transports were cloned from `http.DefaultTransport`, inheriting `Proxy: http.ProxyFromEnvironment`, so an environment proxy variable could silently redirect Pipelock's own egress to its configured upstream and route around the SSRF-safe dialer (reverse proxy) and the redirect-disabled SSRF posture (MCP HTTP). All three now dial the configured upstream directly with a nil `Proxy`, matching the forward, fetch, and TLS-interception transports. (#645)
- **`pipelock hermes --mode full`** now loads, enables, and blocks under a real Hermes runtime. (#629)
- **MCP HTTP listener strips inbound `com.pipelock/mediation`** metadata, closing the stdio-vs-HTTP parity gap so a forged mediation envelope cannot be laundered in on the HTTP listener path. (#601)
- **`file_sentry` surfaces oversized / unreadable file skips instead of dropping them silently, and the size cap is now configurable.** A watched file larger than the scan cap (or one that fails to stat/read) was silently left uninspected, so an operator had no signal that content went unscanned. Skips now report through the watcher's error callback, and a new `file_sentry.max_file_bytes` knob overrides the built-in 10 MiB default (0 = default; negative rejected at validation).
- **Forward proxy blocks responses too large to fully scan instead of forwarding a silently-truncated body.** When response scanning, Browser Shield, or media policy buffered a forward-proxy response, a body exceeding the `max_response_mb` scan cap was silently truncated and forwarded as an apparently-successful, scanned response — emitting allow receipts for a corrupted prefix that is not the upstream response. The forward path now reads one byte past the cap and blocks fail-closed (`response too large for scanning`) when the configured scan cap is exceeded, matching the TLS-interception and reverse-proxy paths. Per-agent data-budget truncation is a separate, deliberately-logged policy and is unchanged.
- **`scan_api` `tool_call` runs DLP + injection on demand regardless of the inline `mcp_input_scanning` toggle.** The on-demand scan API gated its `tool_call` content scan on `mcp_input_scanning.enabled` (default off), so a caller that enabled the scan API and submitted a tool call received `allow` with zero findings — the API silently declined to scan what it was asked to. `tool_call` now scans unconditionally like the `url` / `dlp` / `prompt_injection` kinds; whether the kind is offered at all remains governed by `scan_api.kinds.tool_call`.
- **Header DLP consults `cfg.Suppress` before hard-blocking,** giving request-header DLP the same suppression parity as the other entry points and closing a first-hit masking path. (#619)
- **Body redaction hardened and the Databricks DLP pattern tightened** (`dapi[a-z0-9]{30,}` → `dapi[0-9a-f]{32,}`), with an image-data-URL carve-out that closes a vision false-positive root cause. (#580)
- **Redaction runtime hardened: scanner lockstep + `allowlist_unparseable` passthrough.** The body-redaction runtime is now built from the installed scanner and kept in lockstep with the scanner pointer across config-reload publish windows via a `configKey` invariant, so a mixed config/scanner snapshot fails closed and blocks the body scan rather than redacting against a stale matcher. A one-hop previous-runtime fallback lets consistent old-snapshot requests survive the transient reload window; a real scanner-secret change still rejects the stale runtime. `allowlist_unparseable` is now a true passthrough for listed hosts: an unparseable body on an allowlisted host is forwarded unredacted instead of failing closed. (#635)
- **Media metadata strip truncates to the canonical end marker instead of failing closed.** JPEG `EOI` and PNG `IEND` parsing previously rejected any trailing bytes after the end marker, failing closed on real-world images that carry padding or metadata after the canonical end marker. The strip path now truncates to the end marker and passes the cleaned image, so legitimate images with post-marker bytes are no longer blocked while the trailing data is still removed. (#639)
- **Redaction hash-class context and audit fidelity for redaction rewrites.** Redaction rewrites now carry hash-class context so a redacted value's category is recorded, and the audit trail for redaction rewrites is captured with full fidelity instead of being collapsed, giving operators an accurate record of what was rewritten on each path. The hash classes (sha256 / sha512 / sha1 / md5) now require a self-labeled prefix (`sha256:<hex>`, `sha-256=<hex>`, …) so legitimate 64-char-hex OAuth client secrets and opaque session tokens are no longer rewritten in transit. (#639)
- **Response-scan-exempt responses stream through untouched, preserving trusted-host file transfers.** A host in `response_scanning.exempt_domains` is a trusted destination, but its responses were still buffered, size-capped, metadata-stripped by media policy, and run through Browser Shield — truncating large downloads at the scan ceiling and stripping EXIF / embedded thumbnails from images, corrupting the transferred file. Forward and TLS-interception now stream an exempt host's response straight through (no buffering, size block, media strip, shield, or injection scan) when `response_scanning.enabled`; request-side DLP, redaction, SSRF, authority checks, and budget accounting still run. (#639)
- **Redaction no longer corrupts AWS SigV4 pre-signed URLs.** The access-key ID carried in a pre-signed URL's `X-Amz-Credential` parameter (public — the secret signing key is never in the URL) was being rewritten to a placeholder, breaking the signed request at the upstream. A scoped carve-out skips an access-key match only in a real `X-Amz-Credential=…/credential-scope` context across every `RewriteJSON` path; a bare access-key ID is still redacted. (#639)
- **`LoadCA` accepts PKCS8-encoded EC keys,** not only SEC1. (#582)
- **Canonical policy hash no longer depends on `TMPDIR`.** The default `mcp_tool_policy.quarantine_dir` is derived from `os.TempDir()` and was flowing into the canonical policy hash, so identical policy produced a different hash across environments (and any host where `TMPDIR` was not `/tmp`). The operational quarantine path is now excluded from the policy view, restoring the property that identical policy yields an identical hash.

### Security Hardening

- **Provider token DLP patterns tightened against false positives,** then the remaining provider patterns tightened to documented formats, reducing opaque-session-id false positives on outbound model traffic. (#586, #587)
- **Enterprise license expiry warnings + signed-CRL enforcement.** Renewal-band warning events at 30 / 14 / 7 / 1 days, plus signed CRL parsing, verification, runtime refresh, and license-status / doctor visibility. (#592)

### Docs

- **Standards Phase B.** OWASP MCP Top 10 v2.5 refresh (MCP06 renamed to the official "Intent Flow Subversion," hard pattern counts replaced with a `make stats` pointer, v2.5 deltas appendix), a new in-toto agent-action-receipt v0.1 predicate with DSSE wrapping + JSON Schema, and a SCITT signed-statement profile. (#588)
- **Receipt-format v0.1 draft superseded** in public with a forward pointer to the implementation spec, plus a per-primitive prior-art mapping (SCITT, RFC 9421, OpenTelemetry GenAI, Cloudflare Signed Agents, SPIFFE, in-toto, CSA AARM, OASIS CoSAI, OWASP Agentic Skills Top 10, W3C VC). (#583)
- **`request_policy` configuration section** added to `docs/configuration.md`, documenting the operation-rails feature that shipped across #627–#633. (this PR)
- **`pipelock scan` reference** added at `docs/cli/scan.md` for the invisible-Unicode / bidi file scanner. (this PR)

### Dependencies / CI

- Bump `golang.org/x/crypto` to v0.52.0 (13 SSH CVE fixes). (#585)
- Bump `golang.org/x/net` to v0.55.0 (5 HTML-parser CVE fixes). (#584)
- Bump `github.com/CycloneDX/cyclonedx-go` to v0.11.0. (#599)
- Bump `modernc.org/sqlite` to v1.50.1. (#569)
- Bump golangci-lint to v2.12.2 and clean up findings. (#573, #577)
- Polish the Pipelock Helm chart. (#571)
- Bump Helm chart `appVersion` to `2.6.0` and clear the stale default image digest so chart installs follow the v2.6.0 image tag unless operators explicitly pin a digest. (this PR)
- Hold TypeScript and jsonschema majors at known-good versions; bump the TS and Rust verifiers; bump `@types/node`; refresh the oss-fuzz base-builder digest and ci-actions. (#572, #574, #552, #566, #578, #551)

## [2.5.0] - 2026-05-20

### Highlights

The headline arc is **verifiable egress control as a public, language-portable artifact**. The Audit Packet v0 schema ships with first-party verifier implementations in Go, TypeScript, and Rust, plus a standalone `pipelock-verifier` CLI. Auditors, SIEMs, and procurement reviewers can now validate signed evidence of agent activity without running Pipelock itself, in whatever runtime fits their pipeline. The second arc is **containment as a managed lifecycle**: `pipelock contain install` lands the operator-side install / verify / rollback / add-tool / ca-refresh subcommands so the 3-UID containment model is a one-command setup, with a separate state directory the proxy user can read but the agent user cannot replace. The third arc closes the v2.4 federation loop: inbound mediation envelopes now require SPIFFE-format actors by default (was permissive in v2.4), contract tombstones are enforced at activation and accepted-load time (was doc-only in v2.4), and a new `pipelock envelope trust` operator CLI manages the local trust list for peer onboarding. The fourth arc is **integration breadth**: `pipelock cline install`, `pipelock opencode install`, and `pipelock codex install` ship alongside the existing claude-code / cursor / vscode / jetbrains installers, mirroring the same MCP-wrap pattern across three more agent surfaces. Scanner coverage closes three skill-poisoning vector groups (memory-persistence directives, credential-solicitation phrasing, covert-action directives), adds request-body prompt-injection hard-blocking, and adds a SigV4 presigned-URL structural carve-out so legitimate AWS pre-signed URLs no longer trip URL DLP. The rules bundle keyring is now separated from the license key so bundle signing rotates independently. Operators get optional OTel `agent.threat.detection.*` attributes on scanner-decision records for AI-aware threat dashboards. Plus a project-scan audit fix that now applies DLP validators to candidate matches, fail-closed fixes for `pipelock claude-hook` unsupported events and unknown tools, and policy / threat-model docs published in-tree.

### New Features

- **Audit Packet v0 schema and Go bindings.** First-party canonical schema for a procurement-ready evidence bundle after a Pipelock-mediated agent run. The schema binds run identity, observed policy hashes, verifier verdict, signed receipt-chain summary, posture claims, and artifact paths; downstream verifiers in any language can read the same vectors. Published under `sdk/audit-packet/`. (#498)
- **`pipelock-verifier` standalone CLI.** New `cmd/pipelock-verifier/` binary independently validates individual action receipts, receipt chains, and Audit Packet v0 directories without running the proxy. Auditors and SIEMs can run it as a sidecar to the agent platform. (#500)
- **TypeScript Audit Packet verifier.** First-party TypeScript verifier published under `sdk/verifiers/ts/` with schema validation, Go-compatible receipt canonicalization, chain walking, and a conformance test suite that runs against the canonical vectors from the Go schema package. Drop-in for Node-based audit pipelines. (#505)
- **Rust Audit Packet verifier.** First-party Rust verifier published under `sdk/verifiers/rust/` with the same conformance coverage as the Go and TypeScript verifiers. Drop-in for Rust-based audit pipelines and embedded use cases. (#508)
- **CI verifier workflow.** New CI job exercises the TypeScript and Rust verifiers against the canonical vectors on every PR, so a schema change that breaks any verifier fails the release before the tag. (#511, #517)
- **`pipelock contain install` lifecycle.** New `pipelock contain install / verify / rollback / add-tool / grant-workspace / revoke-workspace / ca-refresh` subcommands manage the 3-UID containment model end to end. `install` creates the dedicated `pipelock-proxy` user, lays down state directories with strict ownership and 0o600 / 0o750 permissions, installs the binary into a system path the agent user cannot replace, generates the CA, and writes the systemd unit. `verify` is read-only and reports a structured ownership + permission audit. `rollback` is idempotent and restores managed files from guarded `.bak` backups where prior content existed. `add-tool` registers an additional tool wrapper and allow-list entry without re-running install. `grant-workspace` and `revoke-workspace` manage project-directory ACLs for the contained agent user without widening access to system paths by default. `ca-refresh` rebuilds the local CA export and combined trust bundle. (#512, #527, #549)
- **`pipelock doctor` enforcement diagnostics.** New doctor command reports whether configured protections are actually enforceable in the current process and deployment context: HTTP proxy reachability, TLS interception, request-body scanning, Browser Shield, MCP wrapper usage, MCP binary integrity, MCP tool provenance, file_sentry, Sentry telemetry, containment, and deployment-boundary signals. The command separates "configured" from "enforced" so release and deployment docs do not imply coverage that the host or cluster has not wired. (#549)
- **`pipelock verify-install` enforcement smoke checks.** The install verifier now runs 14 deterministic checks: the existing config, proxy-health, DLP, CONNECT, MCP input, injection, tool-policy, and direct-egress probes plus Browser Shield rewrite, file_sentry detection, MCP binary-integrity manifest/hash smoke, and MCP tool-provenance sign/verify smoke. The same proof setup is reused by `pipelock assess` when running with default config, keeping the assessment evidence path aligned with the standalone verifier. (#562)
- **`pipelock envelope trust` operator CLI.** New `pipelock envelope trust add / list / remove / verify` commands manage a local JSON trust list for peer onboarding, operator review, and manual envelope verification. The runtime proxy verifier still reads trusted keys from `mediation_envelope.verify_inbound.trust_list` in `pipelock.yaml`; the local store does not change runtime admission until runtime trust-store loading is added. (#522)
- **`pipelock cline install`** subcommand. Wraps Cline's MCP server entries through `pipelock mcp proxy` mirroring the existing claude-code / cursor / vscode / jetbrains installer pattern. Discovers Cline's config locations, generates a wrap target per server, and writes an idempotent installation that can be re-run safely. (#519)
- **`pipelock opencode install`** subcommand. Wraps OpenCode's MCP server entries through `pipelock mcp proxy` using the same idempotent installer pattern. Adds OpenCode (the sst coding agent) to the list of supported front-ends. (#523)
- **`pipelock codex install`** subcommand. Wraps Codex CLI's MCP server entries through `pipelock mcp proxy` using the same idempotent installer pattern. Adds Codex to the list of supported front-ends. (#499)
- **`pipelock zed install`** subcommand. Wraps the MCP servers declared in Zed's `settings.json` `context_servers` block through `pipelock mcp proxy` using the same idempotent installer pattern as `cline install` and `opencode install`. Default discovery scans both the user-level `settings.json` (`$XDG_CONFIG_HOME/zed/settings.json` or `~/.config/zed/settings.json`) and the project-level `<cwd>/.zed/settings.json`. Zed's flat MCP config shape (command string, args, env, transport inferred from command vs URL) matches Cline's, so the wrap delegates to the shared Cline path and reuses the existing header-sidecar plumbing for credential-bearing `headers` blocks (0o600 carrier referenced via `--header-file`; values never appear in `/proc/<pid>/cmdline`). Non-`ErrNotExist` stat failures on default paths (EACCES, ENOTDIR, EIO) now surface loudly so a permission-denied probe no longer silently skips wrapping. (#531)
- **Browser Shield productionized with config surface, evidence, and transport parity.** Browser Shield exits the pre-production phase: a documented `browser_shield` YAML block (off by default; `strictness: minimal | standard | aggressive`; `max_shield_bytes` and `oversize_action: block | scan_head | warn`; `exempt_domains` for challenge providers; granular `strip_*` and `inject_fingerprint_shims` knobs) replaces the prior internal-only configuration. Shield decisions emit signed action receipts so an operator can audit what was rewritten across HTML, JavaScript, and SVG responses. Receipt evidence and transport parity are aligned across the forward, intercept, reverse, and fetch paths so the shield's rewrite verdicts show up on the same evidence pipeline as scanner blocks. The `docs/configuration.md` Browser Shield section documents the production soak posture (start with `strictness: minimal` + `oversize_action: warn`, watch receipts and adaptive score, then escalate). (#533)
- **MCP sandbox egress bridged through Pipelock's forward-proxy scanner.** When `pipelock mcp proxy --sandbox` wraps a stdio MCP server on Linux, bridge-style MCP servers that make their own HTTP(S) upstream calls (such as `@upstash/context7-mcp`) are now routed through Pipelock's in-namespace bridge to the parent forward-proxy scanner. `HTTP_PROXY` / `HTTPS_PROXY` inside the namespace point at the bridge so upstream calls traverse Pipelock instead of escaping the namespace. The bridge enables forward-proxy handling internally for sandboxed servers even when `forward_proxy.enabled` is false in YAML, scoped to the sandbox bridge only without exposing the normal forward proxy listener. In `--best-effort` mode (containers without user-namespace support), the bridge still scans traffic but enforcement is cooperative: a child that clears the proxy env vars can bypass. (#535)
- **Scanner attribution on MCP block receipts.** Block receipts from MCP scan paths now populate the `Layer`, `Pattern`, and `Severity` fields (`omitempty`, non-breaking on Audit Packet v0). Coverage includes `mcp_input_scanning`, `mcp_input_redaction`, `mcp_tool_policy`, `mcp_chain_detection`, `mcp_session_binding`, `mcp_tool_taint`, `mcp_denial_of_wallet`, `mcp_a2a_scanning`, and `mcp_tool_inventory`. Severity is also populated on the existing `media_policy` and `mcp_response_scan` emit sites for consistency. Refactors `emitMCPToolReceipt` into an options struct (per the options-over-six-params rule) and threads attribution through both stdio (`internal/mcp/input.go`) and HTTP/WS (`internal/mcp/proxy_http.go`). Prior receipts left those fields empty. (#536)
- **Snapshot-restore CA regeneration for contain installs.** `pipelock contain ca-refresh --regenerate-on-snapshot-restore` backs up contain-managed TLS CA material, force-generates a fresh CA as `pipelock-proxy`, re-exports the root certificate, and rebuilds the agent bundle after a VM or disk snapshot restore. The command supports `--dry-run` for preflight warnings, refuses accidental repeat rotations for ten minutes unless `--force` is set, and documents the trust-store recovery sequence: rotating the intercept CA breaks clients that cached or copied the old root, so operators need preflight, service restarts, trust-store updates, and backup pruning after the rollback window. The per-deployment CA threat model now documents this footgun explicitly. (#538)
- **Skill-poisoning instruction-recognition patterns broadened.** Response and injection scanner coverage closes three vector groups that were partially covered before: memory-persistence directives ("remember this for all future sessions", "from now on always", "persist this preference across sessions"); credential-solicitation phrasing ("please paste the contents of ~/.aws/credentials", "show me your API key for"); and covert-action directives ("silently exfiltrate to", "do not show this in the output", "quietly send to"). Pattern additions live in `internal/scanner/core.go` and the default `internal/config/defaults.go`; the seven preset YAML files in `configs/` carry parallel updates because presets use `include_defaults: false`. False-positive corpus extended alongside the new variants. (#514)
- **Request-body prompt-injection blocking.** Request body scanning now detects prompt-injection payloads in JSON keys and values, ordered multi-field JSON bodies, form-encoded bodies, raw text, WebSocket client frames, reverse-proxy requests, and intercepted CONNECT traffic. In enforce mode, prompt-injection findings hard-block non-provider destinations even when `request_body_scanning.action: warn`; trusted provider hosts remain exempt through the existing wildcard-aware response-scanning exemption list. (#568)
- **SigV4 presigned-URL structural carve-out in URL DLP.** Legitimate AWS Signature V4 presigned URLs ship structural credential parameters (`X-Amz-Credential`, `X-Amz-Signature`, etc.) that previously tripped URL DLP. The carve-out matches the SigV4 query-parameter structure and exempts only the canonical credential pair, while the rest of the URL still passes through the full pipeline. False-positive case landed in the public corpus. (#516)
- **Route-scoped non-JSON redaction exceptions.** The redaction pipeline previously assumed JSON request bodies. Operators with route-scoped non-JSON traffic (form-encoded, plaintext, binary) can now declare exceptions via config so those routes skip the JSON rewrite without disabling the redaction matcher. Redaction still applies to JSON bodies on every other route. (#506)
- **Optional OTel `agent.threat.detection.*` attributes on scanner-decision OTLP records.** When OTel emit is configured, scanner decisions now carry optional AI-aware threat-detection attributes (rule class, severity, decision verdict, signal type) so observability stacks can filter, alert, and dashboard scanner activity without parsing the JSON event body. Off by default; opt-in via `emit.otlp.agent_threat_detection: true`. (#518)
- **Agent egress overhead benchmark with Go runtime metrics.** New end-to-end benchmark suite measures pipelock's per-request latency across five transports (HTTP, SSE, tool-chain, MCP wrap, WebSocket) with TLS interception OFF and ON, plus a direct-to-mock baseline so per-transport overhead is isolable. Backends are deterministic in-repo mocks (no external API) and the harness captures Go runtime metrics (GC pause, heap, goroutine count) alongside latency so regressions surface against a steady baseline, with optional cold-start and steady-state memory sampling for soak runs. `make bench-egress` runs the suite locally; CI emits the JSON report as a release artifact. (#528)
- **Go runtime and process Prometheus collectors.** The metrics registry now exports standard `go_*` and `process_*` metrics — heap, goroutine count, GC pause histograms, process RSS / open-FD gauges — alongside the existing `pipelock_*` metrics. Grafana dashboards built on standard Prometheus client conventions work out of the box; the benchmark harness above re-uses the same collectors so dev-time and prod-time numbers line up. (#528)
- **MCP integrity manifest tooling.** New `pipelock mcp integrity manifest generate / verify / sign / verify-signature` workflow pins resolved MCP server binaries and scripts by SHA-256, supports merge updates, resolves relative scripts with `--workdir`, and can require a trusted Ed25519 manifest signature at runtime. Signature establishment is fail-closed when `require_signature: true`, even if manifest mismatch action is warn. (#557, #560)
- **Cluster MCP proxy launcher contract.** `pipelock init sidecar --mcp-upstream` now generates a companion MCP listener, service port, workload annotations, NetworkPolicy port allowance, `PIPELOCK_MCP_PROXY_URL`, and a mounted `PIPELOCK_MCP_CONFIG` file for launchers that can consume a client config. Re-runs scrub the MCP env, annotations, ConfigMap, volume, and mount when MCP is disabled. The generated contract is explicit: the agent launcher or MCP client must consume one of those values, and Kubernetes egress enforcement still depends on the cluster CNI honoring NetworkPolicy. (#559, #561)
- **Adaptive enforcement operator CLI and burst tuning.** New `pipelock adaptive status / flush / whoami` commands expose runtime adaptive state through the authenticated admin API. Shared IP-domain burst scoring and Browser Shield defaults were tuned so cooperative browser-style bursts are less likely to be confused with attack fan-out while threat escalation remains visible to operators. (#550)

### Internal Refactors / Tech Debt

- **Contract tombstone enforcement at activation and accepted-load time.** v2.4 documented tombstones as evidence markers without activation-time enforcement; a tombstoned hash could be re-promoted under v2.4 semantics. v2.5 closes the gap: `Store.ValidateEnvelope` cross-checks tombstones during contract promotion, the accepted-history chain walk rejects loads that would resurrect a tombstoned hash, and a high-severity audit event fires on attempted re-promotion. Red-team tests prove enforcement at both surfaces. (#521)
- **Drop blockreason severity/retry delegate wrappers.** The local `severityFromReason` / `retryFromReason` wrappers in `blockheaders.go` were pure pass-throughs to `blockreason.SeverityFor` / `RetryFor`. Earlier versions maintained their own switch and silently drifted from the canonical mapping; the wrappers were kept only as a safety harness while that drift was being audited. The canonical helpers are now inlined at the two call sites (`blockInfo`, `blockInfoFor`), the wrappers are deleted, and the Reason → Severity and Reason → Retry vocabulary tables move next to the canonical helpers as `mappings_test.go` in `internal/blockreason`. Single source of truth for the mappings, single test file pinning them. No behavior change; lint clean, race tests pass, coverage on `SeverityFor` / `RetryFor` is 100%. (#537)

### Changed

- **DLP provider-token patterns hardened.** Tightened nine short-prefix patterns (Fireworks, Hugging Face, Databricks, Replicate, Together, Vercel, npm, PyPI, Notion) to bounded vendor-documented shapes and added matching redaction classes. Default `subdomain_entropy_exclusions` now covers `files.pythonhosted.org`, `pypi.org`, and `objects.githubusercontent.com`: path entropy is skipped for those package/object hosts, while query entropy is still scanned. Operators with custom DLP override patterns should mirror the vendor-shaped patterns if they want the same false-positive reduction.
- **DLP provider-token hardening pass 2.** Tightened the remaining short-prefix provider rules for HashiCorp Vault, Supabase, Linear, and Sentry: Vault now requires the documented `hvs.` + 24-character minimum, Supabase matches the documented `sb_secret_<22-char-random>_<8-char-checksum>` shape, and Linear/Sentry keep their existing length floors. All four now require leading and trailing token boundaries, with matching redaction classes for the same token families.

### Fixed

- **`pipelock claude-hook` fail-closed on unsupported hook events.** The `claude-hook` adapter previously fell back to allow for unknown / unsupported hook event types; it now fail-closes (blocks) when the event type is not in the supported set, matching pipelock's fail-closed defaults across every other surface. (#524)
- **`pipelock claude-hook` unknown-tool coverage.** Unknown `tool_name` values now route through the generic tool-use scanner with their full `tool_name` and `tool_input` instead of falling through to allow. Null `tool_input` returns an explicit error rather than bypassing request inspection. (#568)
- **DLP validators applied during `pipelock audit` project scan.** Project scan candidate matches now run through the DLP validator chain so checksum-validated patterns (BIP-39, IBAN, credit-card) don't produce false positives on values that look like the pattern but fail the validator. Brings project-scan false-positive behaviour in line with runtime URL / body scanning. (#510)
- **Rules bundle keyring separated from license key.** Bundle signing keyring is now stored and loaded independently from the license key so rotating one does not force rotating the other. Migration is automatic on first load; existing bundles signed under the prior layout verify unchanged. (#526)
- **SSE streaming activation driven by `Content-Type`, not the parent response scanner toggle.** The forward and TLS-intercept paths previously gated the streaming dispatcher behind `response_scanning.enabled`; when an operator turned the parent response scanner off, the MediaPolicy / Browser Shield arms of the buffered-path OR condition (MediaPolicy defaults true) silently routed `text/event-stream` responses through `io.ReadAll`. The egress bench measured this as a 90 ms proxied TTFB versus 134 µs direct. Activation is now driven by `Content-Type: text/event-stream` alone, and the dispatcher's chunked-flush passthrough preserves per-read flushing whenever the child Enabled flag (`response_scanning.sse_streaming.enabled` or `a2a_scanning.enabled`) is off. Per-event DLP and injection scanning still terminates the stream on detection when SSE scanning is on; by default, the child SSE scanner remains enabled even if the parent response scanner is disabled. Whitebox regression tests cover forward + intercept streaming with the parent scanner off and MediaPolicy default-on, plus forward coverage for child-disabled passthrough, scanner-on flushing, and DLP blocking. (#530)
- **Response-scanner documentation false positives and split-payload DLP hardened.** Educational prompt-injection examples quoted inside defensive docs no longer trip response scanning, while system-prompt disclosure directives remain blocked even when quoted. Text DLP now splits encoded payload candidates on structured-data delimiters such as quotes, braces, brackets, colons, commas, and semicolons so base64 / hex / base32 secrets embedded inside JSON, YAML, or CSV-style bodies are decoded and scanned. WebSocket DLP also joins labeled fragment suffixes across adjacent client text frames (for example, `part 1:` / `part 2:`) so split secrets cannot hide behind human-readable chunk labels. Official AWS example credentials are allowed only in documentation context; bare use still blocks. (#540)
- **Drop misleading `T1046` tag on DNS-resolver-failure blocks.** Closes the SIEM-label half of issue #440. The verdict was always correct (DNS resolver failures fail-closed, classified as `ClassInfrastructureError` since v2.3.0 so adaptive enforcement does not poison the session score on resolver wobble); only the audit-emit label was wrong. The audit path now drops `mitre_technique=T1046` and the "SSRF check failed" reason text when the block is a non-adversarial DNS infrastructure error, surfacing `dns_timeout` / `dns_no_such_host` / `dns_resolver_error` display labels instead so resolver-health alerts can fire without conflating with real T1046 Network Service Discovery attempts. Internal-IP resolutions stay `ClassThreat` with `Scanner=ssrf`, so a real SSRF probe keeps emitting T1046. 13 `LogBlocked` call sites in forward, intercept, proxy, and websocket paths migrated to the new class-aware `LogBlockedDetail` via an `auditDetailFromResult` bridge; the legacy `LogBlocked` wrapper still emits T1046 on threat-class SSRF blocks (regression-tested). (#539)
- **Contain install idempotence fixes.** Re-running `pipelock contain install` now handles managed `.bak` rotations cleanly and the version banner no longer double-prefixes release strings with `v`. (#541)
- **MCP sidecar disable path scrubs stale contract state.** Re-running `pipelock init sidecar` without `--mcp-upstream` now removes stale MCP proxy URL env vars, MCP config env vars, annotations, ConfigMap mounts, and volumes from the generated workload so an old MCP contract cannot linger after the service port is removed. Invalid MCP upstream ports are rejected before manifest generation instead of failing later at Kubernetes apply time. (#559, #561)
- **MCP upstream provenance is visible in generated manifests.** Sidecar-generated workloads now record both the companion proxy URL and the upstream MCP URL in managed annotations, making deployment review possible without digging through container args. (#559)

### Security Hardening

- **Inbound mediation-envelope verification now requires SPIFFE actors by default.** `mediation_envelope.actor_format: spiffe` already emitted SPIFFE actors on outbound envelopes in v2.4; it now also requires verified inbound envelopes to carry syntactically valid SPIFFE IDs. Operators with mixed-mode federations that still receive legacy free-form actor strings must set `mediation_envelope.actor_format: legacy` temporarily to preserve v2.4 behavior during peer migration. The legacy path remains available for one minor release. (#522)
- **Contract tombstones are activation-time enforced.** A tombstoned contract hash cannot be re-promoted, accepted-load cannot resurrect a tombstoned hash, and the audit pipeline emits a high-severity event on attempted re-promotion. Closes the doc-only enforcement gap from v2.4. (#521)
- **`pipelock claude-hook` fail-closed coverage extended.** Unsupported hook events now fail-closed instead of falling through to allow. (#524)

### Docs

- **Security policy and threat-model documents published in-tree.** New `docs/security/coordinated-disclosure.md`, `docs/security/per-deployment-ca-threat-model.md`, and `docs/security/current-unsupported-paths.md` cover the coordinated-disclosure policy, severity-tier response targets, the per-deployment CA threat model, and the current unsupported-paths surface (raw sockets, browsers without explicit proxy config, processes that ignore CA bundle env vars, MCP stdio with no transport wrap, direct UDP/DNS egress). Replaces the prior "see GitHub Security Advisories" pointer with timelines integrators can rely on. (#515)
- **Audit Packet threat model published in-tree.** New `docs/security/audit-packet-threat-model.md` is the hostile-reader threat model for the Audit Packet evidence bundle. States what a verified packet proves, what it does not prove (traffic that did not cross the Pipelock control point, compromised runner environment, sibling-step and out-of-band channels, `self_consistent_only` verdicts, future tampering of artefacts at rest), and the eight trust assumptions a relying party should pin before treating a `valid` verdict as provenance. Companion to the `sdk/audit-packet/README.md` schema reference (which now back-links to the threat model). The customer-facing restatement lives at [pipelab.org/learn/audit-packet-threat-model/](https://pipelab.org/learn/audit-packet-threat-model/).

### Dependencies / CI

- Bump cryptography (#502).
- Bump go-deps group: 6 updates (#503).
- Bump ci-actions group: 4 updates (#504).
- Bump urllib3 from 2.6.3 to 2.7.0 in `/.github` (#507).
- Bump pr-review-deps group: 2 updates (#509).
- prettier + pre-commit hooks for TypeScript and Rust verifiers (#517).
- Migrate dependency updates from Dependabot to Renovate with a 7-day cooldown window so security-relevant bumps still land same-day while non-security version churn lands in batched, reviewable groups (#543).
- Pin pipelock Docker base image by digest in renovate so the build chain ties to a content-addressed image rather than a floating tag (#544).
- Bump Rust crate `thiserror` to v2 across the Rust verifier (#556).
- Bump TypeScript verifier dependencies (#554).
- Bump docker-base-images group (#547).
- Helm chart `appVersion` bumped to `2.5.0`.

### pipelock-verify-python

`pipelock-verify-python` remains the Python companion for ActionReceipt v1 chain verification. v2.5 adds first-party Go, TypeScript, and Rust verifiers for Audit Packet v0; Python Audit Packet verification and EvidenceReceipt v2 chain verification remain follow-up work.

## [2.4.0] - 2026-05-06

### Highlights

The headline feature is **learn-and-lock**: a policy compiler and activation workflow that watches an agent's real traffic, infers a per-agent behavioral envelope, replays the candidate in shadow against captured traffic, records operator-ratified signed contracts in a content-addressed active manifest chained to a verifiable observation root, and **enforces the promoted contract live** on every URL-bearing transport plus the MCP tool-call surface. Live enforcement covers forward proxy (absolute-URI and CONNECT), reverse proxy and redirect-refresh chains, intercept proxy, `/fetch`, WebSocket handshake, MCP HTTP listener and stdio-to-HTTP bridge, and the `mcp_tool_call` rule kind on every MCP transport mode. Contract verdicts compose under a shared scanner-floor invariant: scanner block always wins over contract allow on every gated path. Contract lifecycle events, shadow evidence, and runtime `proxy_decision` receipts ship in the new **EvidenceReceipt v2** envelope alongside the existing ActionReceipt v1; the Go reference verifies v2 receipts today, and a companion `pipelock-verify-python` 0.2.0 update is prepared separately for v1 chains plus individual EvidenceReceipt v2 envelopes. Federation plumbing makes inbound mediator envelopes verifiable across organisations: replay-protected verification of envelopes signed by other Pipelock instances, SPIFFE actor identity (with IP-literal trust-domain rejection), and an RFC 9421 well-known signing-key directory. Redaction grows a Gemini parser and a provider plugin shape so third-party LLM providers drop in without code changes. The `X-Pipelock-Block-Reason` header lets an agent see WHY a request was blocked on every HTTP-capable path (forward / intercept / fetch / reverse / MCP HTTP / WebSocket close-frame), with the same fixed reason vocabulary on the JSON-RPC error metadata for MCP-internal blocks where there is no HTTP response surface. Operators get a wedge-detection watchdog that returns 503 on subsystem stalls, soak observability counters for the capture pipeline and inbound envelope verification, and capture-pipeline race fixes that stamp every record with the active session and policy hash. Plus a tech-debt cleanup that closes the remaining v2.3.0-era TD board (metrics split, reverse-proxy reload hygiene, receipt parity).

### New Features

- **Learn-and-lock policy compiler.** A new four-phase pipeline turns observed agent behaviour into a signed, per-agent behavioural contract. Phase 1 `observe` records flight-recorder evidence with a 5-dimension observation schema and a write-only observation log per session. Phase 2 `compile` infers normalised rule shapes (Wilson-lower-bound confidence with conditional-on-opportunity denominators, frequency-weighted entropy path normalisation, per-host cardinality cap with explicit tail-coverage gating) and emits a signed candidate contract plus an operator review markdown. Phase 3 `shadow` replays captured observations against the candidate without blocking, emitting `would_have_blocked` and `shadow_delta` evidence plus replay fidelity gates so non-replayable surfaces stay flagged. Phase 4 activates via two-phase commit: `pipelock learn ratify` (operator-signed ratification per rule), `pipelock learn promote` (signed promote-intent then atomic active-manifest swap with monotonic generation + `prior_manifest_hash` CAS), `pipelock learn forget` (per-rule withdrawal). Operator workflow includes a content-addressed history under `~/.pipelock/contracts/` with append-only `.activation_journal.jsonl`, signed monotonic active-manifest, immutable per-manifest blobs, and tombstone markers (no overwrites, no symlinks). New signing key purposes: `contract-compile-signing` (warm), `contract-activation-signing` (cold/operator), with deployment-level `roster-root` and break-glass `recovery-root`. Configurable per-agent in the `learn` config block; default-off. (#442, #444, #447, #452, #454, #455, #456, #457, #458, #459, #460, #461, #463)
- **Live policy enforcement on promoted contracts.** Once a contract is promoted, the active manifest is consumed at request time across every URL-bearing transport plus the MCP tool-call surface. A shared `decisionGate` helper wires the contract evaluator alongside the existing scanner verdict on each gated path; the runtime evaluator applies kill-switch first, then scanner verdict, then contract verdict, then mode gating, in a single decision sequence. Transports covered: forward proxy (absolute-URI and CONNECT tunneling), reverse proxy and redirect-refresh chains (the redirected leg is re-evaluated against the redirected URL, not the original, so an allowed origin cannot be used as a redirect bridge to an unapproved destination), intercept proxy, `/fetch` endpoint, WebSocket `/ws` handshake, MCP HTTP listener (`pipelock mcp proxy --listen --upstream`), MCP stdio-to-HTTP bridge (`pipelock mcp proxy --upstream`), and MCP stdio subprocess wrap (`pipelock mcp proxy -- COMMAND`). MCP `tools/call` decisions evaluate the new `mcp_tool_call` rule kind through `runtime.EvaluateMCP`; denied tool calls return a structured JSON-RPC error with block-reason metadata and never reach the upstream. CONNECT gates evaluate against `host:port` only by design (CONNECT cannot see paths). Mode gating preserves capture-mode silence (no block, no shadow record), shadow-mode would-have-blocked telemetry (allow + record), and live-mode enforcement (block). The active manifest store reloads on filesystem change via fsnotify with a 100ms debounce and a 2s maximum-debounce cap, fail-closed on initial reload, and the loader recovers a missed promote via the accepted-history chain walk so a crash between `promote-intent` and `promote-committed` cannot strand the runtime on a stale manifest. (#482, #483, #485, #486, #487, #488, #489, #490)
- **`mcp_tool_call` rule kind and runtime evaluator.** A new schema rule kind matches MCP tool-call requests by tool name and argument shape, with `runtime.EvaluateMCP` applying the kind on every MCP transport mode. Argument matchers compare type-erased values defensively: nil-on-either-side comparisons short-circuit before stringification so a nil matcher cannot match a request value of literal string `"<nil>"`, closing a display-vs-reality bypass class. The compile pipeline emitting `mcp_tool_call` rules is sequenced for a follow-up; v2.4 ships the schema and runtime so an operator-authored contract can already gate tool calls. (#485)
- **Contract block-reason vocabulary and `proxy_decision` receipt builder.** New canonical block-reason codes (`contract_default_deny`, `contract_rule_deny`, `mcp_tool_blocked`, etc.) extend the existing `X-Pipelock-Block-Reason` vocabulary so contract-driven blocks emit a structured response header alongside scanner blocks. The `runtime.BuildProxyDecisionReceipt` builder produces the `proxy_decision` payload kind for the EvidenceReceipt v2 envelope; v2.4 wires receipt emission across the live-lock arc, with the v1-to-v2 cutover for non-contract decisions sequenced as a follow-up sweep so the existing audit pipeline keeps working unchanged for non-contract-aware deployments. (#484)
- **EvidenceReceipt v2 envelope.** A new signed receipt envelope covers contract lifecycle, shadow evidence, and runtime contract-aware proxy decisions. The `proxy_decision` payload kind is built by `runtime.BuildProxyDecisionReceipt` (#484) and emitted from the live-lock arc; the lifecycle and shadow kinds emit from the activation CLI and replay surfaces. Distinguished from the legacy ActionReceipt v1 by a top-level `record_type` field; v1 verifiers reject v2 with explicit `unsupported version 2 (expected 1)` so the existing verifier ecosystem is undisturbed. Payload kinds: `proxy_decision`, `contract_ratified`, `contract_promote_intent`, `contract_promote_committed`, `contract_rollback_authorized`, `contract_rollback_committed`, `contract_demoted`, `contract_expired`, `contract_drift`, `shadow_delta`, `opportunity_missing`, `key_rotation`, `contract_redaction_request`. RFC 8785 JCS canonicalisation over typed structures (not raw YAML/JSON bytes) with strict unknown-field rejection recursively in every signed object. (#442)
- **Inbound mediation envelope verification + replay cache.** New `mediation_envelope.verify_inbound` config block, trust-list of pinned Ed25519 public keys (versioned `pipelock-ed25519-public-v1` or raw 64-character hex, each with optional SPIFFE `trust_domains` restriction), and a nonce-keyed in-process replay cache so envelopes signed by other Pipelock mediators are accepted, verified, and protected against replay. Transport coverage tested across forward / intercept / reverse. When enabled the proxy requires the `Pipelock-Mediation` header on every body-bearing inbound request: missing or invalid signatures reject with 403 / `inbound_verify_failed`. Trust-list entries with empty `trust_domains` accept any actor under that key in v2.4 (migration default); v2.5 will require an explicit pin. (#465)
- **SPIFFE actor format on the mediation envelope.** Envelope `actor` field accepts SPIFFE IDs (`spiffe://trust-domain/workload`) for cross-org interoperability. Schema migration with permissive default: outbound envelopes write SPIFFE format, inbound accepts both unstructured and SPIFFE in v2.4. v2.5 will flip inbound to default-strict (require SPIFFE). (#465)
- **`/.well-known/http-message-signatures-directory` per RFC 9421.** Pipelock serves a directory of its current mediation-envelope public verification keys at the standard well-known path so verifiers can fetch key material without out-of-band SHA pinning. The prepared `pipelock-verify-python` 0.2.0 example switches its key-pinning recipe from a hardcoded SHA to a directory fetch once that verifier release is published. (#465)
- **Generic SSE per-event injection detection scaffolding.** New `internal/mcp/sse_generic.go` scanner runs the per-event DLP and injection passes on any `text/event-stream` response (OpenAI chat completions, Anthropic messages, Kilo Gateway, generic LLM SSE). The cross-event split limitation called out in the v2.3.0 CHANGELOG remains a documented gap in v2.4: a secret split across two consecutive events is still NOT detected for non-A2A streams. A2A's rolling-tail scanner continues to cover that case for A2A protocol traffic. Generalising cross-event detection to any SSE stream is tracked as a follow-up.
- **Redaction Gemini parser + provider plugin shape.** v1 ships Anthropic + OpenAI body parsers. v1.1 adds Gemini and generalises the parser registration so third-party providers drop in without forking the redact package. New `internal/redact/providers.go::DefaultProviderSpecs()` registers `anthropic`, `openai`, and `gemini` with shared JSON walker; `internal/proxy/redaction_runtime.go` wires the registry through forward / intercept / reverse / WebSocket transports. Custom providers ride the same shape. (#462)
- **`X-Pipelock-Block-Reason` response header.** Every HTTP-capable block path emits a structured response header naming the rule class that fired (`dlp_match`, `ssrf_private_ip`, `tool_policy_deny`, `airlock_active`, `kill_switch_active`, etc.), the severity, and an optional retry hint. Transports with an HTTP response surface — forward, intercept, fetch, reverse, MCP HTTP, and WebSocket close-frame payload — set the header. MCP-internal blocks (stdio JSON-RPC, `tool_poisoning`, `tool_chain_blocked`) carry the same fixed reason vocabulary on the JSON-RPC error metadata where no HTTP header surface exists; this is enforced by a static production-path matrix gate so the vocabulary cannot drift from shipped behavior. Lets an agent back off intelligently without parsing the block-body text. (#467, #469, #475)
- **`pipelock mcp proxy --header` flag with strict header hardening.** Pass arbitrary request headers on the upstream-MCP connection (forwarded to every tool call). Header names must be RFC 7230 tokens; values are validated before trimming and reject ASCII control bytes, DEL, CRLF, and Unicode whitespace. Transport-managed and connection-critical headers are blocked case-insensitively: `Content-Type`, `Accept`, `Mcp-Session-Id`, `Content-Length`, `Transfer-Encoding`, and `Host`. The CLI flag-parser and the HTTP transport-level guard both enforce the rejection so an attacker-controlled extra header can't shadow Pipelock's session correlation or smuggle a request via header injection. Pairs with the new `--exempt-domain` wildcard parity (matching every other domain check). (#466, #475)
- **MCP HTTP listener SSE upstream parity.** `pipelock mcp proxy --listen --upstream` now routes `text/event-stream` upstream responses through `SSEReader` so JSON-RPC messages stream to the listener client without waiting for upstream EOF. Closes a regression where SSE-streaming MCP servers (mcp-server-stripe, mcp-server-lakera, etc.) sat silent until the upstream finished or timed out. (#472)
- **Wedge-detection watchdog.** `health_watchdog` defaults enabled; subsystem heartbeats from the proxy hot path, MCP listeners, and the rules-engine reload watcher feed a single watchdog. `/health` returns 503 with the wedged subsystem name when any heartbeat goes stale, so an external healthcheck or the cluster liveness probe surfaces a wedge automatically. New `health_watchdog.expose_subsystems: true` adds a per-subsystem map to the health payload for operator dashboards (omitted by default to keep the response opaque to unauthenticated callers). (#473)
- **Capture pipeline + race fixes for the learn-and-lock recorder.** Capture records now stamp `SessionID` at every observer call site, preserve caller-side `effective_action` / `config_hash` / `profile`, capture **after** suppression for forward and reverse parity, add a per-MCP `ConfigHashFn` so reload-time hash drift is bound to the captured envelope, and fix the canonical-policy-hash race where two reloads could interleave and leave a record stamped with neither hash. Unsafe or overlength session IDs are hashed on disk and `session_id_original` preserves the raw logical key for offline compile/shadow fidelity (omitted on path-safe keys to avoid leaking client IPs into every record). New `validateCaptureSessionDir` rejects sibling-session directories whose first JSONL entry attributes traffic to a different agent, preventing poisoned-capture name discovery. End-to-end regression test landed alongside the fix. (#474)
- **SPIFFE actor IP-literal rejection, block-reason pairing helpers, tombstone scope.** SPIFFE trust domains now reject IPv4 and IPv6 literals at envelope verification AND at config validation so a partner cannot impersonate a domain via a numeric host. `blockreason.NewForReason` and `blockreason.MustNewForReason` constructors look up the canonical severity / retry pair from the v1 spec so call sites cannot accidentally emit a mismatched (`dlp_match` + `info` + `policy`) triple. Tombstone records are scoped explicitly as evidence markers, not activation-time enforcement. Conformance fixtures included. (#470)
- **Soak observability counters and transport parity.** New `pipelock_capture_dropped_total`, `pipelock_capture_session_id_sanitized_total{reason}`, `pipelock_envelope_verify_total{result}`, `pipelock_learn_capture_records_total`, and `pipelock_learn_capture_dropped_total` counters let operators watch the capture pipeline and inbound envelope verification at runtime. New TLS-intercept transport capture metadata test and a static production-path block-reason matrix prove every canonical reason has at least one production emit site (or is documented as an intentional exemption). The unified `captureSessionKeyMaxLen` constant collapses three duplicate definitions into one. (#475)
- **Synthetic replay regression harness.** A deterministic fixture corpus + golden-snapshot test suite for the learn-and-lock pipeline. Compiles a hand-curated multi-session capture corpus, replays it against a frozen candidate config, and byte-compares the contract YAML, compile manifest, replay diff, review markdown, and the rendered corpus JSONL against checked-in goldens. Wires `make test-replay-harness` and a dedicated CI step ahead of the broader test job so byte-level drift in compile / inference / signing logic fails fast. Refresh procedure documented in the test file. (#468)
- **Live-lock decision matrix harness.** A capture-domain test harness that exercises the runtime gate composition end-to-end: kill switch first, then scanner verdict, then contract verdict, then mode gating, across every URL-bearing transport (forward, intercept, reverse, fetch, WebSocket) and the MCP tool-call surface. Closes the verification gap where transport-level gate composition was tested per-transport but never as a unified matrix. (#491)

### Internal Refactors (tech-debt sprint)

- **TD-6: `internal/metrics` per-feature bundle split.** The 1,171-LOC `internal/metrics/metrics.go` is split into typed bundles: `ProxyMetrics`, `ScannerMetrics`, `TLSMetrics`, etc. Maintainability index up; no semantic change. Fresh canonical-hash golden fixtures pin the metrics-shape contract. (#441)
- **TD-7/8/9: reverse-proxy reload hygiene + receipt parity.** Combined PR closes three drift sources: `Close()` on the reverse-proxy scanner during reload (drains in-flight scan goroutines), `toolBaseline` rebuild on the `detect_drift: false → true` rising edge (previously stale state survived the toggle), and reverse-proxy receipt parity for SSE / compressed / oversize blocks (previously a fetch-path-only happy path). (#443)

### Fixed

- **MCP zombie-reaper drains adopted-descendant subprocesses during long-lived wraps.** SIGCHLD-driven goroutine on Linux walks `/proc`, finds zombies whose `PPID == pipelock`, and reaps them PID-specifically so stdio MCP wraps that orphan grandchildren no longer accumulate `<defunct>` entries. Linux-only; non-Linux is a no-op stub. (#449)
- **Sentry scrubber adapted to sentry-go 0.46.** Compatibility shim for upstream BeforeSend signature change. (#453)
- **Python verifier fixture pinned, with CI policy gate.** `testdata/python_verifier_fixture/` now ships a pinned `requirements.txt` with hashes plus a CI policy gate that fails any unpinned addition. The reference verifier is a security boundary; pinning prevents transitive supply-chain drift. (#448)
- **Capture pipeline classifies learn observations for tech-debt metrics.** Soak observability counters now distinguish learn-mode capture records from production decisions, so the debt-metric counters reflect real production traffic rather than inflated learn-mode evidence. (#480)

### Deprecated / Removed

- (none in this release)

### Security Hardening

- Inbound envelope verification rejects mediator envelopes whose actor is not in the trust-list. Replay cache uses the envelope nonce, not URL or body, so legitimate retries with different bodies still verify but a captured signed envelope cannot be replayed within the cache window.
- Inbound envelope verification now reconstructs RFC 9421 `@target-uri` for origin-form server requests before signature verification, so signed mediator requests verify against the absolute URI the peer actually signed instead of Go's relative `RequestURI`. Host or scheme mismatches still fail closed. (#481)
- Scanner block wins over contract allow on every gated transport. The runtime decision sequence applies the scanner verdict before the contract verdict, so a `mcp_tool_call` allow rule (or any contract allow on a URL transport) cannot override a DLP / SSRF / injection block. Proven by named scanner-floor regression tests on each transport.
- Active contracts default-deny on unmatched destinations. Once a contract is promoted, requests that do not match an `http_destination` allow rule (or, for MCP, a `mcp_tool_call` allow rule) are blocked. Pre-promotion or no-active-contract behaviour is unchanged: scanner verdict pass-through.
- Ratify guards low-confidence rule promotion. `pipelock learn ratify` non-interactive mode refuses candidates that contain any rule at confidence `never_confirmed` or `refuted`. Interactive mode refuses candidates that are 100% low-confidence. An explicit `--accept-low-confidence` override is available for deliberate operator-reviewed workflows. Prevents a thin-capture candidate from becoming an enforcing contract that defaults to denying real traffic on every unmatched destination. (#493)
- Redirect-refresh chains re-evaluate the contract on every redirected leg using the redirected URL, not the original. An allowed origin that returns 30x to an unapproved destination terminates the chain with 403 and an `X-Pipelock-Block-Reason` naming the redirected leg. Closes the redirect-bridge bypass class.
- Mode gating preserves capture-mode silence (capture-mode contracts emit no contract block and no shadow record) and shadow-mode would-have-blocked telemetry without blocking. Live mode is the only mode that produces a contract block.
- Kill switch overrides every gated transport regardless of contract verdict. All four kill-switch sources (config, API, SIGUSR1, sentinel file) compose with the contract gate; any one active blocks every gated path.
- Active manifest loader fails closed on initial reload (no manifest, no enforcement difference; an unreadable manifest blocks rather than silently degrading) and recovers a missed promote via the accepted-history chain walk so a crash between `promote-intent` and `promote-committed` cannot strand the runtime on a stale manifest.
- EvidenceReceipt v2 lifecycle and shadow receipts bind the active manifest hash, contract hash, selector ID, and contract generation under signature so replayed evidence cannot impersonate a different policy generation.
- SPIFFE actor IP-literal rejection at both envelope-time and config-time closes the impersonation vector where a federation peer claims a numeric host as its trust domain.
- `pipelock mcp proxy --header` validates names as RFC 7230 tokens and rejects ASCII control bytes, DEL, CRLF, and Unicode whitespace in values. The connection-critical headers `Host`, `Content-Length`, and `Transfer-Encoding` join the existing `Mcp-Session-Id` / `Content-Type` / `Accept` rejection list, closing a header-injection / request-smuggling class.
- Critical-severity request-body DLP findings now hard-block with `X-Pipelock-Block-Reason: dlp_match` in enforce mode even when `request_body_scanning.action: warn`. Operators that intentionally use body-DLP warn mode for audit-only rollout can preserve non-blocking behavior with per-pattern `action: warn` on selected patterns or by running with `enforce: false`.
- Request-body prompt-injection findings now hard-block with `X-Pipelock-Block-Reason: prompt_injection` for non-provider destinations in enforce mode, closing the gap between response/tool-result injection scanning and agent-originated prompt text.
- Capture pipeline rejects sibling-session directories whose first JSONL entry attributes traffic to a different agent. A poisoned capture cannot be discovered by name alone, even if an attacker plants a session directory under a known agent's capture root.
- Production-path block-reason matrix is enforced by a static gate so a new `Reason` constant cannot ship without at least one production emit site (or a documented exemption).
- Tool policy now configurable in the synthetic replay corpus so the regression harness asserts privilege-boundary preservation: a `block → allow` flip on a tool-policy record fails the harness explicitly.

### Other

- `pipelock learn ratify` and `pipelock learn forget` CLI subcommands (#463).
- `pipelock learn ratify --accept-low-confidence` flag to deliberately ratify candidates containing low-confidence rules; default behaviour refuses (#493).
- `pipelock learn promote` and `pipelock learn rollback` activation-lifecycle subcommands wired to the signed two-phase commit + atomic active-manifest swap (#461).
- Runtime contract evaluation package landed for contract-aware decisions (#460); production proxy integration ships in this release across every gated transport plus the MCP tool-call surface (#482, #483, #484, #485, #486, #487, #488, #489, #490).
- Path normalisation with cardinality cap and operator pin/split surface (#454).
- Inference confidence and exposure gates with Wilson lower bound and conditional-on-opportunity denominators (#452).
- Compile candidate pipeline scaffolding (#455).
- Capture contract-aware replay fidelity gates (#456).
- Signed shadow delta receipts (#457).
- Shadow replay reports (#458).
- Active manifest store (#459).
- Cryptography pin bump (#450).
- CI actions group bumps (#446, #451, #477).
- Go-deps group bumps: `github.com/fsnotify/fsnotify` (#476).
- Dependency automation moved from Dependabot to Renovate with a routine-update cooldown; Docker base image updates, pinned image-tag refreshes, and the TypeScript verifier dependency refresh are handled through that path. (#543, #544, #547, #554)
- Helm chart `appVersion` bumped to `2.5.0`.
- pipelab.org pages refreshed (separate site PR).

### pipelock-verify-python

The current published `pipelock-verify-python` package remains 0.1.x at the time these notes were prepared. A 0.2.0 verifier update is prepared separately to add individual EvidenceReceipt v2 verification for all 13 payload kinds, RFC 8785 JCS canonicalisation, RFC 9421 well-known directory fetch helper, and a key-purpose authority matrix that rejects valid signatures from the wrong purpose or wrong root. Until 0.2.0 is published, use the Go reference verifier for EvidenceReceipt v2. v1 chain verification is unchanged; auditors verifying ActionReceipt v1 chains see no behaviour change. EvidenceReceipt v2 chain verification remains a follow-up.

## [2.3.0] - 2026-04-24

### Highlights

Two headline features. **Class-preserving redaction v1** lands as a first-party feature: irreversible, typed-placeholder request-side redaction wired into the fetch / forward / TLS-intercepted / reverse HTTP paths, outbound WebSocket client messages, and MCP `tools/call` `params.arguments` across every MCP transport. **Generic SSE streaming**: the existing A2A-gated streaming path is generalized so every `text/event-stream` response (OpenAI chat completions, Anthropic messages, Kilo Gateway, any LLM SSE) streams inline with per-event DLP and injection scanning, preserving token-by-token UX while keeping body scanning on. Plus a substantial tech-debt pass: runtime server lifecycle extraction, runtime policy resolution consolidation, canonical-hash golden-fixture test, `internal/config` mechanical split, and MCP transport pipeline stage extraction (helpers + HTTP + stdio migrations closing the MCP refactor arc). Remaining tech-debt items (metrics reshape, reverse-proxy scanner close-on-reload, `toolBaseline` drift rebuild, reverse-proxy receipt parity) are queued for v2.4 alongside learn-and-lock design.

### New Features

- **Class-preserving redaction (v1).** New `internal/redact/` library. Matched values are replaced in place with typed placeholders such as `<pl:aws-access-key:1>`, one placeholder per `(class, occurrence)`, so downstream tools can reason about field shape without seeing the secret. Irreversible; no vault. Fail-closed on parse errors. Configured via the new `redaction` config section with per-profile class enablement, optional dictionaries, and limits (`max_body_bytes`, `max_redactions_per_request`, `max_depth`). (#413)
- **Redaction wired into every request-side HTTP transport.** Fetch, forward, reverse, and TLS-intercepted CONNECT paths apply the redaction pipeline to outbound JSON request bodies when enabled. Outbound WebSocket client messages sent through `/ws` go through the same matcher. JSON rewrite uses `json.Decoder.UseNumber()` to preserve numeric fidelity, HTML escaping is disabled on the re-serialized JSON so LLM-bound bodies stay byte-readable, and both keys and values in `map[string]interface{}` are walked to prevent key-smuggling evasion. (#416)
- **Redaction on MCP `tools/call` arguments.** `params.arguments` is redacted before forwarding on every MCP transport: stdio subprocess, Streamable HTTP upstream, the HTTP listener, and MCP-over-WebSocket. Tool responses are NOT redacted in this release (request-side only); transport parity across the four MCP surfaces is proven by regression tests. (#420)
- **Generic SSE streaming with inline scanning.** `text/event-stream` responses no longer buffer. Forward proxy, TLS interception, and reverse proxy (previously buffered entirely with a 1 MB cap) all stream events through with per-event DLP and injection scanning. Clean events flush immediately; detection terminates the stream with a `sse_stream` layer label. Warn mode logs findings and continues forwarding. New `response_scanning.sse_streaming` config section: `enabled` (default `true`), `action` (`block` / `warn`, default `block`), `max_event_bytes` (default `65536`). Existing `response_scanning.exempt_domains` and global `suppress` rules apply before SSE action selection. When `enabled: false`, SSE responses still stream with per-read flushing. Compressed SSE streams are rejected fail-closed. Existing A2A-specific scanning is preserved untouched. (#429)
- **Downstream receipt detection integration guide.** New docs section explaining how SIEMs, audit platforms, and CI workflows verify and chain pipelock action receipts. (#418)

### Documented limitations

- Generic SSE scanning inspects each event's `data:` payload independently. Cross-event payload splitting (a secret broken across two sequential events) is NOT detected in v1; A2A's rolling-tail scanner still catches that case for A2A traffic. Tracked as a follow-up.

### Internal Refactors (tech-debt sprint)

These refactors do not change external behavior but materially improve code health, testability, and coverage ceilings. Shipped as a sprint to clear the TD board before v2.4 / learn-and-lock work opens.

- **TD-1: Frozen config + `ResolveRuntime` clone path.** Runtime policy resolution consolidated into `Config.ResolveRuntime`, eliminating duplicate resolution paths across the CLI and MCP entry points. Loaded config is frozen; runtime policy views are produced by cloning and resolving per-request. (#422)
- **TD-3: Non-blocking CI debt tracker.** New `hardening-report` job surfaces gocyclo / gocognit / maintidx / dupl metrics per PR without blocking merges, giving contributors visibility into regression trends. (#422)
- **TD-5: Runtime server lifecycle extraction.** `pipelock run` no longer owns the lifecycle; it delegates to a new `Server` type with `NewServer`, `Start`, `Shutdown`, `Reload`, and `cleanup` methods. Unlocks `internal/cli/runtime/` coverage ceiling. Six spec tests landed. `RegisterKillSwitchSignal` decoupled from Cobra. A Codex polish pass closed two hot-reload gaps: scan API per-request config/scanner/policy resolution, and MCP listener function-pointer-driven per-message snapshotting. (#424)
- **TD-2a: Canonical-hash golden fixtures (pre-req for TD-2b).** New `canonical_golden_test.go` pins the current `CanonicalPolicyHash` output against a fixed-input config so the mechanical split could not silently invalidate every receipt signed against the current schema. (#425)
- **TD-2b: `internal/config` mechanical split.** The 5,170-LOC `internal/config/config.go` is split into `schema.go`, `defaults.go`, `normalize.go`, `validate.go`, `reloadwarn.go`, `load.go`, and `schema_receiver_methods.go`. Validators now return `[]Warning` instead of writing to stderr. Callers (CLI + verify_install diagnostics) print the returned warnings. No semantic change; the TD-2a canonical-hash golden fixtures prove byte-equivalent policy output. (#431)
- **TD-4 groundwork: transport-parity fixtures + stage helpers.** Eight-test transport-parity harness covering stdio, HTTP, and WebSocket MCP transports locks down the per-transport behavior before extraction. New `MCPFrame` and `MCPDecision` helpers are factored out so pipeline stages (parse / policy / decision / relay) become independently testable. (#426, #427)
- **TD-4 migration: MCP-inbound decision path uses stage helpers (HTTP + stdio).** 34 scattered `extractRPCID` / `extractToolCallName` / `extractToolCallArgs` calls replaced by one `ParseMCPFrame` per message. Six direct receipt/envelope emission sites collapse to one `EmitMCPDecision` helper. New `pipeline_gates.go` holds `EvaluateMCPInputGatesHTTP` and `EvaluateMCPInputGatesStdio` so the gate-evaluation order is identical across transports (policy/taint/redaction/session-binding ordering preserved per the parity fixtures). `ForwardScannedInput` migrated; the MCP refactor arc is closed. Forward / intercept / websocket pipeline migrations deferred to v2.4 per Codex guidance ("don't turn this into abstraction theater"). (#428, #432)

### Fixed

- **Dangerous Capability regex false-positive on runtime-family nouns.** Replaced `(execut|run|launch|spawn)\w*` with explicit verb-form enumeration so `runtime`, `runner`, `launcher`, and `spawner` nouns no longer trigger the tool-poisoning pattern. Seven regression cases added. (#423)
- **Browser Shield binary media short-circuit.** The `shield.DetectPipeline` classifier now runs before the `max_shield_bytes` ceiling, so image / audio / video / PDF / arbitrary binary responses short-circuit out of shield processing. Fail-closed preserved for HTML / JS / SVG. (#421)
- **Sentry noise reduction.** `context.Canceled` errors no longer reach `CaptureError`, dropping a class of benign Sentry reports generated during normal shutdown and timeout paths. (#412)
- **DLP coverage downgrade warning on reload.** `removedOrWeakenedDLPPatterns()` now diffs by `(name, regex)` identity instead of count alone. A reload that replaces a strong regex with a weaker one under the same pattern name was previously silent (count stayed constant). It now surfaces as a reload warning, preserving the "hot reload must preserve security state" invariant. (#433)
- **SSRF DNS failures stay adaptive-neutral.** DNS resolver failures during SSRF checks were classified like threat blocks, so repeated lookup errors could accumulate adaptive `SignalBlock` points and push sessions into airlock. New `ClassInfrastructureError` + `IsAdaptiveNeutral()` helper unifies protective enforcement and infrastructure errors. Fail-closed semantics preserved: requests still block when DNS cannot be verified, but resolver failures no longer count as threat evidence. Honored on the scanner, adaptive enforcement, TLS intercept, forward, WebSocket, and MCP HTTP A2A paths. Also folds in a CodeRabbit follow-up from #429: `TestScanGenericSSEStream_LargeMaxEventBytes` covers `max_event_bytes` values above `bufio.Scanner`'s 64 KB default in both block and warn modes. (#434)

### Security Hardening

- Redaction library runs fail-closed on parse errors. A malformed JSON body is blocked rather than forwarded.
- Generic SSE streaming rejects compressed streams fail-closed. Body scanning cannot be bypassed by requesting `Content-Encoding: gzip` on an SSE response.
- Redaction walks map keys as well as values, so secrets stuffed into JSON keys are caught.
- Reload-time DLP coverage downgrades (same-length pattern replacements) now surface as warnings instead of being silently accepted.

### Other

- Detection integration guide at `docs/detection-integration/`. (#418)
- Tool-response-injection demo points at the published `pipelock-verify` PyPI package instead of a vendored copy. (#411)
- CI composite-action download retry budget hardened. (#410)
- Dependabot bumps for the `ci-actions` group (3 updates) and `go-deps` group (3 updates). (#414, #415)
- Helm chart `appVersion` bumped to `2.3.0`.

## [2.2.0] - 2026-04-17

### ⚠️ Breaking Changes

- **Strict YAML config parsing (#390, #403).** `config.Load()` now rejects unknown top-level and nested fields with a clear error message naming the offending field and line. Configs that silently worked on v2.1.2 — for example, with typos like `sentinel_path` (real field: `sentinel_file`) or `threshold` (real field: `escalation_threshold`) — will fail to load on v2.2.0. **Migration:** run `pipelock check --config <path>` against every config before upgrading, or diff your configs against `configs/balanced.yaml` / the [Configuration Reference](docs/configuration.md). Known renamed fields emit a `staleFieldHint` in the error so the fix is usually one-line. Multi-document YAML (`---` separators) is also rejected; a single policy document per file is required.

### Highlights

The v2.2.0 operationalization arc wires the receipt system into every transport, adds sidecar-injection deployment, and lands a full operator CLI for airlock recovery. The mediation envelope rides sideband metadata on every proxied request so downstream services see pipelock's verdict, action, actor identity, and receipt correlation ID without parsing logs — and now carries an optional RFC 9421 HTTP Message Signature with a canonical policy hash so verifiers can validate the envelope byte-for-byte and detect reformatting-vs-behavioural config changes. Media policy reduces the risk of covered steganographic exfiltration paths by stripping EXIF/XMP/IPTC metadata from JPEG and PNG, rejecting audio/video by default, and hardening SVG active content. Posture capsule graduates into a full verify CLI with a scoring model and a CI gate. DLP patterns can now run in warn mode for safe rollout of new detections, with audit emission wired through the runtime lifecycle. Rules bundles gain tier classification, RequiredFeatures enforcement, and a new `pipelock rules status` subcommand. Taint-aware policy escalation spans all MCP transports with task boundaries scoping trust overrides to individual operations. Action receipt coverage extends into fetch error paths, the MCP proxy itself, WebSocket, and A2A, with a cross-implementation conformance suite and a reference Python verifier. Pre-tag hardening closed media policy parity gaps, made recorder resume atomic with tail-entry signature verification, tightened posture integrity checks, and polished CLI diagnostics for misconfigured public-key paths.

### New Features

#### Deployment and operator tooling
- **Sidecar injection init:** `pipelock init sidecar --inject-spec <manifest>` generates a companion-proxy sidecar patch for Deployment, StatefulSet, Job, and CronJob workloads. Three output formats: strategic-merge patch, Kustomize overlay, and Helm values fragment. Includes canary verification, diff preview, idempotent re-runs, HA defaults with PodDisruptionBudget, config hot reload, and a configured proxy-first network topology. (#400)
- **`pipelock install <dest>` hidden subcommand:** Copies the running binary to a destination path for scratch-based sidecar init containers that need to populate a shared-bin volume without `/bin/sh`. Rejects symlinks and non-regular destinations and writes atomically via temp-file-rename so a partial copy is never observable at the final path. (#408)
- **Bound default agent identity:** sidecar-generated deployments set `bind_default_agent_identity: true` with a derived `default_agent_identity`. Header/query-based agent identity (`X-Pipelock-Agent`, `?agent=`) is ignored for the bound workload, preventing agent spoofing in single-workload companion mode. Shared-proxy multi-agent identity remains deferred follow-up work (tracked in roadmap). (#400)
- **Exemption audit emission:** response-scan exemptions (exempt domains and suppressed findings) emit a `pipelock_response_scan_exempt_total` Prometheus counter with `reason` and `transport` labels across all proxy transports. (#400)
- **`pipelock session` operator CLI:** five subcommands (`list`, `inspect`, `explain`, `release`, `terminate`) plus an interactive `recover` wrapper for airlock recovery. Resolves the admin endpoint from `--api-url` / `--api-token` flags, `PIPELOCK_API_URL` / `PIPELOCK_KILLSWITCH_API_TOKEN` env vars, or the pipelock config file. `list` accepts `--tier=hard` to filter sessions by airlock tier. (#399)
- **Session admin API: inspect, explain, terminate endpoints.** `GET /api/v1/sessions/{key}` returns full session detail including airlock entry time, in-flight count, and recent events. `GET /api/v1/sessions/{key}/explain` returns the recorded trigger, evidence, and next auto-deescalation estimate. `POST /api/v1/sessions/{key}/terminate` performs a destructive full tear-down (cancel in-flight, reset enforcement, clear CEE state). Each *mutating action* (`reset`, `task`, `trust`, `airlock`, `terminate`) and each *detail lookup* (`inspect`, `explain`) has its own 10/minute sliding-window rate-limit bucket; `GET /api/v1/sessions` (list) is intentionally unbounded so recovery tooling can poll. Session list accepts `?tier=hard`; `normal` is an alias for `none`. (#399)

#### Mediation envelope, media policy, taint
- **Mediation envelope** (`mediation_envelope.enabled: true`) attaches sideband metadata to every proxied HTTP request via a `Pipelock-Mediation` header (RFC 8941 Structured Fields Dictionary) and to MCP requests via `_meta["com.pipelock/mediation"]`. Wire fields: action, verdict, actor identity + auth level, policy hash (`ph`), receipt correlation ID, taint state, task ID, authority kind/ref, re-auth requirement. Inbound stripping removes any forged envelope or `pipelock`-prefixed signature members. Envelope signing shipped in v2.2.0; SPIFFE actor format and well-known key discovery remain follow-up work. (#374, #403)
- **Media policy** (`media_policy`) enforces image/audio/video response handling. Audio and video are rejected by default; images are allowed with size limits (5 MiB default) and metadata stripped. JPEG surgery removes APP1 (EXIF, XMP), APP2 (ICC, FlashPix), APP13 (IPTC, Photoshop) markers while preserving APP0 (JFIF) and pixel data. PNG surgery removes tEXt, iTXt, zTXt, eXIf chunks while preserving IHDR/IDAT/PLTE/tRNS/IEND. Decompression-bomb defense runs before any parsing. (#382)
- **SVG active content hardening** handles `image/svg+xml` through the browser shield pipeline: strips `<foreignObject>` elements (including namespace-prefixed variants), `on*` event handlers (quoted and unquoted attrs), external `xlink:href` and `href` references (local `#id` fragments preserved), hidden `<text>` elements (`opacity:0`, `display:none`, `visibility:hidden`), `<script>` blocks, and animation injection via `<set>`/`<animate>` targeting href. (#382, #393)
- **Steganographic Unicode stripping** extends the normalization pipeline: zero-width characters (U+200B-U+200F, word joiners), variation selectors (U+FE00-U+FE0F, U+E0100-U+E01EF), Unicode Tags block, bidirectional overrides, and 18 exotic whitespace codepoints are stripped before DLP matching. `ZalgoDensity` detects 3+ stacked combining marks per base character as suspicious for taint signaling. (#382)
- **Taint-aware policy escalation across MCP transports:** Sessions classify inbound sources (URL, MCP tool result) for taint level, track contamination state across transports, and evaluate action sensitivity before allowing protected operations. Works identically on MCP stdio, MCP HTTP/SSE, WebSocket, and forward proxy paths. Configuration via `taint.*` with `allowlisted_domains`, `protected_paths`, `elevated_paths`, `trust_overrides`, `policy`, and `recent_sources`. (#383)
- **Task boundaries for taint-scoped trust overrides:** Trust overrides are scoped to an individual task ID rather than the whole session. When a task completes, its trust override expires automatically. Session taint level and recent taint sources are carried on every emitted receipt. (#384)
- **Edge-triggered airlock:** Airlock activation from adaptive-enforcement escalation is now edge-triggered. Airlock fires on the transition into elevated/high/critical, not on every request at the same level. Prevents drain→hard→drain loops when a session plateaus at an escalated level. (#388)

#### Envelope signing and canonical policy hash
- **RFC 9421 envelope signing:** the mediation envelope (Pipelock-Mediation header and the `com.pipelock/mediation` MCP `_meta` key) now supports Ed25519 HTTP Message Signatures over a per-request component list. Signing is opt-in via `mediation_envelope.sign: true` plus an Ed25519 signing key path. The pipelock signature uses the `pipelock1` dictionary label and the `pipelock-mediation` tag so it coexists with upstream `sig1` / Web Bot Auth signatures on the same request. New config fields: `sign`, `signing_key_path`, `key_id`, `signed_components`, `created_skew_seconds`, `max_body_bytes`. Fail-closed at startup if `sign: true` is set without a readable Ed25519 key; reload with an unreadable key aborts the entire config swap rather than silently downgrading to unsigned. (#403)
- **Canonical policy hash:** `ph` (the first 16 bytes of the policy hash dictionary key) now derives from a canonicalised, slice-order-preserving JSON projection of the effective config instead of the raw YAML bytes. Reformatting, comments, and reordering noise fields no longer shift `ph`, while behavioural rule reorders (DLP patterns, MCP tool policy rules, chain rules) still do. This makes `ph` admission-grade for downstream verifiers. Per-agent resolved configs each compute their own canonical hash and stamp it via `BuildOpts.PolicyHash` at the transport inject site. (#403)
- **Envelope redirect refresh:** on every allowed redirect through the fetch or forward proxy, pipelock rebuilds the Pipelock-Mediation header on the redirected request so `@target-uri`, `hop`, `ph`, and `action` reflect the redirected leg. Stale Content-Digest is dropped and the signature is re-attached (when signing is enabled). The new `hop` dictionary key counts refresh hops; original requests omit it. (#403)

#### Receipts
- **Extended signed-receipt coverage across every transport (#402):**
  - Fetch handler error paths: audit-mode escalation decisions, session profiling blocks, header DLP, budget exhaustion, cross-request exfiltration detection.
  - WebSocket: handshake-time blocks, frame-level DLP, injection, address-poisoning, CEE blocks, session close.
  - A2A in the forward proxy: header scan, stream scan, response body scan.
- **Fetch error-path receipt coverage:** Post-forward deny paths (redirect block, response scan block) now emit block receipts. Foundation for #402. (#377)
- **Action receipts from MCP proxy:** The MCP proxy emits signed action receipts for every tool call, tool response, and policy decision across stdio, HTTP, and HTTP reverse proxy transports. (#385)
- **Cross-implementation receipt conformance suite:** `sdk/conformance/` ships golden test vectors with deterministic seeds so any language implementation can verify byte-for-byte against the Go reference. Reference Python verifier at [pipelock-verify-python](https://github.com/luckyPipewrench/pipelock-verify-python). (#379)

#### Posture
- **Posture capsule verify CLI:** `pipelock posture verify` evaluates a signed capsule against a named policy (`enterprise`, `strict`, or `none`), computes a weighted evidence score (0-100), and exits with distinct codes for integrity vs policy failure. Flags: `--policy` (default `enterprise`), `--min-score` (default `85`, pass `0` to skip), `--max-age` (default `30d`, `Nd` format only), `--max-receipt-age` (default `7d`, `Nd` format), `--require-discovery`, `--json`. Strict policy treats zero-discovered-MCP-servers as a hard failure (vacuous-truth gap closed). Policy version bumped to `"2"`. (#391, #397, #398)
- **Posture verify CI gate:** Exit codes are part of the CLI's stable contract. Exit `0` = verification passed. Exit `1` = verification could not complete (bad proof, bad key, signature failed, expired capsule, schema mismatch). Exit `2` = verified but failed (signature valid, policy gates or min-score gate did not pass). `--json` output carries failure details for machine consumption.

#### DLP and rules
- **DLP per-pattern warn mode:** Individual DLP patterns can carry `action: warn`. Warn matches route to an `InformationalMatches` audit channel rather than triggering enforcement — useful for safely rolling out new detections in production traffic. Top-level `dlp.action` remains rejected (patterns-only override). (#392)
- **DLP warn audit emission in runtime:** The `DLPWarnHook` is wired through the runtime lifecycle so warn matches emit structured audit events with the matched pattern name, severity, and transport context. Works across URL DLP, text DLP, and fragment buffer scanning. (#396)
- **Rules tier and RequiredFeatures:** Rule bundles declare a `tier` (`standard`, `community`, `pro`) and a `required_features` list (e.g., `dlp`, `checksum`). Unknown features cause the bundle to fail to load with a clear error. Standard-tier rules can be loaded from disk via `rules.standard_dlp_source` / `rules.standard_response_source`. Core SSRF literal enforcement is unconditional regardless of bundle tier. (#373)
- **`pipelock rules status` command:** Reports health, core tier source, standard DLP/response counts, and a per-bundle breakdown (tier, version, rule counts, signed status). JSON output via `--json`. (#373)

#### Scanner and examples
- **Multipart DLP full coverage:** All multipart part bodies are scanned regardless of declared Content-Type. Parts declaring `image/png` or other binary types with text content are no longer skipped. Custom part headers are scanned. Content-Transfer-Encoding (base64, quoted-printable) is decoded before scanning. (#370)
- **Tool-response-injection example harness:** `examples/tool-response-injection/` is a runnable demo showing an MCP tool whose harmless name and description hide a prompt injection in the response body. Demonstrates the block + signed receipt flow across MCP stdio, MCP HTTP, and MCP HTTP reverse proxy with a single shared signing key. (#387)

### Security Hardening

- **Stale-field `hint:` lines** accompany the strict-YAML error (see Breaking Changes above). Known rename map includes `scan_api.enabled` (removed; listener auto-starts when `listen` + `auth.bearer_tokens` are set) and `flight_recorder.path` → `flight_recorder.dir`. Run `pipelock check --config <path>` after upgrade; the hint points at the canonical field or doc reference.
- **Typed LogContext refactor:** Structured log context fields split URL into semantic components (scheme, host, path, query) and route them through typed constructors. Eliminates an entire class of misrouted field bugs. (#378, #389)
- **Exposure-based policy escalation across MCP transports:** Hardened the taint classification and authority evaluation across stdio, HTTP, and HTTP reverse proxy so a contaminated session cannot bypass protected-path gates by switching transports. (#383)
- **Edge-triggered airlock regression test:** Dedicated test ensures airlock does not re-enter drain on plateaued escalated sessions. Closes the drain-hard-drain loop observed in adaptive enforcement testing. (#388)
- **Core SSRF literal unconditional:** Private-IP literal blocking is now part of the immutable core scanner and cannot be disabled by config or bundle configuration. (#373)
- **Session-admin API terminate gate:** `terminate` has its own 10/minute rate-limit bucket independent of other admin endpoints and requires the full kill-switch API token; cannot be issued via the main proxy port. (#399)
- **Structured-fields-safe inbound envelope strip:** `envelope.StripInbound` now parses `Signature` / `Signature-Input` as RFC 8941 dictionaries via httpsfv before dropping pipelock-labelled members. The previous `strings.Split(val, ",")` path treated commas inside quoted parameter values as member separators, corrupting surviving members and leaving dictionary residue that could bypass inbound sanitisation. (#403)
- **Reverse-proxy envelope signing after Director:** reverse-proxy envelope signing now runs in an `http.RoundTripper` wrapper installed on `httputil.ReverseProxy.Transport`, so `@target-uri` reflects the post-Director upstream URL rather than the inbound relative path. (#403)
- **Request body plumbing for signing:** transport inject sites hand the already-scanned body bytes to the signer so `Content-Digest` is computed without a second drain. When request body scanning is disabled but signing is enabled, the envelope emitter drains `req.Body` itself (bounded by `max_body_bytes`) and installs a fresh `GetBody` closure so stdlib can replay the body on 307/308 redirects. (#403)
- **Internal identity strip on forward and intercept paths:** The `X-Pipelock-Agent` header and `?agent=` query parameter are removed from every outbound request before it leaves pipelock, so a caller-supplied identity hint cannot bleed through to the destination when `bind_default_agent_identity` is set. (#408)
- **Forwarded-IP family strip:** The full set of caller-supplied origin-attribution headers (`X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `Forwarded`, `Via`) is scrubbed on both the forward-proxy CONNECT handler and the TLS-intercept request handler. Pipelock knows the verified client IP and must not pass an attacker-supplied lie through to the backend. (#408)
- **MCP subprocess subtree teardown:** Wrapped MCP children now start in their own process group, use `Pdeathsig = SIGTERM`, enable `PR_SET_CHILD_SUBREAPER`, signal the captured pgid from a context-cancellation watcher, and sweep `/proc` for adopted descendants after the pgid kill drains. This closes the common orphaned-child path on normal shutdown and cancellation; hard `SIGKILL` of pipelock itself still requires deployment guidance tracked for v2.2.1. (#408)
- **Content-scanner URL redaction:** Blocks attributed to content-matching scanners now truncate the URL/target to `scheme://host/[redacted]` in structured audit logs and in the fetch proxy's client-facing 403 response body, closing a secret-echo path on query-string DLP hits. (#408)
- **Media policy all-field coverage:** MCP tool-result media payloads are now scanned across every populated `data`/`blob`/`raw` slot rather than stopping at the first non-empty field, closing a bypass where a benign value in `data` could shield blocked media stashed in `blob` or `raw`. (#404)
- **Pure-media tool results routed past prompt scanning:** `jsonrpc.ExtractText` returns only collected `Text` fields once a `ToolResult` parses, so base64 image/audio/video payloads no longer feed into response-injection scanning as raw text. (#404)
- **Flight recorder startup writability probe and mid-run recovery:** Pipelock now refuses to start when `flight_recorder.dir` is not writable, and `ensureFile` re-stats the directory on every entry so a mid-run evidence-directory deletion is caught, recreated, and reopened cleanly instead of silently dropping the audit trail. (#408)
- **Flight recorder signing-key rotation rejected on reload:** Hot-reloading a new `flight_recorder.signing_key_path` would break chain verification, so the reloader preserves the previously loaded key, logs a restart-required warning, and keeps the in-flight chain intact. (#408)
- **Recorder resume is atomic with tail-entry verification:** `resumeSessionLocked` now computes the resumed `sessionID`/`seq`/`prevHash` into local temporaries and only mutates the `Recorder` after `sessionFiles`/`ReadEntries` succeed, so a transient read error no longer leaves a half-initialised chain that restarts from genesis. The receipt-chain resume path additionally verifies the signature of the last persisted receipt before trusting it, and parses recorder sequence numbers as `uint64` (strconv.ParseUint) to keep file ordering correct on 32-bit builds or when sequences exceed `math.MaxInt`. (#404)
- **Posture strict-mode integrity:** posture verify under the strict policy rejects zero-discovered-MCP-server capsules rather than treating an empty discovery set as a vacuously passing score. (#404)
- **Optional-metrics guard in DLP warn emission:** `emitDLPWarn` guards the `*metrics.Metrics` handle with a nil check so the first warn-only DLP match in MCP runtime configs without session profiling emits audit/receipt output instead of panicking. (#404)
- **Config reload coalescing:** fsnotify file-change events and SIGHUP signals are deduplicated so a single config mutation fires exactly one reload even when both arrive in the same two-second window. Single no-op SIGHUPs still emit an acknowledgement so operators can see the signal was received. (#408)
- **Sandbox `--best-effort` degraded-mode warning:** When user namespaces are unavailable and pipelock falls back to `HTTP(S)_PROXY`-only enforcement, a loud startup warning now ships alongside the `DEGRADED` posture banner on both `pipelock sandbox --best-effort` and `pipelock mcp proxy --sandbox-best-effort`. (#408)
- **Broader network-exfil tool policy:** The default tool policy regex for outbound curl-style uploads now covers `-F`, `--form`, `--data-binary`, `--data-raw`, `--data-urlencode`, `--post-file`, `--body-data`, and `--body-file` across all six preset configs. (#408)

### Examples & Docs

- **Deployment recipes by enforcement tier:** `docs/guides/deployment-recipes.md` groups the standard deployment patterns (companion, shared, managed) by the enforcement posture they provide. (#390)
- **Mediation envelope, media policy, receipt verification guides** added to `docs/guides/`. Configuration reference expanded for both new sections.
- **Attacks-blocked gallery** adds SVG active content injection, steganographic metadata exfiltration, and tool response injection entries with config that blocks them.
- **Bypass-resistance matrix** adds media/SVG evasion, exotic whitespace, and zalgo rows.
- **README** restructured defense matrix with mediation envelope, media policy, taint escalation, and receipt conformance rows plus a tool-response-injection demo section.
- **Posture capsule guide** expanded with full `pipelock posture verify` reference (flags, exit codes, strict vs enterprise policies, scoring model, CI example).
- **Rules guide** expanded with `pipelock rules status`, tier taxonomy, RequiredFeatures, standard tier source overrides, and core SSRF literal note.
- **Configuration reference** adds Taint-Aware Policy Escalation section with full `taint:` block + task boundary + trust override semantics and a DLP Per-Pattern Warn Mode subsection.

### Fixed

- **Strict posture vacuous-truth gap:** Zero-discovered-MCP-servers under the strict policy now fails the verify gate rather than silently passing with a 100/100 score. Enterprise policy retains the warning semantics for non-MCP deployments. (#398)
- **Receipt emission for post-fetch deny paths:** Blocks at the fetch-handler redirect or response-scan stages now emit signed block receipts. Previously these paths returned errors with no receipt. (#377)
- **WebSocket DLP warn hook timing:** Race between hook registration and warn match emission in WebSocket relay paths closed. (98074d81)
- **MCP HTTP/stdio receipt parity:** Receipt emission state survives config reload across all MCP transports. (#385)
- **Log context field routing:** Typed constructors close routing bugs where URL fields landed in unrelated context keys. (#389)
- **Accurate MCP block-response wording:** Tool-poisoning blocks and provenance-verification failures now use a dedicated block-reason helper so operators see the actual cause instead of a generic prompt-injection message. (#408)
- **Duplicate posture public-key error prefix:** `loadPublicKey` no longer wraps `"loading public key"` on errors that `postureVerifyCmd` already prefixes, so diagnostics render cleanly. (#404)
- **Transcript root derives session ID from evidence file:** `transcript-root` now reads the session ID from the evidence file's first entry when `--chain` is unset instead of defaulting to the `--session` flag, so JSONL captures from any session print the correct `SessionID`. Empty evidence sets fail with a non-zero exit code. (#404)
- **File-path diagnostics for public-key loading:** `signing.LoadPublicKey` surfaces the underlying `os.ErrNotExist` when the input looks like a filesystem path (contains a separator, starts with `.`, or has an extension), replacing the confusing `"invalid public key"` error that previously masked typo'd paths. (#404)

### Developer & CI

- **govulncheck bumped to Go 1.26.2** in CI. (#376)
- **Strict YAML validation of example configs** ensures every shipped preset loads cleanly under the new unknown-field rejection. (fae9e181)
- **Example configs no longer embed self-scan-triggering credential strings.** Examples use `Credential`-with-colon text that reads naturally without matching DLP patterns. (421b79c2)
- **Patch coverage raised on v2.2.0 additions.** `internal/signing` 95.6%, `internal/receipt` 91.4%, `internal/mcp` 90.4%, `internal/posture` 96.7%, `internal/recorder` 92.8%. New tests focus on the error paths that shipped in the pre-tag hardening PR. (#406)

## [2.1.2] - 2026-04-06

### Highlights

Every proxy decision now produces a cryptographically signed action receipt: verdict, policy hash, transport, and target recorded as a hash-chained evidence trail. New onboarding tools (`pipelock init`, Helm chart, false positive tuning guide) cut first-run setup to minutes. Runtime hardening adds connection-level admission control, browser-aware response scanning, and environment classification. An immutable core scanner layer runs before all configurable patterns and cannot be disabled.

### New Features

- **Action receipts:** every proxy decision produces an Ed25519-signed receipt recording the action type, verdict, policy hash, transport, method, and target. New `internal/receipt/` package. `pipelock verify-receipt` CLI command validates receipt signatures. Receipts are written to the flight recorder. (#351)
- **Hash-chained receipts and transcript roots:** receipts link to their predecessor via `chain_prev_hash` and `chain_seq`, forming a tamper-evident chain. `EmitTranscriptRoot()` seals the chain with a transcript root entry. `pipelock verify-receipt` validates individual receipts and chain integrity. (#354)
- **Onboarding stack:** `pipelock init` discovers IDE configs, generates a starter YAML config, and runs canary verification against the running proxy. Helm chart at `charts/pipelock/` for Kubernetes deployments. False positive tuning guide for common scanner adjustments. README restructured around getting-started flow. (#355)
- **Airlock admission control:** connection-level admission with a drain tier for graceful shutdown. New connections are rejected when the proxy enters drain state, while in-flight requests complete. (#356)
- **Browser Shield:** domain-aware response scanning exemptions for browser traffic. Domains serving rendered HTML (dashboards, documentation sites) skip injection scanning to avoid false positives on legitimate page content. (#356)
- **Posture Capsule:** runtime environment classification detects whether pipelock runs in a container, on bare metal, or in a cloud instance. Classification is exposed via metrics and audit logs. (#356)
- **Immutable core scanner:** built-in DLP and response injection patterns run before all configurable scanners and cannot be disabled or overridden by config. New `core_dlp` and `core_response` scanner labels. Bundle metadata v2 adds freshness checks, deprecation notices, and build-time pinning for pattern bundles. (#359)

### Security Hardening

- **TLS interception receipts:** TLS-intercepted traffic now produces action receipts across 19 emission points in the intercept pipeline. Previously, intercepted requests were scanned but not recorded in the receipt chain. (#362)
- **Flight recorder DLP redaction:** receipt fields containing target URLs and matched patterns are scrubbed by the DLP pipeline before writing to the flight recorder. Receipt structure fields (signature, signer_key, chain hashes) are preserved. Summary field no longer includes raw matched content. (#362)
- **Receipt emitter hot reload:** signing key can be added, removed, or rotated via SIGHUP without restarting the proxy. Receipt emission state survives config reloads. (#362)
- **A2A SSE streaming receipts:** Server-Sent Event streams in the A2A protocol path now produce per-event receipts. (#362)
- **Multipart body scanning:** all multipart part bodies are now scanned regardless of declared Content-Type. Parts declaring image/png or other binary types with text content are no longer skipped. Custom multipart part headers are scanned for DLP patterns. Content-Transfer-Encoding (base64, quoted-printable) is decoded before scanning. Structural header parameters (Content-Disposition, Content-Type values) are parsed and scanned. (#370)

### Fixed

- **Inline suppression in scan-diff:** `pipelock:ignore` inline comments are now respected in GitHub Action scan-diff mode. Previously, suppression comments were only processed in full-scan mode. (#365)
- **Airlock drain timeout:** drain timeout now reads from config instead of using a hardcoded default. (#371)
- **Browser Shield redirect hostname:** post-redirect hostname is used for domain matching instead of the original request hostname. (#371)
- **Session manager lock TOCTOU:** time-of-check-to-time-of-use race in the session manager lock acquisition path is closed. (#371)
- **Quarantined session eviction:** quarantined sessions are protected from LRU eviction. (#371)

### Other

- **Documentation cross-references:** README restored with full feature content, security matrix, and pipelab.org cross-references. OWASP coverage table added. (#363)
- **CI dependency updates:** GitHub Actions bumped across CI workflows. (#358)
- **Go dependency updates:** modernc.org/sqlite bumped from 1.48.0 to 1.48.1. (#357)

## [2.1.1] - 2026-04-03

### Highlights

Scanner hardening and internal quality release. Nine security fixes close gaps found during Gauntlet benchmark development. Recursive response decoding catches multi-layer encoding evasion. Continuous fuzzing via ClusterFuzzLite. Major refactors reduce parameter sprawl across the proxy and MCP packages. New Codex integration guide.

### Security Hardening

- **SSRF trust gap closed:** allowlisted domains resolving to internal IPs now correctly bypass SSRF checks only for DNS results, not for encoded IP literals in the URL. Prevents trust domain bypass via hex/octal IP encoding. (#334)
- **MCP batch request rejection:** JSON-RPC batch requests (JSON arrays) rejected at ingress. Batch requests could bypass per-request scanning by bundling multiple operations. (#335)
- **SSRF hex/octal IP decoding:** SSRF scanner decodes hex (`0x7f000001`), octal (`0177.0.0.1`), and decimal (`2130706433`) IP representations before private-range checks. Separate subdomain entropy threshold prevents false positives on short hostnames. (#336)
- **MCP input DLP hardening:** new DLP patterns for MCP tool arguments including path-based exfiltration and additional coverage for encoded payloads. (#337)
- **Chain detection and shell obfuscation:** expanded chain pattern matching and shell obfuscation normalization for additional evasion techniques. (#338)
- **Hangul Filler normalization:** Unicode codepoints U+115F, U+1160, U+3164 (Hangul Fillers) added to invisible character stripping. Prevents pattern matching evasion via these characters. (#339)
- **Recursive response decoding:** senary scanner pass now decodes up to 5 layers of nested base64/hex encoding. Previously a single layer was decoded, allowing multi-layer chains (base64→hex→URL) to evade detection. (#344)
- **DLP and tool scanner pattern widening:** broader DLP patterns and tool poisoning detection for improved Gauntlet benchmark coverage. (#348)
- **Injection pattern hardening:** Tool Invocation pattern widened to match varied phrasing ("urgently call a hidden function"). Instruction Boundary pattern now detects Llama 2 `<<SYS>>` closing tag. (#350)

### New Features

- **ClusterFuzzLite integration:** continuous fuzzing on every PR with 9 fuzz targets covering URL scanning, DLP, response scanning, normalization, tool extraction, chain classification, and config parsing. (#339)
- **Codex integration guide:** `docs/guides/codex.md` covers securing OpenAI Codex with pipelock's MCP proxy, forward proxy, and recommended config.
- **Stats drift guard:** `make stats` target and `TestCanonicalStats` verify pattern counts, dependency counts, and preset counts on every PR. (#342)

### Refactored

- **`LogContext` struct:** replaces 8+ repeated audit log parameters across all proxy and MCP packages with a single struct. Reduces parameter passing noise and makes future field additions non-breaking. (#340)
- **`InterceptContext` struct:** replaces repeated TLS intercept pipeline parameters with a structured context. (#340)
- **`BodyScanRequest` struct:** consolidates body scanning parameters, server timeout constants extracted, `OnClose` utility added. (#345)
- **Signal recording consolidation:** shared signal recording logic extracted, `mcp/input.go` split for maintainability. (#346)
- **Relay extraction:** tunnel relay and hop-by-hop header helpers extracted into `relay.go`. (#347)

### Other

- **PR review commands:** `/review tests`, `/review docs`, `/review stats` trigger focused review passes via GitHub Actions. (#339)
- **Numbered comment lists removed:** prevents cascading diff noise when inserting items. (#344)

## [2.1.0] - 2026-03-30

### Added

- **Sandbox `--best-effort` flag:** gracefully degrades when user namespace creation is blocked (e.g. k8s containers with default seccomp). Landlock and seccomp containment layers still apply. Network scanning uses proxy-based routing instead of kernel-enforced namespace isolation. (#289)
- **Sandbox `--env` flag:** pass environment variables to sandboxed processes (KEY or KEY=VALUE, repeatable). Validates against dangerous keys (LD_PRELOAD, NODE_OPTIONS, etc.) that could subvert containment. (#289)
- **MCP proxy `--sandbox-best-effort` flag:** parity with `pipelock sandbox --best-effort` for MCP stdio wrapping mode. (#292)
- **Pure Go netlink loopback:** sandbox uses raw netlink syscalls to bring up loopback inside network namespaces. No `ip` binary required. Works in minimal container images without iproute2. (#289)
- **`pipelock assess` command:** signed security assessments with evidence capture, secret redaction, and HTML report. `assess init` starts a session, `assess run` executes attack simulations and captures evidence, `assess finalize` produces a PDF-ready HTML report with visual hierarchy, remediation guidance, and an optional signed attestation bundle. Secrets and server names are redacted from evidence before output. (#296, #301, #306)
- **`pipelock assess finalize --attestation`:** produces `attestation.json` and a detached Ed25519 signature for the finalized report. `--badge` derives an SVG badge from the attestation. (#314)
- **Compliance evidence mappings:** `internal/report/compliance` maps pipelock controls against OWASP MCP Top 10, OWASP Agentic Top 15, NIST 800-53, EU AI Act, and SOC 2. Compliance atlas threads through `assess finalize` output. (#314)
- **`trusted_domains` for forward proxy:** allowlist domains whose DNS resolves to private IPs without disabling SSRF protection globally. Useful for local inference endpoints and internal services. Community contribution. (#297)
- **`exempt_domains` for response scanning:** per-domain opt-out from injection scanning with DLP still applied. Prevents false positives from high-volume API response traffic. (#305)
- **MCP redirect handlers (built-in):** two built-in redirect profiles — `fetch-proxy` routes matched tool calls through pipelock's fetch proxy with full injection scanning, `quarantine-write` captures file write arguments to a quarantine path for review. Handler output is scanned for injection before returning to the agent. (#307)
- **Session admin API:** `GET /api/v1/sessions` lists adaptive enforcement sessions; `POST /api/v1/sessions/{key}/reset` clears escalation state and allows autonomous block_all recovery after clean traffic. Operations are audit-logged. (#308)
- **Flight recorder:** hash-chained JSONL evidence log with configurable retention, signed checkpoints, DLP redaction, and optional X25519 key escrow for encrypted raw capture. New `flight_recorder` config section. (#309)
- **Agent Bill of Materials (aBOM):** CycloneDX 1.6 BOM generation with declared-vs-observed tool inventory, confidence scoring, and dormant/unexpected tool classification. New `internal/abom` package. (#309)
- **MCP binary integrity:** `internal/integrity` package generates and verifies file manifests (SHA-256, permissions) for MCP server directories. Detects modified, added, removed, and permission-changed files. (#310)
- **Denial-of-wallet detection:** `internal/proxy/dow.go` tracks tool call budgets per session — loop detection, runaway expansion, retry storms, fan-out limits, concurrent call limits, and wall-clock caps. New `denial_of_wallet` config section. (#310)
- **Session manifest and signed decision records:** `internal/manifest` captures versioned session snapshots (policy hash, tool inventory, verdict summary, behavioral fingerprint). `internal/recorder` writes signed decision records per enforcement event. (#312)
- **Canary token detection:** `canary_tokens` config section defines synthetic secrets injected via env vars. Detections trigger a block and audit event. `pipelock canary` CLI helper prints config snippets. (#313)
- **`pipelock simulate` expansion:** simulate command extended with new attack scenarios. Covers DLP exfiltration, prompt injection, tool poisoning, SSRF, and URL evasion. Known-limitation tagging distinguishes scanner gaps from failures. (#313)
- **A2A protocol scanning foundation:** `a2a_scanning` config section enables scanning of Google A2A (Agent-to-Agent) protocol traffic in forward proxy and MCP HTTP proxy paths. Field-aware scanning with agent card poisoning detection, card drift (rug-pull) detection, session smuggling detection, and configurable context caps. (#316)
- **SecureIQLab Docker Compose test harness:** `test/secureiqlab/` provides a ready-to-run environment for validating pipelock against adversarial AI agent attack scenarios. Includes mock LLM, mock MCP server, log collector, and pre-baked pipelock configs. (#318)

### Fixed

- **Sandbox best-effort seccomp:** `io_uring` handling changed from KILL_PROCESS to EPERM so runtimes like Node.js 22 that probe io_uring at startup can gracefully fall back to epoll instead of crashing. (#289)
- **Sandbox seccomp `readlink` syscall:** added `SYS_READLINK` (nr 89) to the allowlist. Node.js/libuv uses the legacy readlink syscall directly, not readlinkat. (#289)
- **Sandbox secret dir validation:** `secretDirs()` now only protects directories that actually exist. Prevents false validation errors in containers. (#289)
- **Sandbox bridge proxy dynamic port:** in best-effort mode, uses a dynamically allocated port instead of the hardcoded 8888. (#289)
- **Config reload — sandbox best-effort:** `sandbox.best_effort` changes are detected during hot reload. Per-agent `best_effort` propagated through enterprise merge. Config validation enforces mutual exclusivity of `sandbox.best_effort` and `sandbox.strict`. (#289)
- **File sentry best-effort mode:** file sentry in MCP proxy mode now respects `best_effort` flag and degrades gracefully when filesystem watching is unavailable rather than failing hard. (#292)
- **Scanner result classification:** scanner results carry a structured classification (category, transport, layer) that drives adaptive enforcement signal recording. Prevents the death spiral where every enforcement event generates a new escalation signal. (#295)
- **Autonomous block_all recovery:** adaptive enforcement sessions at `block_all` level now auto-deescalate after a configurable window of clean traffic. Previously, sessions could be permanently locked out with no recovery path outside of a config reload. (#304)
- **Suppress glob port matching:** strip standard ports (:443, :80) and cross-slash glob for URL patterns. Fixes suppress rules silently failing on TLS-intercepted URLs. (#328)
- **Config defaults via Load():** `applySecurityDefaults` for 8 security-critical booleans and `ApplyDefaults` for all v2.1.0 config structs. Prevents unsafe Go zero values when users partially configure new features. (#328)
- **Adaptive enforcement exempt domains:** exempt domains are now scanned for visibility (findings logged as warn) but adaptive scoring is skipped and actions are not upgraded. Prevents death spiral from LLM response false positives. All 5 transports. (#328)
- **DoW tracker wiring:** denial-of-wallet tracking wired into MCP stdio, HTTP, and WS proxy paths. `dow_action: warn` mode supported. Falls back to `_default` agent profile for free tier. (#328)
- **Behavioral baseline directory auto-creation** in `NewManager`. (#328)
- **License gate preserves `_default` profile** when rejecting unlicensed named agents. (#328)
- **Feature wiring:** FlightRecorder, BehavioralBaseline, MCPToolProvenance, and MCPBinaryIntegrity connected to proxy runtime. Previously config-only stubs. (#328)
- **Provenance audit logging** for block and warn-mode unsigned tools. (#328)
- **DoW metadata backfill** for scan-disabled configurations. (#328)

### Refactored

- **Shared escalation recording helper:** `decide.RecordEscalation` extracted as a shared helper used by all proxy and MCP enforcement paths. Eliminates duplicated escalation logic across fetch, forward, WebSocket, and MCP transports. (#290)
- **`MCPProxyOpts` struct:** long MCP proxy parameter lists replaced with a single `MCPProxyOpts` options struct. Reduces argument count from 13+ parameters to a single struct, making future additions non-breaking. (#294)
- **`RunHTTPListenerProxy` refactored** from 20-parameter function to `MCPProxyOpts` struct. (#328)
- **CLI god package split:** 91-file, 10,000+ line CLI package split into 10 focused subpackages: `assess`, `audit`, `canary`, `diag`, `generate`, `git`, `rules`, `runtime`, `setup`, `signing`. Each subpackage is independently testable. (#303)
- **`atomicfile` shared package:** `internal/atomicfile` extracted as a shared atomic write primitive used by signing, integrity, and recorder packages. Eliminates duplicate implementations. (#302)

### Testing & CI

- **Coverage boost — `atomicfile` package:** `internal/atomicfile` covered by dedicated tests including OS-level write error injection via a `WriteFile` dependency injection interface. (#302)
- **Scanner coverage — encoded payloads and cross-transport DLP:** new tests covering base64/hex-encoded payload detection, segment-level decode paths, and DLP scanning across fetch, forward proxy, and MCP stdio transports. (#315)
- **Comprehensive coverage boost:** (#317, #328)
- **GitHub Action references migrated from v1 to v2:** all `actions/checkout`, `actions/setup-go`, `actions/upload-artifact`, and third-party action refs updated to v2+ across CI workflows. (#291)
- **pip deps pinned with hashes:** Python test dependencies pinned with `--require-hashes` in requirements files. Makefile `fmt` and `lint` targets fixed. (#298)
- **`requests` dependency bumped.** (#300)
- **MCP tool provenance and profile-then-lock baseline:** (#311)
- **Policy capture and replay engine:** (#319)
- **Structured exit codes and subprocess error handling:** (#320)
- **v2.1.0 polish fixes:** (#321)
- **Config.Validate split, DRY audit logger, coverage boost:** (#322)
- **Scan redirect handler output through DLP pipeline:** (#323)
- **Grafana dashboard expanded to 45 metrics** across 14 rows with panels for cross-request detection, adaptive enforcement, scan API, TLS interception, address protection, file sentry, reverse proxy, and capture system.
- **Prometheus alert rules expanded to 28** covering all actionable metrics including DLP, TLS, cross-request, adaptive enforcement, address poisoning, file sentry, and kill switch state.
- **Unversioned release archives** for stable `/releases/latest/download/` curl installs. (#324)

## [2.0.0] - 2026-03-22

### Added
- **Process sandbox (Linux):** Landlock filesystem restriction, seccomp syscall filtering, and network namespace isolation for any agent process. Two modes: `pipelock mcp proxy --sandbox` for MCP servers, `pipelock sandbox -- COMMAND` for standalone agents. Agents run in a sandboxed child process with restricted filesystem visibility and no direct network access — HTTP traffic routes through pipelock's scanner pipeline via a bridge proxy. Requires kernel 5.13+ with Landlock and user namespace support. (#267)
- **Process sandbox (macOS):** sandbox-exec with dynamically generated SBPL profiles. Deny-all baseline with explicit allows. Same approach as Anthropic srt, Cursor, and OpenAI Codex. `pipelock sandbox diagnose` reports platform capabilities. (#275)
- **Per-agent sandbox profiles:** Named sandbox configurations with per-profile filesystem grants, network policy, and syscall allowlists. `--sandbox-strict` flag denies all filesystem access outside an explicit allowlist. Subreaper for descendant cleanup. Sandbox preflight and diagnostics. (#272)
- **Redirect policy action:** First-class `redirect` action for MCP tool policy that routes matched tool calls to audited handler programs instead of blocking. Redirect profiles define the handler executable, reason, and argument passing. Synthetic JSON-RPC success responses returned to the agent. Response scanning on handler output prevents injection. Fail-closed on handler failure or timeout. Action precedence: block > redirect > ask > warn. (#271)
- **Full-schema tool poisoning detection:** `collectAllSchemaText` recursively extracts text from nested `inputSchema` objects (properties, descriptions, enums, defaults, examples) for injection scanning. Previously only top-level tool description was scanned. (#270)
- **State and control response patterns:** 6 new injection detection patterns targeting state manipulation, control flow hijacking, and authority assertion with DOTALL matching for multiline payloads. Response pattern count 13 to 19. (#270)
- **Config security scoring:** `pipelock audit score` analyzes configuration for security posture with 12 category checks, 0-100 scoring, letter grades (A-F), and tool policy overpermission audit. JSON output for CI integration. (#273)
- **JetBrains/Junie MCP proxy integration:** `pipelock jetbrains install` wraps JetBrains IDE MCP server configs through pipelock's MCP proxy. Supports `--sandbox` and `--workspace` flags for sandboxed operation. (#260, #269)
- **Adaptive enforcement exempt_domains:** Per-domain exemption from cross-request entropy budget with wildcard matching. Prevents false entropy accumulation from repeated API calls to LLM providers. (#268)
- **OWASP MCP Top 10 coverage mapping:** Comprehensive mapping of pipelock's controls against the OWASP MCP Security Top 10 taxonomy. (#274)
- **NIST 800-53 control mapping:** 7 control families (AC, AU, CA, CM, IR, SC, SI) mapped with per-control coverage assessment. (#274)

- **Attack simulation:** `pipelock simulate` runs 24 synthetic attack scenarios against a config and reports a security scorecard. 5 categories: DLP exfiltration, prompt injection, tool poisoning, SSRF, URL evasion. Scanner attribution verifies the correct layer detected each attack. `--json` output for CI, exit code 1 on misses. (#277)
- **HTTP reverse proxy:** Generic reverse proxy mode for any HTTP service with bidirectional body scanning. Request bodies scanned for DLP (secret exfiltration), response bodies scanned for prompt injection. Fail-closed on compressed bodies, read errors, and ask mode. `pipelock run --reverse-proxy --reverse-upstream URL`. New `reverse_proxy` config section. (#278)
- **SSRF trusted domains:** `trusted_domains` config option allows internal services with public DNS records that resolve to private IPs. Agents connecting to localhost dev servers, local inference endpoints, or internal services with RFC1918 addresses can be explicitly allowed without disabling SSRF protection globally. (#281, closes #276, #279)

### Fixed
- **Reverse proxy fail-closed on oversized responses:** Responses exceeding `max_response_bytes` are now blocked instead of passing through unscanned. (#281)
- **Reverse proxy URL DLP scanning:** Request URL path and query string are now scanned for DLP patterns on the reverse proxy, matching forward proxy behavior. (#281)
- **Kill switch preemption on long-lived transports:** Kill switch state is checked per-read/frame/message on CONNECT tunnels, WebSocket, and MCP stdio/HTTP/WS transports. Previously only checked at connection setup. (#281)
- **SSE reconnect loop kill switch:** GET-mode SSE stream reconnect loop now exits when kill switch is active instead of retrying indefinitely. (#281)
- **Memory persistence pattern expansion:** Additional terminal phrases added to the memory persistence directive injection pattern for broader coverage. (#281)

### Changed
- Action precedence updated: block(4) > redirect(3) > ask(2) > warn(1). Unknown actions still fail closed to block.
- Direct dependencies increased from 15 to 17 (added go-landlock for sandbox, updated protobuf).
- Binary size increased from ~17MB to ~18MB (sandbox + SQLite runtime). Dev builds are ~24MB due to debug symbols.

### Deployment Notes
- **Linux sandbox** requires kernel 5.13+ with Landlock and user namespace support. Run `pipelock sandbox diagnose` to check prerequisites.
- **macOS sandbox** uses sandbox-exec (seatbelt profiles). Beta — CI-tested on GitHub Actions macOS runners.
- **Redirect profiles** reference handler executables that must exist on the host. Validate with `pipelock audit score`.
- New config sections: `sandbox` (profiles, strict mode), `redirect_profiles` (on `mcp_tool_policy`).

## [1.5.0] - 2026-03-20

### Added
- Adaptive enforcement v2: sessions that accumulate threat signals now escalate through three levels (elevated, high, critical), upgrading actions at every enforcement point across all proxy and MCP transports. Live escalation queries tighten enforcement mid-connection. New `internal/session/` package, `UpgradeAction()` in `internal/decide/`, configurable per-level behavior via `adaptive_enforcement.levels`. Prometheus metrics `pipelock_adaptive_upgrades_total` and `pipelock_adaptive_sessions_current`. 181 new tests. (#256)
- Financial DLP with checksum validation: credit card (Luhn) and IBAN (mod-97) detection with post-match checksum validation that eliminates 90-99% of false positives. New `Validator` field on `DLPPattern` for extensible validated patterns. Covers Visa, Mastercard (including 2221-2720), Amex, Discover, JCB, and 80+ IBAN countries. ABA routing number validator available as opt-in. DLP count 44 to 46. 70 new tests. (#258)
- Key-scoped tool policy matching: `arg_key` field scopes `arg_pattern` to specific top-level argument keys. Block `read_file` when `file_path` contains `/etc/shadow` without false positives on other arguments. Raw argument JSON threaded through all enforcement paths. (#257)
- Community rules rollout: `rules.KeyringHex` wired into build ldflags (Makefile, GoReleaser, Dockerfile) so release binaries verify official bundle signatures. Official registry URL set to `pipelab.org/rules/`. `docs/rules.md` user guide. Community Rules section in README. Commented `rules:` section in all 7 presets. (#255)
- Filesystem sentinel for subprocess MCP mode: real-time filesystem monitoring detects secrets written to disk by agent subprocesses that bypass the MCP pipe. Recursive directory watching with 50ms write debounce, DLP content scanning, process lineage attribution (Linux), and rename-into-place bypass prevention. Watches arm synchronously before child launch (no startup race). Fail-closed when enabled. (#261)
- OTLP log export sink: OpenTelemetry log export as a third emit sink alongside webhook and syslog. Events sent as OTLP LogRecords over HTTP/protobuf to a collector endpoint. No gRPC dependency (uses protowire). Async buffered queue with bounded retry on 429/5xx per OTLP spec. 15 new tests. (#262)

### Fixed
- Transport parity: WebSocket header DLP now scans all 7 forwarded headers (was 4 auth-only). Forward HTTP proxy now scans responses for prompt injection when response_scanning is enabled. Fail-closed on compressed responses that cannot be scanned. Closes the last transport parity gap. (#254)
- Shell normalization hardened against 3 evasion techniques: `$@`/`$*` positional parameter insertion, `${HOME:0:1}` path construction, and backtick command substitution now resolve before policy matching. Pipeline ordering fixed so indirect expansion resolves before slash replacement. (#259)
- Windows release builds: `pipelock rules` now uses an OS-specific lock implementation so the CLI cross-compiles cleanly for Windows targets. (#252)
- DLP action validation: `dlp.action` and per-pattern `action` fields were silently dropped by YAML unmarshaling. Now rejected at startup with an error message pointing to the correct transport-level settings. (#264)
- Adaptive enforcement death spiral: CONNECT hostname no longer counted toward CEE entropy budget (the destination hostname is not exfiltration data). Time-based de-escalation added so sessions at block level can recover after clean traffic. Prevents permanent lockout from repeated polling to the same host. (#266)

### Deployment Notes
- TLS interception with `cross_request_detection` enabled: set `bits_per_window` to 500,000+ and configure `exempt_domains` for LLM providers to avoid false entropy accumulation from repeated API calls.

### Tests
- WebSocket and TLS interception transport wiring: integration tests for address poisoning detection, cross-request exfiltration entropy, response scanning strip action, full CONNECT-hijack-SNI-intercept-scan integration, and injection blocking. Coverage: `clientToUpstream` 61% to 88%, `handleConnect` TLS branch 0% to 86%. (#253)

## [1.4.0] - 2026-03-17

### Added
- Community rule bundles (infrastructure): signed YAML detection pattern bundles with Ed25519 keyring verification, `pipelock rules install/update/list/verify/diff/remove` CLI, CalVer versioning, lock file tracking, and bundle provenance threading through all scanner match types. New `rules` config section with `trusted_keys` and `auto_update`. Public rule bundle and hosting will follow in a point release. (#247)
- Crypto address poisoning detection: validates ETH, BTC, SOL, and BNB blockchain addresses against a user-supplied allowlist and flags lookalike addresses using prefix/suffix similarity scoring. New `address_protection` config section. `internal/addressprotect/` package with chain-specific validators and Bech32/Base58/EIP-55 checksum support. (#233)
- Address similarity tracker: session-scoped fingerprinting with LRU eviction detects when multiple similar-looking addresses appear in the same session, a key indicator of address poisoning attacks. (#231)
- Response scanning pre-filter: keyword-gated regex skips expensive normalization and pattern matching when no injection keywords are present in the text. Cuts clean-text scan latency significantly. (#230)
- Response pre-filter extended to opt-space and vowel-fold passes: all three normalization passes now use keyword pre-filtering, not just the first pass. (#245)
- Delimiter-separated hex encoding detection: `normalizeHex()` strips 6 delimiter formats (`:`, `-`, ` `, `,`, `\x` prefix, `0x` prefix) across all DLP paths, catching secrets encoded as colon-separated, space-separated, or C-style hex notation. (#243)
- DLP patterns for Groq, xAI, GitLab, New Relic, and Stripe webhooks: built-in pattern count expanded from 36 to 41. (#246)
- Crypto secret DLP detection: BIP-39 seed phrase detection via dedicated `internal/seedprotect/` package with dictionary lookup, sliding window, and SHA-256 checksum validation. Three new regex patterns for Bitcoin WIF, extended private keys (xprv/yprv/zprv/tprv), and Ethereum private keys. DLP count now 44. New `seed_phrase_detection` config section. (#249)
- VS Code MCP proxy integration: `pipelock vscode install` wraps VS Code MCP server configs through pipelock's MCP proxy for bidirectional scanning. `pipelock vscode remove` cleanly unwraps. Supports project and global scope, dry-run preview, atomic writes with backup. (#248)
- Trial tier and one-time purchase support for license service: Polar webhook handler now processes trial and one-time purchase events alongside subscriptions. (#232)
- Scan API reference documentation (`docs/scan-api.md`): full API reference for the `POST /api/v1/scan` endpoint covering all four scan kinds, auth, rate limiting, error codes, and integration patterns.
- Address protection and scan API config reference sections added to `docs/configuration.md`.
- Hostile-model preset surfaced in README Security Matrix with feature callout.

### Changed
- Minimum Go version bumped from 1.24 to 1.25. CI matrix now tests Go 1.25 and 1.26. (#242)

### Fixed
- K8s Secret volume compatibility: license key and signing key file loading now follows symlinks (required for Kubernetes Secret volume mounts where files are symlinked through `..data/`). (#229)
- MCP `tools/list` false positive on empty responses: skip general response scanning when tools/list returns an empty or all-unnamed tool array. Malformed `tools` values still fall through to injection scanning. (#250)
- Keystore symlink escape: `generateAgent` now validates path containment after symlink resolution, preventing private key writes to attacker-controlled locations outside the keystore boundary. Containment check covers both leaf symlinks and symlinked parent directories.

### Docs
- Adversarial testing methodology section added to security assurance docs. Benchmark data refreshed for Go 1.25. Scanner pipeline description updated from 9 to 11 layers. (#228)
- Security claims hedged and coverage disclaimers added across docs. (#234)
- Demo assets, fleet dashboard screenshot, and egress report updated. (#235)

### CI
- sigstore/cosign-installer bumped from 4.0.0 to 4.1.0. (#237)
- docker/login-action bumped from 3.7.0 to 4.0.0. (#241)

## [1.3.0] - 2026-03-13

### Added
- Scan API endpoint (`POST /api/v1/scan`): evaluate URLs, text, and MCP payloads against the scanner pipeline via HTTP. Returns structured findings with MITRE ATT&CK technique IDs, severity, and per-layer results. Configurable via `scan_api` config section. (#223)
- SARIF output for `pipelock audit` and `pipelock git scan-diff`: `--format sarif` produces SARIF v2.1.0 for GitHub Code Scanning integration. Findings appear as inline annotations on PR diffs via the `upload-sarif` action. (#217)
- CRLF injection detection: blocks `%0d%0a`, double-encoded `%250d%250a`, and raw CR/LF in URL scheme, authority, path, and query components. Fragments excluded (never reach upstream). (#224)
- Path traversal detection: blocks `/../`, encoded variants (`%2e%2e/`, `..%2f`, `..%5c`), partial encoding, double-encoded `%252e%252e`, and mixed-boundary patterns using segment-bounded matching to avoid false positives. (#224)
- CONNECT header DLP scanning: scans Proxy-Authorization and other headers on CONNECT handshake for leaked secrets before tunnel establishment. (#224)
- Subdomain entropy exclusions: `subdomain_entropy_exclusions` config field whitelists domains with legitimately high-entropy subdomains (e.g., RunPod GPU instances). Wildcard matching (`*.runpod.net`) covers all subdomain depths. (#222)
- License service scaffold: cluster-only webhook handler for Polar subscription events. Alpine-based Docker image, SQLite entitlement store, append-only audit ledger. ELv2 licensed. (#218)
- License service build artifacts: GoReleaser pipeline builds linux/amd64+arm64 Docker images for the license service with multi-arch manifests and build provenance attestation. (#226)
- `pipelock license install` command: accepts a license token and writes it to the local license file for pipelock to read at startup. (#216)
- Runtime license loading: load license from `PIPELOCK_LICENSE_KEY` env var or `license_file` config path. (#213)
- License tier and subscription fields: `tier` and `subscription_id` in license tokens for entitlement gating. (#215)
- Sentry error tracking: opt-in Sentry integration for crash reporting in production deployments. (#211)
- OWASP LLM Top 10 mapping document: article-by-article coverage analysis against OWASP LLM Top 10 2025. (#220)

### Changed
- Scanner context threading: `Scanner.Scan` now accepts `context.Context` for DNS cancellation propagation. All proxy paths pass request context through. (#221)
- Metrics refactored: structured initialization, per-transport counters, scan API metrics. (#223)
- License token enrichment: `tier` and `subscription_id` fields are now populated during license service minting. (#226)

### Fixed
- Config fail-open on omitted security booleans: `response_scanning.enabled`, `mcp_input_scanning.enabled`, and `mcp_tool_scanning.enabled` now default to `true` when omitted from YAML (previously defaulted to Go zero value `false`). (#219)
- WebSocket header DLP bypass: headers on WebSocket upgrade requests are now scanned for DLP patterns. (#219)
- `secrets_file` permission gap: file permission check now enforces `0o600` on secrets files. (#219)
- Capability separation language in docs: corrected claims about enforcement vs. deployment guidance. (#220)
- Adaptive enforcement accuracy in docs: clarified that v1 is scoring-only, not enforcement-aware. (#220)
- MCP `tools/list` false positive: instruction-like tool descriptions no longer trigger injection detection. (#224)
- URL fragment DLP coverage: URL fragments containing credential-like parameters are now detected by DLP scanning. (#224)
- Webhook idempotency: concurrent Polar webhook deliveries no longer double-mint licenses. (#226)
- Founding cap honor: paid founding checkouts are honored when cap is reached instead of silently downgrading to regular Pro. (#226)
- CLI license ledger: `pipelock license issue` no longer stores raw signed tokens in the ledger file (stores truncated SHA-256 hash for correlation). (#226)
- License service email and config defaults: corrected domain references from stale addresses to current domains. (#226)

## [1.2.0] - 2026-03-11

### Added
- Cross-request exfiltration detection (CEE): per-session entropy budget tracking and fragment reassembly with DLP re-scan catch secrets split across multiple requests. Integrated across all proxy paths (fetch, forward, TLS intercept, WebSocket, MCP). Strict and hostile-model presets enable CEE by default. (#206)
- DLP pattern expansion from 22 to 36 built-in patterns: AI/ML provider keys (Hugging Face, Databricks, Replicate, Together AI, Pinecone), infrastructure tokens (DigitalOcean, HashiCorp Vault, Vercel, Supabase), package registry tokens (npm, PyPI), and developer platform keys (Linear, Notion, Sentry) (#208)
- DLP prefix pre-filter: fast literal-prefix screening skips regex evaluation on URLs that contain no credential-like substrings, reducing DLP overhead on clean traffic (#209)

### Changed
- Release artifacts (Homebrew, GitHub releases, Docker images) now include paid-tier features that activate with a valid license key. Building from source without the `enterprise` tag produces a Community-only binary. (#212)

### Fixed
- Agent listeners now shut down on config reload when the license is revoked, preventing policy-free traffic after license expiry (#205)
- License headers normalized across all source files; documentation updated for dual-license clarity (#204)

## [1.1.0] - 2026-03-09

### Added
- `pipelock discover` command: scans MCP server configs (Claude Code, Cursor, Windsurf, VS Code) and shows which servers lack pipelock wrapping (#194)
- Parallel scanner benchmarks and concurrent scaling tests with performance documentation (#201)
- Security, Pipelock Scan, and CodeRabbit badges to README (#193)

### Fixed
- IPv6 listener collision detection: `[::]:8888`, `0.0.0.0:8888`, and `:8888` now correctly collide in agent listener validation (dual-stack systems bind all three to the same port)
- Non-canonical IPv6 addresses (e.g. `[0000::1]`) normalized via `net.ParseIP` for consistent collision detection
- Config hot-reload preserves agent listener state across reloads: removing a listener-bearing agent re-adds its full profile (prevents policy downgrade on bound ports), and new agent listeners are stripped (can't bind without restart). License expiry timestamps also preserved (watchdog timer set at startup only).

### Changed
- Enterprise module split: multi-agent features (per-agent identity, budgets, config isolation) moved to `enterprise/` directory under Elastic License 2.0 (ELv2). Core remains Apache 2.0. (#202)
- Enterprise features require `//go:build enterprise` tag at compile time and a valid license key at runtime
- OSS builds silently ignore `agents` config section (no error, agents just don't activate)
- CI tests both OSS and enterprise build modes
- CI dependency updates: actions/checkout v6, docker/setup-buildx-action v4, docker/setup-qemu-action v4, actions/dependency-review-action v4.9, github/codeql-action v4.32.6

## [1.0.0] - 2026-03-07

Pipelock 1.0.0 is the production-ready release. All scanning layers, proxy modes, and MCP security features are stable and commercially supported.

### Added
- Per-agent identity profiles: named agent configurations with independent mode, enforce flag, API allowlist, DLP patterns, rate limits, and session profiling overrides
- Agent identity resolution chain: context override > `X-Pipelock-Agent` header > `?agent=` query param > `_default` fallback
- Per-agent request budgets: configurable request count, byte transfer, and unique domain limits with rolling window enforcement
- Dedicated listener ports per agent for spoof-proof identity without relying on headers
- Source CIDR matching for agent identity
- `--agent` flag for MCP proxy: select agent profile for MCP proxy sessions
- Agent identity threaded through audit logs, Prometheus metrics, and JSON `/stats` breakdown
- `X-Pipelock-Agent` header stripped before forwarding to upstream (prevents agent impersonation)
- Ed25519 license key system: `pipelock license keygen`, `pipelock license issue`, and `pipelock license inspect` CLI commands with build-time public key embedding
- MCP tool policy: audit log tamper protection (blocks rm/truncate/shred on log files, history clearing)
- MCP tool policy: persistence detection for cron, systemd, init.d, launchd, and shell profile write paths with destination-aware matching
- Chain detection: `write-persist` and `persist-callback` patterns with argument-aware exec-to-persist reclassification
- Read-indicator downgrade: introspection tools no longer trigger false-positive persistence alerts
- `request_body_scanning` defaults in programmatic config (previously only available via preset files)
- IPv4/IPv6 multicast ranges added to default SSRF protection
- Social Security Number DLP pattern added to all config presets
- `tool_chain_detection` section added to all config presets
- `--home` flag for signing/keygen/verify/TLS CLI commands (container and rootless environment support)
- Config-relative CA path resolution for TLS interception (paths resolve relative to config file, not CWD)

### Fixed
- TLS interception shared transport: single `http.Transport` with connection pooling across intercepted CONNECT tunnels
- TLS passthrough domain reload warnings: set-diff detection catches same-size domain list replacements during config hot-reload
- TLS `InstallCA` refactored for testable OS-specific branches (certgen coverage improved)
- Config preset sync: all 7 presets now match `Defaults()` for DLP patterns, tool chain detection, and policy rules

### Changed
- Minimum version bump from 0.x to 1.0: public API (config format, CLI flags, audit schema, Prometheus metrics) is now stable. Breaking changes will follow semver.

## [0.3.6] - 2026-03-06

### Added
- TLS interception for CONNECT tunnels: opt-in MITM decrypts tunnel traffic for full request body DLP, header DLP, and response injection scanning. ECDSA P-256 CA with bounded TTL certificate cache.
- `pipelock tls init` command: generates a local CA key pair for TLS interception
- `pipelock tls show-ca` command: displays the CA certificate (PEM) for manual trust
- `pipelock tls install-ca` command: installs the CA into the system trust store
- `tls_interception` config section with `enabled`, `ca_cert`, `ca_key`, `cert_ttl`, and `passthrough_domains` fields. Hot-reload wiring for CA config changes.
- TLS interception SSRF-safe upstream dialer prevents DNS rebinding during intercepted connections
- TLS interception status reported in `/health` endpoint
- `pipelock_tls_intercept_total`, `pipelock_tls_handshake_duration_seconds`, `pipelock_tls_request_blocked_total`, `pipelock_tls_response_blocked_total`, `pipelock_tls_cert_cache_size` Prometheus metrics
- `tls_authority_mismatch`, `tls_response_blocked` audit events with MITRE technique labels
- All 7 config presets updated with `tls_interception` section defaults
- `pipelock report` command: reads JSONL audit logs and produces HTML, JSON, or Ed25519-signed evidence bundle reports with risk rating, event categories, timeline histogram, and evidence appendix. Supports `--format`, `--output`, `--sign`, and `--config` flags.
- MCP tool poisoning: parameter schema scanning extracts parameter key names from `inputSchema` at all nesting depths, expands underscore/hyphen/camelCase names, and scans for exfiltration intent (catches the CyberArk attack variant where data theft is encoded in parameter names while descriptions stay clean)
- Exfiltration Parameter Name poison pattern: detects action+target combinations in tool parameter names (read+private_key, steal+credentials, fetch+access_token)
- MCP tool drift summaries now report which parameters were added or removed instead of generic "description changed" messages
- Audit schema: chain detection structured events, startup/reload config hash metadata, version tracking
- `Config.Hash()` for deterministic SHA256 of raw config file bytes (used in signed reports)
- Dependency review GitHub Actions workflow: blocks PRs that introduce dependencies with known vulnerabilities
- CI concurrency groups: in-progress runs cancelled when new commits push to the same branch
- SPDX Apache 2.0 license headers on all Go source files
- GitHub Sponsors funding configuration
- Contributor License Agreement (Apache ICLA) section in CONTRIBUTING.md
- SPONSORS.md for sponsor recognition

### Fixed
- Environment variable leak scanner: ~50 well-known non-secret variables (HOME, PATH, USER, PWD, SHELL, TERM, LANG, EDITOR, GOPATH, LS_COLORS, and others) are now skipped by name, reducing false positives when agents send standard environment values in tool arguments. Case-insensitive matching handles Windows-style mixed-case names.
- TLS interception: `ActionAsk` treated as block inside intercepted tunnels (no HITL terminal available in TLS context)
- TLS interception: `LoadCA` validates cert.IsCA, KeyUsageCertSign, and key correspondence. Rejects cert_ttl <= 0 and group/world-readable CA keys.
- MCP: skip general injection scanner for tools/list responses when tool scanning is enabled, preventing false positives on instructional tool descriptions (e.g. "you must call this tool")
- Report: chain detection severity derived from action (block=critical, warn=warn) instead of storing caller-provided value
- Report: hash raw client IP in audit session field when Mcp-Session-Id absent, preventing IP leak
- Report: plain blocked events without an action field now get high severity instead of medium
- Report: evidence appendix redacts connect_host and sni_host IP addresses
- Report: admin events (startup, shutdown, config_reload) excluded from timeline histogram
- Report: skipped JSONL lines tracked and surfaced in summary and HTML template
- Report: criticals KPI counter uses severity:critical count (was always 0)
- Report: exec summary uses traffic-only event count as denominator (excludes admin events)
- Report: multi-day timeline labels use "Jan 2" date format instead of "00:00" for all bars

### Changed
- Documentation version references use `v1`/`latest` instead of pinned version numbers so guides stay current across releases

## [0.3.5] - 2026-03-05

### Added
- Kill switch API token can now be set via `PIPELOCK_KILLSWITCH_API_TOKEN` environment variable, overriding the `kill_switch.api_token` config field. Enables Kubernetes deployments to source the token from a Secret instead of a ConfigMap.
- Request body DLP scanning for the forward HTTP proxy. Scans POST/PUT/PATCH bodies for secrets across JSON (recursive string extraction), form-urlencoded, multipart/form-data, and raw text. Unknown content types get a fallback raw-text scan to prevent Content-Type spoofing bypass. Fail-closed on oversized bodies, compressed bodies, parse errors, and multipart limit violations.
- Request header DLP scanning for the forward proxy and fetch handler. Two modes: `sensitive` (scan listed headers only) and `all` (scan everything except structural headers, including header names). Joined scan catches secrets split across multiple headers.
- `request_body_scanning` config section with `enabled`, `action`, `max_body_bytes`, `scan_headers`, `header_mode`, `sensitive_headers`, and `ignore_headers` fields
- `pipelock_body_dlp_hits_total` and `pipelock_header_dlp_hits_total` Prometheus counters
- `body_dlp` and `header_dlp` audit event types
- Shared JSON string extractor (`internal/extract`) used by both proxy body scanning and MCP input scanning
- `hostile-model` config preset for agents running uncensored or jailbroken models
- Windows build support: GoReleaser produces Windows amd64/arm64 binaries (zip archives). Kill switch signal toggle and config reload signal are no-ops on Windows; all other features work identically.
- CONNECT tunnel SNI verification: detects domain fronting (T1090.004) by comparing the CONNECT target hostname against the TLS SNI extension. Enabled via `forward_proxy.sni_verification: true`. `pipelock_sni_total` Prometheus counter tracks matches.
- `pipelock claude hook/setup/remove` commands for Claude Code hook integration
- MCP confused deputy protection: validates that MCP server response IDs match previously tracked request IDs. Blocks unsolicited responses that could hijack agent execution flow.
- IPv4 and IPv6 multicast CIDRs (`224.0.0.0/4`, `ff00::/8`) added to default SSRF internal address list

### Fixed
- IPv6 zone ID SSRF bypass: URLs like `http://[::1%25eth0]/` no longer skip CIDR checks. Zone IDs are stripped before IP parsing.

## [0.3.4] - 2026-03-04

### Fixed
- `pipelock cursor install` now writes Cursor's v1 hooks.json format (map keyed by event name with `version` field). Previously wrote a flat array that Cursor silently ignored, causing hooks to never fire.
- `pipelock cursor install` now preserves `args` fields on existing hooks during merge. Previously, non-pipelock hooks with `args` arrays lost their arguments after install or upgrade.
- `pipelock preflight` now scans both v1 and legacy hooks.json formats. Previously only understood the legacy format and would false-positive on v1 files.

## [0.3.3] - 2026-03-04

### Added
- `pipelock verify-install` command: 10 deterministic checks verifying scanning pipeline and network containment. Produces human-readable or `--json` output with optional Ed25519 `--sign` for tamper-evident reports. Supports `--output` to write results to file.
- `pipelock cursor hook` subcommand: Cursor IDE hook integration. Reads hook events from stdin, evaluates DLP, injection, and tool policy, writes allow/deny JSON to stdout. Always exits 0 with JSON `permission` field as the authoritative decision. Without `--config`, uses a security-focused default profile with 9 tool policy rules, MCP input scanning, and response scanning enabled.
- `pipelock cursor install` subcommand: writes `hooks.json` to register pipelock with Cursor. Supports `--global` (default, `~/.cursor/`) and `--project` (`.cursor/` in cwd). Atomic writes via temp file + rename, `.bak` backup, idempotent merge with existing hooks, upgrade-safe replacement of stale entries.
- `internal/decide` package: shared decision engine for evaluating agent actions against pipelock's scanning pipeline. Supports shell execution, MCP tool calls, and file read events with per-finding action semantics (block vs warn) and `enforce` flag override.
- Fail-closed on malformed MCP tool_input: invalid JSON in tool arguments is treated as block-level evidence. Legitimate MCP tool calls always have valid JSON; parse failure indicates tampering or corruption.
- `pipelock audit --preflight` scanner: detects dangerous IDE configuration files (`.cursor/mcp.json`, `.vscode/mcp.json`) in project directories that could override agent security settings. Reports threat level (critical/high/medium/low) with actionable remediation steps.

### Changed
- Replaced all `//nolint:gosec` G304 suppressions with `filepath.Clean()` across production and test code (84 occurrences in 26 files). No behavioral change.
- Eliminated all `//nolint:goconst` directives, extracted named constants

### Fixed
- Pre-existing lint issues in `tests/ws-helper/main.go`: errcheck on `conn.Close()`, noctx on `net.Listen`

## [0.3.2] - 2026-03-02

### Added
- `pipelock diagnose` command: fully local end-to-end configuration verification. Spins up a mock upstream and temp proxy, runs 6 checks (health, fetch allowed/blocked, hint presence, CONNECT allowed/blocked). Exit 0 on pass, 1 on failure, 2 on config error. Supports `--json` and `--config`.
- `explain_blocks` config field (opt-in, default false): blocked responses include actionable hints explaining why a request was blocked and how to fix it. Fetch proxy gets a JSON `hint` field, CONNECT and WebSocket get an `X-Pipelock-Hint` header. Hints are per-scanner (DLP, blocklist, SSRF, entropy, rate limit, etc.).
- Scanner label constants (`scanner.ScannerDLP`, `scanner.ScannerBlocklist`, etc.): 12 exported constants matching existing on-wire metric label values
- `proxy.Handler()` method: returns the composed HTTP handler for use with `httptest.NewServer` or custom listeners
- Docker Compose quickstart (`examples/quickstart/`): production-ready two-network architecture with `internal: true` isolation, opt-in verification suite (5 tests: network isolation, DLP, response injection, MCP tool poisoning), attacker container for reproducible demos

### Fixed
- `generate mcporter` now preserves per-server extra fields (`alwaysAllow`, `disabled`, `metadata`, `headers`, etc.) during wrapping. Previously only `command`, `args`, and `env` survived.
- WebSocket scanner label split: protocol enforcement events now correctly use `ws_protocol` label
- Grafana dashboard template variable syntax corrected for fleet filtering

### Changed
- Reusable scan workflow actions pinned to commit SHAs for OpenSSF Scorecard compliance

## [0.3.1] - 2026-03-01

### Added
- WebSocket MCP transport: `--upstream ws://` and `wss://` for MCP proxy connections, with the same 6-layer scanning pipeline as stdio and HTTP modes
- `pipelock generate mcporter` CLI: wraps MCP server configs with pipelock scanning. Reads any JSON with `mcpServers`, preserves env blocks, detects already-wrapped servers, idempotent
- `pipelock-init` container image: Alpine-based multi-arch image for K8s initContainer deployments, replaces multi-line wget/tar/chmod scripts with `cp /pipelock /shared-bin/pipelock`
- MITRE ATT&CK technique IDs mapped to all scanner labels (T1048, T1059, T1046, T1071.001, T1190, T1195.002, T1078, T1030) in blocked, anomaly, ws_scan, response_scan, session_anomaly, and mcp_unknown_tool audit events and emitted payloads
- `pipelock_kill_switch_active{source}` Prometheus gauge via custom collector (fresh state per scrape, four sources: config, api, signal, sentinel)
- `pipelock_info{version}` build information metric
- Metrics port isolation: `metrics_listen` config field runs `/metrics` and `/stats` on a dedicated port, preventing agents from scraping operational metadata. Changes rejected on hot-reload with a warning.
- Cosign signature verification in the GitHub Action: release checksums verified against Sigstore attestation before binary install. Graceful degradation when cosign is unavailable.
- Reusable GitHub Actions security scan workflow (`.github/workflows/reusable-scan.yml`) with 7 configurable inputs and `score`, `findings-count`, `critical-count` outputs
- 7 new docs: configuration reference, deployment recipes (Docker/K8s/iptables/macOS PF), bypass resistance matrix, attacks-blocked gallery, policy spec v0.1, transport modes guide, OpenClaw deployment guide
- Prometheus metrics reference (`docs/metrics.md`): all 20 metrics with scrape config and PodMonitor example
- 11 ready-to-use Prometheus alert rules (`examples/prometheus/pipelock-alerts.yaml`)
- Grafana dashboard rebuilt from 4-panel overview to 18-panel fleet monitor with per-source kill switch status, chain detection by pattern, session anomaly breakdown, escalation timeseries, and multi-instance `$instance` filter variable
- `filterAndActOnResponseScan` helper: extracted response scan action handling (suppress, block, ask, strip, warn) to eliminate duplication between raw HTML and extracted text scan paths
- Demo extended with base64-encoded secret detection, git diff scanning, and config generation steps

### Fixed
- `internal: []` in YAML config now correctly disables SSRF checks. Previously, `ApplyDefaults()` treated explicit empty slices the same as absent fields, filling in default CIDRs. This blocked legitimate Docker container traffic on private IPs (172.x.x.x).
- Reject WebSocket compressed frames (RSV1 bit): compressed bytes bypass DLP pattern matching entirely, now closed with StatusProtocolError on both relay directions
- Scan raw HTML body before go-readability extraction: injection hidden in HTML comments, script/style tags, and hidden elements was stripped before the response scanner could detect it
- Use Mozilla Public Suffix List for ccTLD-aware domain grouping: `baseDomain()` now correctly groups `evil.co.uk` instead of merging all `.co.uk` domains into one rate limit bucket
- Prompt injection detection regex broadened to catch determiner-before-modifier evasion variants (e.g. "ignore your previous instructions", "forget the prior rules")
- RFC 6455 compliance: WebSocket proxy now sends masked close frames to upstream connections (previously sent unmasked server-style frames)

### Changed
- **Telemetry label split:** WebSocket protocol enforcement events (binary frame rejection, fragment errors) now emit scanner label `ws_protocol` instead of `policy`. The `policy` label is now exclusively for MCP tool policy violations. MITRE mapping: `ws_protocol` maps to T1071 (Application Layer Protocol), `policy` remains T1059 (Command and Scripting Interpreter). Update any dashboards or alert rules that filter on `scanner="policy"` for WebSocket-specific events.
- `internal/wsutil` package extracted: shared WebSocket utilities (fragment reassembly, close frames, error classification) used by both the HTTP WS proxy and MCP WS transport
- Anomaly audit events now include `scanner` as a structured field with MITRE technique mapping (previously embedded in reason string)
- README slimmed from 829 to ~490 lines; full configuration YAML replaced with link to `docs/configuration.md`, forward proxy quick start moved to collapsible section
- Quick start updated to use `pipelock check` (works without running the proxy)
- `golang.org/x/net` promoted from indirect to direct dependency (publicsuffix for ccTLD handling)

## [0.3.0] - 2026-02-27

### Added
- Kill switch: emergency deny-all with four activation sources (config, SIGUSR1 signal, sentinel file, HTTP API), OR-composed so any single source blocks all proxy traffic
- Kill switch API: `POST /api/v1/killswitch` (activate/deactivate) and `GET /api/v1/killswitch/status` (per-source state) with bearer token auth, rate limiting, and input hardening (MaxBytesReader, DisallowUnknownFields, strict EOF enforcement)
- Kill switch port isolation: `api_listen` config field runs the kill switch API on a dedicated port, preventing agents from deactivating their own kill switch in sidecar deployments
- Event emission: fire-and-forget dispatch to webhook and syslog sinks with independent severity filters (`info`, `warn`, `critical`), configurable `instance_id`, and async buffered delivery
- Webhook sink: HTTP POST with bearer token auth, configurable timeout and queue size, background worker with graceful shutdown
- Syslog sink: UDP/TCP delivery with configurable facility, tag, and severity mapping to syslog priority levels
- Finding suppression: silence known false positives via config (`suppress` entries with rule name, path glob, and reason) or inline `// pipelock:ignore` source comments
- Tool call chain detection: subsequence matching on MCP tool call sequences with 8 built-in attack patterns (recon, credential theft, data staging, exfiltration), configurable window size, time-based eviction, and max-gap constraint
- Session profiling and adaptive enforcement config sections (scoring-only in v1, observability groundwork)
- Health endpoint now reports `kill_switch_active` field
- Preset configs (strict, balanced) updated with kill switch and emit examples (commented out)
- DLP: 6 new patterns: Fireworks API Key, Google API Key, Google OAuth Client Secret (GOCSPX), Slack App Token (`xapp-`), JWT Token, Google OAuth Client ID
- DLP: expanded AWS Access ID detection from AKIA-only to all 9 credential prefixes (AKIA, ASIA, AROA, AIDA, AIPA, AGPA, ANPA, ANVA, A3T)
- DLP: expanded GitHub Token detection to cover all 5 token types (ghp, gho, ghu, ghs, ghr)
- All 6 preset configs (balanced, strict, audit, claude-code, cursor, generic-agent) updated with expanded DLP pattern set (22 patterns)
- DLP `include_defaults` config field: when true (default), user-defined DLP patterns are merged with built-in defaults by name, so new default patterns are automatically added on binary upgrade without requiring config changes. Set `include_defaults: false` to use only user-defined patterns (previous behavior). Same field available for `response_scanning`.
- Finding suppression guide (`docs/guides/suppression.md`): documents all three suppression layers (inline comments, config entries, `--exclude` flag), available rule names, path matching styles, and GitHub Action integration

### Fixed
- Close WebSocket cross-message DLP bypass: secrets split across WebSocket text frames are now detected via fragment reassembly buffer scanning (PR #140)
- Close header rotation evasion: IP-level domain tracking prevents agents from rotating Host/Origin headers to bypass per-domain rate limits (PR #141)

### Changed
- MCP package refactored into sub-packages: `transport`, `tools`, `policy`, `jsonrpc` for clearer separation of concerns
- Audit logger enhanced with event emission dispatch: audit calls now route to configured webhook/syslog sinks based on severity
- Normalize package extracted as `internal/normalize` with `ForPolicy` variant for MCP tool policy command matching

## [0.2.9] - 2026-02-23

### Added
- WebSocket proxy: `/ws?url=ws://...` endpoint with bidirectional frame relay, DLP + injection scanning on text frames, fragment reassembly, message size limits, SSRF-safe upstream dialer, auth header forwarding with DLP scanning, concurrency limits, connection lifetime and idle timeout controls, and Prometheus metrics
- WebSocket configuration: `websocket_proxy` section in config with `max_message_bytes`, `scan_text_frames`, `allow_binary_frames`, `strip_compression`, `max_connection_seconds`, `idle_timeout_seconds`, `origin_policy`, and `max_concurrent_connections`
- WebSocket health reporting: `/health` endpoint includes `websocket_proxy_enabled` field
- All 6 preset configs updated with `websocket_proxy` defaults (disabled by default)
- `--exclude` flag for `pipelock audit` and `pipelock git scan-diff`: filter findings by path using globs (`*.generated.go`) or directory prefixes (`vendor/`). Repeatable for multiple patterns.
- GitHub Action `exclude-paths` input: newline-separated path patterns passed to both audit and scan-diff steps

## [0.2.8] - 2026-02-23

### Fixed
- Close 9 scanner evasion bypasses found during red team testing: hex/base64-encoded secrets in URL query params and path segments, vowel-fold flag corruption on `(?im)` patterns, strip mode fail-open when detection came from non-redactable passes, and missing normalization passes on decoded response content (PR #135)
- Close 3 DLP evasion bypasses in query parameter scanning: iterative URL-decode, noise-stripped values, and dot-collapsed subdomain splits now applied to individual query keys and values (PR #134)

### Changed
- Encoding attribution: segment-level DLP matches now carry correct encoding labels (hex, base64, base32) instead of always reporting "hex"
- Response scanning decoded-content path runs all normalization passes (primary, opt-space, vowel-fold), closing a gap where base64/hex-encoded vowel-substituted injection could bypass detection
- Logo tagline updated to "Agent Firewall"

## [0.2.7] - 2026-02-22

### Added
- MCP HTTP reverse proxy: `--mcp-listen` + `--mcp-upstream` flags on `pipelock run` create an HTTP-to-HTTP scanning proxy with bidirectional JSON-RPC 2.0 validation, Authorization header DLP scanning, and fail-closed parse error handling (PR #127)
- MCP standalone HTTP listener: `pipelock mcp proxy --listen :8889 --upstream http://host/mcp` for deployments that only need MCP scanning without the fetch/forward proxy (PR #127)
- JSON-RPC 2.0 structural validation on HTTP listener: rejects non-string method types, wrong/missing jsonrpc version, and missing method field with proper -32600 error codes; batch requests pass through to per-element scanning (PR #127)
- CI dogfooding: Pipelock's own GitHub Action runs on every PR, scanning diffs for exposed credentials and injection patterns (PR #126)

### Fixed
- Release workflow: semver-only tag filter (`v*.*.*`) prevents floating tags like `v1` from triggering spurious GoReleaser releases (PR #126)
- Auto-move `v1` floating tag after each semver release so the GitHub Action always resolves to the latest version (PR #126)

### Changed
- MCP auto-enable default: `mcp_input_scanning.action` changed from `warn` to `block` when auto-enabled in proxy mode, preventing credential forwarding in balanced configs (PR #127)
- Default response scanning and DLP patterns auto-populated when MCP listener enables scanning on an unconfigured section (PR #127)

## [0.2.6] - 2026-02-21

### Added
- HTTP forward proxy: standard CONNECT tunneling and absolute-URI HTTP forwarding on the same port as the fetch proxy. Set `HTTPS_PROXY=http://localhost:8888` and all agent HTTP traffic flows through the scanner pipeline. Configurable tunnel duration and idle timeout controls (PR #123)
- Tunnel observability: Prometheus metrics (tunnel count, bytes transferred, duration histogram, active gauge), JSON stats, and structured audit logs for tunnel open/close events (PR #123)
- GitHub Action (`luckyPipewrench/pipelock`): composite action for CI/CD agent security scanning with checksum-verified binary download, multi-arch (amd64/arm64) and multi-OS (Linux/macOS) support, fail-closed audit gate, PR diff secret scanning, inline GitHub annotations on findings, and job summary (PR #125)
- CI workflow examples for basic and advanced GitHub Action usage (PR #125)

### Changed
- Forward proxy enabled by default in all 6 preset configs: balanced, strict, audit, claude-code, cursor, generic-agent (PR #125)
- Action string constants extracted to `config` package (`ActionBlock`, `ActionWarn`, `ActionAsk`, `ActionStrip`, `ActionForward`), replacing ~70 hardcoded literals across 12 files (PR #124)
- README rewritten with forward proxy "zero code changes" quickstart as primary path, refreshed benchmarks and testing stats, honest security assessment section (PR #122, #125)
- Copyright updated to legal name in LICENSE (PR #122)

## [0.2.5] - 2026-02-20

### Added
- MCP `--env` flag: pass specific environment variables to child processes without exposing the full environment (PR #119)

### Fixed
- Tool poisoning detection: instruction tag patterns (`<IMPORTANT>`, `<system>`) and dangerous capability patterns (file exfil, cross-tool manipulation) hardened via adversarial testing (PR #117)

### Changed
- Rebrand from "security harness" to "agent firewall" across all user-facing surfaces: CLI, README, docs, demo, Homebrew formula (PR #120)
- Extract `internal/normalize` package: consolidate Unicode normalization pipeline, add `ForPolicy` variant for command matching (PR #116)
- Documentation refresh: updated comparison matrix, stale references, testing stats (PR #118)

## [0.2.4] - 2026-02-19

### Added
- MCP Streamable HTTP transport: `pipelock mcp proxy --upstream <url>` bridges stdio clients to remote MCP servers over HTTP with SSE stream support and session lifecycle management (PR #112)
- Pre-execution tool call policy: configurable `mcp_tool_policy` blocks dangerous commands (rm -rf, curl to external, chmod 777) before MCP tools execute, with pairwise token matching and whitespace normalization (PR #107)
- Known secret scanning: `dlp.secrets_file` config loads explicit secrets from file, scans URLs and MCP tool arguments for raw + base64/hex/base32 encoded variants including unpadded forms (PR #111)
- `pipelock test` CLI command: validates scanner coverage against loaded config with structured pass/fail output per scanner layer (PR #109)
- Framework integration guides: OpenAI Agents SDK, Google ADK, AutoGen (PR #110)
- GOVERNANCE.md, ROADMAP.md, and security assurance documentation for OpenSSF Silver (PR #108)
- OpenSSF Best Practices Silver badge (PR #114)

### Fixed
- Unicode bypass in injection and DLP scanning: full homoglyph normalization (Cyrillic, Greek, Armenian, Cherokee), combining mark stripping, leetspeak normalization, 6 new injection patterns (PR #105)
- govulncheck CI flake: pinned Go version to 1.24.13 to prevent runner cache inconsistency (PR #113)
- Codecov targets raised to 95% project / 90% patch (PR #113)

### Changed
- README Quick Start reordered: `pipelock check` before `pipelock run` since check doesn't need a running proxy (PR #113)
- CONTRIBUTING.md updated with complete CLI command list and project structure (PR #113)
- Demo script uses `DEMO_TMPDIR` instead of `TMPDIR` to avoid shadowing POSIX env var (PR #113)
- CI matrix tests Go 1.24 + 1.25 (PR #113)

## [0.2.3] - 2026-02-16

### Added
- MCP transport abstraction: `MessageReader`/`MessageWriter` interfaces decouple scanning from stdio framing, preparing for HTTP transport
- Demo command: 7 attack scenarios (was 5), adding MCP input secret leak and tool description poisoning demos
- Demo ANSI color output with `NO_COLOR` env var support and TTY detection
- Demo `--interactive` flag for live presentations (pauses between scenarios)
- CrewAI integration guide (`docs/guides/crewai.md`)
- LangGraph integration guide (`docs/guides/langgraph.md`)
- `WriteMessage` size guard (10 MB limit) prevents unbounded memory allocation on malformed input
- `maxLineSize` guard on stdio message reader for consistency with write path

### Fixed
- Strict-mode API allowlist enforcement: requests to non-allowlisted domains now blocked in strict mode (was warn-only)
- MCP no-params DLP bypass: requests with missing `params` field bypassed input scanning entirely
- Encoded secret bypass in MCP input: multi-layer percent-encoding could evade DLP patterns
- Display URL normalization: audit log URLs now consistently decoded for readability
- Three static analysis findings: `ViolationPermissions` field visibility, HITL reload-to-ask warning, stale comment

### Changed
- Demo "MCP Tool Poisoning" scenario renamed to "MCP Response Injection" for clarity
- `iterativeDecode` consolidated into single exported function (was duplicated across scanner paths)
- Write errors in `syncWriter` and `StdioWriter` now wrapped with context
- Bumped `sigstore/cosign-installer` from 3.10.1 to 4.0.0

## [0.2.2] - 2026-02-15

### Added
- MCP tool description scanning: detects poisoned tool descriptions containing hidden instructions (`<IMPORTANT>` tags, file exfiltration directives, cross-tool manipulation)
- MCP tool rug-pull detection: SHA256 baseline tracks tool definitions per session, alerts when descriptions change mid-session
- `mcp_tool_scanning` config section (action: warn/block, detect_drift: true/false)
- Auto-enabled in `mcp proxy` mode unless explicitly configured
- Unicode normalization (NFKC) and C0 control character stripping in tool description scanning
- Recursive schema extraction: scans `description` and `title` fields from nested `inputSchema` objects
- JSON-RPC batch response handling for tool scanning
- `CODEOWNERS` file for automatic review assignment
- Cosign keyless signing for release checksums (Sigstore transparency log)
- Manual trigger (`workflow_dispatch`) for OpenSSF Scorecard workflow

### Fixed
- Fetch proxy URL parameter truncation: unencoded `&` in target URLs silently truncated secrets from DLP scanner
- Fetch proxy control character bypass: `%00`, `%08`, `%09`, `%0a` in target URLs broke DLP regex matching
- Empty-name tool bypass: tools with no `name` field bypassed `tools/list` scanning entirely
- Baseline capacity DoS: malicious servers could force hash computation on unlimited unique tool names (added capacity cap with `ShouldSkip()`)

### Changed
- Branch protection: squash-only merges, stale review dismissal

## [0.2.1] - 2026-02-15

### Added
- SLSA build provenance attestation for all release binaries and container images
- CycloneDX SBOM generated and attached to every release
- OpenSSF Scorecard workflow with results published to GitHub Security tab
- `govulncheck` CI job scanning Go dependencies for known vulnerabilities
- `go mod verify` step in CI and release pipelines
- OpenSSF Scorecard badge in README
- OpenSSF Best Practices passing badge in README
- Release verification instructions in README (`gh attestation verify`)

### Changed
- All GitHub Actions pinned to commit SHAs (supply chain hardening)
- Release workflow now includes `id-token` and `attestations` permissions for provenance signing
- Explicit top-level `permissions: contents: read` in CI workflow (least privilege)
- Release attestation steps use `continue-on-error` with final verification (prevents cascading failures)
- Container digest resolution uses `::warning` annotation instead of silent fallback
- `govulncheck`, `cyclonedx-gomod`, and `crane` pinned to specific versions (not `@latest`)
- Docker base images pinned by SHA256 digest (Scorecard Pinned-Dependencies)
- Write permissions moved from workflow-level to job-level (Scorecard Token-Permissions)
- Branch protection: added PR requirement, lint as required check, strict status policy, review thread resolution

### Fixed
- Fetch proxy DNS subdomain exfiltration: dot-collapse scanning now applied to hostnames in `checkDLP` (was only on MCP text scanning side)
- MCP content block split bypass: `ExtractText` now joins blocks with space separator (was `\n`, allowing between-word injection splits to evade detection)
- Git DLP case sensitivity: `CompileDLPPatterns` now applies `(?i)` prefix, matching URL scanner behavior
- Rate limiter subdomain rotation: `checkRateLimit` now uses `baseDomain()` normalization, preventing per-subdomain rate limit evasion
- Response scanning Unicode whitespace bypass: added `normalizeWhitespace()` for Ogham space (U+1680), Mongolian vowel separator (U+180E), and line/paragraph separators
- Agent name path traversal: `ValidateAgentName` now rejects names containing `..` or equal to `.`
- URL DLP NFKC normalization: applied `norm.NFKC.String()` before DLP pattern matching, consistent with response scanning

## [0.2.0] - 2026-02-13

### Added
- MCP input scanning: bidirectional proxy now scans client requests for DLP leaks and injection in tool arguments
- `mcp_input_scanning` config section (action: warn/block, on_parse_error: block/forward)
- Auto-enabled in `mcp proxy` mode unless explicitly configured
- Iterative URL decoding in text DLP (catches double/triple percent-encoding)
- Method name and request ID fields included in DLP scan coverage
- OPENSSH private key format added to Private Key Header DLP pattern
- Split-key concatenation scanning: detects secrets split across multiple JSON arguments
- DNS subdomain exfiltration detection: dot-collapse scanning catches secrets split across subdomains
- Case-insensitive DLP pattern matching: prevents evasion via `.toUpperCase()` or mixed-case secrets
- Null byte stripping in scanner pipeline: prevents regex-splitting bypass via `\x00` injection
- 55+ new tests for input scanning, text DLP, and config validation

### Changed
- CI workflow: removed redundant `go vet` and `go mod verify` steps, combined duplicate test runs, added job timeouts
- Audit preset `on_parse_error` changed from `block` to `forward` (consistent with observe-only philosophy)
- Config validation rejects `ask` action for input scanning (no terminal interaction on request path)
- CLI auto-enable checks both `enabled` and `action` fields (unconfigured = both at zero values)

## [0.1.8] - 2026-02-12

### Added
- Audit log sanitization: ANSI escapes and control characters stripped from all log fields (`internal/audit/logger.go`)
- Data budget enforcement per registrable domain (prevents subdomain variation bypass)
- Hex-encoded environment variable leak detection
- Container startup warning when running as root
- HITL channel drain before each prompt (prevents stale input from prior timeout)
- DLP patterns for `github_pat_` fine-grained PATs and Stripe keys (`[sr]k_(live|test)_`)
- Fuzz test for audit log sanitizer
- Integrity manifest path traversal protection
- 970+ tests passing with `-race`

### Security
- MCP proxy fail-closed: unparseable responses now blocked in all action modes (was forwarding in warn/strip/ask)
- MCP batch scanning fail-closed: parse errors on individual elements now propagate as dirty verdict
- MCP strip recursion depth limit (`maxStripDepth=4`) prevents stack overflow from nested JSON arrays

### Fixed
- DLP pattern overlap: OpenAI Service Key narrowed to `sk-svcacct-` (was `sk-(proj|svcacct)-`, overlapping with existing `sk-proj-` pattern)
- Redirect-to-SSRF: blocked flag now set on redirect hops (redirect to private IP was not caught)
- Rate limiter returns HTTP 429 Too Many Requests (was returning 403)
- io.Pipe resource leak in HITL tests

### Removed
- SKILL.md (ClawHub listing discontinued)

## [0.1.6] - 2026-02-11

### Added
- `--json` flag for `git scan-diff` command (CI/CD integration)
- Fuzz tests for 8 security-critical functions across 4 packages
- 660+ tests passing with `-race`

### Security
- IPv4-mapped IPv6 SSRF bypass: `::ffff:127.0.0.1` now normalized via `To4()` before CIDR matching
- MCP ToolResult schema bypass: result field uses `json.RawMessage` with recursive string extraction fallback
- MCP zero-width Unicode stripping applied to response content scanning
- DNS subdomain exfiltration: DLP/entropy checks now run on hostname before DNS resolution
- `--no-prefix` git diff bypass: parser accepts `+++ filename` without `b/` prefix
- MCP error messages (`error.message` and `error.data`) now scanned for injection
- Double URL encoding DLP bypass: iterative decode (max 3 rounds) on path segments
- Default SSRF CIDRs: added `0.0.0.0/8` and `100.64.0.0/10` (CGN/Tailscale)
- CRLF line ending normalization in git diff parsing
- `ReadHeaderTimeout` added to HTTP server (Slowloris protection)
- Non-text MCP content blocks now scanned (was skipping non-`text` types)

### Fixed
- Homebrew formula push: use `HOMEBREW_TAP_TOKEN` secret for cross-repo access

## [0.1.5] - 2026-02-10

### Added
- `pipelock audit` command: scans projects for security gaps, generates score (0-100) and suggested config (`internal/projectscan/`)
- `pipelock demo` command: 5 self-contained attack scenarios (DLP, injection, blocklist, entropy, MCP) using real scanner pipeline
- OWASP Agentic AI Top 15 threat mapping (`docs/owasp-agentic-top15-mapping.md`, 12/15 threats covered)
- 14 scanner pipeline benchmarks with `make bench` target (~3 microseconds per allowed URL)
- Grafana dashboard JSON (`configs/grafana-dashboard.json`, 7 panels, 3 rows)
- SVG logo
- Public contributor guide (`CLAUDE.md`)
- CONTRIBUTING.md expanded with detailed development workflow
- 756+ tests passing with `-race`

### Fixed
- Audit score: critical finding penalty (-5 per leaked secret found)
- DLP pattern compilation deduplication
- Follow mode context-aware shutdown in `logs` command
- Blog links updated from GitHub Pages to pipelab.org
- OWASP mapping updated to 2026 final category names

## [0.1.4] - 2026-02-09

### Added
- MCP stdio proxy mode: `pipelock mcp proxy -- <command>` wraps any MCP server, scanning responses in real-time (`internal/mcp/proxy.go`)
- Human-in-the-loop terminal approvals: `action: ask` prompts for y/N/s with configurable timeout (`internal/hitl/`)
- Agent-specific config presets: `configs/claude-code.yaml`, `configs/cursor.yaml`, `configs/generic-agent.yaml`
- Claude Code integration guide (`docs/guides/claude-code.md`)
- Homebrew formula in GoReleaser config
- Asciinema demo recording embedded in README

### Fixed
- Makefile VERSION fallback: `git describe` failure no longer produces empty version string
- OpenAI API key DLP regex: now matches keys containing `-` and `_` characters
- HITL approver data race: single reader goroutine pattern eliminates concurrent `bufio.Reader` access on timeout
- GoReleaser v2: `folder` renamed to `directory` in Homebrew brews config

## [0.1.3] - 2026-02-09

### Added
- File integrity monitoring for agent workspaces (`pipelock integrity init|check|update`)
- SHA256 manifest generation with glob exclusion patterns (`**` doublestar support)
- Integrity check reports: modified, added, and removed file detection
- JSON output mode for integrity checks (`--json` flag)
- Custom manifest path support (`--manifest` flag)
- Atomic manifest writes (temp file + rename) to prevent corruption
- Manifest version validation and nil-files guard on load
- Ed25519 signing for file and manifest verification (`pipelock keygen|sign|verify|trust`)
- Key storage under `~/.pipelock/` with versioned format headers
- Trusted key management for inter-agent signature verification
- Path traversal protection in keystore operations
- MCP JSON-RPC 2.0 response scanning for prompt injection (`pipelock mcp scan`)
- MCP scanning: text extraction from content blocks, split-injection detection via concatenation
- MCP scanning: `--json` output mode (one verdict per line) and `--config` flag
- Blog at pipelab.org/blog/
- 530+ tests passing with `-race`

### Fixed
- DLP bypass: secrets in URL hostnames/subdomains now scanned (full-URL DLP scan)
- DLP bypass: secrets split across query parameters now detected
- README: corrected signing CLI syntax, agent types, health version example
- GoReleaser: added missing BuildDate/GitCommit/GoVersion ldflags
- Blog: fixed hallucinated product name, removed stale "coming next" reference

### Security
- `json.RawMessage` null bypass prevention (MCP result always scanned regardless of error field)

### Removed
- Stale Phase 1.5 planning doc (planning docs live outside the repo)

## [0.1.2] - 2026-02-08

### Added
- CodeQL security scanning workflow
- Codecov coverage integration and badge
- Go Report Card badge

### Fixed
- All 53 golangci-lint warnings resolved (zero-warning CI baseline)
- 363 tests passing with `-race`

## [0.1.1] - 2026-02-08

### Changed
- CLI commands write to `cmd.OutOrStdout()` instead of `os.Stdout` (cobra-idiomatic)
- `run` command uses `cmd.Context()` as signal parent for testability

### Added
- Run command integration test (config loading, flag overrides, health check, graceful shutdown)
- Docker Compose YAML syntax validation test (all agent templates parsed via `yaml.Unmarshal`)
- Base64url environment variable leak detection test
- Rate limiter window rollover test
- Healthcheck command test against running server
- 363 tests passing with `-race`

## [0.1.0] - 2026-02-08

### Added
- Fetch proxy server with `/fetch`, `/health`, `/metrics`, and `/stats` endpoints
- URL scanning pipeline: scheme check, SSRF protection, domain blocklist, rate limiting, URL length, DLP regex, Shannon entropy
- SSRF protection with configurable CIDR ranges (IPv4 + IPv6), fail-closed DNS resolution, DNS rebinding prevention via pinned DialContext
- DLP pattern matching for API keys, tokens, secrets (Anthropic, OpenAI, GitHub, Slack, AWS, Discord, private keys, SSNs)
- Shannon entropy analysis for detecting encoded/encrypted data in URL segments
- Environment variable leak detection: scans URLs for high-entropy env var values (raw + base64-encoded)
- Domain blocklist with wildcard support (`*.pastebin.com`)
- Per-domain rate limiting with sliding window and configurable `max_requests_per_minute`
- Response scanning: fetched page content scanned for prompt injection patterns (block/strip/warn actions)
- Multi-agent support: `X-Pipelock-Agent` header identifies calling agents; agent name included in audit logs and fetch responses
- Agent name sanitization to prevent log injection
- Structured JSON audit logging via zerolog (allowed, blocked, error, anomaly, redirect events)
- YAML configuration with validation and sensible defaults
- Config hot-reload via fsnotify file watching and SIGHUP signal (when using `--config`)
- Hot-reload panic recovery: invalid config reloads are caught and logged without crashing the proxy
- Three operating modes: strict, balanced (default), audit
- CLI commands: `run`, `check`, `generate config`, `generate docker-compose`, `logs`, `git scan-diff`, `git install-hooks`, `version`, `healthcheck`
- Config presets: `configs/balanced.yaml`, `configs/strict.yaml`, `configs/audit.yaml`
- Docker Compose generation for network-isolated agent deployments (`pipelock generate docker-compose`)
- HTML content extraction via go-readability
- Redirect following with per-hop URL scanning (max 5 redirects)
- Graceful shutdown on SIGINT/SIGTERM
- Prometheus metrics: `pipelock_requests_total`, `pipelock_scanner_hits_total`, `pipelock_request_duration_seconds`
- JSON stats endpoint: top blocked domains, scanner hits, block rate, uptime
- Build metadata injection via ldflags (version, date, commit, Go version)
- Docker support: scratch-based image (~15MB), multi-arch (amd64/arm64), GHCR via GoReleaser
- GitHub Actions CI (Go 1.24 + 1.25, race detector, vet)
- 345 tests with `-race`
