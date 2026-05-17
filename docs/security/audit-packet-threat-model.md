# Audit Packet threat model

Threat model for the Pipelock Audit Packet (Audit Packet v0). Audience: a relying party (CISO, auditor, downstream platform, procurement reviewer) deciding whether to treat the packet as evidence about an agent run.

## What an Audit Packet is

An Audit Packet is the bundle Pipelock writes after a Pipelock-mediated agent run. It pairs a verifier verdict over a chain of Ed25519-signed action receipts with the enforcement posture that produced them. The canonical schema is [`sdk/audit-packet/v0.json`](../../sdk/audit-packet/v0.json); the on-wire receipt format is documented at [pipelab.org/learn/action-receipt-spec/](https://pipelab.org/learn/action-receipt-spec/). The first producer is the [`pipelock-agent-egress-action`](https://github.com/luckyPipewrench/pipelock-agent-egress-action) GitHub Action; producers on other CI surfaces follow the same schema.

This document describes what the packet does and does not prove about the run. It is the text a hostile-reader review of a packet should be checked against.

## What a verified packet proves

A packet whose chain hashes correctly and whose receipts verify against a pinned Pipelock signer key proves the following about traffic that crossed the Pipelock control point:

- Receipts in the chain were signed by the holder of the pinned signer key at the time written.
- The hash chain is intact. No receipt in the chain was modified, removed, or reordered after emission without breaking every receipt that follows.
- Each emitted receipt records the policy hash and posture metadata in force at signing time, so a reviewer can confirm the run executed under the declared configuration.
- Decision counts in the summary reconcile with the chain. The standalone `pipelock-verifier` cross-checks the packet's claimed totals, root hash, and final sequence against the actual chain on every invocation.

Receipts are signed by Pipelock at the network boundary, not by the agent process. Verification of the slice the receipts cover does not depend on the agent transcript. It still depends on the signer, binary, wrapper, workflow, and runner-boundary assumptions below.

## What a verified packet does not prove

Five categories sit outside the packet's evidentiary scope. Each is a category where a hostile reader will press, and each is real.

### 1. Traffic that did not cross the Pipelock control point

The chain records what Pipelock observed. It is silent about traffic that bypassed Pipelock entirely. Examples in the GitHub Action's v0 boundary:

- Sibling steps in the caller workflow that run outside the action boundary.
- DNS lookups, raw TCP, and UDP that leave the namespace through other paths.
- Workflow artifact uploads, step outputs, and log writes that never traverse a mediated network call.
- Service containers and Docker daemons reachable from the namespace by paths Pipelock does not see.
- Git pushes via SSH transport in v0. HTTPS git pushes traverse the control point when routed through the action boundary, but unintercepted CONNECT exposes connection metadata, not git pack contents.
- Egress from macOS and Windows runners, where the namespace and iptables enforcement do not apply.

A missing receipt is not a proof of absence. The packet does not enumerate traffic Pipelock should have seen but didn't. A relying party that needs negative-space evidence cannot derive it from the packet alone. Complement with runner-level network telemetry that operates below the agent's reach.

The current set of paths the Pipelock binary itself does not intercept is documented in [current-unsupported-paths](current-unsupported-paths.md). The egress-action's v0 boundary is documented in the [action README](https://github.com/luckyPipewrench/pipelock-agent-egress-action#v0-enforcement-boundary).

### 2. Compromised runner environment

A verified packet does not prove the runner was honest. If the kernel, the runner image, the workflow harness, the action wrapper, or any earlier privileged step is compromised before Pipelock initialises, the packet inherits that compromise in three ways:

- Pipelock binary integrity. A compromised runner can swap the pinned `pipelock` binary for one that signs receipts of the attacker's choosing if it can also use the configured signing key, or if the relying party accepts a runner-supplied key. Mitigation: pin the binary checksum, pin the signer public key from a source outside the runner, and verify both before treating the packet as provenance.
- Signing-key exfiltration. A process with code execution as the Pipelock service account, with capabilities to read its memory, or with iptables override rights can extract the signing key. Receipts signed thereafter are indistinguishable from honest receipts at verify time. Mitigation: rotate the signer key per run from a key custody system outside the runner, or use an ephemeral signer that the relying party knows to treat as `self_consistent_only`.
- Pre-Pipelock exfiltration. Any byte that leaves the runner before Pipelock's iptables rules are in force is invisible to the chain. Mitigation: minimise the secret surface available to earlier workflow steps; treat the wrapped agent script as the sole secret-bearing step in the job.

### 3. Sibling-step and out-of-band channels

The egress-action v0 boundary covers the script executed inside the action. It does not contain other actions in the caller workflow. A relying party reading the packet learns nothing about:

- Other actions in the same job that received secrets via the workflow `env:` mapping.
- Steps that ran before the Pipelock action and emitted data via the workflow `outputs:` channel for later consumption.
- Job-level or workflow-level artifact uploads.

Mitigation: structure the workflow so the wrapped agent script is the only step that holds the secret material. The "Operational requirements" section below makes this concrete.

### 4. Self-consistent-only verdicts

The verifier returns `self_consistent_only` when the chain hashes correctly but no signer key was pinned. This verdict proves internal consistency, not Pipelock provenance. A `self_consistent_only` packet is consistent with any of the following:

- An honest Pipelock run whose operator declined to pin a key.
- A run that synthesised receipts after the fact and hashed them into a consistent chain.
- A run whose signing key was generated by an attacker and discarded after.

Mitigation: consumers must distinguish `self_consistent_only` from `valid` and refuse to treat the former as provenance. The `v0.json` schema requires the verifier verdict enum to include `self_consistent_only` so consumers cannot conflate the two. Conformance fixtures include both verdict cases; consumers that test against the fixtures catch conflation at integration time.

### 5. Future tampering of artefacts at rest

The chain detects tampering of receipts already in the chain. It does not detect substitution of the entire packet by a different packet, or removal of the packet entirely. A relying party who receives the packet from an untrusted channel must validate the receipt of the packet itself (artefact hash, sender authentication, ingestion timestamp) using the surrounding evidence pipeline. The Audit Packet does not include those properties because they belong to the transport, not to the run.

## Trust assumptions

A verified packet's evidentiary value depends on eight assumptions. If any fails, the verdict says less than it appears to.

1. The pinned signer key was obtained from a source outside the run environment. A key fetched from inside the same potentially compromised environment is not pinned in the sense this threat model uses. Pin from a key custody system, a published trust anchor, or a manual handoff to the relying party before the run.
2. The verifier runs outside the run environment. Running the verifier inside the same potentially compromised runner reduces the verdict to "the runner's verifier reported a verdict." The Go, Rust, and TypeScript Audit Packet verifiers run offline and need no network surface, so the relying party can verify on their own workstation.
3. The Pipelock binary matches the expected artifact. A valid chain from an unpinned or swapped binary proves only that some binary holding the signing key emitted those receipts. Pin the release artifact by checksum and verify it before launch.
4. The wrapper that creates the boundary matches the expected action revision. Pin the GitHub Action by full-length commit SHA. Signed tags help identify publisher intent, but tag names can be repointed.
5. The workflow boundary is scoped correctly. The wrapped script should be the only secret-bearing step in the job. Sibling steps, earlier steps, artifact uploads, and workflow outputs are outside the packet's evidence boundary.
6. The receipt schema was not silently changed. The `v0` schema is frozen in `sdk/audit-packet/v0.json`. A producer that emits a packet claiming `schema_version: v0` but with a divergent shape fails schema validation in the verifier. Future schema versions are independent of the binary version.
7. The relying party reads the verifier verdict and posture, not just the summary. The summary file is human-friendly Markdown. Posture fields and the verifier verdict are the contract. Consumers that read only the summary and not the structured fields can be fooled by a producer that lies in Markdown.
8. The cryptographic primitive is not yet broken. Ed25519 is the current signing algorithm. A post-quantum or unforeseen-attack break of Ed25519 invalidates every receipt ever signed under it. The schema version is the rotation point for primitive changes.

## Operational requirements for a usable packet

A relying party who wants the packet to carry weight in their evidence pipeline should require the producer to satisfy these requirements:

- [ ] Signer key pinned from a source outside the run environment. Public key handed over before the run or fetched from a known trust anchor.
- [ ] Pipelock binary pinned by checksum. The runner does not download `latest`. The integrity check happens at start of run.
- [ ] Pipelock action pinned by full-length commit SHA. Tags are mutable; short SHAs are prefix identifiers, not immutable release anchors.
- [ ] Verifier run outside the run environment. Pin the verifier version too.
- [ ] Workflow scoped so the wrapped step is the sole secret-bearing step in the job.
- [ ] Packet transport authenticated. Artefact hash captured, sender authenticated, ingestion timestamp recorded.
- [ ] Verifier verdict consumed structurally (`valid` vs `self_consistent_only` vs others), not from the Markdown summary.

Producers that meet all seven make a `valid` verdict useful as provenance: Pipelock signed these receipts, under a pinned producer and a bounded workflow. Producers that skip signer-key pinning should expect `self_consistent_only`; producers that skip other requirements may still get `valid`, but the verdict carries weaker evidentiary weight.

## What is not in scope

This threat model does not cover:

- The signing-key custody system itself. Key rotation operations are documented in [key-rotation-runbook](key-rotation-runbook.md).
- The TLS interception CA. CA trust is covered in [per-deployment-ca-threat-model](per-deployment-ca-threat-model.md). The TLS CA and the receipt-signing key are independent trust roots.
- Pipelock binary supply-chain integrity. That story belongs to GoReleaser provenance attestation and is tracked in the project release procedure.
- The producer's own software supply chain. A poisoned GitHub Action in the caller workflow can compromise the run before Pipelock starts; the response is workflow hygiene, not packet content.

## See also

- [sdk/audit-packet/README.md](../../sdk/audit-packet/README.md): schema reference and field-by-field contract.
- [current-unsupported-paths.md](current-unsupported-paths.md): network paths the current Pipelock binary does not intercept.
- [action-receipt-spec on pipelab.org](https://pipelab.org/learn/action-receipt-spec/): on-wire format for individual receipts.
- [SECURITY.md](../../SECURITY.md): reporting channel for receipt-format vulnerabilities.
