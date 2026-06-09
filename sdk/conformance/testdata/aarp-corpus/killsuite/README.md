# Evidence Theater Kill Suite

A corpus of evidence packets that look valid and sound strong but **overclaim**,
each paired with the exact appraiser downgrade. The suite exists to prove one
hard-to-copy property of a credible agent-control verifier: it refuses to call an
assertion "proven" beyond what the evidence mechanically supports, and it applies
that refusal uniformly — including to its own strongest-sounding evidence.

Anyone can copy a signature format or a receipt schema. What is hard to copy is a
verifier that publicly downgrades the claims its own evidence most tempts a reader
to believe. This corpus is that proof, expressed as fixtures.

## What each fixture is

Every fixture is an AARP v0.1 assurance **envelope** (`*.aarp.json`), optionally
with an X.509-SVID workload-identity sidecar (`*.svid.json`), plus:

- `*.expect.json` — metadata, the cross-language verdict (`appraise`), the attack
  class, and the **hand-authored gate annotations**:
  - `overclaim_narrative` — the broad property a naive relying party might read in.
  - `must_not_verify` — claim names that MUST be absent from `verified_claims`.
  - `expected_overclaim_risks` — risk codes the appraiser MUST raise.
  - `expected_does_not_assert` — negatives the appraiser MUST list.
  - `pipelock_shaped` — true when the evidence is a genuine, validly-signed
    Pipelock receipt/SVID that is still downgraded.
- `*.appraisal.json` — the exact `ComparableAppraisal` bytes every reference
  verifier MUST emit (the cross-language byte-match surface).

## Two independent gates

1. **Byte-match parity** (`TestAARPCorpus` + `aarp-corpus-gate.sh`): all four
   reference verifiers (Go, TypeScript, Rust, Python) must emit byte-identical
   `*.appraisal.json` output. Cross-language divergence is the bug.
2. **Overclaim gate** (`TestKillSuiteOverclaimGate`): the hand-authored
   `must_not_verify` / `expected_overclaim_risks` / `expected_does_not_assert`
   annotations are asserted against live appraiser output. This gate is
   **independent of the golden** — because the annotations are written by a human,
   regenerating `*.appraisal.json` can never launder an over-broad verified claim
   past it. It is the tripwire a regeneration cannot defeat.

The contract: at least 20 hostile fixtures, of which at least 5 downgrade
Pipelock-shaped evidence. The gate fails if the corpus shrinks below either.

## Regenerating

The fixtures are generated deterministically by the Go reference verifier (no
wall clock, no network). To regenerate after a vocabulary or appraiser change:

```bash
go test ./sdk/conformance/ -run TestGenerateAARPCorpus -update-aarp
go test ./sdk/conformance/ -run 'TestAARPCorpus|TestKillSuiteOverclaimGate'
```

## Publication and drift

This pinned copy is what Pipelock CI runs the gate against — CI reads only this
in-tree directory and never fetches a sibling repo, so an external edit can never
redden Pipelock CI on its own. The suite is also published as a neutral category
artifact in the agent-egress-bench repo (`receipts/v0/evidence-theater/`).
`check-killsuite-drift.sh` compares this pinned copy against that publication; it
is a manual/release step, not a core CI gate. The Go generator here is the source
of truth; the bench publication is a mirror.

## Vendor neutrality

The corpus describes how agent-control evidence can lie and applies the test
uniformly. No competitor names, no "fake/noncompliant" language. Strong-sounding
evidence is simply not the same as proof — for anyone, Pipelock included. All
identities, hosts, and keys are synthetic test material.
