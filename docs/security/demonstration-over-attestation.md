<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Demonstration Over Attestation

Pipelock's evidence story is not "trust the vendor dashboard." A buyer can
re-run the shipped verifier against signed artifacts with a pinned public key.

## What The Buyer Verifies

- Receipt signatures use trusted Ed25519 public keys.
- Receipt chains link by sequence and previous hash.
- Fleet reports bind follower evidence into an offline-verifiable report.
- Tampering, missing links, wrong keys, and unpinned keys fail closed unless the
  operator explicitly chooses structural-only mode.

## Customer-Path Demo

Generate or collect a receipt chain, then verify it offline:

```bash
pipelock verify-receipt \
  --chain /path/to/receipts.jsonl \
  --key 70b991eb77816fc4ef0ae6a54d8a4119ddc5a16c9711c332c39e743079f6c63e
```

What this does: verifies the receipt chain without contacting Pipelock,
Conductor, or a hosted service.

For a fleet report:

```bash
pipelock verify-receipt \
  --fleet-report /path/to/fleet-report.json \
  --key /path/to/fleet-report-signing.pub
```

What this does: verifies the signed fleet report with the pinned report-signing
public key.

## Negative Demo

Change one byte in a receipt or use the wrong public key, then rerun the same
command. Expected result: verification exits non-zero and reports the signature
or chain failure.

## Boundary

Offline verification proves the integrity of the emitted evidence. It does not
prove that no unmediated traffic happened outside Pipelock; that property is
deployment-enforced by routing and egress controls.
