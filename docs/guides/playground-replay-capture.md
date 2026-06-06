# Playground replay capture rig

`pipelock-replay-capture` drives controlled **synthetic** attack scenarios
through a real Pipelock proxy and publishes a gallery of signed
[Audit Packets](receipt-verification.md) plus per-recording replay manifests.
It is the capture half of the Playground "Replay Audit Packet gallery": a public
page can play back a recorded lab scenario, show the mediator-signed receipts,
and let a visitor verify the receipt chain themselves with the shipped
`pipelock-verifier audit-packet`.

The rig is a separate binary from `pipelock`. It is an evidence-publishing tool,
not part of the production firewall.

## What it proves (and does not)

Each recording maps to one Audit Packet whose `evidence.jsonl` is a signed
receipt chain. A verified chain proves the **included mediated decisions** were
signed by the mediator and untampered. It does **not** prove session
completeness, that no event was missed, that the agent was sandboxed, or that
traffic could not bypass Pipelock. The prompts/responses in a recording are
unsigned playback metadata; only the receipt chain of decisions is signed. Every
manifest carries this language verbatim in `completeness_note`.

## Generate the gallery

```bash
go run ./cmd/pipelock-replay-capture generate --out ./playground-gallery
```

This captures every default scenario, assembles a packet per scenario, writes a
replay manifest, verifies each packet, writes a gallery index plus the run's lab
public key, and lints every published byte fail-closed. Any failure aborts the
run with a non-zero exit; treat output as publishable only after a successful
exit.

The full multi-scenario gallery is generated for the playback UI on the
marketing site. This repo commits only a single verifiable example fixture
(`examples/playground-replay/`) as a checked-in conformance and regression
sample (launch gate #8).

Output layout:

```
<out>/
  gallery.json            # index: scenarios + signer key + completeness note
  signing-key.pub         # lab public key pinning every packet in this run
  <scenario>/
    packet.json           # Audit Packet v0 envelope (safe constants only)
    evidence.jsonl        # the signed receipt chain (verifier input)
    manifest.json         # UI playback metadata bound to the packet hash
    verifier.txt          # human-readable verification note + command
    summary.md            # short public-safe summary
```

## Verify a packet yourself

From any packet directory, on a clean machine:

```bash
pipelock-verifier audit-packet . --key <signer key from signing-key.pub>
```

A `result: VALID` with `trusted: true` means the receipt chain was signed by the
pinned lab key and reconciles with the packet summary.

## Public-safety model

The gallery is **public-safe by construction**, never by post-scrub (post-hoc
edits would break the signature):

- **Synthetic only.** Every input is synthetic — AWS's published example key,
  RFC 5737 / RFC 3927 reserved addresses, `example.com` hosts, and reserved
  `.test` fixture hosts. A leak proves nothing.
- **Redact before sign.** The recorder's redactor runs *before* signing inside
  the emitter, so secret-bearing fields carry placeholders in the signed bytes.
- **Field allowlist (fail-closed).** Every receipt is gated against a
  published-field allowlist before assembly; any non-synthetic target host,
  foreign identity, raw secret shape, or context-bearing field aborts the run.
- **Envelope safety.** The packet envelope is built from safe constants only —
  `provider: local`, a lab agent identity, posture honestly `unknown` for probes
  the rig does not run. No repo/run identity, config paths, host/agent IPs, proxy
  URL, or script names.
- **Artifact linter (fail-closed).** A final sweep over every published byte
  blocks on private paths, real-infrastructure hosts/IPs, raw secret shapes, and
  overclaim phrases.

## Scenarios (first drop)

| Scenario | Bench case | Decision |
|---|---|---|
| Allowed safe read | `url-benign-api-call-001` | allow |
| Secret exfiltration over a URL | `url-dlp-aws-key-001` | block (DLP) |
| Prompt injection in fetched content | `response-injection-ignore-002` | block (response scan) |
| Reach for cloud metadata | `url-ssrf-metadata-009` | block (SSRF) |
| Operation-aware policy | `local-lab-request-policy-graphql-mutation-001` | allow safe read, block destructive mutation |

Mapping a recording to a bench case id is the only permitted benchmark link; the
gallery is **not** a benchmark. The operation-aware policy recording is labeled
as a local lab scenario until the public corpus has a matching case.
