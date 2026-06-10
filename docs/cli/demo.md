<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# `pipelock demo`

Run self-contained attack scenarios that show what Pipelock catches. No server,
config file, or network access required — the scenarios run against an
in-process scanner built from the default config, so `pipelock demo` is the
fastest way to see the detection layers fire.

```bash
pipelock demo
pipelock demo --interactive
pipelock demo --receipts-dir ./demo-receipts
```

| Flag | Default | Description |
|---|---|---|
| `--interactive`, `-i` | `false` | Pause between scenarios (for live demos). |
| `--no-color` | `false` | Disable color output. |
| `--receipts-dir` | (none) | Write a signed receipt JSON per scenario, plus the signer public key (`signer.pub`), to this directory. |

## Scenarios

Each scenario simulates an attack vector AI agents face in production:

| Scenario | What it demonstrates |
|---|---|
| Credential Exfiltration | A secret smuggled into an outbound URL, caught by DLP |
| Prompt Injection | Injection patterns in fetched content, caught by response scanning |
| Cloud Metadata SSRF | A cloud metadata endpoint probe, caught by SSRF protection |
| Data Exfiltration via Paste Service | An upload to a known exfiltration destination, caught by the domain blocklist |
| MCP Response Injection | Injection inside an MCP tool result |
| MCP Input Secret Leak | A secret inside MCP tool-call arguments |
| MCP Tool Description Attack | A poisoned tool description in `tools/list` |

## Signed receipts

Every demo action produces an Ed25519-signed action receipt binding the
detection layer, pattern, and verdict. The demo generates an ephemeral signing
key per run, prints the public key, and verifies each receipt inline against
that exact key — proving authenticity, not just internal consistency.

With `--receipts-dir`, each receipt is written to disk alongside `signer.pub`
so a third party can verify it offline:

```bash
pipelock demo --receipts-dir ./demo-receipts
pipelock verify-receipt ./demo-receipts/<receipt>.json --key "$(cat ./demo-receipts/signer.pub)"
```

See the [receipt verification guide](../guides/receipt-verification.md) for the
full verification flow.
