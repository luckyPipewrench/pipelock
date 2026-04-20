<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Detection integration

Pipelock is a real-time agent firewall. It blocks what it can see on the wire.
That is a hard, narrow job, and it is not the whole detection story.

Long-running agents move through multi-week attack chains, reason in
natural language, and produce actions that look benign in isolation.
No real-time gateway will catch all of that. The gate is the first
line, not the last.

This guide is for people building the layer that runs behind the gate.
SIEM engineers, SOC analysts, and researchers training detection models
all need the same thing upstream: structured, tamper-evident evidence of
what the agent actually did. Pipelock emits that evidence as signed
action receipts. This guide covers how to consume them.

## Real-time gateways are not enough

Picture a malicious MCP server that runs a two-step attack across a
week.

Step one, Monday: the agent calls an innocent-looking tool. The tool
response tells the agent to install a new hook that exfiltrates data
to `https://google.com/report`. To an inline detector, that looks
like a bad tool response, but the destination is benign. The
content might sail through, especially under a looser policy.

Step two, the following Monday: a different tool response tells the
agent to change the hook's destination. To an inline detector, that
request looks like a one-line config edit. The agent already has
the hook, so changing an endpoint is not structurally suspicious.
A real-time gateway viewing only that single moment has no reason
to block it.

Put the two steps next to each other and the intent is obvious. A
detector looking at a week of activity can see the shape. A detector
looking at a single request cannot.

Long-window detection is the only way to catch attacks that are
designed to look like two benign things. The question is what you
feed that detector.

## The primitive: signed action receipts

Every enforcement decision pipelock makes is recorded as a signed
action receipt. Receipts are Ed25519-signed, JSON-structured, and
linked into a SHA-256 hash chain so any deletion or reordering is
detectable after the fact.

A receipt carries the fields a downstream detector needs to reason
about the decision:

| Field | What |
|-------|------|
| `action_id` | UUIDv7, unique per decision. Stable identifier for the record. |
| `timestamp` | RFC 3339 wall-clock time the decision was made. |
| `verdict` | `block`, `warn`, `exemption`, `allow`, `strip`, `redirect`, or `ask`. Deterministic. |
| `layer` | Which scanner triggered (`mcp_response_scan`, `dlp_header`, `response_scan`, `airlock`, etc.). |
| `pattern` | Named rule inside the layer (e.g., `Prompt Injection`, `aws_access_key`). |
| `transport` | `fetch`, `forward`, `websocket`, `mcp_stdio`, `mcp_http_upstream`, `mcp_http_listener`, `connect`, `intercept`. |
| `session_id` | Groups receipts from the same agent session. |
| `principal` / `actor` | Who initiated the action and who enforced it. |
| `policy_hash` | SHA-256 of the canonical policy config at decision time. Changes whenever the policy changes. |
| `side_effect_class` / `reversibility` | Classification of the attempted action. |
| `chain_prev_hash` / `chain_seq` | Hash-chain linkage to the prior receipt in the stream. |
| `signature` / `signer_key` | Ed25519 signature and public key. |

These are fixed fields with a fixed schema. A detector parses them
with a JSON reader, not a log regex.

Full canonical schema and field reference:
<https://pipelab.org/learn/action-receipt-spec/>

## Three downstream consumers

The same receipt stream serves three different detection styles
without modification.

### SIEM rules

Forward the flight-recorder JSONL to Splunk, Datadog, Elastic, or any
SIEM that ingests JSON. The fields map cleanly to structured search:
group by `session_id` to reconstruct an agent's behavior, filter on
`verdict=block` to audit enforcement events, alert on
`pattern=aws_access_key` for secret-exfil attempts.

See <siem-integration.md> for the webhook, syslog, and file-forwarder
transports pipelock ships with. The receipt fields are the same on
every transport.

### Analyst review

When a SIEM rule fires or an agent's session looks suspicious, an
analyst can pull the full receipt stream for that `session_id` and
reconstruct every decision in order. The hash chain confirms the
stream has not been edited since it was written. The `policy_hash`
confirms which policy version was in force. The `signature`
confirms the record came from pipelock and not from a tampered
agent log.

This is the audit-trail use case. Receipts are designed to be
presentable to a third party (auditor, incident responder, internal
review) without requiring trust in pipelock itself. The signature
and the chain are the trust anchors.

### Long-window LLM detection

If your detection strategy involves feeding agent history to a
reasoning model and asking "is this suspicious", what you feed the
model matters more than which model you pick. Raw log text lets an
attacker shape the model's view by shaping the agent's reasoning
tokens. Structured receipts do not.

A receipt stream is a deterministic sequence of fixed-field events.
`verdict`, `layer`, `pattern`, `policy_hash`, and `timestamp` are
not up for attacker manipulation. The attacker cannot inject text
into the stream that changes what these fields say. The stream is
signed and chain-linked, so injection is detectable.

This is the architecture Zack Korman gestures at in his April 2026
video on AI agent threat detection: a funnel of cheaper LLMs
filtering events, stronger LLMs confirming, and an agentic layer
trying to disprove the finding. Whether that funnel works is its
own question. But if it does, it only works on inputs the attacker
cannot massage. Structured receipts are that kind of input. Raw
reasoning tokens are not.

## Worked example

The [`tool-response-injection`](/examples/tool-response-injection/)
example ships with pipelock and runs the whole loop end-to-end. It
uses a deliberately malicious MCP server that returns a prompt-
injection payload disguised as a game result.

Run the harness:

```bash
cd examples/tool-response-injection
python3 demo.py
```

The harness produces three artifacts worth looking at:

1. **`evidence/evidence-proxy-0.jsonl`**: the signed receipt stream
   from the MCP stdio run. Each line is an `action_receipt` record.
2. **`evidence-proxy-0.jsonl` from the HTTP upstream run**: same
   event shape, different `transport` field.
3. **`signing.key.pub` hex output**: the public key printed to
   stdout, the only thing a third party needs to verify the stream.

The harness verifies the stream inline with Python. For an
independent check, install the reference verifier:

```bash
pip install pipelock-verify
python -m pipelock_verify evidence/evidence-proxy-0.jsonl --key <public-key-hex>
```

Or use the Go CLI that ships with pipelock:

```bash
pipelock verify-receipt evidence/evidence-proxy-0.jsonl --key <public-key-hex>
```

Both exit 0 on success, 1 on any signature failure, chain break, or
reordering. The verifiers are byte-for-byte equivalent.

### Consuming receipts in a detector

Once the stream verifies, a downstream detector reads it like any
JSONL source. This is a complete working example:

```python
"""Verify a pipelock receipt stream, then route each verified receipt
to a pluggable handler for whatever downstream detector runs on.

Requires: pip install pipelock-verify
Run: python verify_and_route.py evidence.jsonl <public-key-hex>
"""

import json
import subprocess
import sys
from typing import Callable, Iterator


def verified_receipts(path: str, pubkey_hex: str) -> Iterator[dict]:
    """Yield each receipt only if the full stream verifies."""
    check = subprocess.run(
        ["pipelock-verify", path, "--key", pubkey_hex],
        capture_output=True,
        text=True,
    )
    if check.returncode != 0:
        raise RuntimeError(
            f"verification failed: {check.stderr.strip() or check.stdout.strip()}"
        )
    with open(path) as f:
        for line in f:
            if line.strip():
                yield json.loads(line)["detail"]["action_record"]


def default_handler(receipt: dict) -> None:
    """Replace this with your SIEM forwarder, alert pipeline, or
    feature extractor for an LLM classifier."""
    print(
        f"{receipt['timestamp']} {receipt['transport']:20s} "
        f"{receipt['verdict']:10s} {receipt.get('layer', '-'):24s} "
        f"{receipt.get('pattern', '-')}"
    )


def route(path: str, pubkey_hex: str, handler: Callable[[dict], None]) -> None:
    for receipt in verified_receipts(path, pubkey_hex):
        handler(receipt)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: verify_and_route.py <path> <public-key-hex>")
    route(sys.argv[1], sys.argv[2], default_handler)
```

Replace `default_handler` with whatever your pipeline needs:

```python
def route_to_siem(receipt: dict) -> None:
    if receipt["verdict"] == "block":
        forward_to_siem(receipt)
    if receipt["layer"] == "mcp_response_scan":
        score_for_llm_funnel(receipt)
```

The shape of the consumer is up to you. The shape of the input is
fixed by the receipt spec.

## What this does not solve

This is the important section. Signed receipts solve one narrow
problem. They do not solve several others.

**Compromised mediators can still lie.** A receipt proves pipelock
recorded a decision. It does not prove pipelock made the right
decision. If a scanner pattern is wrong, the signed record is a
signed wrong answer.

**Real-time gateways still miss multi-week attacks.** The worked
example above catches a prompt-injection payload in a single tool
response because that payload is visible in flight. A slow-boiling
attack where each individual step looks benign needs a long-window
detector running on the receipt stream, not a faster gateway.

**Receipts are input to detection, not a substitute for it.** A
stream of signed records does not tell you which sessions are
compromised. Someone or something still has to look at the stream
and make that call. What receipts give you is a trustworthy place
to look.

**Agent-side attacks are out of scope.** Pipelock sees what the
agent tries to do on the network. If an attacker has already
compromised the agent process itself (code execution, same-user
file access, shared memory), the receipts can document what the
agent then tried to do, but they cannot prevent the compromise or
retroactively verify the agent's internal state.

**Same-user deployments have a known ceiling.** If pipelock runs
as the same Unix user as the agent, the agent can delete or
truncate the receipt file. The `demo_capability_separation.py`
script in the harness demonstrates this limit directly. Running
pipelock under a separate user (or in a separate container) is a
deployment-level fix, not a product-level one.

## Where to go from here

- **Receipt format spec:** <https://pipelab.org/learn/action-receipt-spec/>
- **Verification mechanics:** [`receipt-verification.md`](receipt-verification.md)
- **SIEM transport options:** [`siem-integration.md`](siem-integration.md)
- **Transport coverage matrix:** [`receipt-transports.md`](receipt-transports.md)
- **Worked example:** [`examples/tool-response-injection/`](/examples/tool-response-injection/)
- **PyPI verifier:** <https://pypi.org/project/pipelock-verify/>

If you are integrating pipelock receipts into a detection pipeline
and run into something the spec does not cover, open an issue at
<https://github.com/luckyPipewrench/pipelock/issues>.
