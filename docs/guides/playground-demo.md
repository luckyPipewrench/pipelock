# Playground live demo engine

`pipelock-playground-demo` drives a **deterministic toy agent** through a real Pipelock
proxy and produces an offline-verifiable evidence bundle. It is the live counterpart to the
[replay-capture rig](playground-replay-capture.md): instead of pre-recording scenarios, it
runs one live, and lets a viewer verify the result afterward — with Pipelock already stopped.

It is demo/evidence tooling, not part of the production firewall.

## What it shows

A deterministic toy agent runs as a separate process, holds an inert credential-shaped canary
in its environment, and uses a small "web tool" to make HTTP. Pipelock runs as a separate
process, is not preloaded with the exact canary value, detects the credential class in the
request body, mediates each action, and signs each decision:

1. **Allowed action** — the agent fetches a safe lab URL; Pipelock allows it; a signed receipt
   is recorded.
2. **Blocked exfiltration** — the agent tries to send the canary to a lab collector; Pipelock
   blocks it before the collector receives it; a signed receipt is recorded, and a separate
   **signed collector witness** independently records that the canary did not arrive.
3. **Direct-egress bypass** *(contained mode only)* — the agent tries raw egress that ignores
   the proxy; host containment denies it at the kernel.
4. **Offline verification** — the run's evidence verifies with one command after the Pipelock
   process is stopped.

## What it proves (and does not)

> This proves the **included mediated decisions** and the **lab collector's observation for
> this lab run** — not universal session completeness, not global non-exfiltration, not that
> no event was missed.

Each on-screen claim carries one of four explicit **evidence classes**, and no element is shown
as a stronger class than it is:

| Class | Meaning | Signed by |
|---|---|---|
| `pipelock_decision` | an allow/block decision in the receipt chain | the Pipelock mediator key |
| `collector_witness` | the lab collector's target-side observation | the collector key (separate) |
| `host_containment` | the direct-egress bypass denied by the kernel | not a receipt — operational result |
| `narration` | the agent's printed intent | unsigned playback |

The proxy mediation and the signed receipts/witness are **binary-enforced**. The direct-egress
block (contained mode) is **host/deployment-enforced** via `pipelock contain` (kernel nftables);
it is not a property of this tool's binary and is only present when the agent is actually
contained.

## Run it

The demo material is **synthetic by construction** — the canary is an inert published-example
value and the lab targets are reserved `.test` hosts. Nothing real is ever in the agent's
environment, on the wire, or in the artifacts.

### Uncontained (development / iteration — no privileges)

```bash
pipelock-playground-demo run --run-dir ./demo-run --scenario secret-exfil-body-blocked
```

This boots a real Pipelock proxy + lab targets on loopback, drives the toy agent through the
proxy, renders the evidence-class-labeled mediator timeline, assembles the Audit Packet, and
verifies it. The direct-egress bypass beat is **skipped** here: without containment there is no
kernel boundary to demonstrate, and the tool says so rather than implying one.

### Contained (the real demo — requires a prepared host)

```bash
sudo pipelock-playground-demo run --contained --run-dir ./demo-run --scenario secret-exfil-body-blocked
```

Contained mode requires root, the `pipelock-agent` OS user, and a host where
`pipelock contain install` has been run. The bypass beat is executed by the toy-agent process
after dropping to that contained user; if the direct-egress request connects, the run aborts
rather than claim a containment that is not in effect. Off such a host the command fails loudly
— it never silently falls back to uncontained while claiming contained.

## Verify it yourself

From the run directory, on a clean machine, with the Pipelock process stopped:

```bash
pipelock-playground-demo verify ./demo-run --orchestrator-key <published orchestrator key hex>
```

This is one all-or-nothing check rooted in a single published key. It passes only when **all**
of the following hold: the launch manifest is signed by the orchestrator key; the Audit Packet's
receipt chain and totals verify under the Pipelock key the manifest pins; the packet manifest
matches the launch manifest's scenario and policy hash; the collector witness verifies under
the collector key the manifest pins; the witness binds this run's nonce and manifest; the
collector observed zero requests for the blocked exfil run; the packet contains the expected
allow and `body_dlp` block receipts; and the witness carries a genuine red-case calibration
backed by a signed `red-witness.json` artifact. Any single failure exits non-zero.

The receipt chain alone is also verifiable with the shipped `pipelock-verifier audit-packet`
against `./demo-run/packet` — but note that verifier checks the packet and chain only, not the
collector witness; the witness checks are part of `pipelock-playground-demo verify`.

### Red-case calibration

The collector witness is only trusted when the *same* collector build has been shown to detect
the canary. The run includes a **red-case calibration**: a deliberately unmediated run in which
the canary reaches the collector and the witness goes red (`observed > 0`). The calibration
result is signed into the live run's witness, and the signed red witness is written as
`red-witness.json`, so verification can require proof that the collector demonstrably detects
what it claims to have not observed.

## Reset and fallback

```bash
pipelock-playground-demo reset --run-dir ./demo-run        # idempotent clean slate
pipelock-playground-demo fallback ./demo-run --orchestrator-key <hex>   # replay a recorded run
```

`fallback` replays a previously recorded run with a prominent `*** REPLAY MODE ***` watermark,
the recorded packet hash, and the verifier command — so a replayed run is never mistaken for a
live one.

## Public-safety model

Inherited from the replay-capture rig: synthetic inputs only; receipts redacted before signing;
a fail-closed field allowlist and artifact linter over the published text artifacts; the canary
value lives only in the agent's environment and the request body Pipelock inspects, never on a
command line, in a URL, or on screen. Screenshots and social images are a separate manual
curation step (the text linter does not inspect pixels).
