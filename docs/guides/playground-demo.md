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
3. **Kernel containment** *(contained mode only)* — proven separately from the mediated
   decisions (a "split proof"). A probe runs from the **contained agent's network position**
   (dropped to the `pipelock-agent` uid) against a host-local control target and the real
   direct-egress suite (cloud metadata, RFC-1918, public DNS/HTTPS). The result is a **signed
   host-containment witness**. Its honesty rests on a **differential**: the same control target
   is reachable for the operator but explicitly blocked for the contained agent, which isolates
   the kernel owner-match rule for the host-local control proof. The direct-egress suite must
   also be explicitly blocked from the contained position; reachable-but-closed responses such
   as TCP connection refusal do not count as containment.
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
| `host_containment` | the contained agent's direct egress denied by the kernel | the orchestrator key (host-containment witness) |
| `narration` | the agent's printed intent | unsigned playback |

The proxy mediation and the signed receipts/witness are **binary-enforced**. The kernel
containment (contained mode) is **host/deployment-enforced** via `pipelock contain` (kernel
nftables) — it is not a property of this tool's binary, only present when the agent is actually
contained. The tool's contribution is to *attest* that property for a specific run: the signed,
offline-verifiable host-containment witness records what was probed from the contained position
and proves the operator-vs-agent differential. Verifying the witness confirms the attestation;
the underlying egress block remains host-enforced, not something this binary can guarantee on its
own.

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
verifies it. No host-containment witness is produced here: without containment there is no
kernel boundary to attest, and the tool says so rather than implying one.

### Contained (the real demo — requires a prepared host)

```bash
sudo pipelock-playground-demo run --contained --run-dir ./demo-run --scenario secret-exfil-body-blocked
```

Contained mode requires root, the `pipelock-agent` OS user, and a host where
`pipelock contain install` has been run. Under the **split-proof** model the mediated steps
(allow, block) run as the operator through the lab proxy — exactly as in uncontained mode — and
a separate probe phase drops to the `pipelock-agent` uid to build the signed host-containment
witness. This split is deliberate: the proxy's allow/block decision does not depend on the
agent's uid, and on a host with global owner-match containment the contained user cannot reach
the demo's ephemeral lab proxy at all, so running the mediated steps contained would simply
time out. Off a prepared host, the contained run fails loudly — it never silently falls back to
uncontained while claiming containment.

## Verify it yourself

From the run directory, on a clean machine, with the Pipelock process stopped:

```bash
pipelock-playground-demo verify ./demo-run
```

This is one all-or-nothing check rooted in the compiled-in published key by default. For
ephemeral/custom-key development runs, pass `--orchestrator-key <hex>`. It passes only when
**all** of the following hold: the launch manifest is signed by the orchestrator key; the Audit Packet's
receipt chain and totals verify under the Pipelock key the manifest pins; the packet manifest
matches the launch manifest's scenario and policy hash; the collector witness verifies under
the collector key the manifest pins; the witness binds this run's nonce and manifest; the
collector observed zero requests for the blocked exfil run; the packet contains the expected
allow and `body_dlp` block receipts; and the witness carries a genuine red-case calibration
backed by a signed `red-witness.json` artifact. Any single failure exits non-zero.

For **contained** runs (the signed manifest records this), three additional checks are required
and must also pass: the host-containment witness is signed by the orchestrator key; it binds
this run's nonce and manifest hash; and it proves enforcement — the operator-vs-agent
differential holds, the exact direct-egress suite was probed from the contained position, and
every route in that suite was explicitly blocked. A contained run therefore reports **11** checks; an
uncontained run reports 8. The `Contained` flag is covered by the manifest signature, so an
attacker cannot strip the containment requirement without invalidating the manifest.

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
pipelock-playground-demo fallback ./demo-run               # replay a recorded run
```

`fallback` replays a previously recorded run with a prominent `*** REPLAY MODE ***` watermark,
the recorded packet hash, and the verifier command — so a replayed run is never mistaken for a
live one.

## Interactive mode with a model-backed agent

The batch engine above drives a deterministic agent. The **interactive playground**
(`pipelock-playground-live`) can instead drive a real, OpenAI-compatible model, so a visitor
types to a live model-backed agent and watches Pipelock mediate every request it makes. Point
the live server at a model to enable it. `--llm-agent-bin` selects the model-agent
subprocess, `--model-base-url` accepts any OpenAI-compatible `/chat/completions`
endpoint, and `--model-secret-file` keeps the API key out of argv:

```bash
pipelock-playground-live \
  --llm-agent-bin     ./pipelock-playground-llm-agent \
  --model-base-url    https://api.provider.example/v1 \
  --model             your-model-name \
  --model-secret-file ./model.key
```

Without the model flags the interactive playground falls back to the deterministic agent. The
model-backed agent is held to the same fail-closed boundary as everything else:

- **Subprocess isolation.** The agent runs as a separate process, never in-process with the
  server, because a jailbroken model can be talked into arbitrary actions.
- **Proxy-only egress.** A transport guard lets the agent dial only the Pipelock proxy; any
  direct connection fails closed.
- **Per-turn receipt invariant.** Every mediated agent request that gets a proxy response must
  be backed by a signed receipt for that turn, or the turn fails closed. There is no narrated
  mediated action without a receipt to prove it.
- **Pre-DNS host allowlist.** A model run permits only the lab targets and the model API host;
  any other destination is refused before DNS, so a jailbroken model cannot reach an arbitrary
  host through the lab proxy. The allowlist does not bypass content scanning: a credential-shaped
  body to an allowlisted host is still blocked by DLP.
- **Secret stays in the box.** The synthetic canary is never written into the model prompt, and
  the lab tools refuse the model API host as a target, so an allowlisted model endpoint cannot be
  turned into an opaque exfiltration tunnel.

The production firewall imports no playground code; the model-backed agent ships as a separate
side-binary.

## The published orchestrator key

Every run's launch manifest and host-containment witness are signed by an **orchestrator key**,
and `verify` checks a run against the *public* half of that key. The point of publishing the key
is that a verifier looks it up ahead of time — from the docs or the compiled-in
`PublishedOrchestratorPubKeyHex` — rather than trusting a key the bundle hands it. A `VERIFY OK`
then means "signed by the key you already trust", not merely "internally consistent".

This is a **fixed demo identity with no security stakes**: the demo proves the Pipelock
mechanism, so the key only needs to be stable and published. It is generated once and never
rotated, and it is deliberately **not** any production signing key. `run` uses the installed
stable key automatically when present (otherwise it falls back to an ephemeral per-run key for
local iteration). The default key file must derive `PublishedOrchestratorPubKeyHex`; if it does
not, the run fails loudly rather than producing evidence that cannot verify under the published
trust root. Pass `--orchestrator-key-file <path>` to select an explicit custom signer.

Generate or rotate it with:

```bash
pipelock-playground-demo keygen-orchestrator        # writes the private key, prints the public hex
```

The private key is written to the standard config path (e.g.
`~/.config/pipelock/playground-demo-signing.key`, mode `0600`) and is never committed; publish
the printed public hex as `PublishedOrchestratorPubKeyHex`. The command refuses to overwrite an
existing key unless `--force`, so the stable demo key is not rotated by accident.

## Generate the viewer bundle

The Playground viewer renders a run from a `bundle.json`. Produce it from a verified run with:

```bash
pipelock-playground-demo bundle ./demo-run --out bundle.json
```

The bundle splits **scripted narrative** from **real proof**. The beat labels, chat dialogue, and
agent action cards are authored and deterministic — a run directory cannot produce human
dialogue, so these are scripted for a repeatable demo. Everything in the proof column is lifted
from the run's signed artifacts: the allow/block verdicts and the signed block-receipt envelope
come from the receipt chain; the host-containment decision (contained runs only) from the signed
host-containment witness; the collector observation count from the signed witness; the check list
from the offline verification; and the verifier block carries the real published key and the exact
`verify` command. Like `verify` and `fallback`, `bundle` uses the compiled-in published key by
default; pass `--orchestrator-key <hex>` only for ephemeral/custom-key development runs. `bundle`
runs the same offline verification first and **fails closed** if the run does not verify, so a
generated bundle can never overstate what was proven.

## Public-safety model

Inherited from the replay-capture rig: synthetic inputs only; receipts redacted before signing;
a fail-closed field allowlist and artifact linter over the published text artifacts; the canary
value lives only in the agent's environment and the request body Pipelock inspects, never on a
command line, in a URL, or on screen. Screenshots and social images are a separate manual
curation step (the text linter does not inspect pixels).
