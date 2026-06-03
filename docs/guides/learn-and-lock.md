# Learn-and-Lock: Per-Agent Behavioral Contracts

Pipelock can watch an agent's real traffic, compile a behavioral envelope from what it observed, replay that envelope in shadow against captured traffic, and record operator-ratified signed contracts in a content-addressed active manifest. The contract binds the agent to what it actually did; lifecycle and shadow receipts emitted by the workflow are independently verifiable.

> **v2.4 status:** v2.4 ships the full learn-and-lock arc: policy compiler, candidate signing, shadow replay, ratification, signed active-manifest workflow, **and live proxy enforcement of promoted contracts on every URL-bearing transport plus the MCP tool-call surface** (forward absolute-URI and CONNECT, reverse and redirect-refresh chains, intercept, `/fetch`, WebSocket handshake, MCP HTTP listener and stdio-to-HTTP bridge, MCP stdio subprocess wrap, and the `mcp_tool_call` rule kind via `runtime.EvaluateMCP`). Scanner block always wins over contract allow on every gated transport. See ["Live enforcement"](#live-enforcement) below for the transport matrix, scanner-floor invariant, mode gating, and kill-switch override.

This is the v2.4 headline feature. It is **opt-in** and **default-off**. A new agent runs without a contract until you choose to compile, ratify, and promote one for it.

## Why a behavioral contract

Pipelock's network policy is rule-based: blocklist these domains, allow these MCP tools, redact these patterns. That rule set is necessarily generic. It does not know that *this particular agent* never POSTs to `repos.example.com` or that *that particular agent* always speaks JSON-RPC, never JSON-LD.

A behavioral contract is the missing per-agent layer. It distills observed behaviour into a typed, signed envelope. The v2.4 surface produces the signed contract, shadow evidence, signed active-manifest activation state, and live runtime enforcement of the promoted contract on every gated transport. Lifecycle, shadow, and runtime `proxy_decision` receipts use the new `EvidenceReceipt v2` envelope. Shadow receipts are bound to the candidate contract hash before promotion; lifecycle and runtime receipts bind the active manifest hash, contract hash, selector ID, and contract generation under signature after promotion, so an external auditor can prove which contract the operator ratified, promoted, and enforced.

## Four-phase pipeline

| Phase | Subcommand | What it does |
|---|---|---|
| 1 — observe | `pipelock learn observe` | Run the proxy in capture mode. Flight-recorder evidence accumulates in a hash-chained JSONL log per session under `learn.capture_dir`. |
| 2 — compile | `pipelock learn compile` | Read recorder JSONL, infer rule shapes, emit a signed candidate contract YAML and a Markdown review report for the operator. |
| 3 — shadow | `pipelock learn shadow` | Replay captured evidence through the candidate contract without enforcing. Emits would-have-blocked deltas and a signed `shadow_delta` receipt stream. Lets you see what the contract *would* have done before you ratify it. |
| 4 — activate | `pipelock learn ratify` + `pipelock learn promote` | Two-phase activation: operator ratification per rule, then signed active-manifest swap with monotonic generation + `prior_manifest_hash` CAS. Lifecycle receipts are emitted during ratify / promote / rollback. Once promoted, the contract is enforced live on every gated transport and `proxy_decision` receipts are emitted per request decision. |

Operator-facing supporting commands:

- `pipelock learn review <candidate.yaml>` — render the human-readable review.
- `pipelock learn diff <shadow-a.json> <shadow-b.json>` — diff two shadow runs.
- `pipelock learn split --candidate <path> --rule <rule_id>` — demote a collapsed normalisation segment back into its literal values.
- `pipelock learn pin --candidate <path> --rule <rule_id> --segment <value>` — pin a literal so future recompiles cannot collapse it.
- `pipelock learn rollback --to <manifest-hash>` — withdraw the active manifest back to a previous accepted hash (requires signed authorisation).
- `pipelock learn forget --candidate <path> --rule-id <id> --reason <legal>` — remove a single rule from the candidate before ratification.

The full source-of-truth command surface is in `pipelock learn --help`.

## Quickstart

The example below assumes `agent-a` is a configured agent in `pipelock.yaml`.

```bash
# Phase 1 — observe for a few days.
pipelock learn observe --capture-dir /var/lib/pipelock/learn

# Generate or reuse the compile-signing key for this agent.
pipelock keygen agent-a

# Phase 2 — compile the captured evidence into a signed candidate.
pipelock learn compile --agent agent-a
# Outputs (under ~/.pipelock/contracts/candidates/):
#   agent-a.candidate.yaml
#   agent-a.candidate.review.md
#   agent-a.candidate.manifest.json

# Read the review. Adjust thresholds in pipelock.yaml under
# `learn.inference.{floors,normalization}` if rules look off.
pipelock learn review ~/.pipelock/contracts/candidates/agent-a.candidate.yaml

# Phase 3 — shadow-replay against captured sessions to see what the
# candidate would block. Use `pipelock learn diff` to compare two runs.
pipelock learn shadow --contract ~/.pipelock/contracts/candidates/agent-a.candidate.yaml \
                      --contract-key ~/.pipelock/agents/agent-a/id_ed25519.pub \
                      --sessions /var/lib/pipelock/learn

# Phase 4a — operator ratifies the candidate (interactive per-rule approval).
pipelock learn ratify --candidate ~/.pipelock/contracts/candidates/agent-a.candidate.yaml \
                      --interactive

# Phase 4b — promote the ratified contract. Promotion is a signed, dual-
# control lifecycle operation. Required flags:
pipelock learn promote \
    --contract <ratified-contract-hash> \
    --selector agent-a \
    --contract-store /etc/pipelock/contracts \
    --roster /etc/pipelock/roster.signed.yaml \
    --roster-root-fingerprint sha256:<roster-root-fingerprint> \
    --activation-key <keystore-key-id-for-primary-signature>
# Production deployments add --production (enforces dual-control) and
# --dual-control-from <secondary-keystore-key-id> for the second
# operator's signature.
```

Run `pipelock learn promote --help` for the full flag list and the rollback / authorisation flow.

Promotion is a two-phase commit. The CLI emits a signed `contract_promote_intent` receipt, swaps the active manifest atomically (compare-and-swap on `prior_manifest_hash`, monotonic generation counter), validates the new manifest, and emits a signed `contract_promote_committed` receipt. Failure at any point keeps the previous manifest active.

## Storage layout

```text
~/.pipelock/contracts/
├── active.json                              # signed monotonic active manifest
├── manifests/
│   └── sha256-<hex>.json                    # immutable per-manifest blobs
├── history/
│   └── sha256-<hex>.yaml                    # write-once contract bodies
├── tombstones/
│   └── sha256-<hex>.tombstone.yaml          # withdrawal markers (no overwrites)
├── candidates/
│   └── <agent>.candidate.yaml               # output of `learn compile`
└── .activation_journal.jsonl                # append-only local journal
```

No symlinks. No plain pointers. Every active swap is signed; every accepted manifest is immutable.

### Tombstone enforcement (v2.5)

A tombstone is a signed withdrawal marker — operator-emitted proof that a specific contract hash must never be enforced again. v2.4 wrote tombstones as evidence markers but didn't enforce them at activation time. **v2.5 closes that gap.** The active-manifest store now cross-checks tombstones in three places:

1. **Promotion-time check.** `Store.ValidateEnvelope` rejects any `promote-intent` whose target hash has a matching tombstone. The runtime refuses to swap to a tombstoned contract.
2. **Accepted-load chain walk.** When the runtime rebuilds the accepted history during startup or missed-promote recovery, the chain walk refuses to load a contract whose hash is tombstoned — even if a partial swap had already begun.
3. **Audit emission.** Every attempted re-promote of a tombstoned contract emits a high-severity `contract_promote_intent` audit event with `denied: tombstoned` so the operator sees the attempt regardless of who initiated it.

The combination means a tombstoned contract is operationally dead: it cannot be re-introduced by editing config, by replaying a signed envelope, or by a poisoned `prior_manifest_hash`. Red-team tests prove enforcement at both the promotion-time and accepted-load surfaces.

## Capture metadata hardening

Every capture record carries a fixed metadata header so an offline `pipelock learn compile` or `pipelock learn shadow` run reproduces the live decision exactly: `session_id`, `event_kind`, `type: capture`, `surface`, `subsurface`, `config_hash`, `profile`, `agent`, `effective_action`, and `outcome`. The capture pipeline stamps these at every observer call site (forward, intercept, reverse, fetch, MCP HTTP, MCP stdio) so a record's policy provenance is unambiguous regardless of which transport produced it.

When the logical session key is path-safe (printable ASCII, no traversal, fits within `captureSessionKeyMaxLen`), the on-disk session directory uses the raw key and `session_id_original` is omitted from the record — keeping it would leak the raw key (often a client IP) into every capture line for path-safe traffic. When the raw key is unsafe or overlength, the on-disk directory is hashed and `session_id_original` preserves the raw logical key inline so offline replay binds to the correct session even though the directory name is a hash.

A poisoned-capture defence runs whenever the compile / shadow / replay paths walk a capture root: `validateCaptureSessionDir` reads the first JSONL entry of each candidate session directory and rejects siblings whose first record attributes traffic to a different agent. An attacker who can write a session directory under a known agent's capture root cannot trick the discovery path into ingesting it as that agent's traffic.

For a real soak, put `learn.capture_dir` on persistent storage. Kubernetes
`emptyDir`, container scratch space, and other pod-lifetime volumes are fine
for smoke tests, but they are not durable evidence: a restart can erase the
JSONL corpus that `compile` and `shadow` need. Treat Prometheus counters as
liveness signals only; a release gate or policy promotion should preserve
sample capture files and prove they can be replayed from disk.

### Operator metrics

Watch these counters during soak and after each policy reload:

| Metric | What it means |
|---|---|
| `pipelock_capture_dropped_total` | A capture record was constructed but could not be written to disk (queue full, fsync failed, sanitizer rejected). Should stay at zero in steady state. |
| `pipelock_capture_session_id_sanitized_total{reason}` | A session ID needed sanitisation before becoming a directory name. `reason` is one of `unsafe_path` (the raw key contained characters that aren't safe as a directory segment), `overlength` (the raw key exceeded `captureSessionKeyMaxLen`), or `unknown` (sanitisation triggered for an uncategorised reason). The label domain is closed — non-canonical reasons are dropped silently to bound cardinality. Non-zero is fine; a sudden spike on `unsafe_path` after a config change is worth investigating. |
| `pipelock_learn_capture_records_total` | Total capture records successfully written. Should rise with traffic. |
| `pipelock_learn_capture_dropped_total` | Total capture records dropped (any reason). Should stay at zero in steady state. |

Reload bumps `pipelock_envelope_verify_total{result}` if you have inbound mediation envelope verification enabled — see [`federation.md`](federation.md) for that observability surface.

## Configuration

The `learn` config block (top-level in `pipelock.yaml`) controls capture, privacy, and the inference engine. All defaults are tuned for production; tighten only after observing real traffic.

```yaml
learn:
  enabled: false                             # opt-in
  capture_dir: /var/lib/pipelock/learn       # recorder JSONL output
  privacy:
    salt_source: "${PIPELOCK_LEARN_SALT}"    # env / file:/abs / literal (fail-closed when empty)
    public_allowlist_default: true           # ship canonical seed allowlist when explicit list is empty
  inference:
    floors:
      min_sessions: 5                        # conditional-on-opportunity floor
      min_events: 20
      min_windows: 3
    normalization:
      min_events: 10
      min_distinct_values: 5
      entropy_threshold_bits: 3.0
      cardinality_cap_per_host: 1000
      tail_promotion_block_pct: 5.0
```

The fixed thresholds (Wilson alpha, `tau_brittle`, `tau_stable`, headroom) are part of the statistical contract and are hardcoded in the inference package; they are not exposed in YAML. Floors and normalisation parameters ARE deployment-configurable because traffic volumes differ across deployments and floors function as exposure gates.

The schema lives at `internal/config/schema.go` (`type Learn struct`); a dedicated configuration reference is at [`docs/configuration.md#learn-and-lock`](../configuration.md#learn-and-lock).

## Confidence model

Every inferred rule carries:

- **Wilson lower bound at 95% confidence** with conditional-on-opportunity denominators at every level (a rule isn't "stable" because *all* requests fit it; it's stable because *requests where this opportunity existed* mostly fit it).
- **Floors as hard gates.** A rule cannot be classified `stable` unless it clears Wilson AND the configured `min_sessions` / `min_events` / `min_windows`.
- **Lifecycle states:** `proposed` → `capture_only` → `enforce` → `expired` (or `demoted`).
- **Lifecycle transitions are operator-driven in v2.4.** Auto-demotion with hysteresis, paging, and cooldown is part of the locked design (see `learn-and-lock-design.md`) but the wiring lands in a follow-up. v2.4 ships the rule states and `contract_demoted` payload kind in the receipt schema; the runtime logic that drives state transitions is not yet wired end-to-end.

## Path normalisation

Per-bucket frequency-weighted entropy. Buckets are `(host, method, parent-prefix, segment-position)` — never global. The normaliser collapses high-cardinality segments (`/users/123` → `/users/<id>`) but never merges across high-risk siblings (`/admin/*` and `/users/*` stay separate). A reserved-segment blocklist keeps sensitive nouns (`admin`, `auth`, `oauth`, `token`, `billing`, `vault`, etc.) from being merged.

A per-host cardinality cap (default 1000) bounds memory. Tail coverage is explicit: when the `_other` bucket exceeds 5% of total events on a host, promotion is **blocked** unless the operator annotates `accept_tail: true`. No silent tail.

## Receipts

The v2.4 receipt schema defines an `EvidenceReceipt v2` envelope for contract-aware proxy decisions (`proxy_decision`) and contract-lifecycle events (`contract_ratified`, `contract_promote_intent`, `contract_promote_committed`, `contract_rollback_authorized`, `contract_rollback_committed`, `contract_demoted`, `contract_expired`, `contract_drift` with `drift_kind`, `shadow_delta`, `opportunity_missing`, `key_rotation`, `contract_redaction_request`). Lifecycle kinds emit from the activation CLI; `shadow_delta` and `opportunity_missing` emit from the shadow-replay path; `proxy_decision` emits from the live-lock runtime on every gated transport. Auditors get a decision trail that is candidate-contract-bound during shadow and active-manifest-bound after promotion.

v2 envelopes are distinguished from legacy v1 by the top-level `record_type` field. v1 verifiers reject v2 with `unsupported version 2 (expected 1)`; the existing audit pipeline keeps working unchanged for non-contract-aware deployments.

External verification for individual EvidenceReceipt v2 envelopes and v2 receipt chains is supported by the standalone Go `pipelock-verifier` today. Use `pipelock-verifier receipt --key <receipt-signing.pub> ...` for a single envelope, or `pipelock-verifier chain --key <receipt-signing.pub> ...` / `pipelock-verifier evidence ...` for a recorder JSONL chain. Without `--key`, v2 chain verification reports self-consistency only; provenance requires a pinned public key. A prepared `pipelock-verify-python` 0.2.0 update adds individual v2-envelope verification once published; v2 chain verification is not part of that Python update. See [`docs/guides/receipt-verification.md`](receipt-verification.md) for the full `pipelock-verifier` recipe covering v2 envelopes and chains.

## Signing keys

Four product key purposes; verifiers reject signatures from the wrong purpose:

- `receipt-signing` — hot, 90-day rotation, signs every individual receipt.
- `contract-compile-signing` — warm, ~yearly rotation, signs candidate contracts and compile manifests.
- `contract-activation-signing` — cold/operator key, irregular ceremony, signs the active manifest. Production deployments require **two** distinct operator signatures (dual control).
- `rules-official-signing` — release key, project-controlled, signs official rules bundles.

Deployment-level keys:

- `roster-root` — signs the deployment's key roster (which keys the deployment trusts for which purpose).
- `recovery-root` — separate, pinned, used only for break-glass recovery if the roster-root is compromised.

Two CLI surfaces:

- `pipelock keygen <agent>` writes a per-agent compile signing keypair under `~/.pipelock/agents/<agent>/`. Used by the agent's owner to sign that agent's candidate contracts.
- `pipelock signing key generate --purpose <purpose> --out <path>` writes a deployment-level keypair (root, activation, recovery, receipt-signing) to a 0o600 JSON file. Used by the operator to bootstrap the trust topology.

A complete bootstrap looks like:

```bash
# Operator: deployment root + activation key + receipt-signing key.
pipelock signing key generate --purpose roster-root --out /etc/pipelock/keys/fleet-root.json
pipelock signing key generate --purpose contract-activation-signing --out /etc/pipelock/keys/activation.json --id activation-primary
pipelock signing key generate --purpose receipt-signing --out /etc/pipelock/keys/receipt-signing.json --id receipt-signing

# Per-agent: compile signing keys under the agent keystore.
pipelock keygen agent-a
pipelock keygen agent-b

# Operator: compose and sign the roster.
pipelock signing roster build \
  --root /etc/pipelock/keys/fleet-root.json \
  --include id=activation-primary,key=/etc/pipelock/keys/activation.json,purpose=contract-activation-signing,role=operator \
  --include id=receipt-signing,key=/etc/pipelock/keys/receipt-signing.json,purpose=receipt-signing,role=runtime \
  --include id=compile-agent-a,key=$HOME/.pipelock/agents/agent-a/id_ed25519.pub,purpose=contract-compile-signing \
  --include id=compile-agent-b,key=$HOME/.pipelock/agents/agent-b/id_ed25519.pub,purpose=contract-compile-signing \
  --out /etc/pipelock/roster.json

pipelock signing roster verify --path /etc/pipelock/roster.json --root-fingerprint sha256:<from-key-generate-output>
```

The roster MUST include a `receipt-signing` entry. `pipelock learn promote` signs the lifecycle receipts with this key, and the runtime verifies them against the roster on load; if the roster does not name a `receipt-signing` key, the runtime rejects the receipts the operator just produced. The same applies to any compile signing key whose contracts you intend to promote: the agent's compile key must be in the roster the deploying runtime trusts.

Run `pipelock signing --help` for the full surface (roster show / verify, recovery / transition verification). See [Live lock trust topology](../configuration.md#live-lock-trust-topology) in the configuration reference for the refusal cases enforced by `roster build`.

## Soak window

A new contract is not enforced the moment you ratify it. Pipelock's recommended workflow is:

1. **Observe ≥7 days of representative traffic** before compiling. Short windows produce thin-sample rules.
2. **Run the candidate in shadow ≥3 days.** Watch the shadow-delta report for `would_have_blocked` events that match real legitimate traffic. Adjust `learn.inference.floors` or `accept_tail` annotations as needed.
3. **Ratify per rule.** Sign each rule individually. The operator-facing review tells you which rules cleared the confidence floor and which are thin-sample.
4. **Promote.** The active manifest swap is atomic with a compare-and-swap on `prior_manifest_hash` and a monotonic generation counter. v2.4 records the promoted manifest, the `contract_promote_intent` / `contract_promote_committed` lifecycle receipts, and the activation journal entry. Once the swap commits, the runtime picks up the new active manifest via fsnotify (100ms debounce, 2s maximum-debounce cap, fail-closed on initial reload, missed-promote recovery via accepted-history chain walk) and starts enforcing it on every gated transport. See ["Live enforcement"](#live-enforcement) below.
5. **Watch the receipt stream.** A spike in `contract_drift` receipts means the contract is over-fit. A spike in `opportunity_missing` health alerts means parent opportunity dropped (the agent stopped doing the thing the rule covers); auto-demotion is BLOCKED in this case so a benign change doesn't silently weaken the contract.

### Ratify safety guard

`pipelock learn ratify` refuses to promote candidates whose rules cannot pass the configured confidence floor. The default behaviour:

- **Non-interactive (`--interactive=false`):** refuses the candidate if any rule has `confidence: never_confirmed` or `confidence: refuted`.
- **Interactive (`--interactive`):** refuses the candidate if 100% of rules are at one of those low-confidence states. Mixed-confidence candidates remain operator-reviewable per rule.

If your captures are thin and you deliberately want to ratify a low-confidence candidate (typically for an operator-supervised dogfood window), pass `--accept-low-confidence` to override. The override is explicit by name so it cannot be set by accident; the safer path is to gather more captures and recompile until rules pass the floor naturally. The compile-time floor itself is configurable via `learn.inference.floors` in pipelock config.

### Promote workflow gotchas

Two ergonomic notes the help text alone does not surface:

- **`learn promote` reads from the contract store's `history/` directory.** `learn ratify` writes the ratified contract YAML to `--out`, but does not stage it inside the store. Before invoking `learn promote --contract <hash>`, copy the ratified file to `<contract-store>/history/sha256-<hash>.yaml`. A future v2.4.x ergonomic improvement will auto-stage it.
- **Promote requires the activation key in the keystore AND the receipt-signing key in the roster.** `--activation-key <key-id>` looks up the key by ID in `--keystore`, signs the manifest, and signs the lifecycle receipts under the keystore's receipt-signing agent (`--receipt-key-agent`, defaults to `receipt-signing`). The runtime then verifies those receipts against the roster. If the receipt-signing key is not named in the roster, the receipts the operator just produced will not validate on load.

### Promoting in a Kubernetes deployment

Pipelock's published image is `FROM scratch`: no shell, no `tar`, no `cp`, no `ls`. `kubectl exec`, `kubectl cp`, and `kubectl debug --target=<pipelock-container>` therefore cannot ship the active manifest into the pipelock pod's `pipelock-active-manifest` PVC directly. The operator pattern is a short-lived shuttle pod that mounts the same PVC:

```bash
# 1. Generate, ratify, and promote locally so you have an on-disk
#    contract store at e.g. /etc/pipelock/contracts/store on the
#    operator workstation.
pipelock learn promote ...

# 2. Apply a shuttle pod that mounts the deployment's
#    pipelock-active-manifest PVC. Match the namespace, fsGroup, and
#    nodeSelector to the deployment. With Longhorn RWO, the shuttle
#    must land on the same node as any other pod that has the PVC
#    attached, OR you scale those pods to zero first.
kubectl apply -f shuttle.yaml

# 3. Stream the contract store contents into the PVC via tar.
tar c -C /etc/pipelock/contracts/store \
    active.json manifests history .activation_journal.jsonl \
  | kubectl exec -n <ns> shuttle -i -- sh -c \
    'cat > /tmp/store.tar && tar xf /tmp/store.tar -C /active/'

# 4. Delete the shuttle pod. Pipelock pods will pick up the new
#    active.json on next start (or on fsnotify reload if they are
#    already running with the PVC attached).
kubectl delete pod -n <ns> shuttle
```

A minimal shuttle pod manifest (alpine + same PVC mount, conforming to the namespace's PodSecurity policy) is short enough to keep inline as part of the operator runbook. v2.4.x is expected to ship a `pipelock contract install --pod <ns/name>` helper that automates the shuttle.

## Live enforcement

Once an active manifest is promoted, the runtime gates every URL-bearing transport plus the MCP tool-call surface. A shared `decisionGate` helper composes the contract verdict with the existing scanner verdict on each gated path so call sites stay small and the security floor is enforced uniformly.

**Decision sequence (every gated path):**

1. **Kill switch.** Any of the four kill-switch sources (config, API, SIGUSR1, sentinel file) blocks the request before any other check.
2. **Scanner verdict.** DLP / SSRF / injection / blocklist run as today. A scanner block returns 403 with the existing `X-Pipelock-Block-Reason` and skips contract evaluation. **Scanner block always wins over contract allow.**
3. **No active contract.** If no manifest is active for the agent, the scanner verdict passes through unchanged.
4. **Contract verdict.** With an active manifest, the runtime evaluates the request against the matching rule kind (`http_destination` for URL transports; `mcp_tool_call` for MCP). An allow rule passes the request; an unmatched destination is **default-deny**.
5. **Mode gate.** Live mode emits the contract block. Shadow mode allows the request and emits a `would_have_blocked` shadow-delta record. Capture mode is silent (no block, no shadow record); capture is for the observation phase only.

**Transport coverage:**

| Transport | URL gate | MCP tool-call gate | Notes |
|---|---|---|---|
| Forward proxy (absolute-URI) | yes | n/a | Full URL visible. |
| Forward proxy (CONNECT) | yes (host:port) | n/a | CONNECT cannot see paths. Path-keyed rules cannot match CONNECT requests by design. |
| Reverse proxy | yes | n/a | Pre-configured upstream URL. |
| Redirect-refresh chain | yes (per leg) | n/a | Each redirected leg is re-evaluated against the redirected URL. An allowed origin cannot redirect-bridge to an unapproved destination. |
| Intercept proxy | yes | n/a | TLS-intercepted CONNECT path. |
| `/fetch` | yes | n/a | Target URL from query parameter. |
| WebSocket `/ws` | yes (handshake) | n/a | Per-frame scanning unchanged. |
| MCP HTTP listener (`--listen --upstream`) | yes (configured upstream) | yes (per `tools/call`) | |
| MCP stdio-to-HTTP bridge (`--upstream`) | yes (configured upstream) | yes (per `tools/call`) | |
| MCP stdio subprocess wrap (`-- COMMAND`) | n/a (no remote URL) | yes (per `tools/call`) | Denied tool calls return a JSON-RPC error with block-reason metadata; subprocess is not invoked. |

**Block-reason vocabulary additions:**

Contract-driven blocks use canonical block-reason codes alongside the existing scanner vocabulary. The codes are visible on the `X-Pipelock-Block-Reason` HTTP header (HTTP-capable transports) and on JSON-RPC error metadata (MCP-internal blocks).

**Receipts:**

Every contract decision (allow OR block) emits an EvidenceReceipt v2 envelope with the `proxy_decision` payload kind, bound to the active manifest hash, contract hash, rule ID, generation, transport, and verdict. Receipts ride the existing emit channels and the existing audit pipeline keeps working unchanged for non-contract decisions.

**Active-manifest reload:**

The runtime watches the active-manifest store via fsnotify with a 100ms debounce window and a 2s maximum-debounce cap. Reload is fail-closed on initial load (an unreadable manifest blocks rather than silently falling back to no-contract). A missed promote (crash between `promote-intent` and `promote-committed`) is recovered by walking the accepted-history chain on next reload, so the runtime cannot strand on a stale manifest.

## Anti-patterns

- **Ratifying without reviewing.** The review markdown lists thin-sample rules and opportunity-health flags. Skipping the review means promoting rules backed by 5 events.
- **Compiling on a trivial workload.** A two-day capture against an idle agent produces a contract that blocks every novel request the agent ever makes. Capture across the agent's full operational range.
- **Reusing one contract across agents.** The whole point is per-agent. Contracts are scoped by the `selector_set_hash`; a contract for `agent-a` does not apply to `agent-b`.
- **Disabling drift firing on the active contract.** If you don't want to know when the agent strays, you don't need a contract. Run pipelock without one.

## See also

- [`docs/configuration.md`](../configuration.md#learn-and-lock) — `learn` configuration reference.
- [`docs/guides/receipt-transports.md`](receipt-transports.md) — verifying receipts externally.
- [`docs/guides/federation.md`](federation.md) — cross-org envelope verification (independent of contracts).
- [`pipelock-verify-python`](https://github.com/luckyPipewrench/pipelock-verify-python) — external Python verifier; prepared v0.2.0 update adds individual EvidenceReceipt v2 envelope verification once published.
