<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Containment conformance fixtures

These fixtures package pipelock's workstation-containment direct-egress probes
(`pipelock contain verify`, probe 8 and probe 9) as a publishable conformance
artifact. They prove that the **egress-denied** test is real: a fixture in which
the agent's direct-egress canary succeeds (containment broken) MUST make the
gate fail.

The two probes under test:

- **Probe 8 — `cc_agent_egress_denied`**: the unprivileged agent user
  (`pipelock-agent`) must NOT reach the internet directly. The probe runs a
  DNS-free `curl --noproxy * http://192.0.2.1:9/` canary as the agent user.
  If curl exits 0 (egress succeeded), containment is BROKEN → `fail`. A
  connection refusal/timeout is `pass` only when the managed catch-all DROP
  counter increases across the probe; otherwise the result is `unknown`.
- **Probe 9 — `operator_egress_reachable`**: the operator user must still reach
  the internet (proves the containment rule is scoped to the agent, not a blanket
  network outage). A 2xx/3xx HTTP code → `pass`.

No real network, sudo, curl, or nftables is touched. The probes run against a
**canned command runner and DROP-counter reader** built from the fixture.

## File pairs

Each fixture is a pair:

- `<name>.probe.json` — the canned command-runner inputs.
- `<name>.expect.json` — the expected per-probe status and the aggregate exit
  code.

| Fixture | Input | Probe 8 | Overall exit | Role |
|---|---|---|---|---|
| `pass-all` | `drop_counter_reads` | `pass` (egress blocked) | 0 | clean baseline — gate must PASS |
| `leaky-egress` | `drop_counter_reads` | `fail` (egress leaked) | 1 | **must-fail** — gate must DETECT a leaked canary |
| `agent-accept-before-drop` | `nft_chain_text` | `fail` (structural hole) | 1 | **must-fail** — gate must DETECT a bare agent-UID accept rule ahead of the managed catch-all DROP |

## Compatibility (`nft_chain_text` / `agent_uid` / `proxy_uid` / `operator_uid` / `proxy_port`)

The schema addition below is **additive and backward compatible**:

- `pass-all` and `leaky-egress` are unchanged and still validate and pass
  exactly as before; neither sets any of the new fields.
- The new fields are all optional. A fixture (or a consumer) that never sets
  `nft_chain_text` behaves identically to before this change.
- `nft_chain_text` and `drop_counter_reads` are **mutually exclusive**: a
  fixture setting both is rejected at load as ambiguous. This is the only new
  rejection that can affect a fixture nobody has written yet; no existing
  fixture sets both.
- `agent_uid`, `proxy_uid`, `operator_uid`, and `proxy_port` are meaningful
  only together with `nft_chain_text`. Setting any of them without
  `nft_chain_text` is rejected at load (a dead field that looks like an input
  but drives nothing), the same way an unused canned `runs` rule is rejected.
- The loader now rejects any field outside this schema
  (`json.Decoder.DisallowUnknownFields`). This is a tightening, not a
  widening: it cannot break a fixture that only uses documented fields, which
  both original fixtures and the new one do.
- A consumer (a language binding, a CI script) that only reads
  `drop_counter_reads`-style fixtures and ignores unknown top-level JSON keys
  is unaffected: `pass-all` and `leaky-egress` carry none of the new fields,
  so nothing about them changes.

## `*.probe.json` schema

```jsonc
{
  "description": "free text",
  "agent_user": "pipelock-agent",   // optional; defaults to pipelock-agent
  "operator_user": "operator",      // optional; empty => probe 9 runs curl directly
  "drop_counter_reads": [12, 13],   // probe 8 before/after reads

  // --- OR (mutually exclusive with drop_counter_reads) ---
  // "nft_chain_text": "table inet pipelock_containment {\n  chain output_filter {\n    ...\n  }\n}\n",
  // "agent_uid": 987,               // required with nft_chain_text
  // "proxy_uid": 988,               // required with nft_chain_text; must differ from agent_uid
  // "operator_uid": 1000,           // optional; 0 means "no managed operator uid recorded"
  // "proxy_port": 8888,             // optional; defaults to the production proxy port (8888)

  "runs": [
    {
      "comment": "free text (ignored by the loader)",
      "match": [
        "sudo -n -u pipelock-agent -- /usr/bin/curl",
        "--connect-timeout 1",
        "--max-time 2",
        "--noproxy *",
        "PLK_TIME_CONNECT=%{time_connect}",
        "http://192.0.2.1:9/"
      ],
      "stdout": "curl: (7) Failed to connect\nPLK_TIME_CONNECT=0.000000\n000",
      "exit_code": 7
    }
  ]
}
```

`nft_chain_text` is the literal `nft -n -a list chain inet <table> <chain>`
output text. When set, probe 8's DROP-counter evidence is produced by
routing this text through the SAME chain-text recognizer `contain verify`
(probe 3, `probeNFTContainment`) uses in production —
`agentUIDBareAcceptBeforeDrop` and `chainLinesHaveUnsafeVerdictBeforeAgentDrop`
— rather than a pre-baked counter value pair. This is what lets a fixture
express a *structural* containment hole (an agent-UID accept rule that admits
every packet ahead of the managed catch-all DROP), which no
`drop_counter_reads` pair can represent: `drop_counter_reads` only ever
supplies a raw before/after counter value, with no way to encode "the chain's
own structure bypasses containment." Because the same text is read for both
the before and after sample, a *clean* chain (no bypass, no unsafe verdict)
never shows a counter delta and resolves to `unknown`, not `pass` — a PASS
baseline stays on `drop_counter_reads` (see `pass-all`). Malformed chain text
that the recognizer cannot parse is not rejected at load (fixture syntax is
not a load-time-checkable property without duplicating the unexported
recognizer); it resolves to `unknown` at run time, the same fail-closed
direction production takes on a parse error.

`runs` is a list of command-match rules. When a probe invokes the runner with
`(name, args...)`, the harness joins `name` + all `args` into one string and
selects the rule whose every `match` substring is present. Matching is audited:
each command line must match EXACTLY ONE rule. Zero matches (the runner returns
a non-nil error the probe surfaces as `skip`), more than one matching rule
(ambiguous), or a rule never used by any probe all fail the test loud, so a
fixture cannot be blessed by a matching expectation through a broad, duplicate,
or dead rule. The selected rule's `stdout` and `exit_code` are returned to the
probe.

- `match`: substrings that ALL must appear in the joined command line. The
  harness requires exact invocation, timeout, `--noproxy *`, and URL anchors
  for both probes so a raw-egress canary regression cannot keep matching a
  broad username-only rule.
- `stdout`: the merged stdout/stderr the probe sees. Probe 8 parses the
  `PLK_TIME_CONNECT=` sentinel and combines it with the exit code and DROP
  counter; probe 9 reads the trailing whitespace-separated token as the HTTP
  code.
- `exit_code`: the process exit code. `0` means curl succeeded.
- `drop_counter_reads`: the managed catch-all DROP-counter values returned to
  probe 8. The UID-wide counter only corroborates this canary's time_connect
  result; a missing reader, read error, or non-increasing pair is inconclusive.
  Mutually exclusive with `nft_chain_text`.

## `*.expect.json` schema

```jsonc
{
  "description": "free text",
  "exit_code": 1,                   // aggregate: 0 pass, 1 any fail, 2 incomplete
  "probes": [
    { "probe": 8, "name": "cc_agent_egress_denied",   "status": "fail" },
    { "probe": 9, "name": "operator_egress_reachable", "status": "pass" }
  ]
}
```

Status is one of `pass` / `fail` / `skip` / `unknown`. The aggregate
`exit_code` follows the `fail > incomplete > pass` precedence the real
`contain verify` uses: a single `fail` yields exit 1 regardless of how many
probes passed; `skip` or `unknown` without a failure yields exit 2.

Each probe entry also accepts an optional `detail_contains` string: when set, the probe's detail text must contain it. This is what
distinguishes two production outcomes that share the same `status` — the
`agent-accept-before-drop` structural hole and `leaky-egress`'s counter-based
leak both report probe 8 as `fail`, and `detail_contains` is how each
fixture asserts WHICH one it is. It is optional and absent from both original
fixtures, so their comparison is unchanged.

## How they run

- Go: `go test -run TestContainmentConformance ./sdk/conformance/` loads each
  pair, drives the probes through the exported
  `contain.RunContainmentConformance` seam, and asserts status + exit code.
- Gate: `sdk/conformance/containment-gate.sh` runs that test and additionally
  asserts the must-fail property (flip `leaky-egress.expect.json` to expect a
  pass and the gate fails).
