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

| Fixture | Probe 8 | Overall exit | Role |
|---|---|---|---|
| `pass-all` | `pass` (egress blocked) | 0 | clean baseline — gate must PASS |
| `leaky-egress` | `fail` (egress leaked) | 1 | **must-fail** — gate must DETECT |

## `*.probe.json` schema

```jsonc
{
  "description": "free text",
  "agent_user": "pipelock-agent",   // optional; defaults to pipelock-agent
  "operator_user": "operator",      // optional; empty => probe 9 runs curl directly
  "drop_counter_reads": [12, 13],   // probe 8 before/after reads
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

## How they run

- Go: `go test -run TestContainmentConformance ./sdk/conformance/` loads each
  pair, drives the probes through the exported
  `contain.RunContainmentConformance` seam, and asserts status + exit code.
- Gate: `sdk/conformance/containment-gate.sh` runs that test and additionally
  asserts the must-fail property (flip `leaky-egress.expect.json` to expect a
  pass and the gate fails).
