<!--
Copyright 2026 Josh Waldrep
SPDX-License-Identifier: Apache-2.0
-->

# Posture capsule

A posture capsule is a signed `proof.json` artifact that captures the current
Pipelock posture at one point in time. It is intended for operators who need a
portable record of:

- the loaded tool version
- a hash of the active config
- discovery counts for local MCP client protection
- simulated scanner coverage
- current flight recorder receipt activity

## When to generate one

Generate a capsule when you want a signed snapshot of the current installation,
for example:

- after enabling or changing the flight recorder
- before handing an environment to another operator
- before attaching posture evidence to a ticket or audit trail
- after config changes that should be reflected in signed evidence

## Emit a capsule

```bash
pipelock posture emit --config pipelock.yaml --output .pipelock/posture
```

The command writes:

- `.pipelock/posture/proof.json`

`proof.json` is written with `0o600` permissions.

## Signing model

`pipelock posture emit` reuses the Ed25519 private key configured at
`flight_recorder.signing_key_path`.

The signature covers canonical JSON for these fields:

- `schema_version`
- `generated_at`
- `expires_at`
- `tool_version`
- `config_hash`
- `evidence`

The canonical form sorts object keys and omits extra whitespace so the signed
payload is deterministic.

## Verification model

Consumers should verify:

1. `schema_version` is supported.
2. `expires_at` is still in the future.
3. `signer_key_id` matches the trusted public key they expect.
4. the Ed25519 signature matches the canonical JSON payload.

The CLI `pipelock posture verify` is the primary verification surface; the Go package API is available for embedding.

```go
err := posture.Verify(capsule, trustedPublicKey)
```

## `pipelock posture verify`

Verify a signed capsule against a named policy, with optional freshness and minimum-score gates. Intended for CI pipelines and release signing.

```bash
pipelock posture verify \
  --proof .pipelock/posture/proof.json \
  --key /path/to/pipelock-posture.pub \
  --policy strict
```

Flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--proof` | `.pipelock/posture/proof.json` | Path to the signed capsule |
| `--key` | (required) | Path to the Ed25519 public key PEM or hex |
| `--policy` | `strict` | Policy name: `strict` or `enterprise` |
| `--config` | (optional) | Path to local `pipelock.yaml` for config-hash comparison |
| `--min-score` | `0` | Minimum weighted evidence score (0-100). `0` skips the score gate. |
| `--max-age` | `30d` | Maximum capsule age. Use `0` to skip freshness. Accepts `d`, `h`, or bare seconds. |
| `--max-receipt-age` | `7d` | Maximum age of the most recent flight-recorder receipt. `0` skips. |
| `--require-discovery` | `false` | Require at least one discovered MCP server (strict already enforces). |
| `--json` | `false` | Machine-readable output including per-factor score breakdown. |

### Exit codes

`pipelock posture verify` uses distinct exit codes so CI gates can distinguish integrity failure from policy failure:

| Exit | Meaning |
|------|---------|
| `0` | Signature valid, schema supported, capsule fresh, policy gates passed (or `--min-score 0` skips the score gate). |
| `10` | **Policy failed.** One or more named policy checks failed: score below `--min-score`, capsule older than `--max-age`, receipts stale, or a required factor missing. The capsule itself is valid. |
| `11` | **Integrity failed.** Signature did not verify, schema is unsupported, the JSON would not parse, or the public key is unreadable. The capsule cannot be trusted. |

### Policies

Two named policies ship with the current `PolicyVersion = "2"`:

- **`strict`** (default) — recommended for new installations. Requires flight recorder active, MCP discovery to have found at least one server (zero discovered is a hard failure, closes the vacuous-truth gap), receipts fresh within `--max-receipt-age`, and no parse errors in discovery.
- **`enterprise`** — looser gate for environments where pipelock may legitimately see no MCP servers (e.g., non-MCP deployments, empty home directories). Zero discovery becomes a warning rather than a hard failure. All other checks are the same as strict.

The policy evaluation produces hard failures (gate-blocking) and warnings (informational). JSON output lists both categories separately.

### Scoring model

The score (0-100) is a weighted sum of evidence factors. High-level factor groups:

- **Discovery** — count of discovered MCP clients and servers, portion under pipelock protection, parse errors.
- **Simulate** — pass rate on the built-in scenario corpus, grade (A/B/C/D/F).
- **Flight recorder** — receipt count in the recent window, verdict distribution (proportion of clean vs blocked), recency of the most recent receipt.
- **Verify install** — proxying active, flight recorder active.

The weighting is encoded in `internal/posture/score.go` and bumps `PolicyVersion` whenever weights change. Capsule consumers should record the `policy_version` alongside score for reproducibility across pipelock upgrades.

### CI example

```yaml
- name: Verify pipelock posture
  run: |
    pipelock posture emit \
      --config pipelock.yaml \
      --output .pipelock/posture
    pipelock posture verify \
      --proof .pipelock/posture/proof.json \
      --key "${{ secrets.POSTURE_PUB_KEY_PATH }}" \
      --policy strict \
      --min-score 80 \
      --json > posture-result.json
```

An exit code of `10` from the verify step fails the CI job because of a policy gate. A `11` fails because the capsule is not trustworthy — different remediation paths.

## Artifact shape

Minimal example:

```json
{
  "config_hash":"7d3ec7c0c7d1f2c9d5e44c4f1fbe2fbc08d63fcac2c7248d8c3066cb917d6d0d",
  "evidence":{
    "discover":{
      "high_risk":0,
      "parse_errors":0,
      "protected_other":0,
      "protected_pipelock":2,
      "total_clients":1,
      "total_servers":2,
      "unknown":0,
      "unprotected":0
    },
    "flight_recorder":{
      "last_receipt_at":"2026-04-11T13:05:12Z",
      "receipt_count":4,
      "scanner_verdict":{
        "dlp":{"allow":0,"block":3,"warn":0},
        "unknown":{"allow":1,"block":0,"warn":0}
      }
    },
    "simulate":{
      "config_file":"",
      "failed":0,
      "grade":"A",
      "known_limitations":0,
      "mode":"balanced",
      "passed":24,
      "percentage":100,
      "scenarios":[],
      "total":24
    },
    "verify_install":{
      "flight_recorder_active":true,
      "proxying":true,
      "receipt_count":4
    }
  },
  "expires_at":"2026-05-11T13:05:12Z",
  "generated_at":"2026-04-11T13:05:12Z",
  "schema_version":"1",
  "signature":"c1b8b9c4f4d2...",
  "signer_key_id":"9f6b9d7c...",
  "tool_version":"0.1.0-dev"
}
```

## Notes

- `pipelock posture emit` writes only `proof.json`. Companion artifacts (`proof.md`, `badge.svg`) are planned follow-ups.
- The verify CLI is the supported gate surface. Earlier documentation called CI gates and scores "follow-up work" — both are shipping.
- SARIF and human-readable summary output are planned for later releases.
