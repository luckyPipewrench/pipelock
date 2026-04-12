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

The current scaffold exposes verification through the package API:

```go
err := posture.Verify(capsule, trustedPublicKey)
```

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

- The scaffold writes only `proof.json`.
- Human-readable summaries, CI gates, scores, SARIF, and badges are follow-up
  work.
