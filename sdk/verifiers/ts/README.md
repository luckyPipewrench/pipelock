# Pipelock TypeScript Verifier

Reference TypeScript verifier for Pipelock Audit Packet v0, action receipts, and receipt chains.

## Install

```bash
npm install
npm run build
```

The package exposes `pipelock-verifier-ts` after build.

## Usage

```bash
pipelock-verifier-ts audit-packet PATH [--json] [--key HEX_OR_FILE] [--offline]
pipelock-verifier-ts chain PATH [--json] [--key HEX_OR_FILE] [--dir] [--session-id ID]
pipelock-verifier-ts receipt PATH [--json] [--key HEX_OR_FILE]
```

Exit codes match the Go verifier:

| Code | Meaning         |
| ---- | --------------- |
| 0    | valid           |
| 1    | invalid         |
| 2    | runtime error   |
| 64   | CLI usage error |

`audit-packet` validates `packet.json` against `sdk/audit-packet/v0.json`, applies the structural v0 checks, and re-verifies the referenced receipt chain unless `--offline` is set. `chain` accepts either an `evidence.jsonl` file or a recorder session directory with `--dir`. `receipt` verifies one receipt JSON file.

## Development

```bash
npm run typecheck
npm run build
npm test
```

The canonical encoder intentionally mirrors Go `encoding/json` for the receipt structs: declaration-order fields, Go `omitempty`, sorted map keys, compact output, and Go's default HTML escaping. This byte-level behavior is part of the verifier contract.
