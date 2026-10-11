# pipelock verify-receipt

Verify a signed receipt, a chain, a whole recorder, or a receipt group. Pin the trusted signer with `--key`; repeat it for rotated keys. See the [receipt verification guide](../guides/receipt-verification.md) for formats and trust limits.

```bash
pipelock verify-receipt receipt.json --key signer.pub
pipelock verify-receipt --chain evidence --whole-recorder --key signer.pub
pipelock verify-receipt --chain evidence --session proxy --allow-prefix --key signer.pub
```

Chain verification reports integrity and endpoint proof separately. A terminal signed session close proves an action-chain end. A transcript root covered by its trailing signed checkpoint proves a whole-recorder end. A complete group close proves the group scope. `--expect-head HASH` or `--expect-seq N` pins an independently known receipt endpoint. Restart links and recovery seals don't prove an end. Mixed v1/v2 input verifies both chains; endpoint pins apply to v2. A pin must select one run when the directory has several.

| Flag | Effect |
|---|---|
| `--chain DIR` | Verify the selected session or every run of its base. |
| `--session ID` | Select one exact run; its restart base is still checked. |
| `--whole-recorder` | Verify every recorder entry and the authenticated outer boundary. |
| `--require-seal` | Treat a missing transcript root as invalid evidence. Requires `--whole-recorder`. |
| `--allow-prefix` | Return 0 for a valid prefix while retaining `VALID PREFIX, END UNPROVEN`. |
| `--expect-head HASH` | Require the independently known final receipt hash. |
| `--expect-seq N` | Require the independently known final unsigned sequence. |
| `--json` | Emit separate `integrity`, `end_proof`, `scope`, and `status` fields plus per-chain signer trust. |
| `--clean-report PATH` | Write `pipelock.clean_report.v1` JSON with the same endpoint status and separate signer-trust mode. |
| `--group ID` | Verify a complete signed group in `--chain DIR` with pinned keys. |
| `--allow-unpinned` | Acknowledge reduced signer trust; this doesn't accept an unproven end. |

For chains, exit 0 means integrity verified and the endpoint proven for the declared scope. Exit 1 means invalid evidence; exit 2 means usage or configuration failure; exit 3 means `VALID PREFIX, END UNPROVEN`. `--allow-prefix` changes only the last exit to 0. Single receipts and fleet reports keep their existing exit contracts. Report-write failures remain errors.
