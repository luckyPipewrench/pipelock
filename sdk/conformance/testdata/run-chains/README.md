# Run-chain directory fixtures

Evidence directories written by real `pipelock run` processes sharing one flight-recorder directory. Each current process run writes its own receipt chain, `proxy.run.<id>`, and a restart can publish a signed `chain-link-<predecessor>.json` naming the exact tail it continues. Every verifier's directory mode must reach the Go reference verdict on each variant.

## Regenerating

```bash
go build -o /tmp/pipelock ./cmd/pipelock
sdk/conformance/testdata/run-chains/generate.sh /tmp/pipelock
```

`generate.sh` drives the binary through four runs in a private `HOME`: run A, run B restarting after A (links A), run C started from a copy of the directory holding only A (also links A), and run D restarting after A with a rotated signing key, using the documented `pipelock signing key generate` and `pipelock signing receipt-rotation endorse` ceremony. It then derives the byte-edited variants and runs the Go generator, `PIPELOCK_RUN_CHAIN_FIXTURES=1 go test ./sdk/conformance/ -run TestGenerateRunChainFixtures`, with that generation's throwaway signing key in `PIPELOCK_RUN_CHAIN_SIGNING_KEY`. The Go generator signs the two re-signed link variants with it and writes every `expect*.json` from `receipt.VerifyBase`, so no expectation is hand-written. The script deletes the key with its temporary directory on exit, so no private key is committed.

Running the Go generator by hand without `PIPELOCK_RUN_CHAIN_SIGNING_KEY` rewrites only the `expect*.json` files and keeps the committed re-signed links. `TestRunChainFixturesMatchGoReference` fails when an expectation drifts from the Go reference.

## Variants

| Directory | Contents | Go verdict |
|---|---|---|
| `valid` | Runs A and B, link B to A | valid; A unlinked, B linked (`same_key`) |
| `tampered-predecessor` | `valid` with one receipt edited in A | broken: `corrupt_chain`, `predecessor_unverified` |
| `tampered-successor` | `valid` with one receipt edited in B | broken: `corrupt_chain` |
| `link-edited` | `valid` with the link's tail sequence edited, signature kept | broken: `invalid_link` |
| `link-deleted` | Runs A and B, no link file | valid; both runs unlinked |
| `double-successor` | Runs A, B, and C, both links claim A | broken: `double_successor`, `link_name_mismatch` |
| `link-wrong-tail` | `valid` with a re-signed link naming a hash A never had | broken: `link_tail_mismatch` |
| `link-appended` | `valid` with a re-signed link naming A's second-to-last receipt | broken: `appended_after_link` |
| `key-rotated` | Runs A and D, link D to A across a key change, and the rotation endorsement | first key only: broken (`corrupt_chain`, `untrusted_successor_key`); both keys: valid (`trusted_key`); first key and endorsement: valid (`endorsed`) |

`signer-key.hex` is the first signing key and `rotated-signer-key.hex` is run D's key. Every verifier also reports `outer_chain_broken` for the tampered variants, from the recorder file's own entry hash chain: the edits were made without recomputing it.
