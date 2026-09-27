# Verifier parity fixtures

Tampered copies of real run evidence, one directory per tamper class. Every Pipelock verifier must reach the verdict each `expect.json` states, in directory mode, for each named run, and for each file. The source evidence is the real two-run and key-rotation evidence in `../run-chains`: run A, run B restarting after A with a signed link, and run D restarting after A under a rotated key with its rotation endorsement.

"Rehash" means the recorder entry hash chain was recomputed after the edit, with Go's `recorder.ComputeHash`. That models an attacker who can write the evidence directory and holds no signing key.

## Regenerating

```bash
PIPELOCK_PARITY_FIXTURES=1 go test ./sdk/conformance/ -run TestParityFixturesMatchGenerator
```

`sdk/conformance/parity_fixtures_test.go` derives every class from `../run-chains`, so a tamper is reproducible and never hand-edited. The expectations are stated there per class as the parity contract; they are not copied from any verifier's output. `TestParityFixturesMatchGenerator` fails when a committed file differs from what the generator writes. `TestParityFixturesAreConsistent` checks that each tamper is present and that each session's recorder hash chain is intact, broken, or rehashed as `recorder_chain` says. It asks no verifier for a verdict. The TypeScript and Rust tests (`sdk/verifiers/ts/tests/parity.test.ts`, `sdk/verifiers/rust/tests/parity.rs`) run their CLIs over every cell.

## expect.json

| Field | Meaning |
|---|---|
| `description` | The tamper and why the verdict follows. |
| `recorder_chain` | `intact`, `broken` (the edit left the recorder hash chain broken), or `rehashed`. |
| `symlinks` | Links to create before running: `name` in the directory pointing at `target`. The repository holds no symlinks. |
| `cells[]` | One verifier run each. |

Each cell names its `mode`, its `target`, the trust inputs (`keys` and `endorsements`, file names in the class directory), the expected `valid`, and what the output must name:

- `dir`: `chain DIR --dir` with every `--key` and `--rotation-endorsement` given. `target` is `.`.
- `session`: the same with `--session-id TARGET`. A named run is verified with its whole base, so it fails on any base finding.
- `file`: `chain DIR/TARGET` for the one file. A file named on the command line is read as given.

`findings` is the exact set of restart-continuity findings (kind and session) a `dir` or `session` run reports. `errors` lists chain reports that must fail and an error kind each must name; every chain report not listed must be valid. For `file`, `errors` names kinds the file's error must carry, and `valid` is true exactly when `findings` and `errors` are both empty. Exit status is 0 when valid and 1 otherwise, and every failing run prints a `verification failed:` line on stderr.

| Error kind | Phrase in the error text |
|---|---|
| `outer_chain_broken` | `outer_chain_broken` |
| `action_receipt_chain` | `action receipt chain` |
| `evidence_receipt_chain` | `evidence receipt chain` |
| `session_mismatch` | `does not match requested session` |
| `symlink_refused` | `refuse symlink in evidence directory` |

## Classes

| Class | Tamper | Verdict |
|---|---|---|
| `v2-forge-norehash` | Run B's last EvidenceReceipt v2 verdict edited, no rehash | broken: `outer_chain_broken` for B; B's v2 chain fails |
| `v2-forge-rehash` | Same, rehashed | broken where B is verified; a named run A passes |
| `v2-strip-norehash` | Run B's v2 entries deleted, no rehash | broken: `outer_chain_broken` |
| `v2-strip-rehash` | Same, rehashed | valid everywhere; only a signed checkpoint detects it |
| `v2-drop-norehash` | Run B's last v2 entry deleted, no rehash | broken: `outer_chain_broken` |
| `v2-drop-rehash` | Same, rehashed | valid everywhere; only a signed checkpoint detects it |
| `envelope-edit-norehash` | An unsigned recorder summary edited, no rehash | broken: `outer_chain_broken` |
| `envelope-edit-rehash` | Same, rehashed | valid everywhere; only a signed checkpoint detects it |
| `dup-run` | Run A's file copied under a new run name | broken: the copy's entries name run A |
| `rename-run` | Run B's file moved to a new run name | broken: entries name run B; A's link dangles |
| `run-as-legacy` | Run A's file renamed to the legacy base session | broken: entries name run A; B's link dangles |
| `symlink-run` | Run B's file is a symlink | broken in directory modes; the file itself verifies |
| `dup-run-nonce` | Run A replayed as a new run: session_id rewritten, rehashed | broken: `duplicate_run_nonce` for both chains |
| `rotated` | Honest runs A and D across a signing key rotation | valid with the first key and the endorsement, or both keys; with the first key alone D is untrusted |
| `v2-only-shard` | Run B split into three shards, the middle one holding one v2 receipt | valid as a directory; the later shards fail alone because their first entry does not start the recorder hash chain |
