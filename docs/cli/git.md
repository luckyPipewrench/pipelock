# `pipelock git scan-diff`

Reads a unified diff on stdin and scans its added lines for credential patterns.
Built for a pre-commit hook or a CI step, where the thing you need to know is
whether this change introduces a secret.

```bash
git diff HEAD~1 | pipelock git scan-diff
git diff --cached | pipelock git scan-diff --config pipelock.yaml
git diff HEAD~1 | pipelock git scan-diff --format sarif -o results.sarif
```

The diff arrives on stdin. Nothing is read from the repository directly, so the
command scans exactly the range you pipe to it.

## Exit codes

The three values mean different things and a caller has to tell them apart.

| Code | Meaning |
|---|---|
| `0` | The diff was scanned and no credential was found. |
| `1` | The diff was scanned and secrets were found. |
| `2` | No verified result was produced. |

Exit `2` covers input that could not be read or parsed, and configuration,
encoding, or report-writing failures. It is not a finding. **A caller that treats
every non-zero status as "secrets found" reports leaks that were never
detected**, and one that treats every non-zero status as failure-to-scan lets
real findings through. Branch on the two separately:

```bash
git diff --cached | pipelock git scan-diff
case $? in
  0) ;;                                        # clean, continue
  1) echo "secret found in this change" >&2; exit 1 ;;
  2) echo "scan did not complete; not a clean result" >&2; exit 1 ;;
esac
```

An empty diff exits `0`. A commit that changes nothing has nothing to leak, so a
no-op commit does not fail the hook. If the command that produces your diff can
fail silently, check that separately: an empty diff and a broken `git diff`
invocation look the same on stdin.

## Deleted files

A whole-file deletion emits a hunk header whose new-side start and count are both
zero. That is a valid hunk that adds nothing, and it scans clean.

## Output

Results go to stdout. Diagnostics, including errors and verbose suppression
notes, go to stderr. `--output` writes a SARIF result to a file instead.

| Flag | Purpose |
|---|---|
| `--config` | Config file, for `suppress` entries and pattern overrides. |
| `--json` | Machine-readable findings on stdout. |
| `--format` | `text`, `json`, or `sarif`. |
| `-o`, `--output` | Write the report to a file. |
| `--exclude` | Exclude paths by glob or directory prefix; repeatable. |
| `--verbose` | Include suppression notes on stderr. |

## Related

- [`pipelock scan`](scan.md) scans files rather than a diff.
- [`pipelock explain`](explain.md) explains a URL verdict and names the knob that
  would change it.
