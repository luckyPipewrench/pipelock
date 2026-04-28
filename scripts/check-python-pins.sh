#!/usr/bin/env bash
# check-python-pins.sh
#
# Enforces the full Python dep policy on every tracked requirements*.txt:
#
#   1. Every package spec must use exactly `==` (rejects `>=`, `<=`, `~=`,
#      `>`, `<`, `===`, and bare unpinned names).
#   2. Every `==` pin must be followed by at least one `--hash=` continuation
#      line in the same stanza. A `==` pin without hashes is a violation.
#
# Why both checks: OpenSSF Scorecard's OSV-Scanner over-reports on `>=`
# ranges (rule 1 keeps it quiet). `pip install --require-hashes` rejects
# unpinned or hash-missing inputs (rule 2 keeps the supply-chain integrity
# guarantee documented in CONTRIBUTING.md).
#
# Skips blank lines, comment lines, pip-compile metadata, trailing
# `# via ...` comments, and pip flag continuations other than `--hash=`.
#
# requirements*.in files are intentionally NOT scanned; they are the
# human-editable source manifest for pip-compile and may carry loose
# bounds.

set -euo pipefail

mapfile -t files < <(
  git ls-files \
    'requirements.txt' \
    '*/requirements.txt' \
    'requirements-*.txt' \
    '*/requirements-*.txt' \
    | sort -u
)

if [[ ${#files[@]} -eq 0 ]]; then
  echo "check-python-pins: no requirements*.txt found, nothing to lint"
  exit 0
fi

violations=0

# Strict pin: name then exactly `==` then version. Rejects `===` because
# `=` is not in the version character class, so `pkg===1.0` cannot match.
strict_pin_re='^[A-Za-z0-9_.-]+[[:space:]]*==[[:space:]]*[0-9A-Za-z._+!-]+'
forbidden_op_re='(>=|<=|~=|===|[><])'

for file in "${files[@]}"; do
  pending_pin_lineno=0
  pending_pin_line=""
  pending_hash_seen=0
  lineno=0

  while IFS= read -r raw_line; do
    lineno=$((lineno + 1))

    # Strip leading whitespace, trailing continuation backslash, trailing
    # `# ...` comment (e.g. `# via cryptography`), and trailing whitespace.
    trimmed="$(printf '%s' "$raw_line" \
      | sed 's/^[[:space:]]*//; s/[[:space:]]*\\$//; s/[[:space:]]*#.*$//; s/[[:space:]]*$//')"

    case "$trimmed" in
      "" )
        continue
        ;;
      --hash=* )
        if [[ "$pending_pin_lineno" -gt 0 ]]; then
          pending_hash_seen=1
        fi
        continue
        ;;
      --* )
        # Other pip flag (e.g. --require-hashes); does not satisfy the
        # hash requirement and does not break the pending stanza either.
        continue
        ;;
    esac

    # New package spec line. Finalize the prior pending stanza first:
    # if a pin was outstanding without a hash, that is a violation.
    if [[ "$pending_pin_lineno" -gt 0 && "$pending_hash_seen" -eq 0 ]]; then
      printf 'check-python-pins: %s:%s: pin missing --hash= continuation: %s\n' \
        "$file" "$pending_pin_lineno" "$pending_pin_line"
      violations=$((violations + 1))
    fi
    pending_pin_lineno=0
    pending_pin_line=""
    pending_hash_seen=0

    # Strict-== match: open a new pending stanza.
    if [[ "$trimmed" =~ $strict_pin_re ]]; then
      pending_pin_lineno="$lineno"
      pending_pin_line="$trimmed"
      pending_hash_seen=0
      continue
    fi

    # Anything else with a comparator OR a bare unpinned name is a violation.
    if [[ "$trimmed" =~ $forbidden_op_re ]] || [[ "$trimmed" =~ ^[A-Za-z0-9_.-]+[[:space:]]*$ ]]; then
      printf 'check-python-pins: %s:%s: forbidden non-== pin: %s\n' "$file" "$lineno" "$trimmed"
      violations=$((violations + 1))
    fi
  done < "$file"

  # End of file: finalize any trailing pending pin.
  if [[ "$pending_pin_lineno" -gt 0 && "$pending_hash_seen" -eq 0 ]]; then
    printf 'check-python-pins: %s:%s: pin missing --hash= continuation: %s\n' \
      "$file" "$pending_pin_lineno" "$pending_pin_line"
    violations=$((violations + 1))
  fi
done

if [[ $violations -gt 0 ]]; then
  echo ""
  echo "check-python-pins: $violations violation(s). Repo policy is ==-pinned with --hash."
  echo "See CONTRIBUTING.md 'Python dependencies' and regen instructions in"
  echo "testdata/python_verifier_fixture/README.md."
  exit 1
fi

echo "check-python-pins: ${#files[@]} requirements file(s) clean"
