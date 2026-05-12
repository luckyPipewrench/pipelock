#!/usr/bin/env bash
# opsec-grep.sh — scan added lines in a diff for OPSEC-banned substrings.
#
# Modes:
#   --staged              Scan `git diff --cached` (default for pre-commit).
#   --range <BASE..HEAD>  Scan `git diff <BASE>..HEAD` (default for CI).
#
# Pattern sources (concatenated, in order):
#   1. .opsec-patterns at the repo root (always read if present).
#   2. $PIPELOCK_OPSEC_EXTRA if set (default $HOME/.config/pipelock/opsec-extra.patterns).
#   3. Contents of the OPSEC_EXTRA_PATTERNS environment variable, treated as
#      if it were the body of a patterns file. Lets CI pass a private list
#      via a GitHub secret without committing it.
#
# Exit code: 0 if no matches in *added* lines, 1 if any match.
#
# Pattern file format: PCRE-style regex, a single tab, then a short reason.
# Lines starting with `#` and blank lines are ignored.
#
# An added line containing the literal substring `OPSEC-OK` is exempt
# from every pattern. Use sparingly.

set -euo pipefail

mode="staged"
range=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --staged)
      mode="staged"
      shift
      ;;
    --range)
      mode="range"
      range="${2:-}"
      if [[ -z "${range}" ]]; then
        echo "opsec-grep: --range requires an argument" >&2
        exit 2
      fi
      shift 2
      ;;
    -h|--help)
      sed -n '2,22p' "$0"
      exit 0
      ;;
    *)
      echo "opsec-grep: unknown arg: $1" >&2
      exit 2
      ;;
  esac
done

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

# Collect patterns from each source into a single temp file. Each row stays
# as <regex>\t<reason>; we split on the first tab when reporting.
patterns_file="$(mktemp)"
trap 'rm -f "${patterns_file}"' EXIT

emit_patterns() {
  # Strips comments and blank lines, preserves tab between regex and reason.
  awk 'BEGIN{FS=OFS="\t"} /^[[:space:]]*#/ || /^[[:space:]]*$/ {next} {print}'
}

if [[ -f ".opsec-patterns" ]]; then
  emit_patterns < ".opsec-patterns" >> "${patterns_file}"
fi

extra_path="${PIPELOCK_OPSEC_EXTRA:-${HOME}/.config/pipelock/opsec-extra.patterns}"
if [[ -f "${extra_path}" ]]; then
  emit_patterns < "${extra_path}" >> "${patterns_file}"
fi

if [[ -n "${OPSEC_EXTRA_PATTERNS:-}" ]]; then
  printf '%s\n' "${OPSEC_EXTRA_PATTERNS}" | emit_patterns >> "${patterns_file}"
fi

if [[ ! -s "${patterns_file}" ]]; then
  # Nothing to enforce. Be loud about it so a broken config is not silent.
  echo "opsec-grep: no patterns loaded (.opsec-patterns missing and no extras)" >&2
  exit 0
fi

# Get the diff. Only +added lines outside of file headers are scanned, so
# context lines and removals never produce hits.
# Exclude paths whose job is to *define* or *test* the banlist — those
# files legitimately contain the very patterns they enforce.
exclude_paths=(
  ':!**/CHANGELOG.md'
  ':!.opsec-patterns'
  ':!scripts/opsec-grep.sh'
  ':!scripts/opsec-grep_test.sh'
  ':!scripts/opsec-path-block.sh'
)

if [[ "${mode}" == "staged" ]]; then
  diff_output="$(git diff --cached --unified=0 -- "${exclude_paths[@]}" || true)"
else
  diff_output="$(git diff --unified=0 "${range}" -- "${exclude_paths[@]}" || true)"
fi

if [[ -z "${diff_output}" ]]; then
  exit 0
fi

# Walk the diff, tracking the current file path. Emit `<file>:<line>:<text>`
# rows only for `+<text>` lines (skipping `+++` headers). Line numbers come
# from `@@ -a,b +c,d @@` hunk markers.
candidates_file="$(mktemp)"
trap 'rm -f "${patterns_file}" "${candidates_file}"' EXIT

awk '
  function reset_hunk() { in_hunk = 0; line_no = 0 }
  BEGIN { current = ""; reset_hunk() }
  /^diff --git / {
    # parse "diff --git a/path b/path" — take the b/ side
    n = split($0, parts, " ")
    bpath = parts[n]
    sub(/^b\//, "", bpath)
    current = bpath
    reset_hunk()
    next
  }
  /^\+\+\+ / { next }
  /^--- / { next }
  /^@@ / {
    # extract +start from "@@ -a,b +c,d @@"
    if (match($0, /\+[0-9]+/)) {
      line_no = substr($0, RSTART + 1, RLENGTH - 1) + 0
      in_hunk = 1
    }
    next
  }
  in_hunk && /^\+/ {
    text = substr($0, 2)
    if (current != "") {
      printf "%s\t%d\t%s\n", current, line_no, text
    }
    line_no++
    next
  }
  in_hunk && /^-/ { next }
  in_hunk && /^ / { line_no++; next }
' <<< "${diff_output}" > "${candidates_file}"

# Apply every pattern to every candidate. Print one row per violation.
violations_file="$(mktemp)"
trap 'rm -f "${patterns_file}" "${candidates_file}" "${violations_file}"' EXIT

while IFS=$'\t' read -r pattern reason; do
  [[ -z "${pattern}" ]] && continue
  # Filter: candidates lacking OPSEC-OK whose text field matches the pattern.
  # awk '{print $3}' splits on whitespace; instead, strip the file/line prefix
  # by hand. The candidate format is file\tlineno\ttext (single tab between).
  while IFS=$'\t' read -r file lineno text; do
    [[ "${text}" == *"OPSEC-OK"* ]] && continue
    if printf '%s' "${text}" | grep -P --quiet -- "${pattern}"; then
      printf '%s:%s\t%s\t%s\n' "${file}" "${lineno}" "${reason}" "${text}" >> "${violations_file}"
    fi
  done < "${candidates_file}"
done < "${patterns_file}"

if [[ -s "${violations_file}" ]]; then
  echo "OPSEC banlist violations in added lines:" >&2
  echo "(suppress an intentional match by adding the substring OPSEC-OK to the line)" >&2
  echo "" >&2
  # Pretty-print: file:line  [reason]  text
  awk -F'\t' '{ printf "  %-40s [%s]\n    %s\n", $1, $2, $3 }' "${violations_file}" >&2
  exit 1
fi

exit 0
