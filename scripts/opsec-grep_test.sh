#!/usr/bin/env bash
# Tests for scripts/opsec-grep.sh. Builds an ephemeral repo in $TMPDIR,
# stages synthetic content, runs the script, and asserts on the output.
#
# Run via: bash scripts/opsec-grep_test.sh
# Exit 0 on all-pass, 1 on any failure.

set -euo pipefail

repo_root="$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)"
script="${repo_root}/scripts/opsec-grep.sh"
patterns="${repo_root}/.opsec-patterns"

fail_count=0
test_count=0

mktemp_repo() {
  local d
  d="$(mktemp -d)"
  (
    cd "${d}"
    git init -q
    cp "${patterns}" .
    cp "${script}" .
    chmod +x opsec-grep.sh
    touch baseline.txt
    git add baseline.txt
    GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@t \
      GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@t \
      git -c core.hooksPath=/dev/null commit -qm seed
  )
  printf '%s' "${d}"
}

run_case() {
  local name="$1"
  local want_exit="$2"
  local want_substr="$3"
  local repo="$4"
  shift 4
  test_count=$((test_count + 1))

  local out
  set +e
  out="$(cd "${repo}" && "$@" bash ./opsec-grep.sh --staged 2>&1)"
  local got_exit=$?
  set -e

  if [[ "${got_exit}" != "${want_exit}" ]]; then
    echo "FAIL [${name}]: exit got=${got_exit} want=${want_exit}"
    echo "  output: ${out}"
    fail_count=$((fail_count + 1))
    return
  fi
  if [[ -n "${want_substr}" && "${out}" != *"${want_substr}"* ]]; then
    echo "FAIL [${name}]: output missing substring '${want_substr}'"
    echo "  got: ${out}"
    fail_count=$((fail_count + 1))
    return
  fi
  echo "PASS [${name}]"
}

# Case 1: TD-N in added prose should fail.
r="$(mktemp_repo)"
cat > "${r}/td.md" <<EOF
This refers to TD-7 in the planning doc.
EOF
(cd "${r}" && git add td.md)
run_case "td-tracker-fails" 1 "tracker ID" "${r}"

# Case 2: PR-N in added prose should fail.
r="$(mktemp_repo)"
cat > "${r}/pr.md" <<EOF
PR-3 of the series ships verify.
EOF
(cd "${r}" && git add pr.md)
run_case "pr-tracker-fails" 1 "sequencing label" "${r}"

# Case 3: Private 10.x IP should fail.
r="$(mktemp_repo)"
cat > "${r}/ip.md" <<EOF
host at 10.10.0.104 is the cluster server.
EOF
(cd "${r}" && git add ip.md)
run_case "private-ip-fails" 1 "RFC1918" "${r}"

# Case 4: Legitimate code "Phase 1: Detect" should pass.
r="$(mktemp_repo)"
cat > "${r}/code.go" <<EOF
package main

// Phase 1: Detect file types
// Phase 2: Compute hashes
func main() {}
EOF
(cd "${r}" && git add code.go)
run_case "phase-comments-pass" 0 "" "${r}"

# Case 5: AES-256-GCM and RFC 9421 must pass (no false positives on alphanum-dashes).
r="$(mktemp_repo)"
cat > "${r}/crypto.go" <<EOF
package main

// AES-256-GCM signing per RFC 9421
const KeyName = "abc-123"
EOF
(cd "${r}" && git add crypto.go)
run_case "crypto-references-pass" 0 "" "${r}"

# Case 6: Allowlist token OPSEC-OK exempts an otherwise-banned line.
r="$(mktemp_repo)"
cat > "${r}/ok.md" <<EOF
Internal reference TD-7 OPSEC-OK
EOF
(cd "${r}" && git add ok.md)
run_case "opsec-ok-exempts" 0 "" "${r}"

# Case 7: PR-1234 (4+ digits) is not the internal-sequencing form — should pass.
r="$(mktemp_repo)"
cat > "${r}/longpr.md" <<EOF
GitHub PR-1234 reference.
EOF
(cd "${r}" && git add longpr.md)
run_case "long-pr-not-flagged" 0 "" "${r}"

# Case 8: PIPELOCK_OPSEC_EXTRA picks up custom patterns.
r="$(mktemp_repo)"
cat > "${r}/extra.patterns" <<EOF
\bSecretName\b	Internal codename
EOF
cat > "${r}/leak.md" <<EOF
Mentioned SecretName in passing.
EOF
(cd "${r}" && git add leak.md)
run_case "extra-patterns-from-env" 1 "codename" "${r}" env PIPELOCK_OPSEC_EXTRA="${r}/extra.patterns"

# Case 9: OPSEC_EXTRA_PATTERNS env-var passes patterns inline (CI mode).
r="$(mktemp_repo)"
cat > "${r}/leak.md" <<EOF
Mentioned SecretName2 in passing.
EOF
(cd "${r}" && git add leak.md)
run_case "extra-patterns-from-content" 1 "Another codename" \
  "${r}" env OPSEC_EXTRA_PATTERNS=$'\\bSecretName2\\b\tAnother codename'

# Case 10: Public RFC1918 ranges all flagged.
r="$(mktemp_repo)"
cat > "${r}/ips.md" <<EOF
LAN: 192.168.1.10
DMZ: 172.20.0.5
Pod: 10.244.0.7
EOF
(cd "${r}" && git add ips.md)
run_case "all-rfc1918-flagged" 1 "192.168" "${r}"

echo ""
echo "Total: ${test_count}, Failed: ${fail_count}"
if [[ "${fail_count}" -gt 0 ]]; then
  exit 1
fi
exit 0
