// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package secperm centralizes the cross-platform decision of whether a file's
// permission bits are security-meaningful and, if so, whether they are too
// permissive for a secret-bearing file or directory.
//
// On Unix, fs.FileMode permission bits map directly to the kernel's
// owner/group/other access model, so pipelock enforces them as a fail-closed
// gate: a private key, license, salt, or credential file that is group- or
// world-accessible is rejected before it is read. The Unix behavior is exactly
// perm&disallowed != 0 — byte-for-byte identical to the inline checks this
// package replaced, including the 0o040 group-read allowance for Kubernetes
// fsGroup Secret mounts (0o037 and 0o077 masks do not include 0o040).
//
// On Windows, Go derives fs.FileMode from the read-only file attribute alone —
// it never reflects the NTFS ACL — so the bits report 0666 or 0444 regardless
// of the real access control. Enforcing the Unix mask there would reject every
// key unconditionally (0o666 & 0o037 != 0), which is why a recorder signing
// key could never load on native Windows (issue #695). The Windows build
// therefore treats the bits as non-meaningful and skips the check. This is a
// documented fail-open: access control on Windows must be enforced via NTFS
// ACLs at deployment time, which pipelock does not inspect. Callers that need
// to surface this to operators can branch on Enforced.
package secperm
