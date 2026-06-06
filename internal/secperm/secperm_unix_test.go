// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package secperm

import (
	"io/fs"
	"testing"
)

func TestEnforcedOnUnix(t *testing.T) {
	if !Enforced {
		t.Fatal("Enforced must be true on Unix: file-mode bits are security-meaningful")
	}
}

// TestTooPermissiveUnix proves the Unix behavior is exactly perm&disallowed != 0
// for every mask the codebase uses, including the 0o040 k8s group-read
// allowance. This is the byte-for-byte equivalence guarantee for the inline
// checks secperm replaced.
func TestTooPermissiveUnix(t *testing.T) {
	cases := []struct {
		name     string
		perm     fs.FileMode
		disallow fs.FileMode
		reject   bool
	}{
		// 0o037 gate (signing key, license, secrets, header-file).
		{"key 0600 ok", 0o600, 0o037, false},
		{"key 0640 ok (k8s group-read)", 0o640, 0o037, false},
		{"key 0660 group-write rejected", 0o660, 0o037, true},
		{"key 0644 other-read rejected", 0o644, 0o037, true},
		{"key 0666 rejected (Windows-reported mode)", 0o666, 0o037, true},
		{"key 0444 other-read rejected (Windows-reported mode)", 0o444, 0o037, true},
		// 0o077 gate (salt, sidecar dir).
		{"salt 0600 ok", 0o600, 0o077, false},
		{"salt 0640 group-read rejected under 0o077", 0o640, 0o077, true},
		{"salt 0666 rejected", 0o666, 0o077, true},
		// 0o137 gate (CA key): rejects other-read, any write, any exec.
		{"ca 0600 ok", 0o600, 0o137, false},
		{"ca 0640 ok (k8s group-read)", 0o640, 0o137, false},
		{"ca 0444 other-read rejected", 0o444, 0o137, true},
		{"ca 0700 owner-exec rejected", 0o700, 0o137, true},
		// 0o002 gate (world-writable parent dir).
		{"parent 0755 ok", 0o755, 0o002, false},
		{"parent 0757 world-write rejected", 0o757, 0o002, true},
		// 0o177 gate (admin-API session config): owner-rw only, no exec/group/other.
		{"admin-cfg 0600 ok", 0o600, 0o177, false},
		{"admin-cfg 0400 ok", 0o400, 0o177, false},
		{"admin-cfg 0700 owner-exec rejected", 0o700, 0o177, true},
		{"admin-cfg 0640 group-read rejected under 0o177", 0o640, 0o177, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := TooPermissive(tc.perm, tc.disallow)
			if got != tc.reject {
				t.Fatalf("TooPermissive(%04o, %04o) = %v, want %v", tc.perm, tc.disallow, got, tc.reject)
			}
			// Equivalence with the raw inline expression it replaced.
			if want := tc.perm&tc.disallow != 0; got != want {
				t.Fatalf("TooPermissive(%04o, %04o) = %v, raw perm&mask != 0 = %v (must be identical)", tc.perm, tc.disallow, got, want)
			}
		})
	}
}
