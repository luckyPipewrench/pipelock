// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSyncDurableAuditParentFailurePaths(t *testing.T) {
	t.Run("parent does not exist", func(t *testing.T) {
		err := syncDurableAuditParent(filepath.Join(t.TempDir(), "missing", "audit.jsonl"))
		if err == nil || !strings.Contains(err.Error(), "open parent directory") {
			t.Fatalf("syncDurableAuditParent error = %v, want parent open failure", err)
		}
	})

	t.Run("procfs does not support directory sync", func(t *testing.T) {
		if !supportsProcfsDirectorySyncFailure(runtime.GOOS) {
			t.Skip("procfs is only available on Linux")
		}
		err := syncDurableAuditParent("/proc/self/audit.jsonl")
		if err == nil || !strings.Contains(err.Error(), "sync parent directory") {
			t.Fatalf("syncDurableAuditParent error = %v, want parent sync failure", err)
		}
	})
}

func TestSupportsProcfsDirectorySyncFailure(t *testing.T) {
	for _, tc := range []struct {
		goos string
		want bool
	}{
		{goos: "linux", want: true},
		{goos: "darwin", want: false},
		{goos: "freebsd", want: false},
	} {
		if got := supportsProcfsDirectorySyncFailure(tc.goos); got != tc.want {
			t.Fatalf("supportsProcfsDirectorySyncFailure(%q) = %t, want %t", tc.goos, got, tc.want)
		}
	}
}

func supportsProcfsDirectorySyncFailure(goos string) bool {
	return goos == "linux"
}
