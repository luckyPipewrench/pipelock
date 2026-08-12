// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package audit

import (
	"path/filepath"
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
		err := syncDurableAuditParent("/proc/self/audit.jsonl")
		if err == nil || !strings.Contains(err.Error(), "sync parent directory") {
			t.Fatalf("syncDurableAuditParent error = %v, want parent sync failure", err)
		}
	})
}
