// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package contain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The browser-defaults record was written, then the config write failed and
// removing the record failed once. Rollback must retry and remove it.
func TestBrowserDefaultsFailedRecordRestoreIsRetriedByRollback(t *testing.T) {
	env, _, path, record := browserDefaultsEnv(t)
	writeAgentBrowserConfigFixture(t, path, `{"args": "--keep"}`)
	priorWrite := env.agentBrowserWrite
	env.agentBrowserWrite = func(_ *os.File, _ []byte) (int, error) { return 0, errors.New("disk full") }
	t.Cleanup(func() { env.agentBrowserWrite = priorWrite })
	removeDenied := 0
	removeFile := env.removeFile
	env.removeFile = func(p string) error {
		if filepath.Clean(p) == filepath.Clean(record) && removeDenied == 0 {
			removeDenied++
			return errors.New("remove denied once")
		}
		return removeFile(p)
	}
	var out strings.Builder
	_, err := runSteps(context.Background(), env, &out, []step{stepWriteAgentBrowserDefaults()})
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("runSteps error = %v, want the write failure", err)
	}
	if removeDenied == 0 {
		t.Fatal("positive control: the inline record removal never ran")
	}
	if strings.Contains(err.Error(), "rollback incomplete") {
		t.Fatalf("rollback retry should have removed the record: %v\n%s", err, out.String())
	}
	assertAbsent(t, record)
}
