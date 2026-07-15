//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtimesnapshot

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadRejectsDuplicateSnapshotKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snapshot.json")
	now := time.Now().UTC()
	raw := []byte(`{"version":1,"version":1,"produced_at":"` + now.Format(time.RFC3339Nano) + `"}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Read(path, time.Minute, now); err == nil {
		t.Fatal("Read accepted duplicate keys")
	}
}
