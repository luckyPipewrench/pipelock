//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package controlplane

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPersistedControlPlaneStateRejectsDuplicateKeys(t *testing.T) {
	tests := []struct {
		name string
		read func(string) error
	}{
		{"bundle record", func(path string) error { _, err := readBundleRecord(path); return err }},
		{"stream head", func(path string) error { _, err := readStreamHeadRecord(path); return err }},
		{"emergency state", func(path string) error { _, err := readEmergencyState(path); return err }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state.json")
			if err := os.WriteFile(path, []byte(`{"version":1,"version":2}`), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := tt.read(path); err == nil {
				t.Fatal("persisted state accepted duplicate keys")
			}
		})
	}
}
