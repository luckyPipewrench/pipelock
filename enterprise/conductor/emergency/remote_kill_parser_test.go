//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package emergency

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadRemoteKillStateRejectsDuplicateMembers(t *testing.T) {
	path := filepath.Join(t.TempDir(), RemoteKillStateFileName)
	if err := os.WriteFile(path, []byte(`{"last_counter":1,"last_counter":2,"last_message_hash":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRemoteKillStateFile(path); err == nil {
		t.Fatal("readRemoteKillStateFile accepted duplicate counter")
	}
}
