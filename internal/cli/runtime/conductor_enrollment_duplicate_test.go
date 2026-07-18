//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package runtime

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReadConductorEnrollmentMarkerRejectsDuplicateKeysStandalone(t *testing.T) {
	path := filepath.Join(t.TempDir(), conductorEnrolledStateFileName)
	raw := `{"version":1,"version":1,"org_id":"org","fleet_id":"fleet","instance_id":"instance","audit_key_id":"key"}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write marker: %v", err)
	}
	_, _, err := readConductorEnrollmentMarker(path, config.Conductor{
		OrgID: "org", FleetID: "fleet", InstanceID: "instance", AuditSigningKeyID: "key",
	})
	if err == nil {
		t.Fatal("readConductorEnrollmentMarker accepted duplicate keys")
	}
}
