// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import "testing"

func TestFilesystemProbeEnvForDoctorNilUsesDefaults(t *testing.T) {
	probe := filesystemProbeEnvForDoctor(nil)
	if probe == nil || probe.runCmd == nil || probe.lookupUser == nil || probe.agentUserName == "" {
		t.Fatalf("nil doctor env = %+v", probe)
	}
}
