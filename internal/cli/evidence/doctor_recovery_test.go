// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package evidence

import (
	"strings"
	"testing"
)

func TestEvidenceDoctorRecoveryDiscontinuityRemainsDamaged(t *testing.T) {
	t.Parallel()
	out, err := runDoctorCmd(t, "../../../sdk/conformance/testdata/recovery-seals/valid/evidence")
	if err == nil {
		t.Fatalf("damaged archive must fail despite its seal: %s", out)
	}
	for _, want := range []string{"linked across attested discontinuity", "evidence doctor: damaged"} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q: %s", want, out)
		}
	}
	if strings.Contains(out, "evidence doctor: healthy") {
		t.Fatalf("damaged archive reported healthy: %s", out)
	}
}
