// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"strings"
	"testing"
)

func TestStrictIPCWithoutSeccomp(t *testing.T) {
	for _, version := range []int{1, 5, 6, 8, 9, 10} {
		landlock := LayerStatus{Active: true, Version: version}
		outcome, err := appliedLaunchOutcome(true, false, false, landlock, LayerStatus{})
		if outcome != LaunchOutcomeRefused || err == nil {
			t.Fatalf("strict ABI %d admitted: %s, %v", version, outcome, err)
		}
		if version < 9 && !strings.Contains(err.Error(), "Landlock ABI 9") {
			t.Errorf("ABI %d lacks actionable IPC refusal: %v", version, err)
		}
		if !strings.Contains(err.Error(), "seccomp") {
			t.Errorf("ABI %d lost existing strict seccomp requirement: %v", version, err)
		}
		outcome, err = appliedLaunchOutcome(false, false, false, landlock, LayerStatus{})
		if outcome != LaunchOutcomePartial || err != nil {
			t.Fatalf("normal ABI %d contract changed: %s, %v", version, outcome, err)
		}
	}
}
