// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"bytes"
	"strings"
	"testing"
)

func TestPartialOutcomeNamesUnenforcedUnixSockets(t *testing.T) {
	for _, outcome := range []AppliedLaunchOutcome{LaunchOutcomePartial, LaunchOutcomeAdvisoryOverridePartial} {
		for _, version := range []int{1, 5, 6, 8, 9} {
			var out bytes.Buffer
			reportAppliedLaunchOutcome(&out, outcome, version)
			if strings.Contains(out.String(), "pathname AF_UNIX is not enforced") != (version < 9) {
				t.Errorf("ABI %d pathname output = %q", version, out.String())
			}
			if strings.Contains(out.String(), "abstract AF_UNIX is not enforced") != (version < 6) {
				t.Errorf("ABI %d abstract output = %q", version, out.String())
			}
		}
	}
}

func TestAppliedOutcomeNamesUnixSocketFallback(t *testing.T) {
	for _, outcome := range []AppliedLaunchOutcome{LaunchOutcomeFull, LaunchOutcomeAdvisoryOverride} {
		for _, version := range []int{1, 5, 6, 8, 9} {
			var out bytes.Buffer
			reportAppliedLaunchOutcome(&out, outcome, version)
			if strings.Contains(out.String(), "Unix socket fallback: AF_UNIX sockets, datagram pairs and recvmsg/recvmmsg denied") != (version < 9) {
				t.Errorf("ABI %d outcome %s fallback notice = %q", version, outcome, out.String())
			}
		}
	}
}
