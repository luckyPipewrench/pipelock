// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestParseDoWSubjectTrustAndString(t *testing.T) {
	t.Parallel()

	got, ok := ParseDoWSubjectTrust("")
	if !ok || got != DoWTrustNetwork {
		t.Fatalf("empty = %v %v, want network true", got, ok)
	}
	got, ok = ParseDoWSubjectTrust(" NETWORK ")
	if !ok || got != DoWTrustNetwork {
		t.Fatalf("network = %v %v", got, ok)
	}
	got, ok = ParseDoWSubjectTrust("agent")
	if !ok || got != DoWTrustAgent {
		t.Fatalf("agent = %v %v", got, ok)
	}
	got, ok = ParseDoWSubjectTrust("principal")
	if !ok || got != DoWTrustPrincipal {
		t.Fatalf("principal = %v %v", got, ok)
	}
	got, ok = ParseDoWSubjectTrust("supervisor")
	if ok || got != DoWTrustNetwork {
		t.Fatalf("unknown = %v %v, want network false", got, ok)
	}

	if DoWTrustPrincipal.String() != "principal" || DoWTrustAgent.String() != "agent" || DoWTrustNetwork.String() != "network" {
		t.Fatalf("known String() mappings changed")
	}
	if got := DoWSubjectTrust(99).String(); got != "unknown" {
		t.Fatalf("unknown grade String = %q, want unknown", got)
	}
	if !DoWTrustPrincipal.Meets(DoWTrustAgent) {
		t.Fatal("principal should meet agent")
	}
	if DoWTrustNetwork.Meets(DoWTrustAgent) {
		t.Fatal("network should not meet agent")
	}
}
