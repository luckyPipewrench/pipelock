// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import "testing"

func TestLiveCanaryValue(t *testing.T) {
	if got := liveCanaryValue(""); got != liveCanaryPrefix+liveCanaryPublicExampleSuffix {
		t.Fatalf("empty nonce canary = %q", got)
	}
	if got := liveCanaryValue("N1"); got != liveCanaryPrefix+liveCanaryPublicExampleSuffix+"-N1" {
		t.Fatalf("nonce canary = %q", got)
	}
}

func TestLookupPlaygroundScenario(t *testing.T) {
	scenario, ok := lookupPlaygroundScenario(LiveDemoScenarioID)
	if !ok {
		t.Fatal("live demo scenario not found")
	}
	if scenario.ID != LiveDemoScenarioID {
		t.Fatalf("scenario ID = %q", scenario.ID)
	}

	if _, ok := lookupPlaygroundScenario("missing-playground-scenario"); ok {
		t.Fatal("unexpected scenario match")
	}
}
