// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !js

package playground

import "github.com/luckyPipewrench/pipelock/internal/replaycapture"

func liveDemoScenario() replaycapture.Scenario {
	return replaycapture.Scenario{
		ID:               LiveDemoScenarioID,
		Title:            "Blocked: secret exfiltration in a request body",
		BenchCaseID:      "url-dlp-aws-key-001",
		Transport:        replaycapture.TransportForward,
		Category:         "Secret exfiltration",
		ExpectedLayer:    liveDemoExpectedBlockLayer,
		ExpectedVerdict:  liveDemoExpectedVerdict,
		DestinationClass: "attacker-controlled collector (reserved example host)",
		Without:          "A bare agent posts a credential-shaped value to a collector and the value escapes.",
		With:             "Pipelock scans the request body, detects the credential-shaped value, blocks the request, and signs a receipt recording the block.",
		RedactedShape:    "AKIA************EXAMPLE -> blocked",
	}
}

func lookupPlaygroundScenario(id string) (replaycapture.Scenario, bool) {
	if id == LiveDemoScenarioID {
		return liveDemoScenario(), true
	}
	for _, s := range replaycapture.DefaultScenarios() {
		if s.ID == id {
			return s, true
		}
	}
	return replaycapture.Scenario{}, false
}
