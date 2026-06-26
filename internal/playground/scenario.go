// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

// LiveDemoScenarioID is the playground live-demo scenario. It is intentionally
// separate from the replay gallery's URL-exfil scenario because the live toy
// agent sends the synthetic canary in a POST body.
const LiveDemoScenarioID = "secret-exfil-body-blocked"

const (
	liveDemoExpectedBlockLayer = "body_dlp"
	liveDemoExpectedVerdict    = "block"
	liveDemoAllowedVerdict     = "allow"
)
