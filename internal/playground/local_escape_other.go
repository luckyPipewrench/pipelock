// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !js

package playground

import "fmt"

func probeLocalCapability(target, capability string) ProbeResult {
	return ProbeResult{
		Target:  target,
		Open:    false,
		Blocked: true,
		Detail:  fmt.Sprintf("blocked/unavailable: %s capability probe is Linux-only", capability),
	}
}
