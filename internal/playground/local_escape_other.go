// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !js

package playground

import "fmt"

func probeLocalCapability(target, capability string) ProbeResult {
	return ProbeResult{
		Target:  target,
		Open:    false,
		Blocked: false,
		Detail:  fmt.Sprintf("unknown: %s capability probe is Linux-only", capability),
	}
}
