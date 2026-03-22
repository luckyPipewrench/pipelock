// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"fmt"
	"runtime"
)

// PreflightStatus indicates the overall sandbox readiness.
const (
	StatusReady    = "capabilities_ok"
	StatusDegraded = "degraded"
	StatusError    = "error"
)

// PreflightResult captures the outcome of a sandbox preflight check.
type PreflightResult struct {
	Status     string       `json:"status"`             // ready, degraded, error
	Workspace  string       `json:"workspace"`          // resolved absolute path
	Command    []string     `json:"command"`            // resolved command argv
	Mode       string       `json:"mode"`               // best-effort or strict
	Layers     []LayerProbe `json:"layers"`             // per-layer availability
	PrivateShm bool         `json:"private_shm"`        // would mount private /dev/shm
	Errors     []string     `json:"errors,omitempty"`   // validation errors
	Warnings   []string     `json:"warnings,omitempty"` // degradation warnings
}

// LayerProbe reports availability of a single containment layer.
type LayerProbe struct {
	Name      LayerName `json:"name"`
	Available bool      `json:"available"`
	Required  bool      `json:"required"`         // true in strict mode
	Reason    string    `json:"reason,omitempty"` // why unavailable
	Detail    string    `json:"detail,omitempty"` // e.g. "ABI v7"
}

// Preflight runs a sandbox readiness check without actually launching.
// Validates workspace, resolves command, probes kernel capabilities,
// and returns a structured result.
func Preflight(workspace string, argv []string, policy *Policy, strict bool) PreflightResult {
	result := PreflightResult{
		Command: argv,
		Mode:    "best-effort",
	}
	if strict {
		result.Mode = "strict"
	}

	// Platform check.
	if runtime.GOOS != osLinux {
		result.Status = StatusError
		result.Errors = append(result.Errors, "sandbox requires Linux")
		return result
	}

	// Validate workspace.
	if err := ValidateWorkspace(workspace); err != nil {
		result.Status = StatusError
		result.Errors = append(result.Errors, fmt.Sprintf("workspace: %v", err))
		return result
	}
	result.Workspace = workspace

	// Validate policy.
	effectivePolicy := DefaultPolicy(workspace)
	if policy != nil {
		effectivePolicy = *policy
	}
	if err := ValidatePolicy(effectivePolicy); err != nil {
		result.Status = StatusError
		result.Errors = append(result.Errors, fmt.Sprintf("policy: %v", err))
		return result
	}

	// Resolve command.
	if len(argv) > 0 {
		resolved, err := lookPathIn(argv[0], nil)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("command %q: %v", argv[0], err))
		} else {
			result.Command = append([]string{resolved}, argv[1:]...)
		}
	}

	// Probe capabilities.
	caps := Detect()

	// NOTE: These are capability probes, not launch guarantees.
	// User namespaces may probe as available while loopback setup or
	// /dev/shm mount fails under AppArmor/container restrictions.
	result.Layers = []LayerProbe{
		{
			Name:      LayerLandlock,
			Available: caps.LandlockABI > 0,
			Required:  strict,
			Detail:    fmt.Sprintf("ABI v%d", caps.LandlockABI),
		},
		{
			Name:      LayerNetNS,
			Available: caps.UserNamespaces,
			Required:  strict,
			Detail:    "capability probe only — launch may still fail under AppArmor",
		},
		{
			Name:      LayerSeccomp,
			Available: caps.Seccomp,
			Required:  strict,
		},
	}

	if caps.LandlockABI <= 0 {
		result.Layers[0].Reason = "Landlock not available (kernel 5.13+ required)"
	}
	if !caps.UserNamespaces {
		result.Layers[1].Reason = "user namespaces unavailable"
	}
	if !caps.Seccomp {
		result.Layers[2].Reason = "seccomp unavailable"
	}

	// Private /dev/shm requires strict mode AND user namespace support
	// (for CLONE_NEWNS mount namespace).
	result.PrivateShm = strict && caps.UserNamespaces

	// Determine status.
	activeCount := 0
	for _, l := range result.Layers {
		if l.Available {
			activeCount++
		} else {
			result.Warnings = append(result.Warnings, fmt.Sprintf("%s: %s", l.Name, l.Reason))
		}
	}

	switch {
	case len(result.Errors) > 0:
		result.Status = StatusError
	case activeCount == len(result.Layers):
		result.Status = StatusReady
	case strict && activeCount < len(result.Layers):
		result.Status = StatusError
		result.Errors = append(result.Errors, fmt.Sprintf("strict mode requires all %d layers, only %d available", len(result.Layers), activeCount))
	default:
		result.Status = StatusDegraded
	}

	return result
}
