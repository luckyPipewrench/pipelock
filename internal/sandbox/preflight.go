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
	Status       string                 `json:"status"`                 // ready, degraded, error
	Workspace    string                 `json:"workspace"`              // resolved absolute path
	Command      []string               `json:"command"`                // resolved command argv
	Mode         string                 `json:"mode"`                   // best-effort, strict, or required
	Requirements *PreflightRequirements `json:"requirements,omitempty"` // independently declared requirements
	Layers       []LayerProbe           `json:"layers"`                 // per-layer availability
	PrivateShm   bool                   `json:"private_shm"`            // would mount private /dev/shm
	Errors       []string               `json:"errors,omitempty"`       // validation errors
	Warnings     []string               `json:"warnings,omitempty"`     // degradation warnings
}

// PreflightRequirements independently declares the containment properties a
// caller needs. RequireProxyHandler is reported but cannot be capability-probed
// here; LaunchStandalone validates the actual handler before child start.
type PreflightRequirements struct {
	RequireNetNS        bool `json:"network"`
	RequireProxyHandler bool `json:"handler"`
	RequireLandlock     bool `json:"landlock"`
	RequireSeccomp      bool `json:"seccomp"`
}

// LayerProbe reports availability of a single containment layer.
type LayerProbe struct {
	Name      LayerName `json:"name"`
	Available bool      `json:"available"`
	Required  bool      `json:"required"`         // true when this layer is required
	Reason    string    `json:"reason,omitempty"` // why unavailable
	Detail    string    `json:"detail,omitempty"` // e.g. "ABI v7"
}

// Preflight runs the legacy strict-or-best-effort readiness check. New callers
// that need independently required layers should use PreflightWithRequirements.
func Preflight(workspace string, argv []string, policy *Policy, strict bool) PreflightResult {
	return preflight(workspace, argv, policy, PreflightRequirements{
		RequireNetNS:    strict,
		RequireLandlock: strict,
		RequireSeccomp:  strict,
	}, strict, false)
}

// PreflightWithRequirements runs a sandbox readiness check with independently
// declared network, handler, Landlock, and seccomp requirements.
func PreflightWithRequirements(workspace string, argv []string, policy *Policy, requirements PreflightRequirements) PreflightResult {
	return preflight(workspace, argv, policy, requirements, false, true)
}

func preflight(workspace string, argv []string, policy *Policy, requirements PreflightRequirements, strict, reportRequirements bool) PreflightResult {
	result := PreflightResult{
		Command: argv,
		Mode:    "best-effort",
	}
	if strict {
		result.Mode = "strict"
	} else if requirements.RequireNetNS || requirements.RequireProxyHandler || requirements.RequireLandlock || requirements.RequireSeccomp {
		result.Mode = "required"
	}
	if reportRequirements {
		result.Requirements = &requirements
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
			Required:  requirements.RequireLandlock,
			Detail:    fmt.Sprintf("ABI v%d", caps.LandlockABI),
		},
		{
			Name:      LayerNetNS,
			Available: caps.UserNamespaces,
			Required:  requirements.RequireNetNS,
			Detail:    "capability probe only — launch may still fail under AppArmor",
		},
		{
			Name:      LayerSeccomp,
			Available: caps.Seccomp,
			Required:  requirements.RequireSeccomp,
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

	missingRequired := make([]LayerProbe, 0, len(result.Layers))
	for _, layer := range result.Layers {
		if layer.Required && !layer.Available {
			missingRequired = append(missingRequired, layer)
		}
	}

	switch {
	case len(result.Errors) > 0:
		result.Status = StatusError
	case activeCount == len(result.Layers):
		result.Status = StatusReady
	case strict && len(missingRequired) > 0:
		result.Status = StatusError
		result.Errors = append(result.Errors, fmt.Sprintf("strict mode requires all %d layers, only %d available", len(result.Layers), activeCount))
	case len(missingRequired) > 0:
		result.Status = StatusError
		for _, layer := range missingRequired {
			result.Errors = append(result.Errors, fmt.Sprintf("%s is required but unavailable: %s", layer.Name, layer.Reason))
		}
	default:
		result.Status = StatusDegraded
	}

	return result
}
