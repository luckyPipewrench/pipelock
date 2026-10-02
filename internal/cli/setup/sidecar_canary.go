// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// sidecarCanaryResult holds the outcome of the local synthetic canary phase.
type sidecarCanaryResult struct {
	Detected bool   `json:"detected"`
	Skipped  bool   `json:"skipped"`
	Detail   string `json:"detail,omitempty"`
}

// runSidecarCanary runs the synthetic secret injection canary against the
// generated config. Reuses the same canary logic as the IDE init flow.
func runSidecarCanary(w io.Writer, cfg *config.Config, opts sidecarOptions, jsonOutput bool) *sidecarCanaryResult {
	if opts.skipCanary {
		return &sidecarCanaryResult{Skipped: true, Detail: "skipped (--skip-canary)"}
	}

	// Use the same canary URL and scanner as the IDE init flow.
	canaryURL := "https://github.com/test?key=" + canaryToken()
	canary := scanCanaryResult(cfg, canaryURL)

	if canary.Detected {
		return &sidecarCanaryResult{
			Detected: true,
			Detail:   canary.Detail,
		}
	}

	detail := fmt.Sprintf("%s After deploying the generated proxy, run inside its container: /pipelock check --config %s --url %s", canary.Detail,
		initCommandQuote(sidecarConfigMount+"/"+sidecarConfigFile, "linux"), initCommandQuote(canaryURL, "linux"))
	if !jsonOutput {
		_, _ = fmt.Fprintln(w, "  "+detail)
	}

	return &sidecarCanaryResult{
		Detected: false,
		Detail:   detail,
	}
}
