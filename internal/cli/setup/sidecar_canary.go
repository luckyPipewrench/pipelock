// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// sidecarCanaryResult holds the outcome of the in-cluster canary phase.
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
	detected := scanCanaryURL(cfg, canaryURL)

	if detected {
		return &sidecarCanaryResult{
			Detected: true,
			Detail:   "Canary secret detected in URL scan. DLP is working.",
		}
	}

	if !jsonOutput {
		_, _ = fmt.Fprintln(w, "  Canary was not detected. Check the generated config.")
	}

	return &sidecarCanaryResult{
		Detected: false,
		Detail:   "Canary was not detected. Run 'pipelock check --url \"" + canaryURL + "\"' to debug.",
	}
}
