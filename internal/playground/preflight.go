// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	liveCanaryPrefix              = "AKIA"
	liveCanaryPublicExampleSuffix = "IOSFODNN7EXAMPLE"
)

func liveCanaryValue(runNonce string) string {
	if runNonce == "" {
		return liveCanaryPrefix + liveCanaryPublicExampleSuffix
	}
	return liveCanaryPrefix + liveCanaryPublicExampleSuffix + "-" + runNonce
}

// Preflight runs cheap stage-hygiene checks before a demo run. It confirms:
//   - the canary value looks synthetic (not a real-looking secret),
//   - the run directory is writable,
//   - if contained mode is requested, the containment hook is wired.
func Preflight(opts DemoOpts) error {
	// --- Canary shape check ---
	// The demo plants a credential-shaped but inert public example value. It is
	// deliberately AWS-shaped so normal DLP catches the class; Pipelock is not
	// configured with the exact value as a canary token.
	canary := liveCanaryValue(opts.RunNonce)
	if !strings.HasPrefix(canary, liveCanaryPrefix) || !strings.Contains(canary, liveCanaryPublicExampleSuffix) {
		return fmt.Errorf("preflight: canary value is not the expected inert public example shape")
	}

	// --- RunDir writable check ---
	cleanDir := filepath.Clean(opts.RunDir)
	if err := os.MkdirAll(cleanDir, 0o750); err != nil {
		return fmt.Errorf("preflight: run dir %q not writable: %w", opts.RunDir, err)
	}
	// Probe write by creating and removing a sentinel file.
	probe := filepath.Join(cleanDir, ".preflight-probe")
	if err := os.WriteFile(probe, []byte("probe"), 0o600); err != nil {
		return fmt.Errorf("preflight: cannot write to run dir %q: %w", opts.RunDir, err)
	}
	_ = os.Remove(probe)

	// --- Containment hook check ---
	if opts.Contained {
		if getContainmentHook() == nil {
			return ErrContainmentNotWired
		}
	}

	return nil
}
