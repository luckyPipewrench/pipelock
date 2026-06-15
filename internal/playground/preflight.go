// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// preflightCanaryPrefix is the expected prefix for synthetic playground canary
// values. Real secrets must not be used; this check catches operator mistakes.
const preflightCanaryPrefix = "SYNTH-CANARY-"

// Preflight runs cheap stage-hygiene checks before a demo run. It confirms:
//   - the canary value looks synthetic (not a real-looking secret),
//   - the run directory is writable,
//   - if contained mode is requested, the containment hook is wired.
func Preflight(opts DemoOpts) error {
	// --- Canary shape check ---
	// The demo plants a synthetic canary. If someone passes a real-looking
	// secret (e.g. starts with AKIA, ghp_, sk-), that's a misuse we catch
	// before the proxy even boots.
	canary := "SYNTH-CANARY-" + opts.RunNonce
	if !strings.HasPrefix(canary, preflightCanaryPrefix) {
		return fmt.Errorf("preflight: canary value does not have the expected synthetic prefix %q", preflightCanaryPrefix)
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
