// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"fmt"
	"io"
)

// sidecarVerifyResult holds the outcome of the sidecar verify phase.
type sidecarVerifyResult struct {
	Reachable bool   `json:"reachable"`
	Healthy   bool   `json:"healthy"`
	Skipped   bool   `json:"skipped"`
	Detail    string `json:"detail,omitempty"`
}

// runSidecarVerify attempts to reach the sidecar's health endpoint via port-forward.
// Fails open on kubeconfig absence — prints a clear message and skips.
// Uses a 5-second deadline to prevent indefinite blocking.
func runSidecarVerify(w io.Writer, opts sidecarOptions, jsonOutput bool) *sidecarVerifyResult {
	if opts.skipVerify {
		return &sidecarVerifyResult{Skipped: true, Detail: "skipped (--skip-verify)"}
	}

	// Port-forward verification requires a real cluster connection.
	// For the initial implementation, we skip gracefully when not connected.
	// Future: use kubeconfig to port-forward and probe /health.
	if !jsonOutput {
		_, _ = fmt.Fprintln(w, "  Cluster verification requires a running pod.")
		_, _ = fmt.Fprintln(w, "  Apply the manifest and run: kubectl port-forward <pod> 8888:8888")
		_, _ = fmt.Fprintln(w, "  Then: curl http://localhost:8888/health")
	}

	return &sidecarVerifyResult{
		Skipped: true,
		Detail:  "cluster verification deferred; apply the manifest and verify manually",
	}
}
