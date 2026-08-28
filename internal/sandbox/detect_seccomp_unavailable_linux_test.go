// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux && !amd64

package sandbox

import "testing"

func TestDetectAndPreflightReportSeccompUnavailableWithoutFilter(t *testing.T) {
	if seccompFilterSupportedByBuild() {
		t.Fatal("build without the seccomp filter reported support")
	}

	if caps := Detect(); caps.Seccomp {
		t.Fatal("Detect reported seccomp available without Pipelock's filter")
	}

	result := Preflight(t.TempDir(), []string{"true"}, nil, false)
	seen := false
	for _, layer := range result.Layers {
		if layer.Name != LayerSeccomp {
			continue
		}
		seen = true
		if layer.Available {
			t.Fatal("preflight reported seccomp available without Pipelock's filter")
		}
		if layer.Reason != "seccomp unavailable" {
			t.Fatalf("preflight seccomp reason = %q, want seccomp unavailable", layer.Reason)
		}
	}
	if !seen {
		t.Fatal("preflight did not report a seccomp layer")
	}

	// Strict mode promises every layer, so on a build that cannot apply the
	// filter it must REFUSE rather than report ready and launch without it.
	// Reporting the layer honestly is only half the fix; this is the half an
	// operator actually feels, and it is the one behaviour change in this
	// commit, so it gets its own assertion rather than riding on the layer
	// report.
	if strict := Preflight(t.TempDir(), []string{"true"}, nil, true); strict.Status != StatusError {
		t.Fatalf("strict preflight status = %q, want %q when the build cannot apply seccomp",
			strict.Status, StatusError)
	}
}
