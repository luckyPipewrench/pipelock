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
	for _, layer := range result.Layers {
		if layer.Name != LayerSeccomp {
			continue
		}
		if layer.Available {
			t.Fatal("preflight reported seccomp available without Pipelock's filter")
		}
		if layer.Reason != "seccomp unavailable" {
			t.Fatalf("preflight seccomp reason = %q, want seccomp unavailable", layer.Reason)
		}
		return
	}

	t.Fatal("preflight did not report a seccomp layer")
}
