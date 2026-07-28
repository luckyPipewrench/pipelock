// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"strings"
	"testing"
)

// TestResponseSizeBlockReasonOnlyNamesConsultedKnobs guards the operator-UX
// invariant that a block reason never recommends a knob the blocking path does
// not consult. The forward and TLS-interception paths gate this block on
// response_scanning.size_exempt_domains, so naming it there is correct. The
// fetch path has no size-exempt branch at all (see the documented exception in
// transport_control_parity_test.go), so naming it there sends an operator to a
// knob that cannot lift their block.
func TestResponseSizeBlockReasonOnlyNamesConsultedKnobs(t *testing.T) {
	t.Parallel()

	const exemptKnob = "response_scanning.size_exempt_domains"

	t.Run("path that consults the knob names it", func(t *testing.T) {
		t.Parallel()
		got := responseSizeBlockReason("api.vendor.example", 2048, 1024, "fetch_proxy.max_response_mb", true)
		if !strings.Contains(got, exemptKnob) {
			t.Errorf("reason omits the remediation knob the path consults: %q", got)
		}
		if !strings.Contains(got, "fetch_proxy.max_response_mb") {
			t.Errorf("reason omits the limit knob: %q", got)
		}
	})

	t.Run("path without a size-exempt branch does not name it", func(t *testing.T) {
		t.Parallel()
		got := responseSizeBlockReason("api.vendor.example", 2048, 1024, "fetch_proxy.max_response_mb", false)
		if strings.Contains(got, exemptKnob) {
			t.Errorf("reason recommends a knob this path never consults: %q", got)
		}
		// The operator still needs a real way out.
		if !strings.Contains(got, "fetch_proxy.max_response_mb") {
			t.Errorf("reason must still name the knob that does work: %q", got)
		}
		// Silence would leave an operator who knows the knob from another
		// transport assuming it applies here, so the gap is stated outright.
		if !strings.Contains(got, "no per-host size exemption") {
			t.Errorf("reason must say the exemption is unavailable here: %q", got)
		}
	})
}
