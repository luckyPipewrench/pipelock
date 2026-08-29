// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
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

func TestResponseSizeObservedBlockReasonMarksLowerBound(t *testing.T) {
	t.Parallel()

	got := responseSizeObservedBlockReason("api.vendor.example", 2048, 1024, "", true, false)
	if !strings.Contains(got, "is at least 2048 bytes") {
		t.Fatalf("reason = %q, want streamed lower-bound wording", got)
	}
	if strings.Contains(got, "is 2048 bytes") {
		t.Fatalf("reason = %q, must not claim an exact streamed size", got)
	}
}

func TestReverseObservedBodyBytesPreservesKnownInformation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name          string
		contentLength int64
		observed      int
		complete      bool
		wantBytes     int
		wantExact     bool
	}{
		{name: "complete read", contentLength: -1, observed: 17, complete: true, wantBytes: 17, wantExact: true},
		{name: "declared length", contentLength: 29, observed: 17, wantBytes: 29, wantExact: true},
		{name: "unknown length", contentLength: -1, observed: 17, wantBytes: 17, wantExact: false},
		{name: "invalid short declared length", contentLength: 12, observed: 17, wantBytes: 17, wantExact: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotBytes, gotExact := reverseObservedBodyBytes(tc.contentLength, tc.observed, tc.complete)
			if gotBytes != tc.wantBytes || gotExact != tc.wantExact {
				t.Fatalf("reverseObservedBodyBytes() = (%d, %t), want (%d, %t)", gotBytes, gotExact, tc.wantBytes, tc.wantExact)
			}
		})
	}
}

func TestReverseProxyResponseScanBodyLimit(t *testing.T) {
	t.Parallel()
	if reverseProxyMaxBodyBytes != 1<<20 {
		t.Fatalf("production response scan body limit = %d, want exactly 1 MiB", reverseProxyMaxBodyBytes)
	}

	for _, tc := range []struct {
		name string
		rp   *ReverseProxyHandler
		want int
	}{
		{name: "nil handler uses production limit", want: reverseProxyMaxBodyBytes},
		{name: "zero value uses production limit", rp: &ReverseProxyHandler{}, want: reverseProxyMaxBodyBytes},
		{name: "test override", rp: &ReverseProxyHandler{responseBodyLimit: 4096}, want: 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.rp.responseScanBodyLimit(); got != tc.want {
				t.Fatalf("responseScanBodyLimit() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestProxyResponseScanBodyLimit(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	wantDefault := int64(cfg.FetchProxy.MaxResponseMB) * 1024 * 1024

	for _, tc := range []struct {
		name string
		p    *Proxy
		want int64
	}{
		{name: "nil proxy uses configured limit", want: wantDefault},
		{name: "zero value uses configured limit", p: &Proxy{}, want: wantDefault},
		{name: "test override", p: &Proxy{responseBodyLimit: 4096}, want: 4096},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.p.responseScanBodyLimit(cfg); got != tc.want {
				t.Fatalf("responseScanBodyLimit() = %d, want %d", got, tc.want)
			}
		})
	}
}
