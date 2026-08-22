// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// pathSecretHalves returns the two halves of a synthetic AWS access key ID.
// Built at runtime from split literals so the credential scanners in CI do not
// flag the source file, and deliberately not the AWS documentation example key,
// which carries a dummy-key exemption that would make these tests vacuous.
func pathSecretHalves() (string, string) {
	return "AKIA" + "QRST", "UVWXYZ2345678901"
}

// newPathFragmentProxy builds a proxy whose only active CEE layer is fragment
// reassembly, so a verdict can only come from reassembled path data.
func newPathFragmentProxy(t *testing.T) (*Proxy, *httptest.Server) {
	t.Helper()

	upstream := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(upstream.Close)

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.Action = config.ActionBlock
	cfg.CrossRequestDetection.FragmentReassembly.Enabled = true
	// Set explicitly: these are filled by config normalization, which
	// Defaults() alone does not run, and a zero cap silently truncates every
	// fragment to nothing.
	cfg.CrossRequestDetection.FragmentReassembly.MaxBufferBytes = 65536
	cfg.CrossRequestDetection.FragmentReassembly.WindowMinutes = 5
	// Entropy budget off: this lane must be attributable to path fragments.
	cfg.CrossRequestDetection.EntropyBudget.Enabled = false

	logger := audit.NewNop()
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	p, err := New(cfg, logger, sc, metrics.New())
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	t.Cleanup(p.Close)
	return p, upstream
}

// fetchPath drives the real fetch handler so the path payload is produced by
// production extraction rather than handed to ceeAdmit directly.
func fetchPath(t *testing.T, p *Proxy, base, path string) int {
	t.Helper()
	target := base + path
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/fetch?url="+url.QueryEscape(target), nil)
	w := httptest.NewRecorder()
	p.handleFetch(w, req)
	return w.Code
}

// TestFetchEndpoint_CEEPathFragmentSplitSecret is the bypass regression: a
// secret split across two request paths under a repeated static route must be
// reassembled and blocked. Before path data reached CEE, each request carried
// only an incomplete half and per-request DLP saw nothing.
func TestFetchEndpoint_CEEPathFragmentSplitSecret(t *testing.T) {
	p, upstream := newPathFragmentProxy(t)
	half1, half2 := pathSecretHalves()

	if code := fetchPath(t, p, upstream.URL, "/upload/"+half1); code == http.StatusForbidden {
		t.Fatalf("first half must not block on its own, got %d", code)
	}
	if code := fetchPath(t, p, upstream.URL, "/upload/"+half2); code != http.StatusForbidden {
		t.Fatalf("expected 403 once the split secret reassembles across paths, got %d", code)
	}
}

func TestFetchEndpoint_CEEPathFragmentMatchPersistsWithinWindow(t *testing.T) {
	p, upstream := newPathFragmentProxy(t)
	half1, half2 := pathSecretHalves()

	if code := fetchPath(t, p, upstream.URL, "/upload/"+half1); code == http.StatusForbidden {
		t.Fatalf("first half must not block on its own, got %d", code)
	}
	if code := fetchPath(t, p, upstream.URL, "/upload/"+half2); code != http.StatusForbidden {
		t.Fatalf("completing half = %d, want 403", code)
	}
	// The same retained evidence must not disappear after one enforcement
	// decision. ResetCEEState or the configured window is the operator escape
	// hatch, rather than an uninspected request clearing the detection.
	if code := fetchPath(t, p, upstream.URL, "/upload/ordinary"); code != http.StatusForbidden {
		t.Fatalf("post-match request = %d, want retained CEE block", code)
	}
}

// TestFetchEndpoint_CEEPathFragmentPoisonedSuppression covers the bypass that
// substring-based novelty suppression would have opened: sending a harmless
// segment that CONTAINS the second half first, so the real second half looks
// already-seen and is dropped. Position-aware streams retain every later
// value after a position varies, so the halves still become contiguous.
func TestFetchEndpoint_CEEPathFragmentPoisonedSuppression(t *testing.T) {
	p, upstream := newPathFragmentProxy(t)
	half1, half2 := pathSecretHalves()

	if code := fetchPath(t, p, upstream.URL, "/upload/z"+half2+"z"); code == http.StatusForbidden {
		t.Fatalf("priming segment must not block on its own, got %d", code)
	}
	if code := fetchPath(t, p, upstream.URL, "/upload/"+half1); code == http.StatusForbidden {
		t.Fatalf("first half must not block on its own, got %d", code)
	}
	if code := fetchPath(t, p, upstream.URL, "/upload/"+half2); code != http.StatusForbidden {
		t.Fatalf("expected 403: a primed superstring must not suppress the real half, got %d", code)
	}
}

// TestFetchEndpoint_CEEPathFragmentRepeatedRoute is the availability direction:
// a busy static route carries no secret, so it must never block and must not
// consume the session buffer on every request.
func TestFetchEndpoint_CEEPathFragmentRepeatedRoute(t *testing.T) {
	p, upstream := newPathFragmentProxy(t)

	for i := 0; i < 50; i++ {
		if code := fetchPath(t, p, upstream.URL, "/api/v1/status"); code == http.StatusForbidden {
			t.Fatalf("repeated static route blocked on request %d", i+1)
		}
	}
	if got := p.fragmentBufferPtr.Load().TotalBufferBytes(); got > len("apiv1status") {
		t.Errorf("repeated static route buffered %d bytes, want the route stored once", got)
	}
}

// TestFetchEndpoint_CEEPathFragmentPositionShiftDocumentsCoverageBound proves
// the explicit limitation of absolute-position reassembly. The two halves are
// at positions one and two, so CEE must not invent a cross-position join.
// Per-request DLP still scans each full URL, but neither incomplete half is a
// match on its own.
func TestFetchEndpoint_CEEPathFragmentPositionShiftDocumentsCoverageBound(t *testing.T) {
	p, upstream := newPathFragmentProxy(t)
	half1, half2 := pathSecretHalves()

	if code := fetchPath(t, p, upstream.URL, "/a/"+half1); code == http.StatusForbidden {
		t.Fatalf("first incomplete position-shift half blocked, got %d", code)
	}
	if code := fetchPath(t, p, upstream.URL, "/b/c/"+half2); code == http.StatusForbidden {
		t.Fatalf("position-shifted half unexpectedly reassembled, got %d", code)
	}
}

func TestFetchEndpoint_CEEPathDepthCapFailsClosedWithoutBufferState(t *testing.T) {
	p, upstream := newPathFragmentProxy(t)
	path := "/" + strings.Repeat("x/", scanner.MaxPathPositions+1)

	if code := fetchPath(t, p, upstream.URL, path); code != http.StatusForbidden {
		t.Fatalf("over-depth path = %d, want 403", code)
	}
	if got := p.fragmentBufferPtr.Load().TotalBufferBytes(); got != 0 {
		t.Fatalf("over-depth path buffered %d bytes", got)
	}
}

func TestPathSegments(t *testing.T) {
	tests := []struct {
		name string
		u    *url.URL
		want []string
	}{
		{"nil url", nil, nil},
		{"empty", &url.URL{}, nil},
		{"root only", &url.URL{Path: "/"}, nil},
		{"empty segments only", &url.URL{Path: "///"}, nil},
		{"single", &url.URL{Path: "/data"}, []string{"data"}},
		{"multi", &url.URL{Path: "/api/v1/tokens"}, []string{"api", "v1", "tokens"}},
		{"collapses empty segments", &url.URL{Path: "//api///v1/"}, []string{"api", "v1"}},
		{"decoded by net/url", &url.URL{Path: "/a b/c"}, []string{"a b", "c"}},
		{"raw path fallback", &url.URL{RawPath: "/raw/path"}, []string{"raw", "path"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := pathSegments(tt.u)
			var got [][]byte
			if payload != nil {
				got = payload.segments
			}
			if len(got) != len(tt.want) {
				t.Fatalf("pathSegments = %q, want %q", got, tt.want)
			}
			for i := range got {
				if string(got[i]) != tt.want[i] {
					t.Errorf("segment %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestPathSegments_DepthBoundStopsParsing(t *testing.T) {
	payload := pathSegments(&url.URL{Path: "/" + strings.Repeat("x/", scanner.MaxPathPositions+1)})
	if payload == nil || !payload.depthExceeded {
		t.Fatal("over-depth path did not report a bounded-parser failure")
	}
	if got := len(payload.segments); got != scanner.MaxPathPositions {
		t.Fatalf("retained path positions = %d, want %d", got, scanner.MaxPathPositions)
	}
}
