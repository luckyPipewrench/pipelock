// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package livechat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientIP_CloudflareConnectingIP(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "173.245.48.9:443"
	req.Header.Set("CF-Connecting-IP", "198.51.100.7")
	req.Header.Set("X-Forwarded-For", "192.0.2.66, 198.51.100.4")

	if got := ClientIP(req, false); got != "198.51.100.7" {
		t.Fatalf("ClientIP = %q, want Cloudflare connecting IP", got)
	}
}

func TestClientIP_CloudflareBehindFlyEdge(t *testing.T) {
	t.Setenv("FLY_APP_NAME", "pipelock-playground")
	// On Fly the direct peer is Fly's internal proxy, not Cloudflare, so the
	// real visitor must be resolved via Fly-Client-IP (Cloudflare's edge) plus
	// CF-Connecting-IP (the visitor). Without this, every visitor collapses into
	// one shared rate/budget bucket on the Fly proxy address.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "172.19.0.5:443"                // Fly internal proxy, not a Cloudflare range
	req.Header.Set(flyClientIPHeader, "162.158.0.1") // a Cloudflare proxy IP
	req.Header.Set(cfConnectingIPHeader, "198.51.100.7")

	if got := ClientIP(req, false); got != "198.51.100.7" {
		t.Fatalf("ClientIP = %q, want real visitor IP via the CF-behind-Fly chain", got)
	}
}

func TestClientIP_FlyEdgeNotCloudflareIgnoresForgedCFHeader(t *testing.T) {
	t.Setenv("FLY_APP_NAME", "pipelock-playground")
	// A client hitting .fly.dev directly cannot forge identity: Fly overwrites
	// Fly-Client-IP with the client's own (non-Cloudflare) address, so the
	// CF-Connecting-IP header is ignored and the identity falls back to the peer.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "172.19.0.5:443"                 // Fly internal proxy
	req.Header.Set(flyClientIPHeader, "203.0.113.10") // attacker's own IP, NOT Cloudflare
	req.Header.Set(cfConnectingIPHeader, "198.51.100.7")

	if got := ClientIP(req, false); got != "172.19.0.5" {
		t.Fatalf("ClientIP = %q, want fallback to peer (forged CF header ignored)", got)
	}
}

func TestClientIP_PublicPeerIgnoresForgedFlyClientIP(t *testing.T) {
	t.Setenv("FLY_APP_NAME", "pipelock-playground")
	// A directly-exposed (non-Fly) deployment sees a PUBLIC peer. A client that
	// sets both Fly-Client-IP (to a Cloudflare range) and CF-Connecting-IP must
	// NOT forge identity: the Fly-behind-edge path is gated on a private/Fly
	// internal peer, so a public peer skips it and falls back to the real peer.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.50:443"              // public peer (directly exposed)
	req.Header.Set(flyClientIPHeader, "162.158.0.1") // forged Cloudflare-range edge
	req.Header.Set(cfConnectingIPHeader, "198.51.100.7")

	if got := ClientIP(req, false); got != "203.0.113.50" {
		t.Fatalf("ClientIP = %q, want public peer (forged Fly-Client-IP ignored)", got)
	}
}

func TestClientIP_NonFlyPrivatePeerIgnoresForgedFlyClientIP(t *testing.T) {
	t.Setenv("FLY_APP_NAME", "")
	t.Setenv("FLY_MACHINE_ID", "")
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "172.19.0.5:443"
	req.Header.Set(flyClientIPHeader, "162.158.0.1")
	req.Header.Set(cfConnectingIPHeader, "198.51.100.7")

	if got := ClientIP(req, false); got != "172.19.0.5" {
		t.Fatalf("ClientIP = %q, want private peer when not running on Fly", got)
	}
}

func TestClientIP_CloudflareConnectingIPv6BucketsToSlash64(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "[2606:4700::1234]:443"
	req.Header.Set("CF-Connecting-IP", "2001:db8::7")

	if got := ClientIP(req, false); got != "2001:db8::/64" {
		t.Fatalf("ClientIP = %q, want IPv6 /64 bucket", got)
	}
	if got := ClientIPExact(req, false); got != "2001:db8::7" {
		t.Fatalf("ClientIPExact = %q, want full IPv6", got)
	}
}

func TestClientIP_IPv6RotationSharesBucket(t *testing.T) {
	t.Parallel()
	mk := func(connecting string) *http.Request {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
		req.RemoteAddr = "[2606:4700::1234]:443"
		req.Header.Set("CF-Connecting-IP", connecting)
		return req
	}
	// Two distinct addresses inside one /64 collapse to one abuse bucket.
	a := ClientIP(mk("2001:db8:1:2::1"), false)
	b := ClientIP(mk("2001:db8:1:2:dead:beef:cafe:f00d"), false)
	if a != b || a != "2001:db8:1:2::/64" {
		t.Fatalf("same-/64 rotation: a=%q b=%q, want shared 2001:db8:1:2::/64", a, b)
	}
	// A different /64 is a different bucket.
	if c := ClientIP(mk("2001:db8:1:3::1"), false); c == a {
		t.Fatalf("different /64 collapsed to same bucket %q", c)
	}
}

func TestClientIP_IPv4NotBucketed(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "173.245.48.9:443"
	req.Header.Set("CF-Connecting-IP", "198.51.100.7")

	// IPv4 is a /32 identity and must never be collapsed to a /64.
	if got := ClientIP(req, false); got != "198.51.100.7" {
		t.Fatalf("ClientIP = %q, want exact IPv4", got)
	}
}

func TestClientIP_IPv4MappedNotMaskedAsV6(t *testing.T) {
	t.Parallel()
	// abuseBucket must leave IPv4-mapped IPv6 alone (no /64 collapse).
	if got := abuseBucket("::ffff:198.51.100.7"); strings.HasSuffix(got, "/64") {
		t.Fatalf("abuseBucket(IPv4-mapped) = %q, must not be a /64 bucket", got)
	}
	if got := abuseBucket("not-an-ip"); got != "not-an-ip" {
		t.Fatalf("abuseBucket(non-IP) = %q, want passthrough", got)
	}
}

func TestClientIP_RejectsForgedCloudflareHeader(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:443"
	req.Header.Set("CF-Connecting-IP", "198.51.100.7")

	if got := ClientIP(req, false); got != "203.0.113.10" {
		t.Fatalf("ClientIP = %q, want direct peer", got)
	}
}

func TestClientIP_InvalidCloudflareHeaderFallsBack(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "173.245.48.9:443"
	req.Header.Set("CF-Connecting-IP", "not an ip")

	if got := ClientIP(req, false); got != "173.245.48.9" {
		t.Fatalf("ClientIP = %q, want Cloudflare peer fallback", got)
	}
}

func TestClientIP_ForwardedForRequiresTrust(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:443"
	req.Header.Set("X-Forwarded-For", "198.51.100.7, 192.0.2.4")

	if got := ClientIP(req, false); got != "203.0.113.10" {
		t.Fatalf("untrusted ClientIP = %q, want direct peer", got)
	}
	if got := ClientIP(req, true); got != "198.51.100.7" {
		t.Fatalf("trusted ClientIP = %q, want first XFF", got)
	}
}

func TestClientIP_NilRequest(t *testing.T) {
	t.Parallel()
	if got := ClientIP(nil, true); got != "" {
		t.Fatalf("ClientIP(nil) = %q, want empty", got)
	}
	if got := ClientIPExact(nil, true); got != "" {
		t.Fatalf("ClientIPExact(nil) = %q, want empty", got)
	}
}

func TestClientIP_CloudflareHeaderEmptyFallsBack(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "173.245.48.9:443"
	req.Header.Set("CF-Connecting-IP", " \t")

	if got := ClientIPExact(req, false); got != "173.245.48.9" {
		t.Fatalf("ClientIPExact = %q, want Cloudflare peer fallback", got)
	}
}

func TestClientIP_MalformedCloudflarePeerFallsBack(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "not-an-ip:443"
	req.Header.Set("CF-Connecting-IP", "198.51.100.7")

	if got := ClientIPExact(req, false); got != "not-an-ip" {
		t.Fatalf("ClientIPExact = %q, want raw malformed peer fallback", got)
	}
}

func TestClientIP_EmptyForwardedForFallsBack(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:443"
	req.Header.Set("X-Forwarded-For", "")

	if got := ClientIPExact(req, true); got != "203.0.113.10" {
		t.Fatalf("ClientIPExact = %q, want peer fallback", got)
	}
}

func TestClientIP_RemoteAddrWithoutPort(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10"

	if got := ClientIPExact(req, false); got != "203.0.113.10" {
		t.Fatalf("ClientIPExact = %q, want raw remote address", got)
	}
}

func TestClientIP_InvalidXFFSegmentFallsToPeer(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		xff  string
		want string
	}{
		{name: "garbage_first_segment", xff: "not-an-ip, 1.2.3.4", want: "203.0.113.10"},
		{name: "empty_first_segment", xff: ", 1.2.3.4", want: "203.0.113.10"},
		{name: "valid_first_segment", xff: "198.51.100.7, 1.2.3.4", want: "198.51.100.7"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
			req.RemoteAddr = "203.0.113.10:443"
			req.Header.Set("X-Forwarded-For", tc.xff)
			if got := ClientIPExact(req, true); got != tc.want {
				t.Fatalf("ClientIPExact = %q, want %q", got, tc.want)
			}
		})
	}
}
