// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package killswitch

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// absProxyRequest builds a forward-proxy request the way net/http parses one off
// the wire: an absolute-URI request-target, so r.URL carries the DESTINATION
// host and path. This is the shape every pre-existing test in this package
// omitted, which is why the exemption bypass survived.
func absProxyRequest(t *testing.T, method, rawURL string) *http.Request {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	if !u.IsAbs() || u.Host == "" {
		t.Fatalf("test bug: %q is not an absolute URI", rawURL)
	}
	r := httptest.NewRequestWithContext(context.Background(), method, rawURL, nil)
	r.URL = u
	r.RequestURI = rawURL
	return r
}

// activeController returns a controller with the kill switch active via the
// signal source, matching the SIGUSR1 activation an operator actually uses.
func activeController(t *testing.T) *Controller {
	t.Helper()
	c := New(testConfig())
	if !c.ToggleSignal() {
		t.Fatal("ToggleSignal should report the switch now active")
	}
	if !c.IsActive() {
		t.Fatal("precondition: kill switch should be active")
	}
	return c
}

// TestIsActiveHTTP_ForwardProxyGetsNoEndpointExemption is the regression test
// for the kill-switch bypass: with the switch active, a forward-proxy request
// for an arbitrary host must be denied even when the DESTINATION path happens to
// equal one of pipelock's own exempt endpoint paths.
func TestIsActiveHTTP_ForwardProxyGetsNoEndpointExemption(t *testing.T) {
	// Every path that IsActiveHTTP exempts on pipelock's own listener. Each is
	// attacker-chosen on a forward-proxy request, so each must NOT exempt.
	exemptPaths := []string{
		"/health",
		"/metrics",
		"/api/v1/killswitch",
		"/api/v1/killswitch/status",
		"/api/v1/sessions",
		"/api/v1/sessions/abc123",
		"/api/v1/sessions/abc123/reset",
		"/api/v1/sessions/abc123/airlock",
		"/api/v1/sessions/abc123/task",
		"/api/v1/sessions/abc123/trust",
		"/api/v1/sessions/abc123/explain",
		"/api/v1/sessions/abc123/terminate",
	}
	methods := []string{http.MethodGet, http.MethodPost}

	for _, path := range exemptPaths {
		for _, method := range methods {
			t.Run(method+" "+path, func(t *testing.T) {
				c := activeController(t)
				req := absProxyRequest(t, method, "http://proxy-target.vendor.example"+path)
				if d := c.IsActiveHTTP(req); !d.Active {
					t.Errorf("forward-proxy %s http://proxy-target.vendor.example%s was EXEMPTED under an active kill switch; egress bypass", method, path)
				}
			})
		}
	}

	t.Run("query string does not change the verdict", func(t *testing.T) {
		c := activeController(t)
		req := absProxyRequest(t, http.MethodGet, "http://proxy-target.vendor.example/health?exfil=secret")
		if d := c.IsActiveHTTP(req); !d.Active {
			t.Error("forward-proxy request with exempt path plus query was exempted")
		}
	})

	t.Run("CONNECT is denied", func(t *testing.T) {
		c := activeController(t)
		r := httptest.NewRequestWithContext(context.Background(), http.MethodConnect, "/", nil)
		r.URL = &url.URL{Host: "proxy-target.vendor.example:443"}
		r.RequestURI = "proxy-target.vendor.example:443"
		if d := c.IsActiveHTTP(r); !d.Active {
			t.Error("CONNECT was exempted under an active kill switch")
		}
	})
}

// TestIsActiveHTTP_OwnEndpointExemptionsStillWork guards the availability
// direction. An over-strict fix that also denies pipelock's own /health would
// break liveness probes under lockdown, which gets the control switched off.
func TestIsActiveHTTP_OwnEndpointExemptionsStillWork(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"health probe", "/health"},
		{"metrics scrape", "/metrics"},
		{"killswitch api", "/api/v1/killswitch"},
		{"killswitch status", "/api/v1/killswitch/status"},
		{"sessions list", "/api/v1/sessions"},
		{"session terminate", "/api/v1/sessions/abc123/terminate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := activeController(t)
			// Origin-form request-target, i.e. a request to pipelock itself.
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.path, nil)
			if d := c.IsActiveHTTP(req); d.Active {
				t.Errorf("pipelock's own %s was DENIED under lockdown; probes and the deactivation API must survive", tc.path)
			}
		})
	}

	t.Run("non-exempt own path is still denied", func(t *testing.T) {
		c := activeController(t)
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/fetch?url=http://api.vendor.example", nil)
		if d := c.IsActiveHTTP(req); !d.Active {
			t.Error("/fetch was exempted under an active kill switch")
		}
	})
}

// TestIsActiveHTTP_ExemptionMatchesRouterEncoding pins the exemption to the same
// path encoding the session API router uses. Matching the decoded path made the
// exemption broader than the routes it covers.
func TestIsActiveHTTP_ExemptionMatchesRouterEncoding(t *testing.T) {
	c := activeController(t)
	// %74 decodes to 't', so the decoded path reads as .../terminate while the
	// router, which routes on EscapedPath, would 404 it. It must not be exempt.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/sessions/abc123/%74erminate", nil)
	if d := c.IsActiveHTTP(req); !d.Active {
		t.Error("percent-encoded non-route was exempted; exemption is broader than the router")
	}
}

// TestIsActiveHTTP_AllowlistStillAppliesToProxiedTraffic documents the one
// exemption that is deliberately preserved for proxied requests. The IP
// allowlist keys on the client address, which the client cannot choose the way
// it chooses a request path, so an operator's break-glass host keeps working.
func TestIsActiveHTTP_AllowlistStillAppliesToProxiedTraffic(t *testing.T) {
	cfg := testConfig()
	cfg.KillSwitch.AllowlistIPs = []string{"10.9.9.0/24"}
	c := New(cfg)
	if !c.ToggleSignal() {
		t.Fatal("ToggleSignal should report the switch now active")
	}

	t.Run("allowlisted client is exempt", func(t *testing.T) {
		req := absProxyRequest(t, http.MethodGet, "http://proxy-target.vendor.example/health")
		req.RemoteAddr = "10.9.9.5:5555"
		if d := c.IsActiveHTTP(req); d.Active {
			t.Error("allowlisted client IP should stay exempt for proxied traffic")
		}
	})

	t.Run("non-allowlisted client is denied", func(t *testing.T) {
		req := absProxyRequest(t, http.MethodGet, "http://proxy-target.vendor.example/health")
		req.RemoteAddr = "203.0.113.7:5555"
		if d := c.IsActiveHTTP(req); !d.Active {
			t.Error("non-allowlisted client was exempted via the destination path")
		}
	})
}

// TestAllowlistExempt_MalformedClientAddress covers the two error paths in
// allowlistExempt, both of which decide whether traffic is exempt and so must
// fail in the safe direction.
//
// RemoteAddr is normally host:port, but it is not guaranteed to be: a Unix
// socket or a synthetic request can carry a bare address. SplitHostPort fails
// there, and the fallback treats the whole string as the host so a legitimate
// allowlisted operator is not locked out. An address that is neither parses to
// a nil IP, and that must NOT be treated as allowlisted, because a client
// choosing an unparseable address would otherwise select its own exemption.
func TestAllowlistExempt_MalformedClientAddress(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		wantActive bool // true = denied, false = exempt
	}{
		{
			name:       "bare allowlisted ip without a port stays exempt",
			remoteAddr: "10.9.9.5",
			wantActive: false,
		},
		{
			name:       "bare non-allowlisted ip is denied",
			remoteAddr: "203.0.113.7",
			wantActive: true,
		},
		{
			name:       "unparseable address is denied",
			remoteAddr: "not-an-ip-address",
			wantActive: true,
		},
		{
			name:       "empty address is denied",
			remoteAddr: "",
			wantActive: true,
		},
		{
			name:       "host:port with a non-ip host is denied",
			remoteAddr: "some-hostname:5555",
			wantActive: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.KillSwitch.AllowlistIPs = []string{"10.9.9.0/24"}
			c := New(cfg)
			if !c.ToggleSignal() {
				t.Fatal("ToggleSignal should report the switch now active")
			}

			req := absProxyRequest(t, http.MethodGet, "http://proxy-target.vendor.example/health")
			req.RemoteAddr = tc.remoteAddr

			got := c.IsActiveHTTP(req).Active
			if got != tc.wantActive {
				verb := "denied"
				if !tc.wantActive {
					verb = "exempt"
				}
				t.Errorf("RemoteAddr %q: Active = %v, want %v (expected %s)",
					tc.remoteAddr, got, tc.wantActive, verb)
			}
		})
	}
}

// TestAllowlistExempt_NoAllowlistConfigured pins the common case: with no
// allowlist set, no client address can produce an exemption.
func TestAllowlistExempt_NoAllowlistConfigured(t *testing.T) {
	c := activeController(t)
	req := absProxyRequest(t, http.MethodGet, "http://proxy-target.vendor.example/health")
	req.RemoteAddr = "10.9.9.5:5555"
	if d := c.IsActiveHTTP(req); !d.Active {
		t.Error("an unconfigured allowlist exempted a client")
	}
}

// TestIsProxiedRequest covers the helper directly, including the nil-URL case a
// hand-built request can present.
func TestIsProxiedRequest(t *testing.T) {
	cases := []struct {
		name   string
		method string
		u      *url.URL
		want   bool
	}{
		{"absolute uri", http.MethodGet, &url.URL{Scheme: "http", Host: "api.vendor.example", Path: "/health"}, true},
		{"connect authority form", http.MethodConnect, &url.URL{Host: "api.vendor.example:443"}, true},
		{"connect with nil url", http.MethodConnect, nil, true},
		{"origin form", http.MethodGet, &url.URL{Path: "/health"}, false},
		{"scheme without host", http.MethodGet, &url.URL{Scheme: "http", Path: "/health"}, false},
		{"nil url", http.MethodGet, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{Method: tc.method, URL: tc.u}
			if got := isProxiedRequest(r); got != tc.want {
				t.Errorf("isProxiedRequest = %v, want %v", got, tc.want)
			}
		})
	}
}
