//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package siemforward

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/emit"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const testPublicIP = "203.0.113.10"

type sequenceResolver struct {
	mu      sync.Mutex
	answers [][]string
	calls   int
}

type blockingResolver struct{}

type resolverFunc func(context.Context, string) ([]string, error)

func (f resolverFunc) LookupHost(ctx context.Context, host string) ([]string, error) {
	return f(ctx, host)
}

func (blockingResolver) LookupHost(ctx context.Context, _ string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (r *sequenceResolver) LookupHost(_ context.Context, _ string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.answers) == 0 {
		return nil, errors.New("no resolver answer")
	}
	idx := r.calls
	if idx >= len(r.answers) {
		idx = len(r.answers) - 1
	}
	r.calls++
	return append([]string(nil), r.answers[idx]...), nil
}

func testConfig(t *testing.T, rawURL string) Config {
	t.Helper()
	dir := t.TempDir()
	return Config{
		URL:          rawURL,
		AllowedHosts: []string{"api.vendor.example"},
		SpoolFile:    filepath.Join(dir, "forward.spool"),
		CursorFile:   filepath.Join(dir, "forward.cursor"),
		QueueSize:    8,
		Timeout:      time.Second,
		// The harness talks plaintext http to a fake endpoint; opt in so the
		// transport-confidentiality policy does not reject the fixture URLs.
		// Dedicated tests exercise that policy with the flag unset.
		AllowInsecureHTTP: true,
	}
}

func testEvent(n int) emit.Event {
	return emit.Event{
		Severity:   emit.SeverityWarn,
		Type:       "blocked",
		Timestamp:  time.Unix(int64(n), 0).UTC(),
		InstanceID: "agent-a",
		Fields:     map[string]any{"sequence": n},
	}
}

func TestNewFailsClosedForUnsafeDestinations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		rawURL  string
		allowed []string
		resolve []string
	}{
		{name: "loopback DNS", rawURL: "http://api.vendor.example/events", allowed: []string{"api.vendor.example"}, resolve: []string{"127.0.0.1"}},
		{name: "private DNS", rawURL: "http://api.vendor.example/events", allowed: []string{"api.vendor.example"}, resolve: []string{"10.2.3.4"}},
		{name: "link local DNS", rawURL: "http://api.vendor.example/events", allowed: []string{"api.vendor.example"}, resolve: []string{"169.254.10.2"}},
		{name: "metadata DNS", rawURL: "http://api.vendor.example/events", allowed: []string{"api.vendor.example"}, resolve: []string{"169.254.169.254"}},
		{name: "metadata literal 169.254.169.254 allowlisted", rawURL: "http://169.254.169.254/events", allowed: []string{"169.254.169.254"}},
		{name: "azure wireserver literal 168.63.129.16 allowlisted", rawURL: "http://168.63.129.16/events", allowed: []string{"168.63.129.16"}},
		{name: "ipv6 metadata literal fd00:ec2::254 allowlisted", rawURL: "http://[fd00:ec2::254]/events", allowed: []string{"fd00:ec2::254"}},
		{name: "encoded metadata", rawURL: "http://0xa9fea9fe/events", allowed: []string{"169.254.169.254"}},
		{name: "encoded unspecified", rawURL: "http://0x00000000/events", allowed: []string{"0.0.0.0"}},
		{name: "encoded multicast", rawURL: "http://0xe0000001/events", allowed: []string{"224.0.0.1"}},
		{name: "IPv4-mapped metadata", rawURL: "http://[::ffff:169.254.169.254]/events", allowed: []string{"169.254.169.254"}},
		{name: "trailing root metadata", rawURL: "http://169.254.169.254./events", allowed: []string{"169.254.169.254"}},
		{name: "zoned IPv6 multicast", rawURL: "http://[ff02::1%25eth0]/events", allowed: []string{"ff02::1"}},
		{name: "private DNS", rawURL: "https://api.vendor.example/events", allowed: []string{"api.vendor.example"}, resolve: []string{"192.168.1.20"}},
		{name: "missing allowlist", rawURL: "https://api.vendor.example/events", resolve: []string{testPublicIP}},
		{name: "wrong allowlist", rawURL: "https://api.vendor.example/events", allowed: []string{"other.vendor.example"}, resolve: []string{testPublicIP}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, tc.rawURL)
			cfg.AllowedHosts = tc.allowed
			resolver := &sequenceResolver{answers: [][]string{tc.resolve}}
			if _, err := New(cfg, Options{Resolver: resolver}); err == nil {
				t.Fatal("New() succeeded for unsafe destination")
			}
		})
	}
}

func TestNewBoundsStartupDNSResolution(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, "http://api.vendor.example/events")
	cfg.Timeout = 20 * time.Millisecond
	f, err := New(cfg, Options{Resolver: blockingResolver{}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !strings.Contains(f.Health().LastError, "destination unresolved") {
		t.Fatalf("health = %+v, want degraded resolver state", f.Health())
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNewAllowsExplicitPrivateIPLiteral(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		rawURL string
		host   string
	}{
		{name: "loopback sidecar", rawURL: "http://127.0.0.1/events", host: "127.0.0.1"},
		{name: "rfc1918 siem", rawURL: "http://10.0.0.5/events", host: "10.0.0.5"},
		{name: "encoded rfc1918 siem", rawURL: "http://0x0a000005/events", host: "10.0.0.5"},
		{name: "public target", rawURL: "https://0x08080808/events", host: "8.8.8.8"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, tc.rawURL)
			cfg.AllowedHosts = []string{tc.host}
			f, err := New(cfg, Options{})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := f.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
		})
	}
}

func TestValidateResolvedHostTreatsIPv4ZoneSuffixAsLiteral(t *testing.T) {
	t.Parallel()
	internalChecks := 0
	err := validateResolvedHost(t.Context(), resolverFunc(func(context.Context, string) ([]string, error) {
		t.Fatal("literal target unexpectedly reached DNS resolution")
		return nil, nil
	}), "10.0.0.1%x", func(ip net.IP) bool {
		internalChecks++
		return ip.Equal(net.ParseIP("10.0.0.1"))
	}, resolvedHostPolicy{allowPrivate: true})
	if err != nil {
		t.Fatalf("validateResolvedHost: %v", err)
	}
	if internalChecks != 1 {
		t.Fatalf("internal checks = %d, want 1 canonical literal check", internalChecks)
	}
}

func TestValidateTargetCanonicalIPAllowlistEquality(t *testing.T) {
	t.Parallel()
	if _, err := validateTarget("https://0x08080808/events", []string{"8.8.8.8"}, "", false); err != nil {
		t.Fatalf("validateTarget canonical equality: %v", err)
	}
}

func TestConfigAndRuntimeForwarderCanonicalizationParity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		rawURL    string
		allowlist string
	}{
		{name: "standard IPv4", rawURL: "https://8.8.8.8/events", allowlist: "8.8.8.8"},
		{name: "full hex IPv4", rawURL: "https://0x08080808/events", allowlist: "8.8.8.8"},
		{name: "dotted hex IPv4", rawURL: "https://0x08.0x08.0x08.0x08/events", allowlist: "8.8.8.8"},
		{name: "dotted octal IPv4", rawURL: "https://010.010.010.010/events", allowlist: "8.8.8.8"},
		{name: "mixed radix IPv4", rawURL: "https://0x08.010.8.0x08/events", allowlist: "8.8.8.8"},
		{name: "full octal IPv4", rawURL: "https://01002004010/events", allowlist: "8.8.8.8"},
		{name: "decimal IPv4", rawURL: "https://134744072/events", allowlist: "8.8.8.8"},
		{name: "IPv4 mapped IPv6", rawURL: "https://[::ffff:8.8.8.8]/events", allowlist: "8.8.8.8"},
		{name: "uppercase IPv4 mapped IPv6", rawURL: "https://[::FFFF:8.8.8.8]/events", allowlist: "8.8.8.8"},
		{name: "IPv6 zone", rawURL: "https://[2001:db8::1%25eth0]/events", allowlist: "2001:db8::1"},
		{name: "trailing root dot", rawURL: "https://8.8.8.8./events", allowlist: "8.8.8.8"},
		{name: "allowlist whitespace", rawURL: "https://8.8.8.8/events", allowlist: " 8.8.8.8 "},
		{name: "IPv4 bogus zone allowlist", rawURL: "https://10.0.0.1/events", allowlist: "10.0.0.1%x"},
		{name: "hostname percent rejected", rawURL: "https://api.vendor.example/events", allowlist: "api%zone.vendor.example"},
		{name: "only one trailing root dot stripped", rawURL: "https://8.8.8.8../events", allowlist: "8.8.8.8"},
		{name: "bracketed allowlist rejected", rawURL: "https://[2001:db8::1]/events", allowlist: "[2001:db8::1]"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := config.Defaults()
			cfg.Emit.Forwarder = config.ForwarderConfig{
				URL: tc.rawURL, DestinationAllowlist: []string{tc.allowlist},
				SpoolFile: "/var/lib/pipelock/siem.spool", CursorFile: "/var/lib/pipelock/siem.cursor",
				MinSeverity: config.SeverityWarn, TimeoutSeconds: 5, QueueSize: 256,
			}
			configErr := cfg.Validate()
			_, runtimeErr := validateTarget(tc.rawURL, []string{tc.allowlist}, "", false)
			if (configErr == nil) != (runtimeErr == nil) {
				t.Fatalf("canonicalization parity: config error = %v, runtime error = %v", configErr, runtimeErr)
			}
		})
	}
}

func TestConfigForwarderAllowlistParserParityWithScanner(t *testing.T) {
	t.Parallel()
	forms := []struct {
		form       string
		targetHost string
		wantIP     string
	}{
		{form: "8.8.8.8", targetHost: "8.8.8.8", wantIP: "8.8.8.8"},
		{form: "0x08080808", targetHost: "8.8.8.8", wantIP: "8.8.8.8"},
		{form: "0X08080808", targetHost: "8.8.8.8", wantIP: "8.8.8.8"},
		{form: "0x08.0x08.0x08.0x08", targetHost: "8.8.8.8", wantIP: "8.8.8.8"},
		{form: "0X08.010.8.0x08", targetHost: "8.8.8.8", wantIP: "8.8.8.8"},
		{form: "010.010.010.010", targetHost: "8.8.8.8", wantIP: "8.8.8.8"},
		{form: "01002004010", targetHost: "8.8.8.8", wantIP: "8.8.8.8"},
		{form: "134744072", targetHost: "8.8.8.8", wantIP: "8.8.8.8"},
		{form: "8.8.8.8.", targetHost: "8.8.8.8", wantIP: "8.8.8.8"},
		{form: "8.8.8.8..", targetHost: "8.8.8.8"},
		{form: " 8.8.8.8 ", targetHost: "8.8.8.8", wantIP: "8.8.8.8"},
		{form: "8.8.8.8%x", targetHost: "8.8.8.8", wantIP: "8.8.8.8"},
		{form: "::ffff:8.8.8.8", targetHost: "8.8.8.8", wantIP: "8.8.8.8"},
		{form: "::FFFF:8.8.8.8", targetHost: "8.8.8.8", wantIP: "8.8.8.8"},
		{form: "2001:db8::1", targetHost: "[2001:db8::1]", wantIP: "2001:db8::1"},
		{form: "2001:db8::1%eth0", targetHost: "[2001:db8::1]", wantIP: "2001:db8::1"},
		{form: "[2001:db8::1]", targetHost: "[2001:db8::1]"},
	}
	for _, tc := range forms {
		t.Run(tc.form, func(t *testing.T) {
			t.Parallel()
			ip := scanner.ParseIPLiteral(tc.form)
			if tc.wantIP == "" {
				if ip != nil {
					t.Fatalf("scanner.ParseIPLiteral(%q) = %s, want nil", tc.form, ip)
				}
			} else if ip == nil || ip.String() != tc.wantIP {
				t.Fatalf("scanner.ParseIPLiteral(%q) = %v, want %s", tc.form, ip, tc.wantIP)
			}
			rawURL := "https://" + tc.targetHost + "/events"
			cfg := config.Defaults()
			cfg.Emit.Forwarder = config.ForwarderConfig{
				URL: rawURL, DestinationAllowlist: []string{tc.form},
				SpoolFile: "/var/lib/pipelock/siem.spool", CursorFile: "/var/lib/pipelock/siem.cursor",
				MinSeverity: config.SeverityWarn, TimeoutSeconds: 5, QueueSize: 256,
			}
			configErr := cfg.Validate()
			_, runtimeErr := validateTarget(rawURL, []string{tc.form}, "", false)
			if tc.wantIP == "" {
				if configErr == nil || runtimeErr == nil {
					t.Fatalf("unsupported form %q accepted: config error=%v runtime error=%v", tc.form, configErr, runtimeErr)
				}
				return
			}
			if configErr != nil || runtimeErr != nil {
				t.Fatalf("parser drift for %q -> %s: config error=%v runtime error=%v", tc.form, ip, configErr, runtimeErr)
			}
		})
	}
}

func TestAssertResolvedIPsSafeDeniesImmutableRangesWithPrivateAllowed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ip   string
	}{
		{name: "metadata", ip: "169.254.169.254"},
		{name: "azure wireserver", ip: "168.63.129.16"},
		{name: "ipv6 metadata", ip: "fd00:ec2::254"},
		{name: "link local", ip: "169.254.10.2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := assertResolvedIPsSafe("api.vendor.example", []string{tc.ip}, func(net.IP) bool {
				return false
			}, resolvedHostPolicy{allowPrivate: true})
			if err == nil {
				t.Fatal("assertResolvedIPsSafe allowed immutable-deny IP with allowPrivate=true")
			}
			if !strings.Contains(err.Error(), "non-overridable IP") {
				t.Fatalf("error = %q, want immutable-deny reason", err)
			}
		})
	}
}

func TestSafeDialContextDeniesImmutableLiteralWithPrivateAllowed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		rawURL string
		host   string
	}{
		{name: "metadata", rawURL: "http://169.254.169.254/events", host: "169.254.169.254"},
		{name: "azure wireserver", rawURL: "http://168.63.129.16/events", host: "168.63.129.16"},
		{name: "ipv6 metadata", rawURL: "http://[fd00:ec2::254]/events", host: "fd00:ec2::254"},
		{name: "link local", rawURL: "http://169.254.10.2/events", host: "169.254.10.2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			target, err := validateTarget(tc.rawURL, []string{tc.host}, "", true)
			if err != nil {
				t.Fatalf("validateTarget: %v", err)
			}
			dialed := false
			f := &Forwarder{
				target:              target,
				targetLiteral:       scanner.ParseIPLiteral(tc.host),
				isInternalIP:        func(net.IP) bool { return false },
				allowPrivateLiteral: true,
				dial: func(context.Context, string, string) (net.Conn, error) {
					dialed = true
					return nil, errors.New("dial should not be reached")
				},
			}
			_, err = f.safeDialContext(t.Context(), "tcp", net.JoinHostPort(tc.host, "80"))
			if err == nil {
				t.Fatal("safeDialContext allowed immutable-deny literal with allowPrivateLiteral=true")
			}
			if !strings.Contains(err.Error(), "non-overridable IP") {
				t.Fatalf("error = %q, want immutable-deny reason", err)
			}
			if dialed {
				t.Fatal("dialer called for immutable-deny literal")
			}
		})
	}
}

func TestForwarderIPLiteralCannotBeRetargetedByResolver(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, "http://0xcb00710a/events")
	cfg.AllowedHosts = []string{testPublicIP}
	dialed := make(chan string, 1)
	f, err := New(cfg, Options{
		Resolver: &sequenceResolver{answers: [][]string{{"127.0.0.1"}}},
		DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialed <- addr
			return nil, errors.New("test dial failure")
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := f.Emit(t.Context(), testEvent(1)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	select {
	case addr := <-dialed:
		if addr != net.JoinHostPort(testPublicIP, "80") {
			t.Fatalf("dial address = %q, want pinned literal", addr)
		}
	case <-time.After(time.Second):
		t.Fatal("dial was not attempted")
	}
}

func TestForwarderDeniesDNSRebindingAtSendTime(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, "http://api.vendor.example/events")
	resolver := &sequenceResolver{answers: [][]string{{testPublicIP}, {"127.0.0.1"}}}
	dialed := make(chan struct{}, 1)
	f, err := New(cfg, Options{
		Resolver: resolver,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed <- struct{}{}
			return nil, errors.New("must not dial")
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := f.Emit(t.Context(), testEvent(1)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	waitFor(t, func() bool { return f.Health().Failed > 0 })
	select {
	case <-dialed:
		t.Fatal("dialer called after DNS rebound to loopback")
	default:
	}
	if got := f.Health().Delivered; got != 0 {
		t.Fatalf("Delivered = %d, want 0", got)
	}
}

func TestForwarderPlaintextLocalhostRequiresLoopbackResolution(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		answers       []string
		authToken     string
		allowInsecure bool
	}{
		{name: "public", answers: []string{testPublicIP}},
		{name: "mixed", answers: []string{"127.0.0.1", testPublicIP}},
		{name: "insecure flag does not retarget localhost", answers: []string{testPublicIP}, allowInsecure: true},
		{name: "auth token still requires loopback with insecure flag", answers: []string{testPublicIP}, authToken: "secret", allowInsecure: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, "http://localhost/events")
			cfg.AllowedHosts = []string{"localhost"}
			cfg.AuthToken = tc.authToken
			cfg.AllowInsecureHTTP = tc.allowInsecure
			if _, err := New(cfg, Options{Resolver: &sequenceResolver{answers: [][]string{tc.answers}}}); err == nil || !strings.Contains(err.Error(), "non-loopback") {
				t.Fatalf("New error = %v, want non-loopback localhost rejection", err)
			}
		})
	}
}

func TestForwarderPlaintextLocalhostPinsLoopbackAndBlocksRebinding(t *testing.T) {
	t.Parallel()
	for _, allowInsecure := range []bool{false, true} {
		t.Run(fmt.Sprintf("allow_insecure_http=%t", allowInsecure), func(t *testing.T) {
			t.Parallel()
			cfg := testConfig(t, "http://localhost/events")
			cfg.AllowedHosts = []string{"localhost"}
			cfg.AllowInsecureHTTP = allowInsecure
			resolver := &sequenceResolver{answers: [][]string{{"127.0.0.1"}, {testPublicIP}}}
			dialed := make(chan string, 1)
			f, err := New(cfg, Options{
				Resolver: resolver,
				DialContext: func(_ context.Context, _, addr string) (net.Conn, error) {
					dialed <- addr
					return nil, errors.New("must not dial rebound address")
				},
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(func() { _ = f.Close() })
			if err := f.Emit(t.Context(), testEvent(1)); err != nil {
				t.Fatalf("Emit: %v", err)
			}
			waitFor(t, func() bool { return f.Health().Failed > 0 })
			select {
			case addr := <-dialed:
				t.Fatalf("dialer called after localhost rebound: %s", addr)
			default:
			}
		})
	}
}

func TestForwarderPlaintextLocalhostServesLoopback(t *testing.T) {
	t.Parallel()
	received := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	cfg := testConfig(t, "http://localhost/events")
	cfg.AllowedHosts = []string{"localhost"}
	cfg.AllowInsecureHTTP = false
	f, err := New(cfg, Options{
		Resolver:    &sequenceResolver{answers: [][]string{{"127.0.0.1"}}},
		DialContext: routeToServer(t, srv),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := f.Emit(t.Context(), testEvent(1)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("loopback localhost delivery was not served")
	}
}

func TestForwarderAllowInsecureLocalhostStillRequiresLoopback(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, "http://localhost/events")
	cfg.AllowedHosts = []string{"localhost"}
	cfg.AllowInsecureHTTP = true
	if _, err := New(cfg, Options{Resolver: &sequenceResolver{answers: [][]string{{testPublicIP}}}}); err == nil || !strings.Contains(err.Error(), "non-loopback") {
		t.Fatalf("New error = %v, want non-loopback localhost rejection despite cleartext opt-in", err)
	}
}

func TestForwarderDoesNotPersistOrReportEndpointCredentials(t *testing.T) {
	t.Parallel()
	const (
		querySecret = "query-secret-value"
		authSecret  = "bearer-secret-value"
	)
	// https because an auth_token over plaintext http to a non-loopback host is
	// rejected by policy; this test exercises credential handling, not scheme.
	cfg := testConfig(t, "https://api.vendor.example/events?token="+querySecret)
	cfg.AuthToken = authSecret
	f, err := New(cfg, Options{
		Resolver: &sequenceResolver{answers: [][]string{{testPublicIP}}},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("test dial failure")
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := f.Emit(t.Context(), testEvent(1)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	waitFor(t, func() bool { return f.Health().Failed > 0 })
	health := f.Health()
	if strings.Contains(health.LastError, querySecret) || strings.Contains(health.LastError, authSecret) {
		t.Fatalf("delivery health leaked endpoint credential: %q", health.LastError)
	}
	spool, err := os.ReadFile(cfg.SpoolFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(spool), querySecret) || strings.Contains(string(spool), authSecret) {
		t.Fatal("spool contains endpoint credential")
	}
}

func TestForwarderRefusesRedirectWithoutForwardingAuthorization(t *testing.T) {
	t.Parallel()
	const token = "redirect-test-token"
	var redirectedHits atomic.Int32
	redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedHits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(redirected.Close)
	authSeen := make(chan string, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authSeen <- r.Header.Get("Authorization")
		http.Redirect(w, r, redirected.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(origin.Close)
	// Loopback host: http with an auth_token is allowed only for loopback, and
	// the dial is routed to the httptest origin regardless of the literal.
	cfg := testConfig(t, "http://127.0.0.1/events")
	cfg.AllowedHosts = []string{"127.0.0.1"}
	cfg.AuthToken = token
	f, err := New(cfg, Options{
		Resolver:    &sequenceResolver{answers: [][]string{{testPublicIP}}},
		DialContext: routeToServer(t, origin),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := f.Emit(t.Context(), testEvent(1)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	select {
	case auth := <-authSeen:
		if auth != "Bearer "+token {
			t.Fatalf("origin Authorization = %q", auth)
		}
	case <-time.After(time.Second):
		t.Fatal("origin did not receive delivery")
	}
	waitFor(t, func() bool { return f.Health().Failed > 0 })
	if redirectedHits.Load() != 0 {
		t.Fatal("redirect target received a request")
	}
}

func TestForwarderReplayCursorResumesWithoutGap(t *testing.T) {
	t.Parallel()
	received := make(chan int, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		var envelope Envelope
		if err := decodeEnvelope(r.Body, &envelope); err != nil {
			t.Errorf("decode envelope: %v", err)
			http.Error(w, "bad envelope", http.StatusBadRequest)
			return
		}
		received <- int(envelope.Event.Fields["sequence"].(float64))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	cfg := testConfig(t, "http://api.vendor.example/events")
	resolver := &sequenceResolver{answers: [][]string{{testPublicIP}}}
	dial := routeToServer(t, srv)
	f, err := New(cfg, Options{Resolver: resolver, DialContext: dial})
	if err != nil {
		t.Fatalf("New first: %v", err)
	}
	for i := 1; i <= 3; i++ {
		if err := f.Emit(t.Context(), testEvent(i)); err != nil {
			t.Fatalf("Emit(%d): %v", i, err)
		}
	}
	waitFor(t, func() bool { return f.Health().Delivered == 3 })
	if err := f.Close(); err != nil {
		t.Fatalf("Close first: %v", err)
	}

	f2, err := New(cfg, Options{Resolver: resolver, DialContext: dial})
	if err != nil {
		t.Fatalf("New restart: %v", err)
	}
	t.Cleanup(func() { _ = f2.Close() })
	if err := f2.Emit(t.Context(), testEvent(4)); err != nil {
		t.Fatalf("Emit(4): %v", err)
	}
	waitFor(t, func() bool { return f2.Health().Delivered == 1 })

	var got []int
	for len(received) > 0 {
		got = append(got, <-received)
	}
	want := []int{1, 2, 3, 4}
	if len(got) != len(want) {
		t.Fatalf("received = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("received = %v, want %v", got, want)
		}
	}
}

func TestForwarderCorruptCursorFailsClosed(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, "http://api.vendor.example/events")
	if err := os.WriteFile(cfg.CursorFile, []byte(`{"version":1,"source_file":"wrong","offset":100,"content_hash":"bad"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := &sequenceResolver{answers: [][]string{{testPublicIP}}}
	if _, err := New(cfg, Options{Resolver: resolver}); err == nil {
		t.Fatal("New succeeded with corrupt cursor")
	}
}

func TestLoadCursorRejectsOversizedState(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, "http://api.vendor.example/events")
	if err := os.WriteFile(cfg.CursorFile, bytes.Repeat([]byte{'x'}, int(maxCursorBytes)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadCursor(cfg.SpoolFile, cfg.CursorFile); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("loadCursor error = %v, want size-limit rejection", err)
	}
}

func TestNewRestrictsExistingStateFilePermissions(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, "http://api.vendor.example/events")
	absSpool, err := filepath.Abs(cfg.SpoolFile)
	if err != nil {
		t.Fatal(err)
	}
	cursorJSON := fmt.Sprintf(`{"version":1,"source_file":%q,"offset":0,"content_hash":""}`, absSpool)
	if err := os.WriteFile(cfg.CursorFile, []byte(cursorJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	cursorFile, err := os.OpenFile(filepath.Clean(cfg.CursorFile), os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := cursorFile.Chmod(0o666); err != nil {
		_ = cursorFile.Close()
		t.Fatal(err)
	}
	if err := cursorFile.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := New(cfg, Options{Resolver: &sequenceResolver{answers: [][]string{{testPublicIP}}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	for _, path := range []string{cfg.SpoolFile, cfg.CursorFile} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = 0o%03o, want 0o600", path, got)
		}
	}
}

func TestForwarderRejectsSpoolSymlinkSwappedAfterValidation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no O_NOFOLLOW equivalent")
	}
	t.Parallel()
	cfg := testConfig(t, "http://api.vendor.example/events")
	f, err := New(cfg, Options{Resolver: &sequenceResolver{answers: [][]string{{testPublicIP}}}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	victim := filepath.Join(t.TempDir(), "victim")
	const victimContent = "must-not-change"
	if err := os.WriteFile(victim, []byte(victimContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfg.SpoolFile); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, cfg.SpoolFile); err != nil {
		t.Fatal(err)
	}
	if err := f.Emit(t.Context(), testEvent(1)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	waitFor(t, func() bool { return f.Health().Failed > 0 })
	got, err := os.ReadFile(filepath.Clean(victim))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != victimContent {
		t.Fatalf("symlink target changed to %q", got)
	}
}

func TestForwarderDeferredStartDoesNotReplayUntilActivated(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, "http://api.vendor.example/events")
	resolver := &sequenceResolver{answers: [][]string{{testPublicIP}}}
	dials := make(chan struct{}, 1)
	f, err := New(cfg, Options{
		Resolver:      resolver,
		DeferredStart: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dials <- struct{}{}
			return nil, errors.New("test dial")
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := f.Emit(t.Context(), testEvent(1)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	select {
	case <-dials:
		t.Fatal("delivery started before Start")
	case <-time.After(50 * time.Millisecond):
	}
	f.Start()
	waitFor(t, func() bool { return f.Health().Failed > 0 })
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestForwarderQueueFullDropsWithoutBlocking(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, "http://api.vendor.example/events")
	cfg.QueueSize = 1
	release := make(chan struct{})
	dialStarted := make(chan struct{}, 1)
	f, err := New(cfg, Options{
		Resolver: &sequenceResolver{answers: [][]string{{testPublicIP}}},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			select {
			case dialStarted <- struct{}{}:
			default:
			}
			<-release
			return nil, errors.New("released")
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() {
		close(release)
		_ = f.Close()
	}()
	if err := f.Emit(t.Context(), testEvent(1)); err != nil {
		t.Fatalf("first Emit: %v", err)
	}
	select {
	case <-dialStarted:
	case <-time.After(time.Second):
		t.Fatal("worker did not start delivery")
	}

	deadline := time.Now().Add(250 * time.Millisecond)
	drops := 0
	for i := 2; i < 1000; i++ {
		if errors.Is(f.Emit(t.Context(), testEvent(i)), ErrQueueFull) {
			drops++
		}
		if time.Now().After(deadline) {
			t.Fatal("Emit blocked while queue was full")
		}
	}
	if drops == 0 || f.Health().Dropped == 0 {
		t.Fatalf("drops = %d, health = %+v", drops, f.Health())
	}
}

func TestForwarderConcurrentCloseReplaysAcceptedEventsAtLeastOnce(t *testing.T) {
	t.Parallel()
	var received atomic.Int32
	var receivedMu sync.Mutex
	receivedBySequence := make(map[int]int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		var envelope Envelope
		if err := decodeEnvelope(r.Body, &envelope); err != nil {
			t.Errorf("decode envelope: %v", err)
			http.Error(w, "bad envelope", http.StatusBadRequest)
			return
		}
		sequence, ok := envelope.Event.Fields["sequence"].(float64)
		if !ok || envelope.Event.ID == "" {
			t.Errorf("delivered event missing stable dedupe fields: %+v", envelope.Event)
			http.Error(w, "bad envelope", http.StatusBadRequest)
			return
		}
		receivedMu.Lock()
		receivedBySequence[int(sequence)]++
		receivedMu.Unlock()
		received.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	cfg := testConfig(t, "http://api.vendor.example/events")
	cfg.QueueSize = 256
	f, err := New(cfg, Options{
		Resolver:    &sequenceResolver{answers: [][]string{{testPublicIP}}},
		DialContext: routeToServer(t, srv),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var accepted atomic.Int32
	var acceptedMu sync.Mutex
	acceptedSequences := make(map[int]struct{})
	var producers sync.WaitGroup
	for i := 0; i < 100; i++ {
		producers.Add(1)
		go func(sequence int) {
			defer producers.Done()
			if err := f.Emit(t.Context(), testEvent(sequence)); err == nil {
				accepted.Add(1)
				acceptedMu.Lock()
				acceptedSequences[sequence] = struct{}{}
				acceptedMu.Unlock()
			} else if !errors.Is(err, errClosed) {
				t.Errorf("Emit: %v", err)
			}
		}(i)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- f.Close() }()
	producers.Wait()
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}
	f2, err := New(cfg, Options{
		Resolver:    &sequenceResolver{answers: [][]string{{testPublicIP}}},
		DialContext: routeToServer(t, srv),
	})
	if err != nil {
		t.Fatalf("New after shutdown: %v", err)
	}
	waitFor(t, func() bool {
		acceptedMu.Lock()
		defer acceptedMu.Unlock()
		receivedMu.Lock()
		defer receivedMu.Unlock()
		for sequence := range acceptedSequences {
			if receivedBySequence[sequence] == 0 {
				return false
			}
		}
		return true
	})
	if err := f2.Close(); err != nil {
		t.Fatalf("Close restarted forwarder: %v", err)
	}
	if got, wantAtLeast := received.Load(), accepted.Load(); got < wantAtLeast {
		t.Fatalf("received %d events, want at least all %d accepted across shutdown replay", got, wantAtLeast)
	}
	acceptedMu.Lock()
	defer acceptedMu.Unlock()
	receivedMu.Lock()
	defer receivedMu.Unlock()
	for sequence := range acceptedSequences {
		if receivedBySequence[sequence] == 0 {
			t.Fatalf("accepted sequence %d was not delivered; received=%v", sequence, receivedBySequence)
		}
	}
}

func TestDeliveryEventIDIsStableForDeduplication(t *testing.T) {
	t.Parallel()

	event := DeliveryEvent{
		Severity:   "warn",
		Type:       "blocked",
		Timestamp:  time.Unix(42, 0).UTC().Format(time.RFC3339Nano),
		InstanceID: "agent-a",
		Fields:     map[string]any{"sequence": 7, "reason": "policy"},
	}
	first, err := deliveryEventID(event)
	if err != nil {
		t.Fatalf("deliveryEventID: %v", err)
	}
	event.ID = "ignored"
	second, err := deliveryEventID(event)
	if err != nil {
		t.Fatalf("deliveryEventID with existing ID: %v", err)
	}
	if first == "" || first != second {
		t.Fatalf("deliveryEventID stability mismatch: first=%q second=%q", first, second)
	}
	event.ID = first
	b, err := json.Marshal(Envelope{Schema: SchemaV1, Event: event})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var envelope Envelope
	if err := decodeEnvelope(strings.NewReader(string(b)), &envelope); err != nil {
		t.Fatalf("decodeEnvelope: %v", err)
	}
	if envelope.Event.ID != event.ID {
		t.Fatalf("decoded event ID = %q, want %q", envelope.Event.ID, event.ID)
	}
}

func TestForwarderRetriesPendingWithoutNewEvent(t *testing.T) {
	t.Parallel()
	received := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	cfg := testConfig(t, "http://api.vendor.example/events")
	cfg.RetryInterval = 20 * time.Millisecond
	var attempts atomic.Int32
	route := routeToServer(t, srv)
	f, err := New(cfg, Options{
		Resolver: &sequenceResolver{answers: [][]string{{testPublicIP}}},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if attempts.Add(1) == 1 {
				return nil, errors.New("temporary outage")
			}
			return route(ctx, network, addr)
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := f.Emit(t.Context(), testEvent(1)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("pending event was not retried")
	}
	waitFor(t, func() bool { return f.Health().Delivered == 1 })
	if f.Health().Delivered != 1 || f.Health().Failed == 0 {
		t.Fatalf("health = %+v", f.Health())
	}
}

func TestForwarderRetriesSpoolAppendWithoutDroppingAcceptedEvent(t *testing.T) {
	t.Parallel()
	received := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received <- struct{}{}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	cfg := testConfig(t, "http://api.vendor.example/events")
	cfg.RetryInterval = 10 * time.Millisecond
	f, err := New(cfg, Options{
		Resolver:      &sequenceResolver{answers: [][]string{{testPublicIP}}},
		DialContext:   routeToServer(t, srv),
		DeferredStart: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	originalAppend := f.appendEvent
	var attempts atomic.Int32
	f.appendEvent = func(event emit.Event) error {
		if attempts.Add(1) == 1 {
			return errors.New("temporary spool failure")
		}
		return originalAppend(event)
	}
	f.Start()
	t.Cleanup(func() { _ = f.Close() })
	if err := f.Emit(t.Context(), testEvent(1)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("accepted event was not delivered after spool recovery")
	}
	waitFor(t, func() bool { return f.Health().Delivered == 1 })
	health := f.Health()
	if health.Failed == 0 || health.Dropped != 0 {
		t.Fatalf("health = %+v, want a recorded failure and no drop", health)
	}
}

func TestNewEnforcesTransportConfidentiality(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		rawURL    string
		allowed   []string
		authToken string
		insecure  bool
		wantErr   string
	}{
		{name: "http remote without flag", rawURL: "http://api.vendor.example/e", allowed: []string{"api.vendor.example"}, wantErr: "allow_insecure_http"},
		{name: "http remote with token even with flag", rawURL: "http://api.vendor.example/e", allowed: []string{"api.vendor.example"}, authToken: "secret", insecure: true, wantErr: "requires an https"},
		{name: "http remote with flag no token ok", rawURL: "http://api.vendor.example/e", allowed: []string{"api.vendor.example"}, insecure: true},
		{name: "http loopback with token ok", rawURL: "http://127.0.0.1/e", allowed: []string{"127.0.0.1"}, authToken: "secret"},
		{name: "https remote with token ok", rawURL: "https://api.vendor.example/e", allowed: []string{"api.vendor.example"}, authToken: "secret"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig(t, tc.rawURL)
			cfg.AllowedHosts = tc.allowed
			cfg.AuthToken = tc.authToken
			cfg.AllowInsecureHTTP = tc.insecure
			f, err := New(cfg, Options{Resolver: &sequenceResolver{answers: [][]string{{testPublicIP}}}})
			if tc.wantErr != "" {
				if err == nil {
					_ = f.Close()
					t.Fatalf("New succeeded, want error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("New error = %q, want contains %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			_ = f.Close()
		})
	}
}

func TestActivationFailureFailsClosedAndIsObservable(t *testing.T) {
	t.Parallel()
	failingDial := func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("no endpoint")
	}
	cfg := testConfig(t, "http://api.vendor.example/events")
	cfg.MinSeverity = emit.SeverityWarn
	first, err := New(cfg, Options{Resolver: &sequenceResolver{answers: [][]string{{testPublicIP}}}, DialContext: failingDial})
	if err != nil {
		t.Fatalf("New first: %v", err)
	}
	// A deferred replacement can be constructed while the old worker holds the
	// spool lock, but Activate must return a stable fail-closed error.
	second, err := New(cfg, Options{
		Resolver: &sequenceResolver{answers: [][]string{{testPublicIP}}}, DialContext: failingDial, DeferredStart: true,
	})
	if err != nil {
		t.Fatalf("New deferred second: %v", err)
	}
	if err := second.Activate(); !errors.Is(err, ErrActivationFailed) {
		t.Fatalf("Activate error = %v, want ErrActivationFailed", err)
	}
	belowThreshold := testEvent(2)
	belowThreshold.Severity = emit.SeverityInfo
	if err := second.Emit(t.Context(), belowThreshold); !errors.Is(err, ErrActivationFailed) {
		t.Fatalf("below-threshold Emit error = %v, want ErrActivationFailed", err)
	}
	health := second.Health()
	if health.Active || !strings.Contains(health.ActivationError, ErrActivationFailed.Error()) {
		t.Fatalf("second health = %+v, want inactive activation failure", health)
	}
	_ = second.Close()

	// The ordinary non-deferred constructor returns the same activation error;
	// it never hands the caller a silently dormant sink.
	if third, thirdErr := New(cfg, Options{Resolver: &sequenceResolver{answers: [][]string{{testPublicIP}}}, DialContext: failingDial}); !errors.Is(thirdErr, ErrActivationFailed) {
		if third != nil {
			_ = third.Close()
		}
		t.Fatalf("New activation error = %v, want ErrActivationFailed", thirdErr)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close first: %v", err)
	}
	// Once the first releases the lock, a fresh forwarder acquires it cleanly.
	fourth, err := New(cfg, Options{Resolver: &sequenceResolver{answers: [][]string{{testPublicIP}}}, DialContext: failingDial})
	if err != nil {
		t.Fatalf("New fourth: %v", err)
	}
	t.Cleanup(func() { _ = fourth.Close() })
	if health := fourth.Health(); !health.Active || health.ActivationError != "" {
		t.Fatalf("fourth forwarder health = %+v, want active", health)
	}
}

func TestForwarderConcurrentEmitActivateClose(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, "http://api.vendor.example/events")
	f, err := New(cfg, Options{
		Resolver:      &sequenceResolver{answers: [][]string{{testPublicIP}}},
		DeferredStart: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("endpoint unavailable")
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = f.Emit(t.Context(), testEvent(n))
		}(i)
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = f.Activate()
	}()
	go func() {
		defer wg.Done()
		_ = f.Close()
	}()
	wg.Wait()
}

func TestForwarderDropsUnencodableEventWithoutBlocking(t *testing.T) {
	t.Parallel()
	delivered := make(chan int, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() { _ = r.Body.Close() }()
		var envelope Envelope
		if err := decodeEnvelope(r.Body, &envelope); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		delivered <- int(envelope.Event.Fields["sequence"].(float64))
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	cfg := testConfig(t, "http://api.vendor.example/events")
	f, err := New(cfg, Options{Resolver: &sequenceResolver{answers: [][]string{{testPublicIP}}}, DialContext: routeToServer(t, srv)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	// A non-finite float can never be JSON-encoded. It must be dropped, not
	// retried forever ahead of every later event.
	bad := emit.Event{Severity: emit.SeverityWarn, Type: "blocked", Timestamp: time.Unix(1, 0).UTC(), InstanceID: "agent-a", Fields: map[string]any{"bad": math.Inf(1)}}
	if err := f.Emit(t.Context(), bad); err != nil {
		t.Fatalf("Emit bad: %v", err)
	}
	if err := f.Emit(t.Context(), testEvent(2)); err != nil {
		t.Fatalf("Emit good: %v", err)
	}
	select {
	case seq := <-delivered:
		if seq != 2 {
			t.Fatalf("delivered sequence %d, want the good event (2)", seq)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("good event was blocked behind the unencodable one")
	}
	waitFor(t, func() bool { return f.Health().Dropped == 1 })
}

func TestForwarderDropsNewEventsWhenSpoolAtCapacity(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t, "http://api.vendor.example/events")
	cfg.MaxSpoolBytes = 150 // room for roughly one record, not two
	f, err := New(cfg, Options{
		Resolver:      &sequenceResolver{answers: [][]string{{testPublicIP}}},
		DeferredStart: true,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("endpoint down")
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	f.Start()
	t.Cleanup(func() { _ = f.Close() })
	for i := 1; i <= 5; i++ {
		if err := f.Emit(t.Context(), testEvent(i)); err != nil {
			t.Fatalf("Emit(%d): %v", i, err)
		}
	}
	waitFor(t, func() bool { return f.Health().Dropped > 0 })
	info, err := os.Stat(cfg.SpoolFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > cfg.MaxSpoolBytes {
		t.Fatalf("spool grew to %d bytes, past the %d cap", info.Size(), cfg.MaxSpoolBytes)
	}
}

func TestForwarderCompactsSpoolAfterFullDelivery(t *testing.T) {
	t.Parallel()
	var delivered atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		delivered.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	cfg := testConfig(t, "http://api.vendor.example/events")
	f, err := New(cfg, Options{Resolver: &sequenceResolver{answers: [][]string{{testPublicIP}}}, DialContext: routeToServer(t, srv)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	for i := 1; i <= 4; i++ {
		if err := f.Emit(t.Context(), testEvent(i)); err != nil {
			t.Fatalf("Emit(%d): %v", i, err)
		}
	}
	waitFor(t, func() bool { return f.Health().Delivered == 4 })
	// After every record is acknowledged the spool is truncated so the file
	// does not grow without bound during healthy operation.
	waitFor(t, func() bool {
		info, statErr := os.Stat(cfg.SpoolFile)
		return statErr == nil && info.Size() == 0
	})
	c, err := loadCursor(cfg.SpoolFile, cfg.CursorFile)
	if err != nil {
		t.Fatalf("loadCursor after compaction: %v", err)
	}
	if c.Offset != 0 {
		t.Fatalf("cursor offset = %d after compaction, want 0", c.Offset)
	}
}

func TestCloseAbortsInFlightDeliveryPromptly(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case entered <- struct{}{}:
		default:
		}
		// Block until the client aborts the request (the behavior under test)
		// or the test releases us, so srv.Close never waits on a stuck handler.
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // LIFO: runs before srv.Close
	cfg := testConfig(t, "http://api.vendor.example/events")
	cfg.Timeout = 30 * time.Second // Close must beat this via cancellation, not timeout
	f, err := New(cfg, Options{Resolver: &sequenceResolver{answers: [][]string{{testPublicIP}}}, DialContext: routeToServer(t, srv)})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := f.Emit(t.Context(), testEvent(1)); err != nil {
		t.Fatalf("Emit: %v", err)
	}
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("delivery did not reach the endpoint")
	}
	done := make(chan struct{})
	go func() {
		_ = f.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close blocked on in-flight delivery instead of cancelling it")
	}
}

func routeToServer(t *testing.T, srv *httptest.Server) func(context.Context, string, string) (net.Conn, error) {
	t.Helper()
	addr := srv.Listener.Addr().String()
	d := &net.Dialer{Timeout: time.Second}
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return d.DialContext(ctx, network, addr)
	}
}

func waitFor(t *testing.T, ok func() bool) {
	t.Helper()
	testwait.For(t, 3*time.Second, ok, "forwarder condition")
}
