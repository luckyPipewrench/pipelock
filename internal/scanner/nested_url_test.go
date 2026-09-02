// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	nestedURLOuterHost    = "https://mirror.vendor.example/pkg"
	nestedURLMetadataPath = "http://169.254.169.254/latest/meta-data/"
	nestedURLPrivatePath  = "http://10.0.0.12:8500/v1/kv/x"
	nestedURLPublicHost   = "https://app.example.com/cb"
)

func nestedURLConfig() *config.Config {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.EntropyThreshold = 8.0
	cfg.FetchProxy.Monitoring.MaxURLLength = 4096
	cfg.DLP.Patterns = nil
	return cfg
}

func nestedURLSSRFConfig() *config.Config {
	cfg := nestedURLConfig()
	// Non-empty Internal activates checkSSRF (and skips the core-literal
	// safety net). Core CIDRs are merged, so metadata/private literals still
	// block, and the scanner label is the production SSRF/metadata label.
	cfg.Internal = []string{"203.0.113.0/24"}
	cfg.SSRF.IPAllowlist = nil
	return cfg
}

func scanNested(t *testing.T, cfg *config.Config, raw string) Result {
	t.Helper()
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	s.resolver = failOnLookupResolver{t: t}
	return s.Scan(context.Background(), raw)
}

func TestScan_NestedURLDestinations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cfg         func() *config.Config
		raw         string
		wantAllow   bool
		wantScanner string
		wantReason  string
	}{
		{
			name:        "nested metadata literal",
			cfg:         nestedURLSSRFConfig,
			raw:         nestedURLOuterHost + "?target=" + nestedURLMetadataPath,
			wantScanner: ScannerSSRFMetadata,
			wantReason:  nestedURLReasonPrefix,
		},
		{
			name:        "nested RFC1918 literal",
			cfg:         nestedURLSSRFConfig,
			raw:         nestedURLOuterHost + "?url=" + nestedURLPrivatePath,
			wantScanner: ScannerSSRF,
			wantReason:  nestedURLReasonPrefix,
		},
		{
			name:        "nested hex loopback",
			cfg:         nestedURLSSRFConfig,
			raw:         nestedURLOuterHost + "?u=http://0x7f000001/",
			wantScanner: ScannerSSRF,
			wantReason:  nestedURLReasonPrefix,
		},
		{
			name:        "nested decimal loopback",
			cfg:         nestedURLSSRFConfig,
			raw:         nestedURLOuterHost + "?u=http://2130706433/",
			wantScanner: ScannerSSRF,
			wantReason:  nestedURLReasonPrefix,
		},
		{
			name:        "nested ipv4-mapped loopback",
			cfg:         nestedURLSSRFConfig,
			raw:         nestedURLOuterHost + "?u=http://[::ffff:127.0.0.1]/",
			wantScanner: ScannerSSRF,
			wantReason:  nestedURLReasonPrefix,
		},
		{
			name:        "nested percent-encoded once",
			cfg:         nestedURLSSRFConfig,
			raw:         nestedURLOuterHost + "?u=http%3A%2F%2F169.254.169.254%2F",
			wantScanner: ScannerSSRFMetadata,
			wantReason:  nestedURLReasonPrefix,
		},
		{
			name:        "nested percent-encoded twice",
			cfg:         nestedURLSSRFConfig,
			raw:         nestedURLOuterHost + "?u=http%253A%252F%252F169.254.169.254%252F",
			wantScanner: ScannerSSRFMetadata,
			wantReason:  nestedURLReasonPrefix,
		},
		{
			name: "nested blocklisted host",
			cfg: func() *config.Config {
				cfg := nestedURLConfig()
				cfg.FetchProxy.Monitoring.Blocklist = []string{"blocked.vendor.example"}
				return cfg
			},
			raw:         nestedURLOuterHost + "?u=https://blocked.vendor.example/pkg",
			wantScanner: ScannerBlocklist,
			wantReason:  nestedURLReasonPrefix,
		},
		{
			name:      "nested public host allowed",
			cfg:       nestedURLConfig,
			raw:       nestedURLOuterHost + "?redirect_uri=" + nestedURLPublicHost,
			wantAllow: true,
		},
		{
			name:      "nested bare word ignored",
			cfg:       nestedURLConfig,
			raw:       nestedURLOuterHost + "?q=hello",
			wantAllow: true,
		},
		{
			name:      "nested relative path ignored",
			cfg:       nestedURLConfig,
			raw:       nestedURLOuterHost + "?path=/a/b",
			wantAllow: true,
		},
		{
			name:      "nested mailto ignored",
			cfg:       nestedURLConfig,
			raw:       nestedURLOuterHost + "?u=mailto:x@y",
			wantAllow: true,
		},
		{
			name:      "nested data URI ignored",
			cfg:       nestedURLConfig,
			raw:       nestedURLOuterHost + "?u=data:text/plain,x",
			wantAllow: true,
		},
		{
			name: "scan_nested_urls false allows metadata",
			cfg: func() *config.Config {
				cfg := nestedURLConfig()
				disabled := false
				cfg.FetchProxy.Monitoring.ScanNestedURLs = &disabled
				return cfg
			},
			raw:       nestedURLOuterHost + "?target=" + nestedURLMetadataPath,
			wantAllow: true,
		},
		{
			name: "strict mode nested host not on allowlist",
			cfg: func() *config.Config {
				cfg := nestedURLConfig()
				cfg.Mode = config.ModeStrict
				cfg.APIAllowlist = []string{"mirror.vendor.example"}
				return cfg
			},
			raw:         nestedURLOuterHost + "?redirect_uri=" + nestedURLPublicHost,
			wantScanner: ScannerAllowlist,
			wantReason:  nestedURLReasonPrefix,
		},
		{
			name: "strict mode nested host on allowlist",
			cfg: func() *config.Config {
				cfg := nestedURLConfig()
				cfg.Mode = config.ModeStrict
				cfg.APIAllowlist = []string{"mirror.vendor.example", "app.example.com"}
				return cfg
			},
			raw:       nestedURLOuterHost + "?redirect_uri=" + nestedURLPublicHost,
			wantAllow: true,
		},
		{
			name: "ssrf ip_allowlist covers nested private IP",
			cfg: func() *config.Config {
				cfg := nestedURLConfig()
				cfg.SSRF.IPAllowlist = []string{"10.0.0.12/32"}
				return cfg
			},
			raw:       nestedURLOuterHost + "?url=" + nestedURLPrivatePath,
			wantAllow: true,
		},
		{
			name: "one-level nesting is not expanded",
			cfg:  nestedURLConfig,
			raw: nestedURLOuterHost + "?u=" + url.QueryEscape(
				nestedURLPublicHost+"?target="+nestedURLMetadataPath,
			),
			wantAllow: true,
		},
		{
			name:      "nested bad port is not a URL",
			cfg:       nestedURLConfig,
			raw:       nestedURLOuterHost + "?u=http://app.example.com:99999/",
			wantAllow: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := scanNested(t, tt.cfg(), tt.raw)
			if tt.wantAllow {
				if !result.Allowed {
					t.Fatalf("allowed=false scanner=%s reason=%s", result.Scanner, result.Reason)
				}
				return
			}
			if result.Allowed {
				t.Fatal("expected block")
			}
			if result.Scanner != tt.wantScanner {
				t.Fatalf("scanner=%s want %s reason=%s", result.Scanner, tt.wantScanner, result.Reason)
			}
			if !strings.Contains(result.Reason, tt.wantReason) {
				t.Fatalf("reason=%q want substring %q", result.Reason, tt.wantReason)
			}
			if result.Score != 1.0 {
				t.Fatalf("score=%v want 1.0", result.Score)
			}
		})
	}
}

// setNestedURLResolveBudgetForTest shrinks the shared nested-DNS budget so a
// test can exhaust it without waiting on the production ceiling.
func setNestedURLResolveBudgetForTest(t *testing.T, d time.Duration) {
	t.Helper()
	prev := nestedURLResolveBudget
	nestedURLResolveBudget = d
	t.Cleanup(func() { nestedURLResolveBudget = prev })
}

// blockingResolver never answers; it returns only when the caller's context
// ends, which is how a stalled resolver behaves against a real request.
type blockingResolver struct{}

func (blockingResolver) LookupHost(ctx context.Context, _ string) ([]string, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// A count cap was a fail-open: pad past it, then relay. There is no count cap.
// The metadata URL must block wherever it sits in the query string.
func TestScan_NestedURLNoCountCap(t *testing.T) {
	t.Parallel()
	cfg := nestedURLConfig()
	for _, position := range []int{0, 31, 32, 39} {
		t.Run(fmt.Sprintf("metadata_at_index_%d_of_40", position), func(t *testing.T) {
			t.Parallel()
			var b strings.Builder
			b.WriteString(nestedURLOuterHost)
			b.WriteByte('?')
			for i := range 40 {
				if i > 0 {
					b.WriteByte('&')
				}
				fmt.Fprintf(&b, "n%02d=", i)
				if i == position {
					b.WriteString(url.QueryEscape(nestedURLMetadataPath))
				} else {
					b.WriteByte('x')
				}
			}
			result := scanNested(t, cfg, b.String())
			if result.Allowed {
				t.Fatalf("metadata URL at index %d was allowed; a positional gap is a fail-open", position)
			}
			if !strings.Contains(result.Reason, nestedURLReasonPrefix) {
				t.Fatalf("reason %q does not name the nested parameter", result.Reason)
			}
		})
	}
}

// Exhausting the shared resolution budget must refuse the request, never
// forward it with nested destinations left unverified.
func TestScan_NestedURLResolveBudgetExhaustionFailsClosed(t *testing.T) {
	setNestedURLResolveBudgetForTest(t, 50*time.Millisecond)
	cfg := nestedURLSSRFConfig()
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	s.resolver = blockingResolver{}
	raw := nestedURLOuterHost + "?a=" + url.QueryEscape("https://one.example.net/") +
		"&b=" + url.QueryEscape("https://two.example.net/") +
		"&c=" + url.QueryEscape("https://three.example.net/")
	result := s.Scan(context.Background(), raw)
	if result.Allowed {
		t.Fatal("budget exhaustion allowed the request; nested destinations were never verified")
	}
	if !strings.Contains(result.Reason, "shared resolution budget") {
		t.Fatalf("reason %q does not name the exhausted budget", result.Reason)
	}
	if result.Scanner != ScannerSSRF {
		t.Fatalf("scanner = %q, want %q", result.Scanner, ScannerSSRF)
	}
}

// Decoding parity with the DLP query loop: keys as well as values, hex and
// base64 layers, scheme-relative references, IPv6 zone ids, and stray
// whitespace must all reach the destination checks.
func TestScan_NestedURLDecodingParity(t *testing.T) {
	t.Parallel()
	cfg := nestedURLConfig()
	// testConfig allowlists 127.0.0.0/8 and ::1/128 as an operator override, and
	// the nested path consults that allowlist exactly as the outer path does.
	// Clear it so these rows measure decoding parity rather than the override.
	cfg.SSRF.IPAllowlist = nil
	meta := nestedURLMetadataPath
	cases := []struct {
		name string
		raw  string
	}{
		{"url_in_key", nestedURLOuterHost + "?" + url.QueryEscape(meta) + "=x"},
		{"base64_value", nestedURLOuterHost + "?u=" + base64.StdEncoding.EncodeToString([]byte(meta))},
		{"hex_value", nestedURLOuterHost + "?u=" + hex.EncodeToString([]byte(meta))},
		{"scheme_relative", nestedURLOuterHost + "?u=" + url.QueryEscape("//169.254.169.254/latest/")},
		{"leading_space", nestedURLOuterHost + "?u=" + url.QueryEscape("  "+meta)},
		{"ipv6_zone_id", nestedURLOuterHost + "?u=http://[fe80::1%25eth0]/"},
		{"ipv6_loopback", nestedURLOuterHost + "?u=" + url.QueryEscape("http://[::1]/")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := scanNested(t, cfg, tc.raw)
			if result.Allowed {
				t.Fatalf("%s: nested private destination was allowed", tc.name)
			}
		})
	}
}

func TestCheckNestedURLs_SkipsOversizeValues(t *testing.T) {
	t.Parallel()
	cfg := nestedURLConfig()
	s := MustNew(cfg)
	defer s.Close()
	s.maxURLLength = 16
	parsed, err := url.Parse(nestedURLOuterHost + "?target=" + nestedURLMetadataPath)
	if err != nil {
		t.Fatal(err)
	}
	result := s.checkNestedURLs(context.Background(), parsed)
	if !result.Allowed {
		t.Fatalf("oversize nested value should be skipped, got %s", result.Reason)
	}
}

func TestCheckNestedURLs_NilAndEmpty(t *testing.T) {
	t.Parallel()
	cfg := nestedURLConfig()
	s := MustNew(cfg)
	defer s.Close()
	if result := s.checkNestedURLs(context.Background(), nil); !result.Allowed {
		t.Fatalf("nil parsed URL: %s", result.Reason)
	}
	parsed, err := url.Parse("https://mirror.vendor.example/pkg")
	if err != nil {
		t.Fatal(err)
	}
	if result := s.checkNestedURLs(context.Background(), parsed); !result.Allowed {
		t.Fatalf("empty query: %s", result.Reason)
	}
}

func TestOperatorHintForNestedURLNamesConsultedKnob(t *testing.T) {
	t.Parallel()
	ssrfHint := OperatorHintForResult(ScannerSSRF, nestedURLReasonPrefix+` "url": SSRF blocked: 10.0.0.12 is an internal IP`)
	for _, want := range []string{
		"fetch_proxy.monitoring.scan_nested_urls",
		"ssrf.ip_allowlist",
		"trusted_domains",
		"dns.host_overrides",
	} {
		if !strings.Contains(ssrfHint, want) {
			t.Fatalf("SSRF nested hint missing %q: %s", want, ssrfHint)
		}
	}

	metaHint := OperatorHintForResult(ScannerSSRFMetadata, nestedURLReasonPrefix+` "target": SSRF blocked: 169.254.169.254 is a cloud metadata endpoint`)
	if !strings.Contains(metaHint, "fetch_proxy.monitoring.scan_nested_urls") {
		t.Fatalf("metadata nested hint missing scan_nested_urls: %s", metaHint)
	}
	if !strings.Contains(metaHint, "no allow knob") {
		t.Fatalf("metadata nested hint must keep the non-overridable wording: %s", metaHint)
	}

	blockHint := OperatorHintForResult(ScannerBlocklist, nestedURLReasonPrefix+` "u": domain blocked: blocked.vendor.example matches blocked.vendor.example`)
	if !strings.Contains(blockHint, "fetch_proxy.monitoring.scan_nested_urls") {
		t.Fatalf("blocklist nested hint missing scan_nested_urls: %s", blockHint)
	}
	if !strings.Contains(blockHint, "blocklist") {
		t.Fatalf("blocklist nested hint missing inner knob: %s", blockHint)
	}
}

// Round 2 finding 1: budget exhaustion is a resolver-availability condition, not
// evidence of an adversary. Classifying it as a threat would let resolver wobble
// accumulate adaptive-enforcement signal until a session is locked down, which is
// the same defect checkSSRF already avoids for the outer host.
func TestScan_NestedURLBudgetExhaustionIsInfrastructureNotThreat(t *testing.T) {
	setNestedURLResolveBudgetForTest(t, 50*time.Millisecond)
	cfg := nestedURLSSRFConfig()
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	s.resolver = blockingResolver{}
	raw := nestedURLOuterHost + "?a=" + url.QueryEscape("https://one.example.net/") +
		"&b=" + url.QueryEscape("https://two.example.net/")
	result := s.Scan(context.Background(), raw)
	if result.Allowed {
		t.Fatal("budget exhaustion allowed the request")
	}
	if result.Class != ClassInfrastructureError {
		t.Fatalf("class = %v, want ClassInfrastructureError: a timeout resolved no destination and is not threat evidence", result.Class)
	}
	if !result.IsAdaptiveNeutral() {
		t.Fatal("budget exhaustion must be adaptive-neutral so resolver wobble cannot drive lockdown")
	}
	// result.Hint is the AGENT surface and must stay terse: no knob, no path.
	for _, knob := range []string{"ip_allowlist", "scan_nested_urls", "config"} {
		if strings.Contains(result.Hint, knob) {
			t.Fatalf("agent hint leaks remediation %q: %q", knob, result.Hint)
		}
	}
	// The operator surface is where the budget is explained, and it must not
	// name an allowlist: no allowlist entry makes a resolver answer faster.
	op := OperatorHintForResult(result.Scanner, result.Reason)
	if strings.Contains(op, "ip_allowlist") {
		t.Fatalf("operator hint names an inert control for a timeout: %q", op)
	}
	if !strings.Contains(op, "resolution budget") {
		t.Fatalf("operator hint does not name the budget: %q", op)
	}
}

// Round 2 finding 2: one verdict per distinct destination. The same callback URL
// repeated across parameters is one destination and must cost one lookup.
func TestScan_NestedURLDeduplicatesDestinations(t *testing.T) {
	t.Parallel()
	cfg := nestedURLSSRFConfig()
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	counting := &countingResolver{hosts: map[string][]string{
		"mirror.vendor.example": {"93.184.216.34"},
		"app.example.com":       {"93.184.216.34"},
	}}
	s.resolver = counting
	var b strings.Builder
	b.WriteString(nestedURLOuterHost)
	for i := range 10 {
		fmt.Fprintf(&b, "%cu%d=%s", map[bool]rune{true: '?', false: '&'}[i == 0], i,
			url.QueryEscape("https://app.example.com/cb"))
	}
	result := s.Scan(context.Background(), b.String())
	if !result.Allowed {
		t.Fatalf("ten copies of one public callback were refused: %s", result.Reason)
	}
	if got := counting.count("app.example.com"); got != 1 {
		t.Fatalf("lookups for the repeated host = %d, want 1", got)
	}
}

// Round 3 finding 1: deciding what is NOT a destination is an allow gate, and the
// round-2 shape rule ("ASCII dot or IP literal") was a detection hole. Every
// single-label internal name and every non-ASCII-dot spelling walked through it.
// The gate is now the same parser the destination checks use.
func TestScan_NestedURLSchemeRelativeFollowsTheParser(t *testing.T) {
	t.Parallel()
	cfg := nestedURLSSRFConfig()
	for _, tc := range []struct {
		name        string
		value       string
		wantAllowed bool
	}{
		{"single label resolves to loopback", "//localhost/admin", false},
		{"single label with port", "//localhost:8080/", false},
		{"single label with userinfo", "//user@localhost/", false},
		{"metadata literal", "//169.254.169.254/latest/", false},
		{"metadata literal without trailing slash", "//169.254.169.254", false},
		{"alt-form literal", "//0x7f000001/", false},
		{"bracketed ipv6", "//[::1]/", false},
		{"unresolvable single label is still a destination", "//tmp/x", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw := nestedURLOuterHost + "?u=" + url.QueryEscape(tc.value)
			result := scanNestedWith(t, cfg, raw, &countingResolver{hosts: map[string][]string{
				"mirror.vendor.example": {"93.184.216.34"},
				"localhost":             {"127.0.0.1"},
			}})
			if result.Allowed != tc.wantAllowed {
				t.Fatalf("%s: allowed = %v, want %v (reason %q)", tc.name, result.Allowed, tc.wantAllowed, result.Reason)
			}
		})
	}
}

// Round 2 finding 4: the query key is attacker-chosen and must not steer operator
// guidance. A parameter named "metadata" must not turn a private-IP block into the
// immutable cloud-metadata explanation that says there is no allow knob.
func TestGuidanceForNestedResultRoutesOnInnerReason(t *testing.T) {
	t.Parallel()
	private := Result{
		Allowed: false,
		Reason:  "SSRF blocked: 10.0.0.12 is an internal IP",
		Scanner: ScannerSSRF,
	}
	hostile := prefixNestedURLResult("metadata", private)
	g, ok := GuidanceForResult(hostile.Scanner, hostile.Reason)
	if !ok {
		t.Fatal("no guidance for a nested SSRF block")
	}
	if g.Immutable {
		t.Fatalf("a parameter named %q routed a private-IP block to immutable metadata guidance: %q", "metadata", g.OperatorKnob)
	}
	genuine := prefixNestedURLResult("target", Result{
		Allowed: false,
		Reason:  "SSRF blocked: 169.254.169.254 is a cloud metadata endpoint",
		Scanner: ScannerSSRF,
	})
	gm, ok := GuidanceForResult(genuine.Scanner, genuine.Reason)
	if !ok || !gm.Immutable {
		t.Fatalf("a genuine nested metadata block lost its immutable guidance: ok=%v immutable=%v", ok, gm.Immutable)
	}
}

// Coverage for the early returns in the nested path: a query with no candidate,
// a parsed URL with no host, and an alternative-form literal carrying a port.
func TestScan_NestedURLEdgeShapes(t *testing.T) {
	t.Parallel()
	cfg := nestedURLConfig()
	cfg.SSRF.IPAllowlist = nil
	for _, tc := range []struct {
		name        string
		raw         string
		wantAllowed bool
	}{
		{"query with no url-shaped candidate", nestedURLOuterHost + "?a=1&b=2", true},
		{"scheme without host", nestedURLOuterHost + "?u=" + url.QueryEscape("http:///etc/passwd"), true},
		{"alt-form literal with port", nestedURLOuterHost + "?u=" + url.QueryEscape("http://0x7f000001:8080/"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			result := scanNested(t, cfg, tc.raw)
			if result.Allowed != tc.wantAllowed {
				t.Fatalf("%s: allowed = %v, want %v (scanner %s reason %q)", tc.name, result.Allowed, tc.wantAllowed, result.Scanner, result.Reason)
			}
		})
	}
}

// countingResolver records how many times each host was looked up.
type countingResolver struct {
	mu    sync.Mutex
	hosts map[string][]string
	seen  map[string]int
}

func (c *countingResolver) LookupHost(_ context.Context, host string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]int{}
	}
	c.seen[host]++
	if ips, ok := c.hosts[host]; ok {
		return ips, nil
	}
	return nil, errors.New("no such host")
}

func (c *countingResolver) count(host string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.seen[host]
}

func scanNestedWith(t *testing.T, cfg *config.Config, raw string, r Resolver) Result {
	t.Helper()
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	s.resolver = r
	return s.Scan(context.Background(), raw)
}

// Round 3 finding 2 and 3: audit and explain do not read result.Hint. They call
// GuidanceForResult(scanner, reason). A timeout must not be explained with an
// allowlist on either surface, and the agent-facing hint must stay terse.
func TestGuidanceForNestedBudgetNamesNoAllowlist(t *testing.T) {
	t.Parallel()
	reason := "nested URL destinations exceeded the shared resolution budget (5s)"
	g, ok := GuidanceForResult(ScannerSSRF, reason)
	if !ok {
		t.Fatal("no guidance for a nested budget block")
	}
	for _, inert := range []string{"ip_allowlist", "trusted_domains", "dns.host_overrides"} {
		if strings.Contains(g.OperatorKnob, inert) {
			t.Fatalf("operator guidance names %q, which cannot lift a resolver timeout: %q", inert, g.OperatorKnob)
		}
	}
	if !strings.Contains(g.OperatorKnob, "scan_nested_urls") {
		t.Fatalf("operator guidance does not name the control that governs this check: %q", g.OperatorKnob)
	}
	// The agent-facing reason must not hand the agent a remediation knob.
	for _, knob := range []string{"scan_nested_urls", "ip_allowlist", "config", "set "} {
		if strings.Contains(g.AgentReason, knob) {
			t.Fatalf("agent reason leaks remediation %q: %q", knob, g.AgentReason)
		}
	}
	if got := OperatorHintForResult(ScannerSSRF, reason); strings.Contains(got, "ip_allowlist") {
		t.Fatalf("operator hint surface still names an inert control: %q", got)
	}
}

// Round 3 finding 4: a nested-resolution timeout is adaptive-neutral, so it must
// not be able to run BEFORE the no-I/O content scanners. If it did, a request
// carrying a credential plus several slow nested hostnames would return the
// timeout, the DLP finding would never reach audit, and nothing would be
// recorded against the session.
func TestScan_NestedURLCannotMaskCredentialFindings(t *testing.T) {
	setNestedURLResolveBudgetForTest(t, 30*time.Millisecond)
	cfg := nestedURLSSRFConfig()
	cfg.DLP = config.Defaults().DLP
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	s.resolver = blockingResolver{}
	raw := nestedURLOuterHost + "?key=" + url.QueryEscape("AKIA"+"IOSFODNN7EXAMPLE") +
		"&a=" + url.QueryEscape("https://one.example.net/") +
		"&b=" + url.QueryEscape("https://two.example.net/")
	result := s.Scan(context.Background(), raw)
	if result.Allowed {
		t.Fatal("credential in the query was allowed")
	}
	if strings.Contains(result.Reason, "shared resolution budget") {
		t.Fatalf("a nested resolution timeout preempted the credential finding: %q", result.Reason)
	}
	if result.IsAdaptiveNeutral() {
		t.Fatalf("a credential block was reported as adaptive-neutral: scanner=%s reason=%q", result.Scanner, result.Reason)
	}
}
