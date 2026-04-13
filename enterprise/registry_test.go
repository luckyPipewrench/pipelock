//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enterprise

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	testProfileClaudeCode = "claude-code"
	testProfileDefault    = "_default"
	testProfileOnlyOne    = "only-one"
	testProfileCursor     = "cursor"
	testListenAddr        = ":8889"
	testListenAddr2       = ":8890"
)

func testConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil // disable SSRF checks (no DNS in unit tests)
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	return cfg
}

func TestAgentRegistryLookup(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {Mode: config.ModeStrict},
		testProfileDefault:    {Mode: config.ModeAudit},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	// Known profile.
	agent := reg.Lookup(testProfileClaudeCode)
	if agent.Name != testProfileClaudeCode {
		t.Errorf("name = %q, want %s", agent.Name, testProfileClaudeCode)
	}
	if agent.Config.Mode != config.ModeStrict {
		t.Errorf("mode = %q, want strict", agent.Config.Mode)
	}

	// Unknown agent -> _default.
	agent = reg.Lookup("unknown-agent")
	if agent.Name != testProfileDefault {
		t.Errorf("name = %q, want %s", agent.Name, testProfileDefault)
	}
	if agent.Config.Mode != config.ModeAudit {
		t.Errorf("mode = %q, want audit", agent.Config.Mode)
	}

	// When no _default is configured, fallback uses base config.
	cfg2 := testConfig()
	cfg2.Mode = config.ModeBalanced
	cfg2.Agents = map[string]config.AgentProfile{
		testProfileOnlyOne: {Mode: config.ModeStrict},
	}
	reg2, err := NewAgentRegistry(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	defer reg2.Close()
	fallback := reg2.Lookup("nonexistent")
	if fallback.Config.Mode != config.ModeBalanced {
		t.Errorf("fallback mode = %q, want balanced", fallback.Config.Mode)
	}
}

func TestAgentRegistryPortLookup(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {
			Listeners: []string{testListenAddr},
			Mode:      config.ModeStrict,
		},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	name, ok := reg.ProfileForPort(testListenAddr)
	if !ok {
		t.Fatal("expected port mapping for", testListenAddr)
	}
	if name != testProfileClaudeCode {
		t.Errorf("port profile = %q, want %s", name, testProfileClaudeCode)
	}

	// Unregistered port returns false.
	_, ok = reg.ProfileForPort(":9999")
	if ok {
		t.Error("expected no mapping for unregistered port")
	}
}

func TestAgentRegistryPorts(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {
			Listeners: []string{testListenAddr, testListenAddr2},
			Mode:      config.ModeStrict,
		},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	ports := reg.Ports()
	if len(ports) != 2 {
		t.Fatalf("Ports() = %d entries, want 2", len(ports))
	}
	if ports[testListenAddr] != testProfileClaudeCode {
		t.Errorf("Ports()[%s] = %q, want %s", testListenAddr, ports[testListenAddr], testProfileClaudeCode)
	}
	if ports[testListenAddr2] != testProfileClaudeCode {
		t.Errorf("Ports()[%s] = %q, want %s", testListenAddr2, ports[testListenAddr2], testProfileClaudeCode)
	}

	// Verify the returned map is a copy (mutations don't affect registry).
	ports["injected"] = "bad"
	_, ok := reg.ProfileForPort("injected")
	if ok {
		t.Error("Ports() returned a reference to internal map, not a copy")
	}
}

func TestAgentRegistryNoAgents(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeBalanced
	cfg.Agents = nil

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	agent := reg.Lookup("anything")
	if agent.Name != edition.ProfileDefault {
		t.Errorf("name = %q, want %s", agent.Name, edition.ProfileDefault)
	}
	if agent.Config.Mode != config.ModeBalanced {
		t.Errorf("mode = %q, want balanced", agent.Config.Mode)
	}
	if agent.Scanner == nil {
		t.Error("expected non-nil scanner on fallback agent")
	}

	profiles := reg.Profiles()
	if len(profiles) != 0 {
		t.Errorf("expected 0 profiles, got %d: %v", len(profiles), profiles)
	}
}

func TestAgentRegistryProfiles(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {Mode: config.ModeStrict},
		testProfileCursor:     {Mode: config.ModeBalanced},
		testProfileDefault:    {Mode: config.ModeAudit},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	profiles := reg.Profiles()
	sort.Strings(profiles)
	expected := []string{testProfileDefault, testProfileClaudeCode, testProfileCursor}
	sort.Strings(expected)

	if len(profiles) != len(expected) {
		t.Fatalf("got %d profiles, want %d", len(profiles), len(expected))
	}
	for i, name := range profiles {
		if name != expected[i] {
			t.Errorf("profiles[%d] = %q, want %q", i, name, expected[i])
		}
	}
}

func TestAgentRegistryCloseIdempotent(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {Mode: config.ModeStrict},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}

	reg.Close()
	reg.Close() // should not panic
}

func TestAgentRegistryFallbackScannerNotNil(t *testing.T) {
	cfg := testConfig()

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	agent := reg.Lookup("anything")
	if agent.Scanner == nil {
		t.Error("expected non-nil scanner on fallback")
	}
	if agent.Config == nil {
		t.Error("expected non-nil config on fallback")
	}
}

func TestAgentRegistryFallbackUsesProvidedScanner(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = nil

	baseScanner := scanner.New(cfg)
	defer baseScanner.Close()

	reg, err := NewAgentRegistry(cfg, baseScanner)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	agent := reg.Lookup("anything")
	if agent.Scanner != baseScanner {
		t.Fatal("expected fallback agent to reuse provided base scanner")
	}
}

func TestAgentRegistryDefaultProfileOverridesFallback(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeBalanced
	cfg.Agents = map[string]config.AgentProfile{
		testProfileDefault: {Mode: config.ModeStrict},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	agent := reg.Lookup("nonexistent")
	if agent.Config.Mode != config.ModeStrict {
		t.Errorf("fallback mode = %q, want strict (_default profile should override base)", agent.Config.Mode)
	}
}

func TestAgentRegistryMatchCIDR(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {SourceCIDRs: []string{"10.0.0.0/24"}},
		testProfileCursor:     {SourceCIDRs: []string{"172.16.5.0/24", "192.168.1.0/24"}},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	tests := []struct {
		ip     string
		want   string
		wantOK bool
	}{
		{"10.0.0.42", testProfileClaudeCode, true},
		{"10.0.0.1", testProfileClaudeCode, true},
		{"172.16.5.100", testProfileCursor, true},
		{"192.168.1.1", testProfileCursor, true},
		{"8.8.8.8", "", false},    // no match
		{"10.0.1.1", "", false},   // outside /24
		{"172.16.6.1", "", false}, // wrong subnet
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			if ip == nil {
				t.Fatalf("failed to parse IP %q", tt.ip)
			}
			got, ok := reg.MatchCIDR(ip)
			if ok != tt.wantOK {
				t.Errorf("MatchCIDR(%s) ok = %v, want %v", tt.ip, ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("MatchCIDR(%s) = %q, want %q", tt.ip, got, tt.want)
			}
		})
	}
}

func TestAgentRegistryMatchCIDR_NoCIDRs(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {Mode: config.ModeStrict},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	_, ok := reg.MatchCIDR(net.ParseIP("10.0.0.1"))
	if ok {
		t.Error("expected no match when no CIDRs configured")
	}
}

func TestAgentRegistryLookup_ExpiredLicense(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {Mode: config.ModeStrict},
		testProfileDefault:    {Mode: config.ModeAudit},
	}
	// Simulate a license that expired 1 hour ago.
	cfg.LicenseExpiresAt = time.Now().Add(-1 * time.Hour).Unix()

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	// Non-default profile should fall back when license is expired.
	agent := reg.Lookup(testProfileClaudeCode)
	if agent.Name != testProfileDefault {
		t.Errorf("expired license: got profile %q, want %q (fallback)", agent.Name, testProfileDefault)
	}

	// _default profile should still work.
	agent = reg.Lookup(testProfileDefault)
	if agent.Name != testProfileDefault {
		t.Errorf("_default lookup failed: got %q", agent.Name)
	}
}

func TestAgentRegistryLookup_PerpetualLicense(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {Mode: config.ModeStrict},
	}
	cfg.LicenseExpiresAt = 0

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	agent := reg.Lookup(testProfileClaudeCode)
	if agent.Name != testProfileClaudeCode {
		t.Errorf("perpetual license: got profile %q, want %q", agent.Name, testProfileClaudeCode)
	}
}

func TestAgentRegistryLookupByName(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {Mode: config.ModeStrict},
		testProfileDefault:    {Mode: config.ModeAudit},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	// Known profile.
	ra, found := reg.LookupByName(testProfileClaudeCode)
	if !found {
		t.Error("expected found=true for known profile")
	}
	if ra.Name != testProfileClaudeCode {
		t.Errorf("name = %q, want %q", ra.Name, testProfileClaudeCode)
	}

	// Unknown profile.
	ra, found = reg.LookupByName("unknown")
	if found {
		t.Error("expected found=false for unknown profile")
	}
	if ra.Name != testProfileDefault {
		t.Errorf("fallback name = %q, want %q", ra.Name, testProfileDefault)
	}
}

func TestAgentRegistryLookupByName_ExpiredLicense(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {Mode: config.ModeStrict},
		testProfileDefault:    {Mode: config.ModeAudit},
	}
	// License expired 1 hour ago.
	cfg.LicenseExpiresAt = time.Now().Add(-1 * time.Hour).Unix()

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	// Non-default profile should fall back when license expired.
	ra, found := reg.LookupByName(testProfileClaudeCode)
	if found {
		t.Error("expected found=false for expired non-default profile")
	}
	if ra.Name != testProfileDefault {
		t.Errorf("expired: got %q, want fallback %q", ra.Name, testProfileDefault)
	}

	// _default should still resolve.
	ra, found = reg.LookupByName(testProfileDefault)
	if !found {
		t.Error("expected found=true for _default even with expired license")
	}
	if ra.Name != testProfileDefault {
		t.Errorf("_default: got %q", ra.Name)
	}
}

func TestAgentRegistryResolveFromRequest_ContextOverride(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {Mode: config.ModeStrict},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	ctx := edition.WithAgentOverride(r.Context(), testProfileClaudeCode)
	r = r.WithContext(ctx)

	ra, id := reg.ResolveFromRequest(r.Context(), r, cfg, nil)
	if id.Profile != testProfileClaudeCode {
		t.Errorf("profile = %q, want %q", id.Profile, testProfileClaudeCode)
	}
	if ra.Name != testProfileClaudeCode {
		t.Errorf("name = %q, want %q", ra.Name, testProfileClaudeCode)
	}
}

func TestAgentRegistryResolveFromRequest_CIDR(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {SourceCIDRs: []string{"10.0.0.0/24"}},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	r.RemoteAddr = "10.0.0.42:12345"

	ra, id := reg.ResolveFromRequest(context.Background(), r, cfg, nil)
	if id.Profile != testProfileClaudeCode {
		t.Errorf("profile = %q, want %q", id.Profile, testProfileClaudeCode)
	}
	if ra.Name != testProfileClaudeCode {
		t.Errorf("name = %q, want %q", ra.Name, testProfileClaudeCode)
	}
}

func TestAgentRegistryResolveFromRequest_Header(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {Mode: config.ModeStrict},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	r.Header.Set(edition.AgentHeader, testProfileClaudeCode)

	ra, id := reg.ResolveFromRequest(context.Background(), r, cfg, nil)
	if id.Profile != testProfileClaudeCode {
		t.Errorf("profile = %q, want %q", id.Profile, testProfileClaudeCode)
	}
	if ra.Name != testProfileClaudeCode {
		t.Errorf("name = %q, want %q", ra.Name, testProfileClaudeCode)
	}
}

func TestAgentRegistryResolveFromRequest_Fallback(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {Mode: config.ModeStrict},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	// No override, no CIDR match, no header.

	ra, id := reg.ResolveFromRequest(context.Background(), r, cfg, nil)
	if id.Profile != edition.ProfileDefault {
		t.Errorf("profile = %q, want %q", id.Profile, edition.ProfileDefault)
	}
	if ra.Name != edition.ProfileDefault {
		t.Errorf("name = %q, want %q", ra.Name, edition.ProfileDefault)
	}
}

func TestAgentRegistryNilClose(t *testing.T) {
	var reg *AgentRegistry
	reg.Close() // should not panic
}

func TestAgentRegistryBudgetIntegration(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {
			Mode: config.ModeStrict,
			Budget: config.BudgetConfig{
				MaxRequestsPerSession: 5,
				WindowMinutes:         60,
			},
		},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	agent := reg.Lookup(testProfileClaudeCode)
	if agent.Budget == nil {
		t.Fatal("expected non-nil budget for agent with budget config")
	}

	// Budget should work through the BudgetChecker interface.
	if err := agent.Budget.CheckAdmission("example.com"); err != nil {
		t.Fatalf("first admission should succeed: %v", err)
	}
}

func TestAgentRegistryNoBudget(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		testProfileClaudeCode: {Mode: config.ModeStrict},
	}

	reg, err := NewAgentRegistry(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()

	agent := reg.Lookup(testProfileClaudeCode)
	if agent.Budget != edition.NoopBudget {
		t.Errorf("expected NoopBudget when no budget config, got %T", agent.Budget)
	}
}
