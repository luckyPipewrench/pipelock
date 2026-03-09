//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package enterprise

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/edition"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// Compile-time check: *enterpriseEdition implements edition.Edition.
var _ edition.Edition = (*enterpriseEdition)(nil)

func TestNewEdition(t *testing.T) {
	cfg := testConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := NewEdition(cfg, sc)
	if err != nil {
		t.Fatalf("NewEdition: %v", err)
	}
	defer ed.Close()

	// Should resolve to default for anonymous requests.
	r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	ra, id := ed.ResolveAgent(context.Background(), r)
	if id.Profile != edition.ProfileDefault {
		t.Errorf("profile = %q, want %q", id.Profile, edition.ProfileDefault)
	}
	if ra == nil {
		t.Fatal("expected non-nil ResolvedAgent")
	}
}

func TestNewEdition_WithAgents(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"claude-code": {Mode: config.ModeStrict},
	}
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := NewEdition(cfg, sc)
	if err != nil {
		t.Fatalf("NewEdition: %v", err)
	}
	defer ed.Close()

	// Request with matching header.
	r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	r.Header.Set(edition.AgentHeader, "claude-code")
	ra, id := ed.ResolveAgent(context.Background(), r)
	if id.Profile != "claude-code" {
		t.Errorf("profile = %q, want claude-code", id.Profile)
	}
	if ra.Config.Mode != config.ModeStrict {
		t.Errorf("mode = %q, want strict", ra.Config.Mode)
	}
}

func TestEnterpriseEdition_LookupProfile(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"claude-code": {Mode: config.ModeStrict},
	}
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := NewEdition(cfg, sc)
	if err != nil {
		t.Fatal(err)
	}
	defer ed.Close()

	tests := []struct {
		name      string
		profile   string
		wantFound bool
		wantName  string
	}{
		{"empty", "", true, edition.ProfileDefault},
		{"default", edition.ProfileDefault, true, edition.ProfileDefault},
		{"known", "claude-code", true, "claude-code"},
		{"unknown", "unknown-agent", false, edition.ProfileDefault},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ra, found := ed.LookupProfile(tt.profile)
			if found != tt.wantFound {
				t.Errorf("found = %v, want %v", found, tt.wantFound)
			}
			if ra == nil {
				t.Fatal("expected non-nil ResolvedAgent")
			}
			if ra.Name != tt.wantName {
				t.Errorf("name = %q, want %q", ra.Name, tt.wantName)
			}
		})
	}
}

// TestEnterpriseEdition_LookupProfile_DefaultOverride verifies that
// LookupProfile("unknown") returns the _default profile's config (strict),
// not the base config (balanced), when _default is configured.
func TestEnterpriseEdition_LookupProfile_DefaultOverride(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = config.ModeBalanced
	cfg.Agents = map[string]config.AgentProfile{
		"claude-code": {Mode: config.ModeStrict},
		"_default":    {Mode: config.ModeStrict},
	}
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := NewEdition(cfg, sc)
	if err != nil {
		t.Fatal(err)
	}
	defer ed.Close()

	// Unknown name should get _default's strict config, not base balanced.
	ra, found := ed.LookupProfile("unknown-agent")
	if found {
		t.Error("expected found=false for unknown agent")
	}
	if ra == nil {
		t.Fatal("expected non-nil ResolvedAgent")
	}
	if ra.Config.Mode != config.ModeStrict {
		t.Errorf("unknown agent got mode %q, want %q (_default override)", ra.Config.Mode, config.ModeStrict)
	}

	// Empty name should also get _default's strict config.
	ra, found = ed.LookupProfile("")
	if !found {
		t.Error("expected found=true for empty name")
	}
	if ra.Config.Mode != config.ModeStrict {
		t.Errorf("empty name got mode %q, want %q (_default override)", ra.Config.Mode, config.ModeStrict)
	}
}

// TestEnterpriseEdition_LookupProfile_ExpiredKnownProfile verifies the
// combination that the MCP CLI depends on for runtime license expiry:
// LookupProfile returns (fallback, false) for a known-but-expired agent,
// while KnownProfiles still lists the agent name. This is what lets the
// CLI distinguish "truly unknown" from "known but license expired".
func TestEnterpriseEdition_LookupProfile_ExpiredKnownProfile(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"claude-code": {Mode: config.ModeStrict},
	}
	// License expired 1 hour ago. Registry was built with this config,
	// so it has the profile registered but expiry-gated.
	cfg.LicenseExpiresAt = time.Now().Add(-1 * time.Hour).Unix()

	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := NewEdition(cfg, sc)
	if err != nil {
		t.Fatal(err)
	}
	defer ed.Close()

	// LookupProfile should return false (expired) with a fallback.
	ra, found := ed.LookupProfile("claude-code")
	if found {
		t.Error("expected found=false for expired agent profile")
	}
	if ra == nil {
		t.Fatal("expected non-nil ResolvedAgent (fallback)")
	}
	if ra.Name != edition.ProfileDefault {
		t.Errorf("fallback name = %q, want %q", ra.Name, edition.ProfileDefault)
	}

	// KnownProfiles should still list the agent (it's registered, just expired).
	known := ed.KnownProfiles()
	if !known["claude-code"] {
		t.Error("expected claude-code in KnownProfiles() even when expired")
	}
}

func TestEnterpriseEdition_Reload(t *testing.T) {
	cfg := testConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := NewEdition(cfg, sc)
	if err != nil {
		t.Fatal(err)
	}
	defer ed.Close()

	// Reload with new config.
	cfg2 := testConfig()
	cfg2.Agents = map[string]config.AgentProfile{
		"new-agent": {Mode: config.ModeStrict},
	}
	sc2 := scanner.New(cfg2)
	defer sc2.Close()

	ed2, err := ed.Reload(cfg2, sc2)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	defer ed2.Close()

	ra, found := ed2.LookupProfile("new-agent")
	if !found {
		t.Error("expected new-agent to be found after reload")
	}
	if ra.Name != "new-agent" {
		t.Errorf("name = %q, want new-agent", ra.Name)
	}
}

func TestEnterpriseEdition_KnownProfiles(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"claude-code": {Mode: config.ModeStrict},
		"cursor":      {Mode: config.ModeBalanced},
	}
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := NewEdition(cfg, sc)
	if err != nil {
		t.Fatal(err)
	}
	defer ed.Close()

	profiles := ed.KnownProfiles()
	if len(profiles) != 2 {
		t.Fatalf("expected 2 profiles, got %d", len(profiles))
	}
	if !profiles["claude-code"] {
		t.Error("expected claude-code in profiles")
	}
	if !profiles["cursor"] {
		t.Error("expected cursor in profiles")
	}
}

func TestEnterpriseEdition_Ports(t *testing.T) {
	cfg := testConfig()
	cfg.Agents = map[string]config.AgentProfile{
		"claude-code": {Listeners: []string{":9001"}},
	}
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := NewEdition(cfg, sc)
	if err != nil {
		t.Fatal(err)
	}
	defer ed.Close()

	ports := ed.Ports()
	if ports[":9001"] != "claude-code" {
		t.Errorf("port :9001 = %q, want claude-code", ports[":9001"])
	}
}

func TestEnterpriseEdition_Close(t *testing.T) {
	cfg := testConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := NewEdition(cfg, sc)
	if err != nil {
		t.Fatal(err)
	}
	ed.Close()
	ed.Close() // idempotent
}
