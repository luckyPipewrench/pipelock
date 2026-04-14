// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package edition

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func testConfig() *config.Config {
	cfg := config.Defaults()
	cfg.Internal = nil // disable SSRF checks (no DNS in unit tests)
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	return cfg
}

func TestNoopEdition_ResolveAgent(t *testing.T) {
	cfg := testConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := newNoopEdition(cfg, sc)
	if err != nil {
		t.Fatalf("newNoopEdition: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	resolved, id := ed.ResolveAgent(context.Background(), r)

	if resolved.Name != ProfileDefault {
		t.Errorf("resolved.Name = %q, want %q", resolved.Name, ProfileDefault)
	}
	if resolved.Config != cfg {
		t.Error("resolved.Config does not match")
	}
	if resolved.Scanner != sc {
		t.Error("resolved.Scanner does not match")
	}
	if resolved.Budget != NoopBudget {
		t.Error("resolved.Budget should be NoopBudget for noop")
	}
	if id.Profile != ProfileDefault {
		t.Errorf("id.Profile = %q, want %q", id.Profile, ProfileDefault)
	}
}

func TestNoopEdition_ResolveAgent_DefaultIdentity(t *testing.T) {
	cfg := testConfig()
	cfg.DefaultAgentIdentity = "deployment/my-sidecar"
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := newNoopEdition(cfg, sc)
	if err != nil {
		t.Fatalf("newNoopEdition: %v", err)
	}

	// No header — should resolve to config default identity with config-default auth.
	r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	_, id := ed.ResolveAgent(context.Background(), r)

	if id.Name != "deployment_my-sidecar" {
		t.Errorf("id.Name = %q, want %q", id.Name, "deployment_my-sidecar")
	}
	if id.Profile != ProfileDefault {
		t.Errorf("id.Profile = %q, want %q", id.Profile, ProfileDefault)
	}
	if id.Auth != envelope.ActorAuthConfigDefault {
		t.Errorf("id.Auth = %q, want %q (config-provided default should not be self-declared)",
			id.Auth, envelope.ActorAuthConfigDefault)
	}

	// Header should override config default with self-declared auth.
	r2 := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	r2.Header.Set(AgentHeader, "explicit-agent")
	_, id2 := ed.ResolveAgent(context.Background(), r2)

	if id2.Name != "explicit-agent" {
		t.Errorf("id2.Name = %q, want %q", id2.Name, "explicit-agent")
	}
	if id2.Auth != envelope.ActorAuthSelfDeclared {
		t.Errorf("id2.Auth = %q, want %q", id2.Auth, envelope.ActorAuthSelfDeclared)
	}
}

func TestNoopEdition_LookupProfile(t *testing.T) {
	cfg := testConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := newNoopEdition(cfg, sc)
	if err != nil {
		t.Fatalf("newNoopEdition: %v", err)
	}

	tests := []struct {
		name      string
		profile   string
		wantFound bool
	}{
		{"empty name", "", true},
		{"default profile", ProfileDefault, true},
		{"unknown profile", "custom-agent", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved, found := ed.LookupProfile(tt.profile)
			if found != tt.wantFound {
				t.Errorf("found = %v, want %v", found, tt.wantFound)
			}
			if resolved == nil {
				t.Fatal("resolved should never be nil")
			}
			if resolved.Name != ProfileDefault {
				t.Errorf("resolved.Name = %q, want %q", resolved.Name, ProfileDefault)
			}
		})
	}
}

func TestNoopEdition_Reload(t *testing.T) {
	cfg := testConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := newNoopEdition(cfg, sc)
	if err != nil {
		t.Fatalf("newNoopEdition: %v", err)
	}

	cfg2 := testConfig()
	sc2 := scanner.New(cfg2)
	defer sc2.Close()

	ed2, err := ed.Reload(cfg2, sc2)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}

	resolved, _ := ed2.ResolveAgent(context.Background(), httptest.NewRequest(http.MethodGet, "http://example.com", nil))
	if resolved.Config != cfg2 {
		t.Error("reloaded edition should use new config")
	}
}

func TestNoopEdition_KnownProfiles(t *testing.T) {
	cfg := testConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, _ := newNoopEdition(cfg, sc)
	if profiles := ed.KnownProfiles(); profiles != nil {
		t.Errorf("KnownProfiles = %v, want nil", profiles)
	}
}

func TestNoopEdition_Ports(t *testing.T) {
	cfg := testConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, _ := newNoopEdition(cfg, sc)
	if ports := ed.Ports(); ports != nil {
		t.Errorf("Ports = %v, want nil", ports)
	}
}

func TestNoopEdition_Close(t *testing.T) {
	cfg := testConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, _ := newNoopEdition(cfg, sc)
	ed.Close() // should not panic
	ed.Close() // idempotent
}

func TestNewEditionFunc_Default(t *testing.T) {
	cfg := testConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := NewEditionFunc(cfg, sc)
	if err != nil {
		t.Fatalf("NewEditionFunc: %v", err)
	}
	defer ed.Close()

	// Default should be noop
	if _, ok := ed.(*noopEdition); !ok {
		t.Errorf("default NewEditionFunc should return *noopEdition, got %T", ed)
	}
}

func TestWithAgentOverride(t *testing.T) {
	ctx := context.Background()

	// No override set
	profile, ok := AgentOverrideFromContext(ctx)
	if ok {
		t.Errorf("expected no override, got %q", profile)
	}

	// Set override
	ctx = WithAgentOverride(ctx, "my-agent")
	profile, ok = AgentOverrideFromContext(ctx)
	if !ok {
		t.Fatal("expected override to be set")
	}
	if profile != "my-agent" {
		t.Errorf("profile = %q, want %q", profile, "my-agent")
	}

	// Empty string override should return false
	ctx2 := WithAgentOverride(context.Background(), "")
	_, ok = AgentOverrideFromContext(ctx2)
	if ok {
		t.Error("empty override should return false")
	}
}

func TestExtractAgent(t *testing.T) {
	tests := []struct {
		name   string
		header string
		query  string
		want   string
	}{
		{"no agent", "", "", "anonymous"},
		{"from header", "my-agent", "", "my-agent"},
		{"from query", "", "my-agent", "my-agent"},
		{"header takes priority", "from-header", "from-query", "from-header"},
		{"sanitizes special chars", "my agent!@#", "", "my_agent___"},
		{"truncates long names", strings.Repeat("a", 100), "", strings.Repeat("a", 64)},
		{"all-invalid chars become underscores", "!@#$%", "", "_____"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			if tt.header != "" {
				r.Header.Set(AgentHeader, tt.header)
			}
			if tt.query != "" {
				q := r.URL.Query()
				q.Set("agent", tt.query)
				r.URL.RawQuery = q.Encode()
			}
			got := ExtractAgent(r)
			if got != tt.want {
				t.Errorf("ExtractAgent = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveAgentIdentity(t *testing.T) {
	known := map[string]bool{"agent-a": true, "agent-b": true}

	tests := []struct {
		name        string
		ctxOverride string
		header      string
		query       string
		wantName    string
		wantProfile string
	}{
		{"context override", "agent-a", "", "", "agent-a", "agent-a"},
		{"context override beats header", "agent-a", "agent-b", "", "agent-a", "agent-a"},
		{"known header agent", "", "agent-a", "", "agent-a", "agent-a"},
		{"unknown header agent", "", "unknown", "", "unknown", ProfileDefault},
		{"query param agent", "", "", "agent-b", "agent-b", "agent-b"},
		{"no agent", "", "", "", "", ProfileDefault},
		{"nil knownProfiles", "", "my-agent", "", "my-agent", ProfileDefault},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			if tt.header != "" {
				r.Header.Set(AgentHeader, tt.header)
			}
			if tt.query != "" {
				q := r.URL.Query()
				q.Set("agent", tt.query)
				r.URL.RawQuery = q.Encode()
			}
			ctx := r.Context()
			if tt.ctxOverride != "" {
				ctx = WithAgentOverride(ctx, tt.ctxOverride)
				r = r.WithContext(ctx)
			}

			profiles := known
			if tt.name == "nil knownProfiles" {
				profiles = nil
			}

			id := ResolveAgentIdentity(r, profiles, "", false)
			if id.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", id.Name, tt.wantName)
			}
			if id.Profile != tt.wantProfile {
				t.Errorf("Profile = %q, want %q", id.Profile, tt.wantProfile)
			}
		})
	}
}

func TestResolveAgentIdentity_ActorAuth(t *testing.T) {
	t.Parallel()

	knownProfiles := map[string]bool{"claude-code": true}

	tests := []struct {
		name     string
		setup    func(r *http.Request) *http.Request
		wantAuth envelope.ActorAuth
	}{
		{
			name: "context override is bound",
			setup: func(r *http.Request) *http.Request {
				return r.WithContext(WithAgentOverride(r.Context(), "claude-code"))
			},
			wantAuth: envelope.ActorAuthBound,
		},
		{
			name: "known profile from header is matched",
			setup: func(r *http.Request) *http.Request {
				r.Header.Set(AgentHeader, "claude-code")
				return r
			},
			wantAuth: envelope.ActorAuthMatched,
		},
		{
			name: "unknown name from header is self-declared",
			setup: func(r *http.Request) *http.Request {
				r.Header.Set(AgentHeader, "unknown-agent")
				return r
			},
			wantAuth: envelope.ActorAuthSelfDeclared,
		},
		{
			name: "no header is self-declared",
			setup: func(r *http.Request) *http.Request {
				return r
			},
			wantAuth: envelope.ActorAuthSelfDeclared,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			r = tt.setup(r)
			id := ResolveAgentIdentity(r, knownProfiles, "", false)
			if id.Auth != tt.wantAuth {
				t.Errorf("Auth = %q, want %q", id.Auth, tt.wantAuth)
			}
		})
	}
}

func TestExtractAgentWithDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		header          string
		query           string
		defaultIdentity string
		bind            bool
		want            string
	}{
		{"no agent no default", "", "", "", false, "anonymous"},
		{"no agent with default", "", "", "deployment/my-app", false, "deployment_my-app"},
		{"header overrides default", "from-header", "", "deployment/my-app", false, "from-header"},
		{"default overrides query", "", "from-query", "deployment/my-app", false, "deployment_my-app"},
		{"header overrides query and default", "from-header", "from-query", "deployment/my-app", false, "from-header"},
		{"default sanitized", "", "", "bad agent!@#", false, "bad_agent___"},
		{"empty default same as anonymous", "", "", "", false, "anonymous"},
		{"bind ignores header and query", "from-header", "from-query", "deployment/my-app", true, "deployment_my-app"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			if tt.header != "" {
				r.Header.Set(AgentHeader, tt.header)
			}
			if tt.query != "" {
				q := r.URL.Query()
				q.Set("agent", tt.query)
				r.URL.RawQuery = q.Encode()
			}
			got := ExtractAgentWithDefault(r, tt.defaultIdentity, tt.bind)
			if got != tt.want {
				t.Errorf("ExtractAgentWithDefault = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveAgentIdentity_DefaultIdentity(t *testing.T) {
	t.Parallel()

	known := map[string]bool{"agent-a": true}

	tests := []struct {
		name            string
		header          string
		query           string
		defaultIdentity string
		wantName        string
		wantProfile     string
	}{
		{
			name:            "no header, no default falls to anonymous",
			defaultIdentity: "",
			wantName:        "",
			wantProfile:     ProfileDefault,
		},
		{
			name:            "no header, default identity used",
			defaultIdentity: "deployment/my-app",
			wantName:        "deployment_my-app",
			wantProfile:     ProfileDefault,
		},
		{
			name:            "header overrides default identity",
			header:          "agent-a",
			defaultIdentity: "deployment/my-app",
			wantName:        "agent-a",
			wantProfile:     "agent-a",
		},
		{
			name:            "default identity overrides query param",
			query:           "agent-a",
			defaultIdentity: "deployment/my-app",
			wantName:        "deployment_my-app",
			wantProfile:     ProfileDefault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			if tt.header != "" {
				r.Header.Set(AgentHeader, tt.header)
			}
			if tt.query != "" {
				q := r.URL.Query()
				q.Set("agent", tt.query)
				r.URL.RawQuery = q.Encode()
			}
			id := ResolveAgentIdentity(r, known, tt.defaultIdentity, false)
			if id.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", id.Name, tt.wantName)
			}
			if id.Profile != tt.wantProfile {
				t.Errorf("Profile = %q, want %q", id.Profile, tt.wantProfile)
			}
		})
	}
}

func TestResolveAgentIdentity_BindDefaultIdentity(t *testing.T) {
	t.Parallel()

	known := map[string]bool{"agent-a": true}
	r := httptest.NewRequest(http.MethodGet, "http://example.com?agent=agent-a", nil)
	r.Header.Set(AgentHeader, "spoofed-header")

	id := ResolveAgentIdentity(r, known, "deployment/my-app", true)
	if id.Name != "deployment_my-app" {
		t.Errorf("Name = %q, want %q", id.Name, "deployment_my-app")
	}
	if id.Profile != ProfileDefault {
		t.Errorf("Profile = %q, want %q", id.Profile, ProfileDefault)
	}
	if id.Auth != envelope.ActorAuthConfigDefault {
		t.Errorf("Auth = %q, want %q", id.Auth, envelope.ActorAuthConfigDefault)
	}
}

func TestNoopEdition_ResolveAgent_BindDefaultIdentity(t *testing.T) {
	cfg := testConfig()
	cfg.DefaultAgentIdentity = "deployment/my-sidecar"
	cfg.BindDefaultAgentIdentity = true
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := newNoopEdition(cfg, sc)
	if err != nil {
		t.Fatalf("newNoopEdition: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "http://example.com?agent=query-agent", nil)
	r.Header.Set(AgentHeader, "header-agent")
	_, id := ed.ResolveAgent(context.Background(), r)

	if id.Name != "deployment_my-sidecar" {
		t.Errorf("id.Name = %q, want %q", id.Name, "deployment_my-sidecar")
	}
	if id.Profile != ProfileDefault {
		t.Errorf("id.Profile = %q, want %q", id.Profile, ProfileDefault)
	}
	if id.Auth != envelope.ActorAuthConfigDefault {
		t.Errorf("id.Auth = %q, want %q", id.Auth, envelope.ActorAuthConfigDefault)
	}
}

func TestNoopBudget(t *testing.T) {
	b := NoopBudget

	if err := b.CheckAdmission("example.com"); err != nil {
		t.Errorf("CheckAdmission error = %v, want nil", err)
	}
	if err := b.RecordBytes(1024); err != nil {
		t.Errorf("RecordBytes error = %v, want nil", err)
	}
	if err := b.RecordRequest("example.com", 512); err != nil {
		t.Errorf("RecordRequest error = %v, want nil", err)
	}
	if remaining := b.RemainingBytes(); remaining != -1 {
		t.Errorf("RemainingBytes = %d, want -1 (unlimited)", remaining)
	}
}

func TestValidateAgentName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"valid simple", "claude-code", false},
		{"valid with dots", "agent.v2", false},
		{"valid with underscore", "my_agent", false},
		{"empty", "", true},
		{"reserved anonymous", "anonymous", true},
		{"spaces", "my agent", true},
		{"special chars", "agent!@#", true},
		{"too long", strings.Repeat("a", 65), true},
		{"max length", strings.Repeat("a", 64), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAgentName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAgentName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
		})
	}
}

func TestResetHooks(t *testing.T) {
	// Set hooks to non-default values
	config.ValidateAgentsFunc = func(_ *config.Config) error { return nil }
	config.EnforceLicenseGateFunc = func(_ *config.Config) {}
	config.MergeAgentProfileFunc = func(_ *config.Config, _ *config.AgentProfile) (*config.Config, error) { return nil, nil }

	ResetHooks()

	if config.ValidateAgentsFunc != nil {
		t.Error("ValidateAgentsFunc should be nil after reset")
	}
	if config.EnforceLicenseGateFunc != nil {
		t.Error("EnforceLicenseGateFunc should be nil after reset")
	}
	if config.MergeAgentProfileFunc != nil {
		t.Error("MergeAgentProfileFunc should be nil after reset")
	}

	// Verify NewEditionFunc returns noop
	cfg := testConfig()
	sc := scanner.New(cfg)
	defer sc.Close()

	ed, err := NewEditionFunc(cfg, sc)
	if err != nil {
		t.Fatalf("NewEditionFunc after reset: %v", err)
	}
	defer ed.Close()
	if _, ok := ed.(*noopEdition); !ok {
		t.Errorf("NewEditionFunc after reset should return *noopEdition, got %T", ed)
	}
}
