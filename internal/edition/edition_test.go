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
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	ed, err := newNoopEdition(cfg, sc)
	if err != nil {
		t.Fatalf("newNoopEdition: %v", err)
	}

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
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
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	ed, err := newNoopEdition(cfg, sc)
	if err != nil {
		t.Fatalf("newNoopEdition: %v", err)
	}

	// No header - should resolve to config default identity with config-default auth.
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
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
	r2 := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
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
	sc := scanner.MustNew(cfg)
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
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	ed, err := newNoopEdition(cfg, sc)
	if err != nil {
		t.Fatalf("newNoopEdition: %v", err)
	}

	cfg2 := testConfig()
	sc2 := scanner.MustNew(cfg2)
	defer sc2.Close()

	ed2, err := ed.Reload(cfg2, sc2)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}

	resolved, _ := ed2.ResolveAgent(context.Background(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil))
	if resolved.Config != cfg2 {
		t.Error("reloaded edition should use new config")
	}
}

func TestNoopEdition_KnownProfiles(t *testing.T) {
	cfg := testConfig()
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	ed, _ := newNoopEdition(cfg, sc)
	if profiles := ed.KnownProfiles(); profiles != nil {
		t.Errorf("KnownProfiles = %v, want nil", profiles)
	}
}

func TestNoopEdition_Ports(t *testing.T) {
	cfg := testConfig()
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	ed, _ := newNoopEdition(cfg, sc)
	if ports := ed.Ports(); ports != nil {
		t.Errorf("Ports = %v, want nil", ports)
	}
}

func TestNoopEdition_Close(t *testing.T) {
	cfg := testConfig()
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	ed, _ := newNoopEdition(cfg, sc)
	ed.Close() // should not panic
	ed.Close() // idempotent
}

func TestNewEditionFunc_Default(t *testing.T) {
	cfg := testConfig()
	sc := scanner.MustNew(cfg)
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
	ctx = WithAgentOverride(ctx, testAgentMyAgent)
	profile, ok = AgentOverrideFromContext(ctx)
	if !ok {
		t.Fatal("expected override to be set")
	}
	if profile != testAgentMyAgent {
		t.Errorf("profile = %q, want %q", profile, testAgentMyAgent)
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
		{"no agent", "", "", agentAnonymous},
		{"from header", testAgentMyAgent, "", testAgentMyAgent},
		{"from query", "", testAgentMyAgent, testAgentMyAgent},
		{"header takes priority", testAgentFromHeader, testAgentFromQuery, testAgentFromHeader},
		{"sanitizes special chars", "my agent!@#", "", "my_agent___"},
		{"truncates long names", strings.Repeat("a", 100), "", strings.Repeat("a", 64)},
		{"all-invalid chars become underscores", "!@#$%", "", "_____"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
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
	known := map[string]bool{testAgentA: true, testAgentB: true}

	tests := []struct {
		name        string
		ctxOverride string
		header      string
		query       string
		wantName    string
		wantProfile string
	}{
		{"context override", testAgentA, "", "", testAgentA, testAgentA},
		{"context override beats header", testAgentA, testAgentB, "", testAgentA, testAgentA},
		{"known header agent", "", testAgentA, "", testAgentA, testAgentA},
		{"unknown header agent", "", "unknown", "", "unknown", ProfileDefault},
		{"query param agent", "", "", testAgentB, testAgentB, testAgentB},
		{"no agent", "", "", "", "", ProfileDefault},
		{"nil knownProfiles", "", testAgentMyAgent, "", testAgentMyAgent, ProfileDefault},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
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

func TestResolveAgentIdentity_NeutralizesSelfDeclaredReservedControlActor(t *testing.T) {
	t.Parallel()

	knownProfiles := map[string]bool{testAgentA: true}

	tests := []struct {
		name            string
		setup           func(r *http.Request) *http.Request
		defaultIdentity string
		wantName        string
		wantProfile     string
		wantAuth        envelope.ActorAuth
	}{
		{
			name: "reserved header",
			setup: func(r *http.Request) *http.Request {
				r.Header.Set(AgentHeader, "pipelock")
				return r
			},
			wantName:    "",
			wantProfile: ProfileDefault,
			wantAuth:    envelope.ActorAuthSelfDeclared,
		},
		{
			name: "reserved query",
			setup: func(r *http.Request) *http.Request {
				q := r.URL.Query()
				q.Set("agent", "pipelock")
				r.URL.RawQuery = q.Encode()
				return r
			},
			wantName:    "",
			wantProfile: ProfileDefault,
			wantAuth:    envelope.ActorAuthSelfDeclared,
		},
		{
			name: "case variant reserved header",
			setup: func(r *http.Request) *http.Request {
				r.Header.Set(AgentHeader, "PIPELOCK")
				return r
			},
			wantName:    "",
			wantProfile: ProfileDefault,
			wantAuth:    envelope.ActorAuthSelfDeclared,
		},
		{
			name: "reserved header does not fall through to config default",
			setup: func(r *http.Request) *http.Request {
				r.Header.Set(AgentHeader, "pipelock")
				return r
			},
			defaultIdentity: testAgentDeployment,
			wantName:        "",
			wantProfile:     ProfileDefault,
			wantAuth:        envelope.ActorAuthSelfDeclared,
		},
		{
			name: "anonymous header does not fall through to config default",
			setup: func(r *http.Request) *http.Request {
				r.Header.Set(AgentHeader, "anonymous")
				return r
			},
			defaultIdentity: testAgentDeployment,
			wantName:        "",
			wantProfile:     ProfileDefault,
			wantAuth:        envelope.ActorAuthSelfDeclared,
		},
		{
			name: "normal self-declared header",
			setup: func(r *http.Request) *http.Request {
				r.Header.Set(AgentHeader, "agent-z")
				return r
			},
			wantName:    "agent-z",
			wantProfile: ProfileDefault,
			wantAuth:    envelope.ActorAuthSelfDeclared,
		},
		{
			name: "registered profile header",
			setup: func(r *http.Request) *http.Request {
				r.Header.Set(AgentHeader, testAgentA)
				return r
			},
			wantName:    testAgentA,
			wantProfile: testAgentA,
			wantAuth:    envelope.ActorAuthMatched,
		},
		{
			name: "context-bound identity unchanged",
			setup: func(r *http.Request) *http.Request {
				r.Header.Set(AgentHeader, "pipelock")
				return r.WithContext(WithAgentOverride(r.Context(), testAgentA))
			},
			wantName:    testAgentA,
			wantProfile: testAgentA,
			wantAuth:    envelope.ActorAuthBound,
		},
		{
			name: "config-default identity unchanged",
			setup: func(r *http.Request) *http.Request {
				return r
			},
			defaultIdentity: testAgentDeployment,
			wantName:        testAgentDeploymentSafe,
			wantProfile:     ProfileDefault,
			wantAuth:        envelope.ActorAuthConfigDefault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
			r = tt.setup(r)
			id := ResolveAgentIdentity(r, knownProfiles, tt.defaultIdentity, false)
			if id.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", id.Name, tt.wantName)
			}
			if id.Name == "pipelock" || id.Name == "PIPELOCK" {
				t.Errorf("Name = %q, reserved control actor must not resolve from self-declared input", id.Name)
			}
			if id.Profile != tt.wantProfile {
				t.Errorf("Profile = %q, want %q", id.Profile, tt.wantProfile)
			}
			if id.Auth != tt.wantAuth {
				t.Errorf("Auth = %q, want %q", id.Auth, tt.wantAuth)
			}
		})
	}
}

func TestRejectedSelfDeclaredReservedControlActor(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		setup           func(*http.Request) *http.Request
		defaultIdentity string
		bindDefault     bool
		wantReserved    string
		wantOK          bool
	}{
		{
			name: "reserved header",
			setup: func(r *http.Request) *http.Request {
				r.Header.Set(AgentHeader, "PIPELOCK")
				return r
			},
			wantReserved: "pipelock",
			wantOK:       true,
		},
		{
			name: "reserved query",
			setup: func(r *http.Request) *http.Request {
				q := r.URL.Query()
				q.Set("agent", "pipelock")
				r.URL.RawQuery = q.Encode()
				return r
			},
			wantReserved: "pipelock",
			wantOK:       true,
		},
		{
			name: "normal header",
			setup: func(r *http.Request) *http.Request {
				r.Header.Set(AgentHeader, "agent-a")
				return r
			},
		},
		{
			name: "context-bound identity ignores reserved header",
			setup: func(r *http.Request) *http.Request {
				r.Header.Set(AgentHeader, "pipelock")
				return r.WithContext(WithAgentOverride(r.Context(), testAgentA))
			},
		},
		{
			name: "bound default ignores reserved header",
			setup: func(r *http.Request) *http.Request {
				r.Header.Set(AgentHeader, "pipelock")
				return r
			},
			defaultIdentity: testAgentDeployment,
			bindDefault:     true,
		},
		{
			name: "config default wins over reserved query",
			setup: func(r *http.Request) *http.Request {
				q := r.URL.Query()
				q.Set("agent", "pipelock")
				r.URL.RawQuery = q.Encode()
				return r
			},
			defaultIdentity: testAgentDeployment,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
			r = tt.setup(r)

			got, ok := RejectedSelfDeclaredReservedControlActor(r, tt.defaultIdentity, tt.bindDefault)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.wantReserved {
				t.Fatalf("reserved = %q, want %q", got, tt.wantReserved)
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
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
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
		{"no agent no default", "", "", "", false, agentAnonymous},
		{"no agent with default", "", "", testAgentDeployment, false, testAgentDeploymentSafe},
		{"header overrides default", testAgentFromHeader, "", testAgentDeployment, false, testAgentFromHeader},
		{"default overrides query", "", testAgentFromQuery, testAgentDeployment, false, testAgentDeploymentSafe},
		{"header overrides query and default", testAgentFromHeader, testAgentFromQuery, testAgentDeployment, false, testAgentFromHeader},
		{"default sanitized", "", "", "bad agent!@#", false, "bad_agent___"},
		{"empty default same as anonymous", "", "", "", false, agentAnonymous},
		{"bind ignores header and query", testAgentFromHeader, testAgentFromQuery, testAgentDeployment, true, testAgentDeploymentSafe},
		{"reserved header becomes anonymous", "pipelock", "", "", false, agentAnonymous},
		{"reserved query becomes anonymous", "", "pipelock", "", false, agentAnonymous},
		{"case variant reserved header becomes anonymous", "PIPELOCK", "", "", false, agentAnonymous},
		{"reserved header does not fall through to config default", "pipelock", "", testAgentDeployment, false, agentAnonymous},
		{"anonymous header does not fall through to config default", "anonymous", "", testAgentDeployment, false, agentAnonymous},
		{"config default reserved-looking value unchanged", "", "", "PIPELOCK", false, "PIPELOCK"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
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

	known := map[string]bool{testAgentA: true}

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
			defaultIdentity: testAgentDeployment,
			wantName:        testAgentDeploymentSafe,
			wantProfile:     ProfileDefault,
		},
		{
			name:            "header overrides default identity",
			header:          testAgentA,
			defaultIdentity: testAgentDeployment,
			wantName:        testAgentA,
			wantProfile:     testAgentA,
		},
		{
			name:            "default identity overrides query param",
			query:           testAgentA,
			defaultIdentity: testAgentDeployment,
			wantName:        testAgentDeploymentSafe,
			wantProfile:     ProfileDefault,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
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

	known := map[string]bool{testAgentA: true}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com?agent=agent-a", nil)
	r.Header.Set(AgentHeader, "spoofed-header")

	id := ResolveAgentIdentity(r, known, testAgentDeployment, true)
	if id.Name != testAgentDeploymentSafe {
		t.Errorf("Name = %q, want %q", id.Name, testAgentDeploymentSafe)
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
	sc := scanner.MustNew(cfg)
	defer sc.Close()

	ed, err := newNoopEdition(cfg, sc)
	if err != nil {
		t.Fatalf("newNoopEdition: %v", err)
	}

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com?agent=query-agent", nil)
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
		{"reserved anonymous", agentAnonymous, true},
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
	sc := scanner.MustNew(cfg)
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

func TestRejectedSelfDeclaredReservedControlActor_AnonymousAndEmpty(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
	r.Header.Set(AgentHeader, "anonymous")
	if reserved, ok := RejectedSelfDeclaredReservedControlActor(r, "", false); !ok || reserved != agentAnonymous {
		t.Errorf("anonymous header: got (%q,%v), want (anonymous,true)", reserved, ok)
	}

	empty := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com", nil)
	if reserved, ok := RejectedSelfDeclaredReservedControlActor(empty, "", false); ok || reserved != "" {
		t.Errorf("empty request: got (%q,%v), want empty/false", reserved, ok)
	}
}
