// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/mcp/identity"
	"github.com/luckyPipewrench/pipelock/internal/mcp/localservice"
)

const (
	testListenerUpstream = "http://127.0.0.1:43111/mcp"
	testListenerLabel    = "docs"
)

func registeredConfig(name, path string, sessionHeader bool) *config.Config {
	uid := uint32(1000)
	v := &config.MCPVerifiedLocalService{
		Scheme:           config.MCPIdentitySchemeHTTP,
		Host:             config.MCPIdentityHostIPv4Loopback,
		Path:             path,
		PrincipalUID:     &uid,
		ExecutableSHA256: testIdentityDigest,
	}
	if sessionHeader {
		v.SessionHeader = &config.MCPIdentitySessionHeader{Name: "Authorization", Scheme: config.MCPIdentitySessionScheme, Carrier: testIdentityCarrier}
	}
	cfg := config.Defaults()
	cfg.MCPIdentities = []config.MCPIdentity{{Name: name, VerifiedLocalService: v}}
	return cfg
}

func TestIdentityHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		file     []string
		flag     []string
		carriers []carrierHeader
		want     []identity.Header
		wantErr  bool
	}{
		{name: "none", want: []identity.Header{}},
		{
			name:     "sources are kept in file, flag, carrier order",
			file:     []string{"X-File: f"},
			flag:     []string{"X-Flag: g"},
			carriers: []carrierHeader{{Header: "Authorization", Carrier: testIdentityCarrier, Value: "Bearer tok"}},
			want: []identity.Header{
				{Name: "X-File", Value: "f", Source: identity.HeaderSourceFile},
				{Name: "X-Flag", Value: "g", Source: identity.HeaderSourceFlag},
				{Name: "Authorization", Value: "Bearer tok", Source: identity.HeaderSourceCarrier, Carrier: testIdentityCarrier},
			},
		},
		{name: "malformed file line", file: []string{"nocolon"}, wantErr: true},
		{name: "malformed flag line", flag: []string{"nocolon"}, wantErr: true},
		{name: "carrier value with a newline", carriers: []carrierHeader{{Header: "Authorization", Carrier: testIdentityCarrier, Value: "Bearer a\r\nX: y"}}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := identityHeaders(tt.file, tt.flag, tt.carriers)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("header %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestResolveHeaderCarrierEntries(t *testing.T) {
	t.Setenv(testIdentityCarrier, "Bearer tok")
	tests := []struct {
		name     string
		mappings []string
		want     []carrierHeader
		wantErr  string
	}{
		{name: "none", want: []carrierHeader{}},
		{name: "resolved", mappings: []string{"Authorization=" + testIdentityCarrier}, want: []carrierHeader{{Header: "Authorization", Carrier: testIdentityCarrier, Value: "Bearer tok"}}},
		{name: "unset carrier", mappings: []string{"Authorization=" + testIdentityCarrier + "_NOPE"}, wantErr: "is unset"},
		{name: "malformed mapping", mappings: []string{"Authorization"}, wantErr: "--header-carrier"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveHeaderCarrierEntries(tt.mappings)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				if err != nil && strings.Contains(err.Error(), "Bearer tok") {
					t.Errorf("error leaked the carrier value: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("entry %d = %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestUpstreamTransportKind(t *testing.T) {
	t.Parallel()
	if got := upstreamTransportKind(true); got != identity.KindWS {
		t.Errorf("ws kind = %q", got)
	}
	if got := upstreamTransportKind(false); got != identity.KindHTTP {
		t.Errorf("http kind = %q", got)
	}
}

func TestResolveLaunchIdentity_PrintsStartupLine(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		cfg      *config.Config
		explicit string
		want     string
		wantErr  bool
	}{
		{name: "unnamed", cfg: config.Defaults(), want: "MCP identity: server=(unnamed) source=unnamed binding=transport-v2\n"},
		{name: "operator label", cfg: config.Defaults(), explicit: testListenerLabel, want: "MCP identity: server=docs source=explicit binding=transport-v2\n"},
		{name: "registered name that matches nothing refuses", cfg: registeredConfig(testListenerLabel, "/other", false), explicit: testListenerLabel, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			_, err := resolveLaunchIdentity(tt.cfg, tt.explicit, identity.Transport{Kind: identity.KindHTTP, UpstreamURL: testListenerUpstream}, &stderr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got := stderr.String(); got != tt.want {
				t.Errorf("stderr = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVerifiedDialContext_NilPinPassesThrough(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	inner := func(context.Context, string, string) (net.Conn, error) {
		calls.Add(1)
		c, _ := net.Pipe()
		return c, nil
	}
	dial := verifiedDialContext(inner, identity.Resolution{}, nil)
	conn, err := dial(context.Background(), "tcp", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if calls.Load() != 1 {
		t.Errorf("inner dial called %d times, want 1", calls.Load())
	}
}

// TestVerifiedDialContext_RefusesUnpinnedOwner dials a listener this test
// process itself owns with a pin no process can satisfy, so the dial must be
// refused on every platform and the connection must not be handed back.
func TestVerifiedDialContext_RefusesUnpinnedOwner(t *testing.T) {
	t.Parallel()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer func() { _ = c.Close() }()
		}
	}()

	res := identity.Resolution{
		Name: "local-tools",
		Pin:  &localservice.Pin{PrincipalUID: 0xFFFFFFFE, ExecutableSHA256: testIdentityDigest},
	}
	inner := (&net.Dialer{}).DialContext
	var logged strings.Builder
	dial := verifiedDialContext(inner, res, &logged)
	conn, err := dial(context.Background(), "tcp", ln.Addr().String())
	if err == nil {
		_ = conn.Close()
		t.Fatal("dial to a service that does not match the pin must be refused")
	}
	if !strings.Contains(logged.String(), "verified local service local-tools") {
		t.Errorf("refusal was not written to the log writer: %q", logged.String())
	}
	if conn != nil {
		t.Error("a refused dial must not return a connection")
	}
	if !strings.Contains(err.Error(), "verified local service local-tools") {
		t.Errorf("error does not name the registration: %v", err)
	}

	// Concurrent refusals share one log writer; under -race an unsynchronized
	// write to the builder fails this test.
	var concurrent strings.Builder
	dialAll := verifiedDialContext(inner, res, &concurrent)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c, derr := dialAll(context.Background(), "tcp", ln.Addr().String()); derr == nil {
				_ = c.Close()
			}
		}()
	}
	wg.Wait()
	if got := strings.Count(concurrent.String(), "refused upstream connection"); got != 8 {
		t.Errorf("concurrent refusals logged %d times, want 8", got)
	}
}

func TestLaunchBinding(t *testing.T) {
	t.Parallel()
	in := mcpBindingInputs{UpstreamURL: "https://api.vendor.example/mcp"}
	tr := identity.Transport{Kind: identity.KindHTTP, UpstreamURL: in.UpstreamURL}

	legacy, err := launchBinding(identity.Resolution{BindingMode: config.MCPAckBindingModeTransportV2}, tr, in)
	if err != nil {
		t.Fatal(err)
	}
	if legacy != mcpServerBinding(in) {
		t.Errorf("legacy binding = %q, want transport digest %q", legacy, mcpServerBinding(in))
	}

	if _, err := launchBinding(identity.Resolution{BindingMode: config.MCPAckBindingModeVerifiedLocalSession}, tr, in); err == nil {
		t.Error("a verified-local-session mode with no registration must not produce a binding")
	}

	cfg := registeredConfig("local-tools", "/mcp", false)
	entry := cfg.MCPIdentities[0]
	pin := &localservice.Pin{PrincipalUID: 1000, ExecutableSHA256: testIdentityDigest}
	res := identity.Resolution{Name: entry.Name, Revision: entry.Revision(), BindingMode: config.MCPAckBindingModeVerifiedLocalSession, Entry: &entry, Pin: pin}
	session, err := launchBinding(res, tr, in)
	if err != nil {
		t.Fatal(err)
	}
	if session == "" || session == legacy {
		t.Errorf("session binding = %q, must be non-empty and differ from the transport digest", session)
	}
	other := res
	other.Revision = "different"
	changed, err := launchBinding(other, tr, in)
	if err != nil {
		t.Fatal(err)
	}
	if changed == session {
		t.Error("a changed registration revision must change the session binding")
	}
}

func TestRunListenerIdentity(t *testing.T) {
	t.Parallel()
	tr := listenerTransport(testListenerUpstream)
	noRegistration := config.Defaults()
	pinned, err := identity.Resolve(noRegistration, testListenerLabel, tr)
	if err != nil {
		t.Fatal(err)
	}
	binding := mcpRunListenerBinding(testListenerUpstream)
	li := newRunListenerIdentity(testListenerLabel, pinned, binding, tr)

	unrelated := config.Defaults()
	registeredElsewhere := registeredConfig(testListenerLabel, "/other", false)

	tests := []struct {
		name        string
		cfg         *config.Config
		wantChanged bool
		wantArming  string
	}{
		{name: "same snapshot", cfg: noRegistration, wantArming: testListenerLabel},
		{name: "unrelated reload", cfg: unrelated, wantArming: testListenerLabel},
		{name: "operator label became a registered name", cfg: registeredElsewhere, wantChanged: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := li.changed(tt.cfg); got != tt.wantChanged {
				t.Errorf("changed = %v, want %v", got, tt.wantChanged)
			}
			if got := li.armingName(tt.cfg); got != tt.wantArming {
				t.Errorf("armingName = %q, want %q", got, tt.wantArming)
			}
			id := li.identityFn(func() *config.Config { return tt.cfg })()
			if tt.wantChanged {
				if !strings.Contains(id.Refusal, "registration changed; restart pipelock run") || id.Name != "" || id.Binding != "" {
					t.Errorf("changed identity = %+v, want only a refusal", id)
				}
				return
			}
			if id.Refusal != "" || id.Name != pinned.Name || id.PolicyName != pinned.ArmingName || id.Binding != binding || id.BindingMode != pinned.BindingMode {
				t.Errorf("identity = %+v", id)
			}
		})
	}
}

func TestRunListenerIdentity_CachesByConfigPointer(t *testing.T) {
	t.Parallel()
	tr := listenerTransport(testListenerUpstream)
	cfg := config.Defaults()
	pinned, err := identity.Resolve(cfg, "", tr)
	if err != nil {
		t.Fatal(err)
	}
	li := newRunListenerIdentity("", pinned, mcpRunListenerBinding(testListenerUpstream), tr)

	li.resolveFor(cfg)
	first := li.current.Load()
	li.resolveFor(cfg)
	if li.current.Load() != first {
		t.Error("a second request on the same snapshot must reuse the cached resolution")
	}
	li.resolveFor(config.Defaults())
	if li.current.Load() == first {
		t.Error("a new snapshot must be re-resolved")
	}
	if displayName(pinned.Name) != "(unnamed)" || displayName("docs") != "docs" {
		t.Error("displayName must label an empty name as (unnamed)")
	}
}

func TestRunListenerIdentity_RegistrationAppearingAfterStartup(t *testing.T) {
	t.Parallel()
	tr := listenerTransport(testListenerUpstream)
	pinned, err := identity.Resolve(config.Defaults(), "", tr)
	if err != nil {
		t.Fatal(err)
	}
	li := newRunListenerIdentity("", pinned, mcpRunListenerBinding(testListenerUpstream), tr)
	// A registration that now matches this upstream changes the resolution on
	// Linux and is refused on other platforms; either way the listener stops.
	if !li.changed(registeredConfig("local-tools", "/mcp", false)) {
		t.Error("a registration that newly matches the listener's upstream must stop the listener")
	}
}

func TestRequireNoSessionHeader(t *testing.T) {
	t.Parallel()
	tr := listenerTransport(testListenerUpstream)
	tests := []struct {
		name    string
		cfg     *config.Config
		wantErr bool
	}{
		{name: "no registration", cfg: config.Defaults()},
		{name: "registration without a session header", cfg: registeredConfig("local-tools", "/mcp", false)},
		{name: "registration for another path", cfg: registeredConfig("local-tools", "/other", true)},
		{name: "registration with a session header", cfg: registeredConfig("local-tools", "/mcp", true), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := requireNoSessionHeader(tt.cfg, tr)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "pipelock mcp proxy") {
				t.Errorf("error should point at mcp proxy: %v", err)
			}
		})
	}
}

func TestListenerTransport(t *testing.T) {
	t.Parallel()
	got := listenerTransport(testListenerUpstream)
	if got.Kind != identity.KindHTTP || got.UpstreamURL != testListenerUpstream || len(got.Headers) != 0 {
		t.Errorf("listenerTransport = %+v", got)
	}
}

func TestListenerIdentityHeadersBinding(t *testing.T) {
	for _, sessionHeader := range []bool{false, true} {
		cfg := registeredConfig(testListenerLabel, "/mcp", sessionHeader)
		entry := cfg.MCPIdentities[0]
		res := identity.Resolution{
			Name: entry.Name, ArmingName: entry.Name, Entry: &entry, Revision: entry.Revision(), BindingMode: config.MCPAckBindingModeVerifiedLocalSession,
			Pin: &localservice.Pin{PrincipalUID: *entry.VerifiedLocalService.PrincipalUID, ExecutableSHA256: entry.VerifiedLocalService.ExecutableSHA256},
		}
		tr := listenerTransport(testListenerUpstream)
		current := mcp.ServerIdentity{Name: res.Name, PolicyName: res.ArmingName, Revision: res.Revision, BindingMode: res.BindingMode}
		fn := listenerIdentityHeadersFn(res, tr, func() mcp.ServerIdentity { return current })
		first := fn(http.Header{"Authorization": {"Bearer first"}})
		second := fn(http.Header{"Authorization": {"Bearer second"}})
		if first.Refusal != "" || second.Refusal != "" || first.Binding == "" || (first.Binding == second.Binding) != sessionHeader {
			t.Fatalf("session header=%v: first=%+v second=%+v", sessionHeader, first, second)
		}
		changed := fn(http.Header{"Authorization": {"Bearer first"}, "X-Tenant": {"other"}})
		if changed.Binding == first.Binding {
			t.Fatal("unrelated forwarded header was not bound")
		}
		current.Refusal = "registration changed"
		if got := fn(nil); got.Refusal != current.Refusal {
			t.Fatalf("request binding erased reload refusal: %+v", got)
		}
		res.Entry = nil
		current.Refusal = ""
		invalid := listenerIdentityHeadersFn(res, tr, func() mcp.ServerIdentity { return current })
		if got := invalid(nil); got.Refusal == "" || got.Binding != "" {
			t.Fatalf("invalid resolution returned usable binding: %+v", got)
		}
	}
	if fn := listenerIdentityHeadersFn(identity.Legacy(testListenerLabel), listenerTransport(testListenerUpstream), nil); fn != nil {
		t.Fatal("legacy listener binding must be unchanged")
	}
}
