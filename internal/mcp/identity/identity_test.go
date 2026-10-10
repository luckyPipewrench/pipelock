// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/localservice"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
)

const (
	nameIndexer = "vendor-indexer"
	nameBridge  = "vendor-bridge"
	nameV6API   = "vendor-v6-api"
	nameOther   = "vendor-other"

	carrierVar = "PIPELOCK_VSCODE_SESSION_TOKEN"

	urlIndexer = "http://127.0.0.1:41873/rpc/v1"
	urlBridge  = "ws://[::1]:9000/bridge"
	urlV6API   = "http://[::1]:7000/api"

	// Distinct, well-formed digests for the pins.
	shaExe   = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	shaLibA  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	shaLibB  = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	shaOther = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	pathLibA = "/opt/vendor/lib/libindex.so"
	pathLibB = "/opt/vendor/lib/libcodec.so"

	bearerOne = "Bearer session-token-one"
	bearerTwo = "Bearer session-token-two"
)

func uidPtr(v uint32) *uint32 { return &v }

// registry is a vendor-neutral registry: a Python-style HTTP indexer with a
// per-session bearer, a WebSocket bridge on IPv6 loopback, and an IPv6 HTTP API
// with no session header.
func registry() []config.MCPIdentity {
	return []config.MCPIdentity{
		{
			Name: nameIndexer,
			VerifiedLocalService: &config.MCPVerifiedLocalService{
				Scheme:           config.MCPIdentitySchemeHTTP,
				Host:             config.MCPIdentityHostIPv4Loopback,
				Path:             "/rpc/v1",
				PrincipalUID:     uidPtr(1001),
				ExecutableSHA256: shaExe,
				MappedFiles: []config.MCPIdentityFilePin{
					{Path: pathLibB, SHA256: shaLibB},
					{Path: pathLibA, SHA256: shaLibA},
				},
				ControlEnvironment: map[string]string{"LD_LIBRARY_PATH": "/opt/vendor/lib"},
				SessionHeader: &config.MCPIdentitySessionHeader{
					Name:    "Authorization",
					Scheme:  config.MCPIdentitySessionScheme,
					Carrier: carrierVar,
				},
			},
		},
		{
			Name: nameBridge,
			VerifiedLocalService: &config.MCPVerifiedLocalService{
				Scheme:           config.MCPIdentitySchemeWS,
				Host:             config.MCPIdentityHostIPv6Loopback,
				Path:             "/bridge",
				PrincipalUID:     uidPtr(1002),
				ExecutableSHA256: shaOther,
			},
		},
		{
			Name: nameV6API,
			VerifiedLocalService: &config.MCPVerifiedLocalService{
				Scheme:           config.MCPIdentitySchemeHTTP,
				Host:             config.MCPIdentityHostIPv6Loopback,
				Path:             "/api",
				PrincipalUID:     uidPtr(0),
				ExecutableSHA256: shaExe,
			},
		},
	}
}

func cfgWith(ids ...config.MCPIdentity) *config.Config {
	cfg := config.Defaults()
	cfg.MCPIdentities = ids
	return cfg
}

func sessionHeader(value string) Header {
	return Header{Name: "Authorization", Value: value, Source: HeaderSourceCarrier, Carrier: carrierVar}
}

func httpLaunch(rawURL string, headers ...Header) Transport {
	return Transport{Kind: KindHTTP, UpstreamURL: rawURL, Headers: headers}
}

func TestResolve_Precedence(t *testing.T) {
	cfg := cfgWith(registry()...)
	good := httpLaunch(urlIndexer, sessionHeader(bearerOne))
	unrelated := httpLaunch("http://127.0.0.1:5000/other")

	tests := []struct {
		name       string
		cfg        *config.Config
		explicit   string
		transport  Transport
		wantSource string
		wantName   string
		wantMode   string
		wantErr    string
	}{
		{
			name: "nil config unnamed is legacy", cfg: nil, transport: unrelated,
			wantSource: SourceUnnamed, wantMode: config.MCPAckBindingModeTransportV2,
		},
		{
			name: "no registry explicit is legacy", cfg: config.Defaults(), explicit: "plain-server", transport: unrelated,
			wantSource: SourceExplicit, wantName: "plain-server", wantMode: config.MCPAckBindingModeTransportV2,
		},
		{
			name: "unmatched unnamed is legacy", cfg: cfg, transport: unrelated,
			wantSource: SourceUnnamed, wantMode: config.MCPAckBindingModeTransportV2,
		},
		{
			name: "unmatched unregistered explicit name is legacy", cfg: cfg, explicit: "plain-server", transport: unrelated,
			wantSource: SourceExplicit, wantName: "plain-server", wantMode: config.MCPAckBindingModeTransportV2,
		},
		{
			name: "match without explicit name resolves the entry", cfg: cfg, transport: good,
			wantSource: SourceVerifiedLocalService, wantName: nameIndexer, wantMode: config.MCPAckBindingModeVerifiedLocalSession,
		},
		{
			name: "match with the same explicit name resolves the entry", cfg: cfg, explicit: nameIndexer, transport: good,
			wantSource: SourceVerifiedLocalService, wantName: nameIndexer, wantMode: config.MCPAckBindingModeVerifiedLocalSession,
		},
		{
			name: "match with a different explicit name is refused", cfg: cfg, explicit: nameOther, transport: good,
			wantErr: "server name \"vendor-other\" conflicts with mcp_identities[0]",
		},
		{
			name: "match with another registered name is refused", cfg: cfg, explicit: nameBridge, transport: good,
			wantErr: "conflicts with mcp_identities[0]",
		},
		{
			name: "registered name on an unmatched http upstream is impersonation", cfg: cfg, explicit: nameIndexer, transport: unrelated,
			wantErr: "identity vendor-indexer is registered as a verified local service; this launch's upstream does not match mcp_identities[0].verified_local_service",
		},
		{
			name: "registered name on a subprocess is impersonation", cfg: cfg, explicit: nameBridge,
			transport: Transport{Kind: KindSubprocess, Command: []string{"/opt/vendor/bin/indexerd"}},
			wantErr:   "identity vendor-bridge is registered as a verified local service; this launch's upstream does not match mcp_identities[1].verified_local_service",
		},
		{
			name: "subprocess unnamed is legacy", cfg: cfg,
			transport:  Transport{Kind: KindSubprocess, Command: []string{"/opt/vendor/bin/indexerd"}},
			wantSource: SourceUnnamed, wantMode: config.MCPAckBindingModeTransportV2,
		},
		{
			name: "websocket entry resolves without a session header", cfg: cfg,
			transport:  Transport{Kind: KindWS, UpstreamURL: urlBridge},
			wantSource: SourceVerifiedLocalService, wantName: nameBridge, wantMode: config.MCPAckBindingModeVerifiedLocalSession,
		},
		{
			name: "bracketed ipv6 host matches", cfg: cfg,
			transport:  httpLaunch(urlV6API),
			wantSource: SourceVerifiedLocalService, wantName: nameV6API, wantMode: config.MCPAckBindingModeVerifiedLocalSession,
		},
		{
			name: "invalid explicit name is refused", cfg: cfg, explicit: "bad name", transport: unrelated,
			wantErr: "MCP server name",
		},
		{
			name: "two entries matching one upstream are refused",
			cfg: cfgWith(
				config.MCPIdentity{Name: "twin-a", VerifiedLocalService: registry()[2].VerifiedLocalService},
				config.MCPIdentity{Name: "twin-b", VerifiedLocalService: registry()[2].VerifiedLocalService},
			),
			transport: httpLaunch(urlV6API),
			wantErr:   "matches more than one mcp_identities entry (mcp_identities[0], mcp_identities[1])",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolve(tt.cfg, tt.explicit, tt.transport, true)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				if got.Pin != nil || got.Entry != nil || got.Name != "" || got.ArmingName != "" {
					t.Fatalf("a refusal must return the zero resolution, got %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Source != tt.wantSource || got.Name != tt.wantName || got.ArmingName != tt.wantName || got.BindingMode != tt.wantMode {
				t.Fatalf("resolution = %+v, want source=%s name=%q mode=%s", got, tt.wantSource, tt.wantName, tt.wantMode)
			}
			verified := tt.wantSource == SourceVerifiedLocalService
			if verified != (got.Pin != nil && got.Entry != nil && got.Revision != "") {
				t.Fatalf("pin/entry/revision presence does not follow source: %+v", got)
			}
		})
	}
}

func TestResolve_VerifiedFields(t *testing.T) {
	cfg := cfgWith(registry()...)
	got, err := resolve(cfg, "", httpLaunch(urlIndexer, sessionHeader(bearerOne)), true)
	if err != nil {
		t.Fatal(err)
	}
	if got.Revision != cfg.MCPIdentities[0].Revision() {
		t.Fatalf("Revision = %q, want the entry revision", got.Revision)
	}
	if got.Pin.PrincipalUID != 1001 || got.Pin.ExecutableSHA256 != shaExe {
		t.Fatalf("pin = %+v", got.Pin)
	}
	if len(got.Pin.MappedFiles) != 2 || got.Pin.ControlEnvironment["LD_LIBRARY_PATH"] != "/opt/vendor/lib" {
		t.Fatalf("pin files/env = %+v", got.Pin)
	}
	got.Pin.ControlEnvironment["LD_LIBRARY_PATH"] = "tampered"
	if cfg.MCPIdentities[0].VerifiedLocalService.ControlEnvironment["LD_LIBRARY_PATH"] != "/opt/vendor/lib" {
		t.Fatal("the pin must not alias the configured control environment")
	}
	got.Entry.Name = "tampered"
	if cfg.MCPIdentities[0].Name != nameIndexer {
		t.Fatal("the resolution entry must be a copy of the configured entry")
	}
}

func TestResolve_UpstreamShape(t *testing.T) {
	cfg := cfgWith(registry()...)
	tests := []struct {
		name      string
		transport Transport
		match     bool
		wantName  string
	}{
		{"exact upstream", httpLaunch(urlIndexer, sessionHeader(bearerOne)), true, nameIndexer},
		{"different ephemeral port", httpLaunch("http://127.0.0.1:50000/rpc/v1", sessionHeader(bearerOne)), true, nameIndexer},
		{"port omitted on another host", httpLaunch("http://127.0.0.2/rpc/v1", sessionHeader(bearerOne)), false, ""},
		{"port omitted on another path", httpLaunch("http://127.0.0.1/other", sessionHeader(bearerOne)), false, ""},
		{"port zero", httpLaunch("http://127.0.0.1:0/rpc/v1", sessionHeader(bearerOne)), false, ""},
		{"port out of range", httpLaunch("http://127.0.0.1:70000/rpc/v1", sessionHeader(bearerOne)), false, ""},
		{"query present", httpLaunch(urlIndexer+"?tenant=a", sessionHeader(bearerOne)), false, ""},
		{"force query", httpLaunch(urlIndexer+"?", sessionHeader(bearerOne)), false, ""},
		{"user info", httpLaunch("http://user:pw@127.0.0.1:41873/rpc/v1", sessionHeader(bearerOne)), false, ""},
		{"username only", httpLaunch("http://user@127.0.0.1:41873/rpc/v1", sessionHeader(bearerOne)), false, ""},
		{"fragment", httpLaunch(urlIndexer+"#section", sessionHeader(bearerOne)), false, ""},
		{"empty fragment", httpLaunch(urlIndexer+"#", sessionHeader(bearerOne)), false, ""},
		{"other scheme", httpLaunch("https://127.0.0.1:41873/rpc/v1", sessionHeader(bearerOne)), false, ""},
		{"hostname instead of literal", httpLaunch("http://localhost:41873/rpc/v1", sessionHeader(bearerOne)), false, ""},
		{"other loopback literal", httpLaunch("http://[::1]:41873/rpc/v1", sessionHeader(bearerOne)), false, ""},
		{"other path", httpLaunch("http://127.0.0.1:41873/rpc/v2", sessionHeader(bearerOne)), false, ""},
		{"trailing slash", httpLaunch("http://127.0.0.1:41873/rpc/v1/", sessionHeader(bearerOne)), false, ""},
		{"escaped slash is a different path", httpLaunch("http://127.0.0.1:41873/rpc%2Fv1", sessionHeader(bearerOne)), false, ""},
		{"empty host", httpLaunch("http://:41873/rpc/v1"), false, ""},
		{"opaque url", httpLaunch("http:127.0.0.1"), false, ""},
		{"unparsable url", httpLaunch("http://[::1"), false, ""},
		{"http kind with a ws scheme", httpLaunch("ws://[::1]:9000/bridge"), false, ""},
		{"ws kind with an http scheme", Transport{Kind: KindWS, UpstreamURL: urlV6API}, false, ""},
		{"ws exact", Transport{Kind: KindWS, UpstreamURL: urlBridge}, true, nameBridge},
		{"ws query", Transport{Kind: KindWS, UpstreamURL: urlBridge + "?x=1"}, false, ""},
		{"unknown kind", Transport{Kind: "stdio", UpstreamURL: urlIndexer}, false, ""},
		{"subprocess with a matching-looking url", Transport{Kind: KindSubprocess, UpstreamURL: urlIndexer, Command: []string{"x"}}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolve(cfg, "", tt.transport, true)
			if err != nil {
				t.Fatalf("unnamed launch must not error: %v", err)
			}
			if tt.match {
				if got.Source != SourceVerifiedLocalService || got.Name != tt.wantName {
					t.Fatalf("resolution = %+v, want verified %s", got, tt.wantName)
				}
				return
			}
			if got.Source != SourceUnnamed || got.Pin != nil {
				t.Fatalf("resolution = %+v, want unmatched legacy", got)
			}
		})
	}
}

func TestResolve_PortlessMatchRefuses(t *testing.T) {
	cfg := cfgWith(registry()...)
	tests := []struct {
		name      string
		explicit  string
		transport Transport
		wantIndex string
	}{
		{"http upstream without a port", "", httpLaunch("http://127.0.0.1/rpc/v1", sessionHeader(bearerOne)), "mcp_identities[0]"},
		{"trailing colon without a port", "", httpLaunch("http://127.0.0.1:/rpc/v1", sessionHeader(bearerOne)), "mcp_identities[0]"},
		{"with the registered name", nameIndexer, httpLaunch("http://127.0.0.1/rpc/v1", sessionHeader(bearerOne)), "mcp_identities[0]"},
		{"before the session header check", "", httpLaunch("http://127.0.0.1/rpc/v1"), "mcp_identities[0]"},
		{"ws upstream without a port", "", Transport{Kind: KindWS, UpstreamURL: "ws://[::1]/bridge"}, "mcp_identities[1]"},
		{"ipv6 http upstream without a port", "", httpLaunch("http://[::1]/api"), "mcp_identities[2]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := resolve(cfg, tt.explicit, tt.transport, true)
			want := tt.wantIndex + " requires an explicit port in the upstream URL"
			if err == nil || err.Error() != want {
				t.Fatalf("error = %v, want %q", err, want)
			}
		})
	}
}

func TestResolve_UnmatchedShapeStillRefusesRegisteredName(t *testing.T) {
	cfg := cfgWith(registry()...)
	// A near miss of a registered upstream must not become a plain server that
	// merely shares the registered name.
	for _, raw := range []string{
		urlIndexer + "?tenant=a",
		"http://user@127.0.0.1:41873/rpc/v1",
		urlIndexer + "#x",
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := resolve(cfg, nameIndexer, httpLaunch(raw, sessionHeader(bearerOne)), true)
			if err == nil || !strings.Contains(err.Error(), "registered as a verified local service") {
				t.Fatalf("err = %v, want impersonation refusal", err)
			}
		})
	}
}

func TestResolve_WebSocketNeverMatchesSessionHeaderEntry(t *testing.T) {
	// Config validation forbids a ws entry with a session header; the resolver
	// still refuses to match one so a hand-built registry cannot weaken it.
	entry := config.MCPIdentity{
		Name: "ws-with-header",
		VerifiedLocalService: &config.MCPVerifiedLocalService{
			Scheme: config.MCPIdentitySchemeWS, Host: config.MCPIdentityHostIPv4Loopback, Path: "/sock",
			PrincipalUID: uidPtr(1001), ExecutableSHA256: shaExe,
			SessionHeader: &config.MCPIdentitySessionHeader{Name: "Authorization", Scheme: config.MCPIdentitySessionScheme, Carrier: carrierVar},
		},
	}
	cfg := cfgWith(entry)
	got, err := resolve(cfg, "", Transport{Kind: KindWS, UpstreamURL: "ws://127.0.0.1:8080/sock"}, true)
	if err != nil || got.Source != SourceUnnamed {
		t.Fatalf("resolution = %+v, err = %v, want legacy", got, err)
	}
	if _, err := resolve(cfg, "ws-with-header", Transport{Kind: KindWS, UpstreamURL: "ws://127.0.0.1:8080/sock"}, true); err == nil {
		t.Fatal("claiming the registered name on an unmatched websocket must be refused")
	}
}

func TestResolve_SessionHeader(t *testing.T) {
	cfg := cfgWith(registry()...)
	field := "mcp_identities[0].verified_local_service.session_header"
	tests := []struct {
		name    string
		headers []Header
		wantErr string
	}{
		{"valid", []Header{sessionHeader(bearerOne)}, ""},
		{"valid among other headers", []Header{{Name: "X-Tenant", Value: "a", Source: HeaderSourceFlag}, sessionHeader(bearerOne)}, ""},
		{"lowercase header name still counts", []Header{{Name: "authorization", Value: bearerOne, Source: HeaderSourceCarrier, Carrier: carrierVar}}, ""},
		{"missing", nil, field + ": header Authorization is required and was not supplied"},
		{"missing with unrelated header", []Header{{Name: "X-Tenant", Value: "a", Source: HeaderSourceFlag}}, "was not supplied"},
		{"from a flag", []Header{{Name: "Authorization", Value: bearerOne, Source: HeaderSourceFlag}}, "must come from the " + carrierVar + " carrier, not a flag"},
		{"from a file", []Header{{Name: "Authorization", Value: bearerOne, Source: HeaderSourceFile}}, "not a file"},
		{"wrong carrier name", []Header{{Name: "Authorization", Value: bearerOne, Source: HeaderSourceCarrier, Carrier: "PIPELOCK_VSCODE_OTHER"}}, "not PIPELOCK_VSCODE_OTHER"},
		{"duplicate from carrier and flag", []Header{sessionHeader(bearerOne), {Name: "Authorization", Value: bearerTwo, Source: HeaderSourceFlag}}, "supplied exactly once across all sources; it was supplied 2 times"},
		{"duplicate differently cased", []Header{sessionHeader(bearerOne), {Name: "AUTHORIZATION", Value: bearerTwo, Source: HeaderSourceCarrier, Carrier: carrierVar}}, "supplied 2 times"},
		{"comma combined", []Header{sessionHeader("Bearer a, Bearer b")}, "comma-combined value is refused"},
		{"comma inside a token", []Header{sessionHeader("Bearer a,b")}, "comma-combined"},
		{"non bearer scheme", []Header{sessionHeader("Basic dXNlcjpwdw==")}, "must be \"Bearer <token>\" with exactly one token"},
		{"lowercase scheme", []Header{sessionHeader("bearer token")}, "exactly one token"},
		{"no space", []Header{sessionHeader("Bearertoken")}, "exactly one token"},
		{"empty token", []Header{sessionHeader("Bearer ")}, "exactly one token"},
		{"two tokens", []Header{sessionHeader("Bearer tok1 tok2")}, "exactly one token"},
		{"tab inside token", []Header{sessionHeader("Bearer tok\t1")}, "exactly one token"},
		{"control character in token", []Header{sessionHeader("Bearer tok\x001")}, "exactly one token"},
		{"newline in token", []Header{sessionHeader("Bearer tok\n1")}, "exactly one token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolve(cfg, "", httpLaunch(urlIndexer, tt.headers...), true)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				if !strings.Contains(err.Error(), field) {
					t.Fatalf("err = %v, want it to name %s", err, field)
				}
				return
			}
			if err != nil || got.Source != SourceVerifiedLocalService {
				t.Fatalf("resolution = %+v, err = %v", got, err)
			}
		})
	}
}

func TestResolve_UnsupportedPlatform(t *testing.T) {
	cfg := cfgWith(registry()...)
	t.Run("matching launch is refused", func(t *testing.T) {
		_, err := resolve(cfg, "", httpLaunch(urlIndexer, sessionHeader(bearerOne)), false)
		want := "verified local service requires Linux; this platform cannot verify mcp_identities[0]"
		if err == nil || err.Error() != want {
			t.Fatalf("err = %v, want %q", err, want)
		}
	})
	t.Run("matching launch with the same explicit name is refused", func(t *testing.T) {
		if _, err := resolve(cfg, nameIndexer, httpLaunch(urlIndexer, sessionHeader(bearerOne)), false); err == nil {
			t.Fatal("expected a refusal")
		}
	})
	t.Run("websocket entry is refused", func(t *testing.T) {
		_, err := resolve(cfg, "", Transport{Kind: KindWS, UpstreamURL: urlBridge}, false)
		if err == nil || !strings.Contains(err.Error(), "mcp_identities[1]") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("session header failure is reported before the platform", func(t *testing.T) {
		_, err := resolve(cfg, "", httpLaunch(urlIndexer), false)
		if err == nil || !strings.Contains(err.Error(), "session_header") {
			t.Fatalf("err = %v, want the session header refusal", err)
		}
	})
	t.Run("unmatched launch is unaffected", func(t *testing.T) {
		got, err := resolve(cfg, "", httpLaunch("http://127.0.0.1:5000/other"), false)
		if err != nil || got.Source != SourceUnnamed {
			t.Fatalf("resolution = %+v, err = %v", got, err)
		}
	})
}

func TestResolve_UsesHostPlatform(t *testing.T) {
	cfg := cfgWith(registry()...)
	got, err := Resolve(cfg, "", httpLaunch(urlIndexer, sessionHeader(bearerOne)))
	if runtime.GOOS == "linux" {
		if err != nil || got.Source != SourceVerifiedLocalService {
			t.Fatalf("resolution = %+v, err = %v", got, err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), "requires Linux") {
		t.Fatalf("err = %v, want the non-Linux refusal", err)
	}
}

func TestBuildPin_RequiresUID(t *testing.T) {
	v := *registry()[0].VerifiedLocalService
	v.PrincipalUID = nil
	if _, err := buildPin(3, &v); err == nil || !strings.Contains(err.Error(), "mcp_identities[3].verified_local_service.principal_uid is not set") {
		t.Fatalf("err = %v", err)
	}
	cfg := cfgWith(config.MCPIdentity{Name: "no-uid", VerifiedLocalService: &v})
	if _, err := resolve(cfg, "", httpLaunch(urlIndexer, sessionHeader(bearerOne)), true); err == nil {
		t.Fatal("a registry entry without a uid must not resolve")
	}
}

func TestBuildPin_NoControlEnvironment(t *testing.T) {
	pin, err := buildPin(0, registry()[2].VerifiedLocalService)
	if err != nil {
		t.Fatal(err)
	}
	if pin.ControlEnvironment != nil || len(pin.MappedFiles) != 0 || pin.PrincipalUID != 0 {
		t.Fatalf("pin = %+v", pin)
	}
}

func TestLegacyAndStartupLine(t *testing.T) {
	named := Legacy("plain-server")
	if named.Name != "plain-server" || named.ArmingName != "plain-server" || named.Source != SourceExplicit ||
		named.BindingMode != config.MCPAckBindingModeTransportV2 || named.Revision != "" || named.Pin != nil || named.Entry != nil {
		t.Fatalf("Legacy(name) = %+v", named)
	}
	unnamed := Legacy("")
	if unnamed.Name != "" || unnamed.ArmingName != "" || unnamed.Source != SourceUnnamed || unnamed.BindingMode != config.MCPAckBindingModeTransportV2 {
		t.Fatalf("Legacy(\"\") = %+v", unnamed)
	}

	verified, err := resolve(cfgWith(registry()...), "", httpLaunch(urlIndexer, sessionHeader(bearerOne)), true)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		r    Resolution
		want string
	}{
		{"explicit", named, "MCP identity: server=plain-server source=explicit binding=transport-v2"},
		{"unnamed", unnamed, "MCP identity: server=(unnamed) source=unnamed binding=transport-v2"},
		{"verified", verified, "MCP identity: server=vendor-indexer source=verified-local-service binding=verified-local-session"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StartupLine(tt.r); got != tt.want {
				t.Fatalf("StartupLine = %q, want %q", got, tt.want)
			}
		})
	}
}

// verifiedFixture resolves the indexer entry and returns the resolution with the
// launch that produced it.
func verifiedFixture(t *testing.T) (Resolution, Transport) {
	t.Helper()
	launch := Transport{
		Kind:        KindHTTP,
		UpstreamURL: urlIndexer,
		Headers: []Header{
			{Name: "X-Tenant", Value: "tenant-a", Source: HeaderSourceFlag},
			sessionHeader(bearerOne),
			{Name: "X-Trace", Value: "t1", Source: HeaderSourceFile},
			{Name: "X-Trace", Value: "t2", Source: HeaderSourceFile},
		},
		ChildEnv: []string{"VENDOR_MODE=fast"},
	}
	r, err := resolve(cfgWith(registry()...), "", launch, true)
	if err != nil {
		t.Fatal(err)
	}
	return r, launch
}

func mustBinding(t *testing.T, r Resolution, launch Transport) string {
	t.Helper()
	got, err := SessionBinding(r, launch)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 64 {
		t.Fatalf("binding %q is not a sha256 hex digest", got)
	}
	return got
}

// cloneResolution deep-copies the parts of a resolution a test mutates, so a
// mutation never leaks into the next case.
func cloneResolution(r Resolution) Resolution {
	pin := *r.Pin
	pin.MappedFiles = append(pin.MappedFiles[:0:0], r.Pin.MappedFiles...)
	r.Pin = &pin
	entry := *r.Entry
	v := *r.Entry.VerifiedLocalService
	if v.SessionHeader != nil {
		sh := *v.SessionHeader
		v.SessionHeader = &sh
	}
	entry.VerifiedLocalService = &v
	r.Entry = &entry
	return r
}

func cloneTransport(t Transport) Transport {
	t.Headers = append(t.Headers[:0:0], t.Headers...)
	t.ChildEnv = append(t.ChildEnv[:0:0], t.ChildEnv...)
	return t
}

func TestSessionBinding_Invariants(t *testing.T) {
	r, launch := verifiedFixture(t)
	base := mustBinding(t, r, launch)

	if again := mustBinding(t, r, launch); again != base {
		t.Fatal("the binding must be deterministic")
	}

	tests := []struct {
		name   string
		mutate func(*Transport)
	}{
		{"another ephemeral port", func(tr *Transport) { tr.UpstreamURL = "http://127.0.0.1:50999/rpc/v1" }},
		{"another session bearer value", func(tr *Transport) { tr.Headers[1].Value = bearerTwo }},
		{"session header name in another case", func(tr *Transport) { tr.Headers[1].Name = "authorization" }},
		{"unrelated header names in another case", func(tr *Transport) { tr.Headers[0].Name = "x-tenant" }},
		{"headers listed in another order across names", func(tr *Transport) {
			tr.Headers = []Header{tr.Headers[2], tr.Headers[3], tr.Headers[1], tr.Headers[0]}
		}},
	}
	for _, tt := range tests {
		t.Run("unchanged by "+tt.name, func(t *testing.T) {
			l := cloneTransport(launch)
			tt.mutate(&l)
			if got := mustBinding(t, r, l); got != base {
				t.Fatalf("binding changed: %s != %s", got, base)
			}
		})
	}
}

func TestSessionBinding_ChangesWithEverythingElse(t *testing.T) {
	r, launch := verifiedFixture(t)
	base := mustBinding(t, r, launch)

	resolutionCases := []struct {
		name   string
		mutate func(*Resolution)
	}{
		{"name", func(r *Resolution) { r.Name = "vendor-renamed" }},
		{"revision", func(r *Resolution) { r.Revision = strings.Repeat("0", 64) }},
		{"principal uid", func(r *Resolution) { r.Pin.PrincipalUID = 1002 }},
		{"principal uid zero", func(r *Resolution) { r.Pin.PrincipalUID = 0 }},
		{"executable digest", func(r *Resolution) { r.Pin.ExecutableSHA256 = shaOther }},
		{"mapped file digest", func(r *Resolution) { r.Pin.MappedFiles[0].SHA256 = shaOther }},
		{"mapped file path", func(r *Resolution) { r.Pin.MappedFiles[0].Path = "/opt/vendor/lib/libother.so" }},
		{"extra mapped file", func(r *Resolution) {
			r.Pin.MappedFiles = append(r.Pin.MappedFiles, r.Pin.MappedFiles[0])
			r.Pin.MappedFiles[2].Path = "/opt/vendor/lib/libextra.so"
		}},
		{"dropped mapped file", func(r *Resolution) { r.Pin.MappedFiles = r.Pin.MappedFiles[:1] }},
		{"no mapped files", func(r *Resolution) { r.Pin.MappedFiles = nil }},
		{"matcher scheme", func(r *Resolution) { r.Entry.VerifiedLocalService.Scheme = config.MCPIdentitySchemeHTTPS }},
		{"matcher host", func(r *Resolution) { r.Entry.VerifiedLocalService.Host = config.MCPIdentityHostIPv6Loopback }},
		{"matcher path", func(r *Resolution) { r.Entry.VerifiedLocalService.Path = "/rpc/v2" }},
		{"session header name", func(r *Resolution) { r.Entry.VerifiedLocalService.SessionHeader.Name = "X-Session" }},
		{"session carrier name", func(r *Resolution) { r.Entry.VerifiedLocalService.SessionHeader.Carrier = "PIPELOCK_VSCODE_OTHER" }},
		{"session scheme", func(r *Resolution) { r.Entry.VerifiedLocalService.SessionHeader.Scheme = "Token" }},
		{"no session header declared", func(r *Resolution) { r.Entry.VerifiedLocalService.SessionHeader = nil }},
	}
	for _, tt := range resolutionCases {
		t.Run("resolution "+tt.name, func(t *testing.T) {
			rr := cloneResolution(r)
			tt.mutate(&rr)
			if got := mustBinding(t, rr, launch); got == base {
				t.Fatal("binding did not change")
			}
		})
	}

	launchCases := []struct {
		name   string
		mutate func(*Transport)
	}{
		{"unrelated header value", func(tr *Transport) { tr.Headers[0].Value = "tenant-b" }},
		{"unrelated header removed", func(tr *Transport) { tr.Headers = append(tr.Headers[:0:0], tr.Headers[1:]...) }},
		{"unrelated header added", func(tr *Transport) {
			tr.Headers = append(tr.Headers, Header{Name: "X-Extra", Value: "1", Source: HeaderSourceFlag})
		}},
		{"unrelated header renamed", func(tr *Transport) { tr.Headers[0].Name = "X-Org" }},
		{"repeated header values reordered", func(tr *Transport) {
			tr.Headers[2].Value, tr.Headers[3].Value = tr.Headers[3].Value, tr.Headers[2].Value
		}},
		{"repeated header value dropped", func(tr *Transport) { tr.Headers = tr.Headers[:3] }},
		{"child environment value", func(tr *Transport) { tr.ChildEnv = []string{"VENDOR_MODE=slow"} }},
		{"child environment added", func(tr *Transport) { tr.ChildEnv = append(tr.ChildEnv, "VENDOR_REGION=eu") }},
		{"child environment removed", func(tr *Transport) { tr.ChildEnv = nil }},
	}
	for _, tt := range launchCases {
		t.Run("launch "+tt.name, func(t *testing.T) {
			l := cloneTransport(launch)
			tt.mutate(&l)
			if got := mustBinding(t, r, l); got == base {
				t.Fatal("binding did not change")
			}
		})
	}
}

func TestSessionBinding_MappedFileOrderDoesNotMatter(t *testing.T) {
	r, launch := verifiedFixture(t)
	base := mustBinding(t, r, launch)
	rr := cloneResolution(r)
	rr.Pin.MappedFiles[0], rr.Pin.MappedFiles[1] = rr.Pin.MappedFiles[1], rr.Pin.MappedFiles[0]
	if got := mustBinding(t, rr, launch); got != base {
		t.Fatal("mapped file order must not change the binding")
	}
}

func TestSessionBinding_DomainAndFieldBoundaries(t *testing.T) {
	r, launch := verifiedFixture(t)
	got := mustBinding(t, r, launch)

	// The digest is under its own ServerBindingDigest kind, not transport-v2's.
	for _, kind := range []string{"transport-v2", "upstream", "subprocess"} {
		if other := tools.ServerBindingDigest(kind, r.Name, r.Revision); other == got {
			t.Fatalf("binding equals a %s digest", kind)
		}
	}
	if BindingDomain == "transport-v2" {
		t.Fatal("the verified session binding must not share transport-v2's kind")
	}

	// Content cannot slide across a field boundary: a mapped file path that
	// ends where the next field begins is a different binding.
	a := cloneResolution(r)
	b := cloneResolution(r)
	a.Pin.MappedFiles = []localservice.FilePin{{Path: "/a", SHA256: shaLibA}}
	b.Pin.MappedFiles = []localservice.FilePin{{Path: "/a" + shaLibA, SHA256: ""}}
	if mustBinding(t, a, launch) == mustBinding(t, b, launch) {
		t.Fatal("field boundary is ambiguous")
	}

	// A header value cannot imitate a header name.
	h1 := cloneTransport(launch)
	h1.Headers = []Header{sessionHeader(bearerOne), {Name: "X-A", Value: "x", Source: HeaderSourceFlag}, {Name: "X-B", Value: "y", Source: HeaderSourceFlag}}
	h2 := cloneTransport(launch)
	h2.Headers = []Header{sessionHeader(bearerOne), {Name: "X-A", Value: "x", Source: HeaderSourceFlag}, {Name: "X-A", Value: "header:X-B", Source: HeaderSourceFlag}, {Name: "X-A", Value: "y", Source: HeaderSourceFlag}}
	if mustBinding(t, r, h1) == mustBinding(t, r, h2) {
		t.Fatal("header framing is ambiguous")
	}
}

func TestSessionBinding_NoSessionHeaderDeclared(t *testing.T) {
	cfg := cfgWith(registry()...)
	launch := Transport{Kind: KindWS, UpstreamURL: urlBridge, Headers: []Header{{Name: "Authorization", Value: bearerOne, Source: HeaderSourceFlag}}}
	r, err := resolve(cfg, "", launch, true)
	if err != nil {
		t.Fatal(err)
	}
	base := mustBinding(t, r, launch)

	// With no declared session header every header is bound, a bearer included.
	l := cloneTransport(launch)
	l.Headers[0].Value = bearerTwo
	if mustBinding(t, r, l) == base {
		t.Fatal("an undeclared header value must change the binding")
	}
	// A different port still does not.
	l = cloneTransport(launch)
	l.UpstreamURL = "ws://[::1]:9999/bridge"
	if mustBinding(t, r, l) != base {
		t.Fatal("the port must not change the binding")
	}
}

func TestSessionBinding_RejectsUnverifiedResolution(t *testing.T) {
	verified, launch := verifiedFixture(t)
	noPin := cloneResolution(verified)
	noPin.Pin = nil
	noEntry := cloneResolution(verified)
	noEntry.Entry = nil
	noMatcher := cloneResolution(verified)
	noMatcher.Entry.VerifiedLocalService = nil
	wrongMode := cloneResolution(verified)
	wrongMode.BindingMode = config.MCPAckBindingModeTransportV2

	tests := []struct {
		name string
		r    Resolution
	}{
		{"legacy named", Legacy("plain-server")},
		{"legacy unnamed", Legacy("")},
		{"zero value", Resolution{}},
		{"no pin", noPin},
		{"no entry", noEntry},
		{"no matcher", noMatcher},
		{"transport-v2 mode", wrongMode},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SessionBinding(tt.r, launch)
			if err == nil || got != "" || !strings.Contains(err.Error(), "is not a verified local service") {
				t.Fatalf("binding = %q, err = %v", got, err)
			}
		})
	}
}

func TestResolution_SameAs(t *testing.T) {
	base := Resolution{
		Name: nameIndexer, ArmingName: nameIndexer, Source: SourceVerifiedLocalService,
		Revision: "rev-1", BindingMode: config.MCPAckBindingModeVerifiedLocalSession,
	}
	tests := []struct {
		name   string
		mutate func(*Resolution)
		want   bool
	}{
		{"identical", func(*Resolution) {}, true},
		{"name", func(r *Resolution) { r.Name = nameOther }, false},
		{"arming name", func(r *Resolution) { r.ArmingName = "" }, false},
		{"source", func(r *Resolution) { r.Source = SourceExplicit }, false},
		{"revision", func(r *Resolution) { r.Revision = "rev-2" }, false},
		{"binding mode", func(r *Resolution) { r.BindingMode = config.MCPAckBindingModeTransportV2 }, false},
		{"pin and entry are not compared", func(r *Resolution) { r.Pin = &localservice.Pin{}; r.Entry = &config.MCPIdentity{} }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			other := base
			tt.mutate(&other)
			if got := base.SameAs(other); got != tt.want {
				t.Errorf("SameAs = %v, want %v", got, tt.want)
			}
			if got := other.SameAs(base); got != tt.want {
				t.Errorf("SameAs is not symmetric: reverse = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeclaresSessionHeader(t *testing.T) {
	dup := registry()[0]
	dup.Name = nameOther
	tests := []struct {
		name    string
		cfg     *config.Config
		launch  Transport
		wantIdx int
		want    bool
	}{
		{"nil config", nil, httpLaunch(urlIndexer), 0, false},
		{"entry with a session header", cfgWith(registry()...), httpLaunch(urlIndexer), 0, true},
		{"entry without a session header", cfgWith(registry()...), httpLaunch(urlV6API), 0, false},
		{"websocket entry without a session header", cfgWith(registry()...), Transport{Kind: KindWS, UpstreamURL: urlBridge}, 0, false},
		{"no registration matches", cfgWith(registry()...), httpLaunch("http://127.0.0.1:5000/other"), 0, false},
		{"empty registry", cfgWith(), httpLaunch(urlIndexer), 0, false},
		{"ambiguous match declares nothing", cfgWith(append(registry(), dup)...), httpLaunch(urlIndexer), 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			idx, got := DeclaresSessionHeader(tt.cfg, tt.launch)
			if got != tt.want || (got && idx != tt.wantIdx) {
				t.Errorf("DeclaresSessionHeader = (%d, %v), want (%d, %v)", idx, got, tt.wantIdx, tt.want)
			}
		})
	}
}
