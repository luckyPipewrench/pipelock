// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy

import (
	"net/http"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func mustMatcher(t *testing.T, rules ...config.RequestPolicyRule) *Matcher {
	t.Helper()
	m, err := NewMatcher(&config.RequestPolicy{Enabled: true, Rules: rules})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	return m
}

func apiWriteRule() config.RequestPolicyRule {
	return config.RequestPolicyRule{
		Name:   "api-write",
		Action: config.ActionBlock,
		Route: config.RequestPolicyRoute{
			Hosts:        []string{"api.service.example.com"},
			Methods:      []string{http.MethodPost},
			PathPrefixes: []string{"/api/write"},
			ContentTypes: []string{"application/json; charset=utf-8"},
		},
		Reason: "destructive API operation",
	}
}

func TestEvaluate_RouteMatch(t *testing.T) {
	m := mustMatcher(t, apiWriteRule())
	tests := []struct {
		name      string
		meta      RequestMeta
		wantBlock bool
	}{
		{
			name:      "full match",
			meta:      RequestMeta{Host: "api.service.example.com", Method: "POST", Path: "/api/write", ContentType: "application/json"},
			wantBlock: true,
		},
		{
			name:      "path prefix deeper still matches",
			meta:      RequestMeta{Host: "api.service.example.com", Method: "POST", Path: "/api/write/v2", ContentType: "application/json"},
			wantBlock: true,
		},
		{
			name:      "host port normalized",
			meta:      RequestMeta{Host: "api.service.example.com:443", Method: "POST", Path: "/api/write", ContentType: "application/json"},
			wantBlock: true,
		},
		{
			name:      "request path normalized before match",
			meta:      RequestMeta{Host: "api.service.example.com", Method: "POST", Path: "/api//write/../write", ContentType: "application/json"},
			wantBlock: true,
		},
		{
			name:      "content type parameters normalized",
			meta:      RequestMeta{Host: "api.service.example.com", Method: "POST", Path: "/api/write", ContentType: "Application/JSON; Charset=UTF-8"},
			wantBlock: true,
		},
		{
			name: "wrong host",
			meta: RequestMeta{Host: "api.other.example.com", Method: "POST", Path: "/api/write", ContentType: "application/json"},
		},
		{
			name: "wrong method",
			meta: RequestMeta{Host: "api.service.example.com", Method: "GET", Path: "/api/write", ContentType: "application/json"},
		},
		{
			name: "wrong path",
			meta: RequestMeta{Host: "api.service.example.com", Method: "POST", Path: "/api/read", ContentType: "application/json"},
		},
		{
			name: "wrong content type",
			meta: RequestMeta{Host: "api.service.example.com", Method: "POST", Path: "/api/write", ContentType: "text/plain"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := m.Evaluate(tc.meta)
			if tc.wantBlock {
				if got.Action != config.ActionBlock || !got.Enforced() || got.RuleName != "api-write" {
					t.Fatalf("want enforced block from api-write, got %+v", got)
				}
			} else if got.Matched() {
				t.Fatalf("want allow (no match), got %+v", got)
			}
		})
	}
}

func TestEvaluate_WildcardHostAndPathPattern(t *testing.T) {
	m := mustMatcher(t, config.RequestPolicyRule{
		Name:   "api-dangerous-path",
		Action: config.ActionBlock,
		Route: config.RequestPolicyRoute{
			Hosts:        []string{"*.service.example.com"},
			Methods:      []string{http.MethodPost, http.MethodDelete},
			PathPatterns: []string{`^/v1/(accounts|users/[^/]+)/dangerous-action$`},
		},
	})
	tests := []struct {
		name      string
		meta      RequestMeta
		wantBlock bool
	}{
		{"subdomain + pattern", RequestMeta{Host: "api.service.example.com", Method: "POST", Path: "/v1/accounts/dangerous-action"}, true},
		{"apex via wildcard", RequestMeta{Host: "service.example.com", Method: "DELETE", Path: "/v1/users/abc/dangerous-action"}, true},
		{"pattern miss", RequestMeta{Host: "api.service.example.com", Method: "POST", Path: "/v1/accounts/messages"}, false},
		{"unrelated host", RequestMeta{Host: "other.example.com", Method: "POST", Path: "/v1/accounts/dangerous-action"}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := m.Evaluate(tc.meta)
			if got.Enforced() != tc.wantBlock {
				t.Fatalf("Enforced()=%v want %v (decision %+v)", got.Enforced(), tc.wantBlock, got)
			}
		})
	}
}

func TestEvaluate_RouteOnlyMatchesAnyPath(t *testing.T) {
	m := mustMatcher(t, config.RequestPolicyRule{
		Name:   "host-only",
		Action: config.ActionWarn,
		Route:  config.RequestPolicyRoute{Hosts: []string{"api.service.example.com"}},
	})
	got := m.Evaluate(RequestMeta{Host: "api.service.example.com", Method: "GET", Path: "/anything/at/all"})
	if got.Action != config.ActionWarn || !got.Enforced() {
		t.Fatalf("want warn, got %+v", got)
	}
}

func TestEvaluate_DisabledAllowsEverything(t *testing.T) {
	m, err := NewMatcher(&config.RequestPolicy{Enabled: false, Rules: []config.RequestPolicyRule{apiWriteRule()}})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	if got := m.Evaluate(RequestMeta{Host: "api.service.example.com", Method: "POST", Path: "/api/write", ContentType: "application/json"}); got.Matched() {
		t.Fatalf("disabled matcher should allow, got %+v", got)
	}
	// nil config and nil matcher both allow.
	nilCfg, _ := NewMatcher(nil)
	if nilCfg.Evaluate(RequestMeta{Host: "x"}).Matched() {
		t.Fatal("nil-config matcher should allow")
	}
	var nilM *Matcher
	if nilM.Evaluate(RequestMeta{Host: "x"}).Matched() {
		t.Fatal("nil matcher should allow")
	}
}

func TestEvaluate_Shadow(t *testing.T) {
	r := apiWriteRule()
	r.Shadow = true
	m := mustMatcher(t, r)
	got := m.Evaluate(RequestMeta{Host: "api.service.example.com", Method: "POST", Path: "/api/write", ContentType: "application/json"})
	if !got.Matched() {
		t.Fatal("shadow rule should match")
	}
	if got.Enforced() {
		t.Fatalf("shadow rule must not enforce, got %+v", got)
	}
	if !got.Shadow || got.Action != config.ActionBlock {
		t.Fatalf("want shadow block decision, got %+v", got)
	}
}

func TestEvaluate_StrictestWins(t *testing.T) {
	warnRule := config.RequestPolicyRule{
		Name:   "warn-all-posts",
		Action: config.ActionWarn,
		Route:  config.RequestPolicyRoute{Hosts: []string{"api.service.example.com"}, Methods: []string{http.MethodPost}},
	}
	blockRule := apiWriteRule()
	meta := RequestMeta{Host: "api.service.example.com", Method: "POST", Path: "/api/write", ContentType: "application/json"}

	// Order must not matter: block wins regardless of which rule is first.
	for _, order := range [][]config.RequestPolicyRule{
		{warnRule, blockRule},
		{blockRule, warnRule},
	} {
		m := mustMatcher(t, order...)
		if got := m.Evaluate(meta); got.Action != config.ActionBlock || got.RuleName != "api-write" {
			t.Fatalf("block must win over warn, got %+v", got)
		}
	}
}

func TestEvaluate_EnforcedPreferredOverShadow(t *testing.T) {
	shadowBlock := apiWriteRule()
	shadowBlock.Name = "shadow-block"
	shadowBlock.Shadow = true
	enforcedBlock := apiWriteRule()
	enforcedBlock.Name = "enforced-block"
	meta := RequestMeta{Host: "api.service.example.com", Method: "POST", Path: "/api/write", ContentType: "application/json"}
	m := mustMatcher(t, shadowBlock, enforcedBlock)
	got := m.Evaluate(meta)
	if !got.Enforced() || got.RuleName != "enforced-block" {
		t.Fatalf("enforced block must be preferred over shadow at same strictness, got %+v", got)
	}
}

func TestMatcher_OperationHelpers(t *testing.T) {
	r := apiWriteRule()
	r.GraphQL = &config.RequestPolicyGraphQL{
		OperationTypes:    []string{gqlMutation},
		RootFieldPatterns: []string{`^deleteRecord$`},
	}
	m, err := NewMatcher(&config.RequestPolicy{
		Enabled:           true,
		OnParseError:      config.ActionWarn,
		OnOpaqueOperation: config.ActionBlock,
		Rules:             []config.RequestPolicyRule{r},
	})
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	meta := RequestMeta{Host: "api.service.example.com", Method: "POST", Path: "/api/write", ContentType: "application/json"}
	if !m.NeedsBodyPredicate(meta) {
		t.Fatal("route-matched GraphQL rule should need operation extraction")
	}
	if m.NeedsBodyPredicate(RequestMeta{Host: "api.service.example.com", Method: "GET", Path: "/api/write", ContentType: "application/json"}) {
		t.Fatal("non-route-matching request should not need operation extraction")
	}
	if got := m.OnParseError(); got != config.ActionWarn {
		t.Fatalf("OnParseError = %q, want warn", got)
	}
	if got := m.OnOpaqueOperation(); got != config.ActionBlock {
		t.Fatalf("OnOpaqueOperation = %q, want block", got)
	}
	parseDecision := m.EvaluateUninspectable(meta, m.OnParseError(), PredGraphQL)
	if parseDecision.Action != config.ActionWarn || parseDecision.RuleName != "api-write" {
		t.Fatalf("parse decision = %+v, want warn from api-write", parseDecision)
	}
	if got := m.EvaluateUninspectable(meta, config.ActionAllow, PredGraphQL); got.Matched() {
		t.Fatalf("allow uninspectable action should produce no decision, got %+v", got)
	}
	var nilM *Matcher
	if nilM.OnParseError() != config.ActionBlock || nilM.OnOpaqueOperation() != config.ActionBlock {
		t.Fatal("nil matcher should default fail-closed actions to block")
	}
}

func TestStricter(t *testing.T) {
	block := Decision{Action: config.ActionBlock, RuleName: "block"}
	warn := Decision{Action: config.ActionWarn, RuleName: "warn"}
	if got := Stricter(warn, block); got.RuleName != "block" {
		t.Fatalf("Stricter(warn, block) = %+v, want block", got)
	}
	if got := Stricter(block, warn); got.RuleName != "block" {
		t.Fatalf("Stricter(block, warn) = %+v, want block", got)
	}
}

func TestNewMatcher_BadPattern(t *testing.T) {
	_, err := NewMatcher(&config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{{
		Name:   "bad",
		Action: config.ActionBlock,
		Route:  config.RequestPolicyRoute{PathPatterns: []string{"("}},
	}}})
	if err == nil {
		t.Fatal("expected compile error for invalid path_pattern")
	}
}

func TestNormalizePath(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", "/"},
		{"/a/b", "/a/b"},
		{"/a//b", "/a/b"},
		{"/a/../b", "/b"},
		{"/a/%2e%2e/b", "/b"},     // single-encoded dot segment
		{"/a/%252e%252e/b", "/b"}, // double-encoded dot segment
		{"/v1/accounts/dangerous-action", "/v1/accounts/dangerous-action"},
		{"/a/%zz/b", "/a/%zz/b"},          // invalid percent-encoding: decode aborts, left as-is
		{"/seg;jsessionid=1/x", "/seg/x"}, // strip path params
		{"/a/b?x=1", "/a/b"},              // drop query
		{"/a/b#frag", "/a/b"},             // drop fragment
		{"/a/b/", "/a/b/"},                // preserve trailing slash
		{"/%2f/x", "/x"},                  // encoded slash revealed then collapsed
	}
	for _, tc := range tests {
		if got := NormalizePath(tc.in); got != tc.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestEffectiveMethod(t *testing.T) {
	tests := []struct {
		name     string
		method   string
		override map[string]string
		want     string
	}{
		{"plain post", "POST", nil, "POST"},
		{"lowercase normalized", "post", nil, "POST"},
		{"x-http-method-override", "POST", map[string]string{"X-HTTP-Method-Override": "DELETE"}, "DELETE"},
		{"x-method-override", "POST", map[string]string{"X-Method-Override": "delete"}, "DELETE"},
		{"x-http-method", "POST", map[string]string{"X-HTTP-Method": "PATCH"}, "PATCH"},
		{"invalid override falls back to base method", "POST", map[string]string{"X-HTTP-Method-Override": "DELETE, GET"}, "POST"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tc.override {
				h.Set(k, v)
			}
			if got := EffectiveMethod(tc.method, h); got != tc.want {
				t.Errorf("EffectiveMethod(%q, %v) = %q, want %q", tc.method, tc.override, got, tc.want)
			}
		})
	}
}

func TestNormalizeHost(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"api.service.example.com", "api.service.example.com"},
		{"API.Service.Example.com.", "api.service.example.com"},
		{"api.service.example.com:443", "api.service.example.com"},
		{"api.service.example.com:", "api.service.example.com"},
		{"https://api.service.example.com:443/path", "api.service.example.com"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"2001:db8::1", "2001:db8::1"},
	}
	for _, tc := range tests {
		if got := NormalizeHost(tc.in); got != tc.want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeContentType(t *testing.T) {
	tests := []struct{ in, want string }{
		{"application/json", "application/json"},
		{"application/json; charset=utf-8", "application/json"},
		{"  Application/JSON ; x=y", "application/json"},
		{"multipart/form-data; boundary=abc", "multipart/form-data"},
	}
	for _, tc := range tests {
		if got := NormalizeContentType(tc.in); got != tc.want {
			t.Errorf("NormalizeContentType(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestBetterDecision(t *testing.T) {
	block := Decision{Action: config.ActionBlock}
	warn := Decision{Action: config.ActionWarn}
	shadowBlock := Decision{Action: config.ActionBlock, Shadow: true}
	none := Decision{}
	tests := []struct {
		name      string
		cand, cur Decision
		want      bool
	}{
		{"block over none", block, none, true},
		{"none over none", none, none, false},
		{"warn under block", warn, block, false},
		{"block over warn", block, warn, true},
		{"enforced over shadow, same action", block, shadowBlock, true},
		{"shadow under enforced, same action", shadowBlock, block, false},
		{"equal enforced does not replace", block, block, false},
	}
	for _, tc := range tests {
		if got := betterDecision(tc.cand, tc.cur); got != tc.want {
			t.Errorf("%s: betterDecision = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestPathEntropyExempt(t *testing.T) {
	const (
		host    = "api.vendor.example"
		idPath  = "/v1/messages/Xp9Qn0vM6Kf2Tz8Lr4Wd1"
		newPath = "/v1/other/Xp9Qn0vM6Kf2Tz8Lr4Wd1"
	)

	govRoute := config.RequestPolicyRoute{
		Hosts:        []string{host},
		PathPatterns: []string{`^/v1/messages/`},
	}
	hostlessRoute := config.RequestPolicyRoute{
		PathPatterns: []string{`^/v1/messages/`},
	}
	hostOnlyRoute := config.RequestPolicyRoute{
		Hosts: []string{host},
	}
	prefixRoute := config.RequestPolicyRoute{
		Hosts:        []string{host},
		PathPrefixes: []string{"/v1/messages/"},
	}
	wildcardRoute := config.RequestPolicyRoute{
		Hosts:        []string{"*.vendor.example"},
		PathPatterns: []string{`^/v1/messages/`},
	}

	rule := func(r config.RequestPolicyRoute) config.RequestPolicyRule {
		return config.RequestPolicyRule{Name: "r", Action: config.ActionBlock, Route: r}
	}

	tests := []struct {
		name    string
		cfg     *config.RequestPolicy
		host    string
		path    string
		want    bool
		comment string
	}{
		{
			name: "governed host and path exempts",
			cfg:  &config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{rule(govRoute)}},
			host: host, path: idPath, want: true,
		},
		{
			name: "governed host but ungoverned path not exempt",
			cfg:  &config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{rule(govRoute)}},
			host: host, path: newPath, want: false,
		},
		{
			name: "ungoverned host not exempt",
			cfg:  &config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{rule(govRoute)}},
			host: "evil.example", path: idPath, want: false,
			comment: "another host must still get path entropy",
		},
		{
			name: "hostless route never exempts (would match every host)",
			cfg:  &config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{rule(hostlessRoute)}},
			host: "evil.example", path: idPath, want: false,
		},
		{
			name: "host-only route (no path constraint) never exempts",
			cfg:  &config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{rule(hostOnlyRoute)}},
			host: host, path: idPath, want: false,
			comment: "host-only would otherwise exempt the whole host",
		},
		{
			name: "path_prefixes governance exempts on prefix match",
			cfg:  &config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{rule(prefixRoute)}},
			host: host, path: idPath, want: true,
		},
		{
			name: "wildcard host exempts matching subdomain",
			cfg:  &config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{rule(wildcardRoute)}},
			host: "tenant1.vendor.example", path: idPath, want: true,
		},
		{
			name: "disabled section never exempts",
			cfg:  &config.RequestPolicy{Enabled: false, Rules: []config.RequestPolicyRule{rule(govRoute)}},
			host: host, path: idPath, want: false,
		},
		{
			name: "shadow route never exempts",
			cfg: &config.RequestPolicy{Enabled: true, Rules: []config.RequestPolicyRule{{
				Name:   "shadow",
				Action: config.ActionBlock,
				Shadow: true,
				Route:  govRoute,
			}}},
			host: host, path: idPath, want: false,
			comment: "shadow rules do not enforce request_policy and must not relax entropy",
		},
		{
			name: "batch route exempts on host and path",
			cfg: &config.RequestPolicy{Enabled: true, Batch: []config.RequestPolicyBatch{{
				Route: govRoute, RequestsField: "requests",
			}}},
			host: host, path: idPath, want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewMatcher(tt.cfg)
			if err != nil {
				t.Fatalf("NewMatcher: %v", err)
			}
			if got := m.PathEntropyExempt(tt.host, tt.path); got != tt.want {
				t.Errorf("PathEntropyExempt(%q, %q) = %v, want %v (%s)", tt.host, tt.path, got, tt.want, tt.comment)
			}
		})
	}
}

func TestPathEntropyExempt_NilMatcher(t *testing.T) {
	var m *Matcher
	if m.PathEntropyExempt("api.vendor.example", "/v1/messages/abc") {
		t.Error("nil matcher must never exempt")
	}
}
