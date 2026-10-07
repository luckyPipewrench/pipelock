// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	prefixRouteHost      = "challenge.vendor.example"
	prefixRoutePrefix    = "/cdn-cgi/challenge/"
	contentTypeFormEnc   = "application/x-www-form-urlencoded"
	contentTypeJSON      = "application/json"
	contentTypeOctet     = "application/octet-stream"
	errNameBothPathKinds = "sets both path and path_prefix"
)

func prefixRoute(prefix string) RequestBodyEntropyWarnRoute {
	return RequestBodyEntropyWarnRoute{
		Host: prefixRouteHost, PathPrefix: prefix, ContentTypes: []string{contentTypeFormEnc, contentTypeJSON},
		Reason: "service-issued bot challenge", Owner: "platform team", Expires: temporaryExpiryDate(MaxRequestBodyEntropyWarnRouteHorizon),
	}
}

func warnRouteConfig(routes ...RequestBodyEntropyWarnRoute) *Config {
	cfg := validEntropyWarnRouteConfig()
	cfg.RequestBodyScanning.ContentEntropyWarnRoutes = routes
	return cfg
}

func TestValidateEntropyWarnRoutePathAndPrefix(t *testing.T) {
	exact := func(path string, types ...string) RequestBodyEntropyWarnRoute {
		r := prefixRoute("")
		r.Path = path
		r.ContentTypes = types
		return r
	}
	withPrefix := func(prefix string, mutate func(*RequestBodyEntropyWarnRoute)) RequestBodyEntropyWarnRoute {
		r := prefixRoute(prefix)
		if mutate != nil {
			mutate(&r)
		}
		return r
	}
	octetPrefix := func(prefix string, mutate func(*RequestBodyEntropyWarnRoute)) RequestBodyEntropyWarnRoute {
		r := prefixRoute(prefix)
		r.ContentTypes = []string{contentTypeOctet}
		if mutate != nil {
			mutate(&r)
		}
		return r
	}
	tests := []struct {
		name   string
		routes []RequestBodyEntropyWarnRoute
		want   string // empty means valid
	}{
		{"prefix with trailing slash and textual types", []RequestBodyEntropyWarnRoute{prefixRoute(prefixRoutePrefix)}, ""},
		{"prefix without trailing slash", []RequestBodyEntropyWarnRoute{prefixRoute("/cdn-cgi/challenge")}, ""},
		{"prefix with text/plain", []RequestBodyEntropyWarnRoute{withPrefix("/c/", func(r *RequestBodyEntropyWarnRoute) { r.ContentTypes = []string{"text/plain"} })}, ""},
		{"exact path non-textual", []RequestBodyEntropyWarnRoute{exact("/v1/files", contentTypeOctet)}, ""},
		{"exact path rejects textual json", []RequestBodyEntropyWarnRoute{exact("/v1/files", contentTypeJSON)}, "textual/scannable"},
		{"exact path rejects textual form", []RequestBodyEntropyWarnRoute{exact("/v1/files", contentTypeFormEnc)}, "textual/scannable"},
		{"exact path rejects textual plain", []RequestBodyEntropyWarnRoute{exact("/v1/files", "text/plain")}, "textual/scannable"},
		{"both path and prefix", []RequestBodyEntropyWarnRoute{withPrefix(prefixRoutePrefix, func(r *RequestBodyEntropyWarnRoute) { r.Path = "/v1/files" })}, errNameBothPathKinds},
		{"neither path nor prefix", []RequestBodyEntropyWarnRoute{withPrefix("", nil)}, "exactly one of path or path_prefix"},
		{"blank prefix is neither", []RequestBodyEntropyWarnRoute{withPrefix("   ", nil)}, "exactly one of path or path_prefix"},
		{"root prefix", []RequestBodyEntropyWarnRoute{withPrefix("/", nil)}, "exempts every path"},
		{"no leading slash", []RequestBodyEntropyWarnRoute{withPrefix("cdn-cgi/challenge/", nil)}, "must start with /"},
		{"url instead of path", []RequestBodyEntropyWarnRoute{withPrefix("https://challenge.vendor.example/x/", nil)}, "must start with /"},
		{"url after slash", []RequestBodyEntropyWarnRoute{withPrefix("/x://y/", nil)}, "not a URL"},
		{"encoded slash", []RequestBodyEntropyWarnRoute{withPrefix("/cdn-cgi%2fchallenge/", nil)}, "encoded slash"},
		{"encoded backslash", []RequestBodyEntropyWarnRoute{withPrefix("/cdn-cgi%5cchallenge/", nil)}, "encoded slash"},
		{"traversal", []RequestBodyEntropyWarnRoute{withPrefix("/cdn-cgi/../challenge/", nil)}, "canonical"},
		{"dot segment", []RequestBodyEntropyWarnRoute{withPrefix("/cdn-cgi/./challenge/", nil)}, "canonical"},
		{"wildcard", []RequestBodyEntropyWarnRoute{withPrefix("/cdn-cgi/*/", nil)}, "wildcard"},
		{"query delimiter", []RequestBodyEntropyWarnRoute{withPrefix("/cdn-cgi/c?x=1", nil)}, "query"},
		{"control character", []RequestBodyEntropyWarnRoute{withPrefix("/cdn-cgi/c\x01/", nil)}, "control"},
		{"double slash segment", []RequestBodyEntropyWarnRoute{withPrefix("/cdn-cgi//challenge/", nil)}, "canonical"},
		{"prefix needs content types", []RequestBodyEntropyWarnRoute{withPrefix(prefixRoutePrefix, func(r *RequestBodyEntropyWarnRoute) { r.ContentTypes = nil })}, "content_types must contain at least one media type"},
		{"prefix needs reason", []RequestBodyEntropyWarnRoute{withPrefix(prefixRoutePrefix, func(r *RequestBodyEntropyWarnRoute) { r.Reason = "" })}, "reason is required"},
		{"prefix needs owner", []RequestBodyEntropyWarnRoute{withPrefix(prefixRoutePrefix, func(r *RequestBodyEntropyWarnRoute) { r.Owner = "" })}, "owner is required"},
		{"prefix needs expires", []RequestBodyEntropyWarnRoute{withPrefix(prefixRoutePrefix, func(r *RequestBodyEntropyWarnRoute) { r.Expires = "" })}, "must be YYYY-MM-DD"},
		{"prefix expired", []RequestBodyEntropyWarnRoute{withPrefix(prefixRoutePrefix, func(r *RequestBodyEntropyWarnRoute) { r.Expires = "2020-01-01" })}, "already expired"},
		{"prefix beyond horizon", []RequestBodyEntropyWarnRoute{withPrefix(prefixRoutePrefix, func(r *RequestBodyEntropyWarnRoute) {
			r.Expires = temporaryExpiryDate(MaxRequestBodyEntropyWarnRouteHorizon + 10*24*time.Hour)
		})}, "maximum temporary horizon"},
		{"prefix wildcard host", []RequestBodyEntropyWarnRoute{withPrefix(prefixRoutePrefix, func(r *RequestBodyEntropyWarnRoute) { r.Host = "*.vendor.example" })}, "exact host"},

		// Overlap: a prefix overlaps any exact or prefix route it covers. Exact
		// routes cannot carry textual types, so the shared type here is octet-stream.
		{"prefix covers exact", []RequestBodyEntropyWarnRoute{octetPrefix(prefixRoutePrefix, nil), exact("/cdn-cgi/challenge/abc", contentTypeOctet)}, "overlaps content_entropy_warn_routes[0]"},
		{"exact then prefix covering it", []RequestBodyEntropyWarnRoute{exact("/cdn-cgi/challenge/abc", contentTypeOctet), octetPrefix(prefixRoutePrefix, nil)}, "overlaps content_entropy_warn_routes[0]"},
		{"prefix covers its own base as exact", []RequestBodyEntropyWarnRoute{octetPrefix("/cdn-cgi/challenge", nil), exact("/cdn-cgi/challenge", contentTypeOctet)}, "overlaps"},
		{"trailing-slash prefix does not cover its base", []RequestBodyEntropyWarnRoute{octetPrefix("/cdn-cgi/challenge/", nil), exact("/cdn-cgi/challenge", contentTypeOctet)}, ""},
		{"nested prefixes", []RequestBodyEntropyWarnRoute{prefixRoute("/cdn-cgi/"), prefixRoute("/cdn-cgi/challenge/")}, "overlaps"},
		{"nested prefixes reversed", []RequestBodyEntropyWarnRoute{prefixRoute("/cdn-cgi/challenge/"), prefixRoute("/cdn-cgi/")}, "overlaps"},
		{"identical prefixes", []RequestBodyEntropyWarnRoute{prefixRoute(prefixRoutePrefix), prefixRoute(prefixRoutePrefix)}, "overlaps"},
		{"slash and bare prefix of one base", []RequestBodyEntropyWarnRoute{prefixRoute("/cdn-cgi/challenge"), prefixRoute("/cdn-cgi/challenge/")}, "overlaps"},
		{"sibling prefix sharing leading characters", []RequestBodyEntropyWarnRoute{prefixRoute("/cdn-cgi/challenge"), prefixRoute("/cdn-cgi/challengeX")}, ""},
		{"exact sibling not under prefix", []RequestBodyEntropyWarnRoute{octetPrefix("/cdn-cgi/challenge", nil), exact("/cdn-cgi/challengeX", contentTypeOctet)}, ""},
		{"prefix and exact with disjoint content types", []RequestBodyEntropyWarnRoute{prefixRoute(prefixRoutePrefix), exact("/cdn-cgi/challenge/abc", contentTypeOctet)}, ""},
		{"prefix and exact with disjoint methods", []RequestBodyEntropyWarnRoute{
			octetPrefix(prefixRoutePrefix, func(r *RequestBodyEntropyWarnRoute) { r.Methods = []string{"POST"} }),
			func() RequestBodyEntropyWarnRoute {
				r := exact("/cdn-cgi/challenge/abc", contentTypeOctet)
				r.Methods = []string{"PUT"}
				return r
			}(),
		}, ""},
		{"prefix and exact on different hosts", []RequestBodyEntropyWarnRoute{
			octetPrefix(prefixRoutePrefix, nil),
			func() RequestBodyEntropyWarnRoute {
				r := exact("/cdn-cgi/challenge/abc", contentTypeOctet)
				r.Host = "other.vendor.example"
				return r
			}(),
		}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := warnRouteConfig(tt.routes...)
			err := cfg.Validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("Validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestValidateEntropyWarnRoutePrefixIsStoredCanonical(t *testing.T) {
	for _, tt := range []struct{ in, want string }{
		{"/cdn-cgi/challenge/", "/cdn-cgi/challenge/"},
		{"/cdn-cgi/challenge", "/cdn-cgi/challenge"},
		{"  /cdn-cgi/challenge/  ", "/cdn-cgi/challenge/"},
	} {
		cfg := warnRouteConfig(prefixRoute(tt.in))
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate(%q): %v", tt.in, err)
		}
		if got := cfg.RequestBodyScanning.ContentEntropyWarnRoutes[0].PathPrefix; got != tt.want {
			t.Fatalf("stored prefix for %q = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRequestPathHasSegmentPrefix(t *testing.T) {
	tests := []struct {
		path, prefix string
		want         bool
	}{
		{"/cdn-cgi/challenge/abc123", "/cdn-cgi/challenge", true},
		{"/cdn-cgi/challenge/abc123", "/cdn-cgi/challenge/", true},
		{"/cdn-cgi/challenge", "/cdn-cgi/challenge", true},
		{"/cdn-cgi/challenge", "/cdn-cgi/challenge/", false},
		{"/cdn-cgi/challengeX", "/cdn-cgi/challenge", false},
		{"/cdn-cgi/challengeX/abc", "/cdn-cgi/challenge", false},
		{"/cdn-cgi/challengeX", "/cdn-cgi/challenge/", false},
		{"/cdn-cgi", "/cdn-cgi/challenge", false},
		{"/other/cdn-cgi/challenge/x", "/cdn-cgi/challenge", false},
		{"/anything", "", false},
		{"/anything", "/", false},
	}
	for _, tt := range tests {
		if got := RequestPathHasSegmentPrefix(tt.path, tt.prefix); got != tt.want {
			t.Errorf("RequestPathHasSegmentPrefix(%q, %q) = %t, want %t", tt.path, tt.prefix, got, tt.want)
		}
	}
}

func TestEntropyHostExclusionYAMLShapes(t *testing.T) {
	future := temporaryExpiryDate(MaxContentEntropyHostExclusionHorizon)
	tests := []struct {
		name string
		yaml string
		want []EntropyHostExclusion
		err  string
	}{
		{"omitted", "request_body_scanning:\n  content_entropy_action: block\n", nil, ""},
		{"null", "request_body_scanning:\n  content_entropy_exclusions: null\n", nil, ""},
		{"blank", "request_body_scanning:\n  content_entropy_exclusions:\n", nil, ""},
		{"empty list", "request_body_scanning:\n  content_entropy_exclusions: []\n", []EntropyHostExclusion{}, ""},
		{"plain strings", "request_body_scanning:\n  content_entropy_exclusions:\n    - a.vendor.example\n    - b.vendor.example\n", EntropyHostExclusions("a.vendor.example", "b.vendor.example"), ""},
		{"mappings", "request_body_scanning:\n  content_entropy_exclusions:\n    - host: a.vendor.example\n      expires: " + future + "\n      reason: challenge\n      owner: platform\n", []EntropyHostExclusion{{Host: "a.vendor.example", Expires: future, Reason: "challenge", Owner: "platform", mapped: true}}, ""},
		{"mapping without reason or owner", "request_body_scanning:\n  content_entropy_exclusions:\n    - host: a.vendor.example\n      expires: " + future + "\n", []EntropyHostExclusion{{Host: "a.vendor.example", Expires: future, mapped: true}}, ""},
		{"mixed", "request_body_scanning:\n  content_entropy_exclusions:\n    - plain.vendor.example\n    - host: a.vendor.example\n      expires: " + future + "\n", []EntropyHostExclusion{{Host: "plain.vendor.example"}, {Host: "a.vendor.example", Expires: future, mapped: true}}, ""},
		{"mapping missing expires", "request_body_scanning:\n  content_entropy_exclusions:\n    - host: a.vendor.example\n", nil, "expires is required"},
		{"mapping missing host", "request_body_scanning:\n  content_entropy_exclusions:\n    - expires: " + future + "\n", nil, "is empty"},
		{"mapping unknown field", "request_body_scanning:\n  content_entropy_exclusions:\n    - host: a.vendor.example\n      expires: " + future + "\n      expiry: 2030-01-01\n", nil, "unsupported field"},
		{"sequence entry", "request_body_scanning:\n  content_entropy_exclusions:\n    - [a.vendor.example]\n", nil, "host string or a"},
		// yaml.v3 skips a null sequence element before it reaches any element type,
		// so this decodes exactly as it did for []string.
		{"null entry is skipped as before", "request_body_scanning:\n  content_entropy_exclusions:\n    -\n", nil, ""},
		{"expired mapping", "request_body_scanning:\n  content_entropy_exclusions:\n    - host: a.vendor.example\n      expires: 2020-01-01\n", nil, "already expired"},
		{"mapping beyond horizon", "request_body_scanning:\n  content_entropy_exclusions:\n    - host: a.vendor.example\n      expires: " + temporaryExpiryDate(MaxContentEntropyHostExclusionHorizon+20*24*time.Hour) + "\n", nil, "maximum temporary horizon"},
		{"bad date", "request_body_scanning:\n  content_entropy_exclusions:\n    - host: a.vendor.example\n      expires: tomorrow\n", nil, "YYYY-MM-DD"},
		{"mapping over-broad host", "request_body_scanning:\n  content_entropy_exclusions:\n    - host: '*.com'\n      expires: " + future + "\n", nil, "content_entropy_exclusions[0]"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(path, []byte("mode: balanced\n"+tt.yaml), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			cfg, err := Load(path)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) {
					t.Fatalf("Load error = %v, want substring %q", err, tt.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			got := cfg.RequestBodyScanning.ContentEntropyExclusions
			if len(got) == 0 && len(tt.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("exclusions = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestEntropyHostExclusionWebSocketYAMLShapes(t *testing.T) {
	future := temporaryExpiryDate(MaxContentEntropyHostExclusionHorizon)
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	body := "mode: balanced\nwebsocket_proxy:\n  content_entropy_exclusions:\n    - ws.vendor.example\n    - host: ws2.vendor.example\n      expires: " + future + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.WebSocketProxy.ContentEntropyExclusions
	if len(got) != 2 || got[0].Host != "ws.vendor.example" || got[0].temporary() || got[1].Expires != future {
		t.Fatalf("websocket exclusions = %+v", got)
	}

	missing := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(missing, []byte("mode: balanced\nwebsocket_proxy:\n  content_entropy_exclusions:\n    - host: ws.vendor.example\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := Load(missing); err == nil || !strings.Contains(err.Error(), "websocket_proxy.content_entropy_exclusions[0].expires is required") {
		t.Fatalf("Load error = %v, want required expires", err)
	}
}

func TestEntropyHostExclusionPlainEntryKeepsLegacyEncodings(t *testing.T) {
	plain := EntropyHostExclusions("a.vendor.example", "b.vendor.example")
	j, err := json.Marshal(plain)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if string(j) != `["a.vendor.example","b.vendor.example"]` {
		t.Fatalf("plain entries must encode like the []string they replaced, got %s", j)
	}
	y, err := yaml.Marshal(plain)
	if err != nil {
		t.Fatalf("yaml.Marshal: %v", err)
	}
	if string(y) != "- a.vendor.example\n- b.vendor.example\n" {
		t.Fatalf("plain entries yaml = %q", y)
	}
	mapped := []EntropyHostExclusion{{Host: "a.vendor.example", Expires: "2099-01-01", Owner: "platform"}}
	j, _ = json.Marshal(mapped)
	if !strings.Contains(string(j), `"expires":"2099-01-01"`) || !strings.Contains(string(j), `"owner":"platform"`) {
		t.Fatalf("mapping entry json lost metadata: %s", j)
	}
	y, _ = yaml.Marshal(mapped)
	if !strings.Contains(string(y), `expires: "2099-01-01"`) {
		t.Fatalf("mapping entry yaml lost metadata: %s", y)
	}
}

func TestActiveEntropyExclusionHostsFollowsWarnRouteExpiryConvention(t *testing.T) {
	entries := []EntropyHostExclusion{
		{Host: "plain.vendor.example"},
		{Host: "temp.vendor.example", Expires: "2026-12-31", mapped: true},
		{Host: "garbled.vendor.example", Expires: "soon", mapped: true},
		{Host: "blank.vendor.example", mapped: true},
	}
	at := func(s string) time.Time {
		ts, err := time.Parse(time.DateTime, s)
		if err != nil {
			t.Fatal(err)
		}
		return ts
	}
	tests := []struct {
		name string
		now  time.Time
		want []string
	}{
		{"before expiry", at("2026-12-30 23:59:59"), []string{"plain.vendor.example", "temp.vendor.example"}},
		{"on the expiry date", at("2026-12-31 23:59:59"), []string{"plain.vendor.example", "temp.vendor.example"}},
		{"after expiry", at("2027-01-01 00:00:00"), []string{"plain.vendor.example"}},
	}
	for _, tt := range tests {
		if got := ActiveEntropyExclusionHosts(entries, tt.now); !reflect.DeepEqual(got, tt.want) {
			t.Errorf("%s: active = %v, want %v", tt.name, got, tt.want)
		}
	}
	if got := ActiveEntropyExclusionHosts(nil, time.Now()); got != nil {
		t.Errorf("nil entries = %v", got)
	}
}

func TestValidateEntropyHostExclusionsGoConstructed(t *testing.T) {
	future := temporaryExpiryDate(MaxContentEntropyHostExclusionHorizon)
	tests := []struct {
		name    string
		entries []EntropyHostExclusion
		want    string
	}{
		{"plain unchanged", EntropyHostExclusions("a.vendor.example"), ""},
		{"plain wildcard unchanged", EntropyHostExclusions("*.vendor.example"), ""},
		{"expiring wildcard", []EntropyHostExclusion{{Host: "*.vendor.example", Expires: future}}, ""},
		{"reason without expires", []EntropyHostExclusion{{Host: "a.vendor.example", Reason: "x"}}, "expires is required"},
		{"owner without expires", []EntropyHostExclusion{{Host: "a.vendor.example", Owner: "x"}}, "expires is required"},
		{"expired", []EntropyHostExclusion{{Host: "a.vendor.example", Expires: "2020-01-01"}}, "already expired"},
		{"reason too long", []EntropyHostExclusion{{Host: "a.vendor.example", Expires: future, Reason: strings.Repeat("x", 201)}}, "200 characters"},
		{"owner control character", []EntropyHostExclusion{{Host: "a.vendor.example", Expires: future, Owner: "a\x07b"}}, "control characters"},
		{"normalizes host", []EntropyHostExclusion{{Host: "A.Vendor.Example.", Expires: future}}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEntropyHostExclusions("request_body_scanning.content_entropy_exclusions", tt.entries)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validate error = %v, want substring %q", err, tt.want)
			}
		})
	}
	entries := []EntropyHostExclusion{{Host: "A.Vendor.Example.", Expires: future}}
	if err := validateEntropyHostExclusions("f", entries); err != nil || entries[0].Host != "a.vendor.example" {
		t.Fatalf("host not normalized: %v %+v", err, entries)
	}
}

func TestValidateExpiryAuthorizationsCoversEntropyHostExclusions(t *testing.T) {
	future := temporaryExpiryDate(MaxContentEntropyHostExclusionHorizon)
	for _, field := range []string{"request_body_scanning", "websocket_proxy"} {
		t.Run(field, func(t *testing.T) {
			set := func(cfg *Config, e []EntropyHostExclusion) {
				if field == "websocket_proxy" {
					cfg.WebSocketProxy.ContentEntropyExclusions = e
				} else {
					cfg.RequestBodyScanning.ContentEntropyExclusions = e
				}
			}
			cfg := Defaults()
			set(cfg, []EntropyHostExclusion{{Host: "a.vendor.example"}, {Host: "b.vendor.example", Expires: future}})
			if err := cfg.ValidateExpiryAuthorizations(); err != nil {
				t.Fatalf("valid entries rejected: %v", err)
			}
			set(cfg, []EntropyHostExclusion{{Host: "b.vendor.example", Expires: "2020-01-01"}})
			err := cfg.ValidateExpiryAuthorizations()
			if err == nil || !strings.Contains(err.Error(), field+".content_entropy_exclusions[0].expires") || !strings.Contains(err.Error(), "already expired") {
				t.Fatalf("expired entry not rejected on reload path: %v", err)
			}
		})
	}
}

func TestEntropyHostExclusionsReloadWarnings(t *testing.T) {
	future := temporaryExpiryDate(MaxContentEntropyHostExclusionHorizon)
	later := temporaryExpiryDate(MaxContentEntropyHostExclusionHorizon - 3*24*time.Hour)
	build := func(e ...EntropyHostExclusion) *Config {
		cfg := Defaults()
		cfg.RequestBodyScanning.ContentEntropyExclusions = e
		cfg.WebSocketProxy.ContentEntropyExclusions = e
		return cfg
	}
	const bodyField, wsField = "request_body_scanning.content_entropy_exclusions", "websocket_proxy.content_entropy_exclusions"
	tests := []struct {
		name     string
		old, upd *Config
		want     bool
	}{
		{"new plain host", build(), build(EntropyHostExclusion{Host: "a.vendor.example"}), true},
		{"new expiring host", build(), build(EntropyHostExclusion{Host: "a.vendor.example", Expires: future}), true},
		{"unchanged plain", build(EntropyHostExclusion{Host: "a.vendor.example"}), build(EntropyHostExclusion{Host: "A.vendor.example"}), false},
		{"unchanged expiring", build(EntropyHostExclusion{Host: "a.vendor.example", Expires: future}), build(EntropyHostExclusion{Host: "a.vendor.example", Expires: future}), false},
		{"expiry extended", build(EntropyHostExclusion{Host: "a.vendor.example", Expires: later}), build(EntropyHostExclusion{Host: "a.vendor.example", Expires: future}), true},
		{"expiring replaced by permanent", build(EntropyHostExclusion{Host: "a.vendor.example", Expires: future}), build(EntropyHostExclusion{Host: "a.vendor.example"}), true},
		{"permanent narrowed to expiring", build(EntropyHostExclusion{Host: "a.vendor.example"}), build(EntropyHostExclusion{Host: "a.vendor.example", Expires: future}), false},
		{"removed", build(EntropyHostExclusion{Host: "a.vendor.example"}), build(), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings := ValidateReload(tt.old, tt.upd)
			if got := hasReloadWarning(warnings, bodyField); got != tt.want {
				t.Fatalf("body warning = %t, want %t: %+v", got, tt.want, warnings)
			}
			if got := hasReloadWarning(warnings, wsField); got != tt.want {
				t.Fatalf("websocket warning = %t, want %t: %+v", got, tt.want, warnings)
			}
		})
	}
	var msg string
	for _, w := range ValidateReload(build(), build(EntropyHostExclusion{Host: "a.vendor.example", Expires: future})) {
		if w.Field == bodyField {
			msg = w.Message
		}
	}
	if !strings.Contains(msg, "a.vendor.example (expires "+future+")") {
		t.Fatalf("reload message omits the expiry: %q", msg)
	}
}

func TestCanonicalPolicyHashTreatsEntropyHostExclusionsLikeStrings(t *testing.T) {
	future := temporaryExpiryDate(MaxContentEntropyHostExclusionHorizon)
	hash := func(e ...EntropyHostExclusion) string {
		cfg := Defaults()
		cfg.RequestBodyScanning.ContentEntropyExclusions = e
		return cfg.CanonicalPolicyHash()
	}
	base := hash(EntropyHostExclusion{Host: "a.vendor.example"}, EntropyHostExclusion{Host: "b.vendor.example"})
	if got := hash(EntropyHostExclusion{Host: "B.VENDOR.EXAMPLE."}, EntropyHostExclusion{Host: "a.vendor.example"}, EntropyHostExclusion{Host: "a.vendor.example"}); got != base {
		t.Fatal("case, trailing dot, order and duplicates must not change the plain-entry hash")
	}
	temp := hash(EntropyHostExclusion{Host: "a.vendor.example", Expires: future}, EntropyHostExclusion{Host: "b.vendor.example"})
	if temp == base {
		t.Fatal("giving an exclusion an expiry must change the policy hash")
	}
	if temp != hash(EntropyHostExclusion{Host: "b.vendor.example"}, EntropyHostExclusion{Host: "A.vendor.example.", Expires: future}) {
		t.Fatal("mapping entry hash must ignore order, case and trailing dot")
	}
	if temp == hash(EntropyHostExclusion{Host: "a.vendor.example", Expires: later(future)}, EntropyHostExclusion{Host: "b.vendor.example"}) {
		t.Fatal("a different expiry must change the policy hash")
	}
}

func later(date string) string {
	d, _ := time.Parse(time.DateOnly, date)
	return d.AddDate(0, 0, -1).Format(time.DateOnly)
}

func TestEntropyWarnRoutePathPrefixSurfacesInCanonicalHashAndReload(t *testing.T) {
	a := warnRouteConfig(prefixRoute("/cdn-cgi/challenge/"))
	b := warnRouteConfig(prefixRoute("/cdn-cgi/other/"))
	if a.CanonicalPolicyHash() == b.CanonicalPolicyHash() {
		t.Fatal("path_prefix must be part of the canonical policy hash")
	}
	if !hasReloadWarning(ValidateReload(b, a), "request_body_scanning.content_entropy_warn_routes") {
		t.Fatal("changing only path_prefix did not surface a reload downgrade warning")
	}
	exactOnly := validEntropyWarnRouteConfig()
	golden := exactOnly.CanonicalPolicyHash()
	exactOnly.RequestBodyScanning.ContentEntropyWarnRoutes[0].PathPrefix = ""
	if exactOnly.CanonicalPolicyHash() != golden {
		t.Fatal("an exact-path route hash must not depend on an empty path_prefix")
	}
}

func TestLoadStrictYAMLRecognizesPrefixWarnRoutes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	body := `mode: balanced
request_body_scanning:
  content_entropy_action: block
  content_entropy_warn_routes:
    - host: challenge.vendor.example
      path_prefix: /cdn-cgi/challenge/
      content_types: [application/x-www-form-urlencoded, application/json]
      methods: [POST]
      reason: service-issued bot challenge
      owner: platform team
      expires: ` + temporaryExpiryDate(MaxRequestBodyEntropyWarnRouteHorizon) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	got := cfg.RequestBodyScanning.ContentEntropyWarnRoutes
	if len(got) != 1 || got[0].PathPrefix != "/cdn-cgi/challenge/" || got[0].Path != "" {
		t.Fatalf("loaded routes = %+v", got)
	}
}

// TestDocumentedEntropyExceptionExampleLoads loads the shapes docs/configuration.md
// shows for the prefix route and the expiring host exclusion, with the date
// placeholder replaced, and checks the docs still carry those shapes.
func TestDocumentedEntropyExceptionExampleLoads(t *testing.T) {
	date := temporaryExpiryDate(MaxRequestBodyEntropyWarnRouteHorizon)
	example := `mode: balanced
request_body_scanning:
  content_entropy_enabled: true
  content_entropy_action: block
  content_entropy_exclusions:
    - uploads.vendor.example
    - host: challenge.vendor.example
      expires: "` + date + `"
      reason: bot challenge payloads
      owner: platform team
  content_entropy_warn_routes:
    - host: upload.vendor.example
      path: /v1/files
      content_types: [application/octet-stream]
      methods: [POST]
      reason: encrypted customer archives
      owner: storage team
      expires: "` + date + `"
    - host: challenge.vendor.example
      path_prefix: /cdn-cgi/challenge/
      content_types: [application/x-www-form-urlencoded, application/json]
      reason: service-issued bot challenge
      owner: platform team
      expires: "` + date + `"
websocket_proxy:
  content_entropy_exclusions:
    - host: stream.vendor.example
      expires: "` + date + `"
`
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(path, []byte(example), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("documented example does not load: %v", err)
	}
	if got := cfg.RequestBodyScanning.ContentEntropyExclusions; len(got) != 2 || got[0].temporary() || !got[1].temporary() {
		t.Fatalf("exclusions = %+v", got)
	}
	if len(cfg.RequestBodyScanning.ContentEntropyWarnRoutes) != 2 {
		t.Fatalf("routes = %+v", cfg.RequestBodyScanning.ContentEntropyWarnRoutes)
	}

	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "configuration.md"))
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}
	for _, want := range []string{"path_prefix: /cdn-cgi/challenge/", "- host: challenge.vendor.example", "- uploads.vendor.example", "application/x-www-form-urlencoded, application/json"} {
		if !strings.Contains(string(doc), want) {
			t.Errorf("docs/configuration.md no longer shows %q", want)
		}
	}
}
