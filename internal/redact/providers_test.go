// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"
	"testing"
)

func TestRewriteRequestJSON_GeminiParserRedactsWholeBody(t *testing.T) {
	t.Parallel()

	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	body := []byte(`{
		"systemInstruction": {"parts": [{"text": "use ` + awsKey + `"}]},
		"contents": [{"role": "user", "parts": [{"text": "connect to 10.0.0.1"}]}],
		"tools": [{"functionDeclarations": [{"name": "lookup", "description": "send mail to root@example.com"}]}]
	}`)

	registry, err := NewProviderRegistry(nil)
	if err != nil {
		t.Fatalf("NewProviderRegistry: %v", err)
	}
	out, report, err := RewriteRequestJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{}, RequestMetadata{
		Host: "generativelanguage.googleapis.com:443",
		Path: "/v1beta/models/gemini-2.5-pro:generateContent",
	}, registry)
	if err != nil {
		t.Fatalf("RewriteRequestJSON: %v", err)
	}
	if report.Provider != "gemini" {
		t.Fatalf("provider = %q, want gemini", report.Provider)
	}
	if report.Parser != ParserJSON {
		t.Fatalf("parser = %q, want %q", report.Parser, ParserJSON)
	}
	outStr := string(out)
	for _, leaked := range []string{awsKey, "10.0.0.1", "root@example.com"} {
		if strings.Contains(outStr, leaked) {
			t.Fatalf("Gemini parser leaked %q in %s", leaked, outStr)
		}
	}
}

func TestRewriteRequestJSON_CustomProviderParserRedactsWithoutCodeChange(t *testing.T) {
	t.Parallel()

	registry, err := NewProviderRegistry(map[string]ProviderSpec{
		"custom_provider": {
			HostPatterns: []string{"api.provider.example"},
			PathPrefixes: []string{"/v1/messages"},
			Parser:       ParserJSON,
		},
	})
	if err != nil {
		t.Fatalf("NewProviderRegistry: %v", err)
	}

	body := []byte(`{"input":[{"text":"customer host dc01.corp.local"}]}`)
	out, report, err := RewriteRequestJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{}, RequestMetadata{
		Host: "api.provider.example",
		Path: "/v1/messages",
	}, registry)
	if err != nil {
		t.Fatalf("RewriteRequestJSON: %v", err)
	}
	if report.Provider != "custom_provider" {
		t.Fatalf("provider = %q, want custom_provider", report.Provider)
	}
	if strings.Contains(string(out), "dc01.corp.local") {
		t.Fatalf("custom provider parser leaked FQDN: %s", out)
	}
}

func TestRewriteRequestJSON_UnsupportedParserBlocks(t *testing.T) {
	t.Parallel()

	registry := &ProviderRegistry{entries: []providerEntry{
		{
			name: "bad_provider",
			spec: ProviderSpec{
				HostPatterns: []string{"api.provider.example"},
				Parser:       "form",
			},
		},
	}}

	body := []byte(`{"input":"connect to 10.0.0.1"}`)
	out, report, err := RewriteRequestJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{}, RequestMetadata{
		Host: "api.provider.example",
		Path: "/token",
	}, registry)
	if err == nil {
		t.Fatalf("RewriteRequestJSON returned out=%s report=%+v, want unsupported-parser block", out, report)
	}
	if !strings.Contains(err.Error(), "unsupported redaction provider parser form") {
		t.Fatalf("RewriteRequestJSON error = %q, want unsupported parser", err)
	}
	if out != nil || report != nil {
		t.Fatalf("RewriteRequestJSON returned out=%s report=%+v, want nil results on block", out, report)
	}
}

func TestProviderRegistry_UnknownProviderFallsBackToGenericJSON(t *testing.T) {
	t.Parallel()

	registry, err := NewProviderRegistry(nil)
	if err != nil {
		t.Fatalf("NewProviderRegistry: %v", err)
	}
	provider, parser := registry.Match(RequestMetadata{Host: "unknown.example", Path: "/chat"})
	if provider != ProviderGenericJSON {
		t.Fatalf("provider = %q, want %q", provider, ProviderGenericJSON)
	}
	if parser != ParserJSON {
		t.Fatalf("parser = %q, want %q", parser, ParserJSON)
	}
}

func TestProviderRegistry_NilRegistryFallsBackToGenericJSON(t *testing.T) {
	t.Parallel()

	var registry *ProviderRegistry
	provider, parser := registry.Match(RequestMetadata{Host: "api.provider.example", Path: "/v1/messages"})
	if provider != ProviderGenericJSON {
		t.Fatalf("provider = %q, want %q", provider, ProviderGenericJSON)
	}
	if parser != ParserJSON {
		t.Fatalf("parser = %q, want %q", parser, ParserJSON)
	}
}

func TestProviderRegistry_SelectsMostSpecificMatch(t *testing.T) {
	t.Parallel()

	registry, err := NewProviderRegistry(map[string]ProviderSpec{
		"aaa_broad_openai": {
			HostPatterns: []string{"api.openai.com"},
			PathPrefixes: []string{"/v1"},
			Parser:       ParserJSON,
		},
		"zzz_exact_gemini": {
			HostPatterns: []string{"us.generativelanguage.googleapis.com"},
			Parser:       ParserJSON,
		},
	})
	if err != nil {
		t.Fatalf("NewProviderRegistry: %v", err)
	}

	provider, _ := registry.Match(RequestMetadata{Host: "api.openai.com", Path: "/v1/responses"})
	if provider != "openai" {
		t.Fatalf("provider = %q, want openai from longer built-in path prefix", provider)
	}

	provider, _ = registry.Match(RequestMetadata{Host: "us.generativelanguage.googleapis.com", Path: "/v1beta/models/gemini-2.5-pro:generateContent"})
	if provider != "zzz_exact_gemini" {
		t.Fatalf("provider = %q, want exact host custom provider over wildcard built-in", provider)
	}
}

func TestProviderRegistry_MatchCanonicalizesHostPortAndDefaultPath(t *testing.T) {
	t.Parallel()

	registry, err := NewProviderRegistry(map[string]ProviderSpec{
		"custom_provider": {
			HostPatterns: []string{"api.provider.example"},
			PathPrefixes: []string{"/"},
			Parser:       ParserJSON,
		},
	})
	if err != nil {
		t.Fatalf("NewProviderRegistry: %v", err)
	}

	provider, parser := registry.Match(RequestMetadata{Host: "API.PROVIDER.EXAMPLE:443"})
	if provider != "custom_provider" {
		t.Fatalf("provider = %q, want custom_provider", provider)
	}
	if parser != ParserJSON {
		t.Fatalf("parser = %q, want %q", parser, ParserJSON)
	}
}

func TestProviderRegistry_RejectsInvalidProviderSpecs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		providerName string // registry key; defaults to "provider" when empty
		spec         ProviderSpec
		want         string
	}{
		{
			name:         "invalid provider name",
			providerName: "Bad Provider",
			spec:         ProviderSpec{HostPatterns: []string{"api.provider.example"}, Parser: ParserJSON},
			want:         "must match [a-z0-9][a-z0-9_-]*",
		},
		{
			name: "missing hosts",
			spec: ProviderSpec{Parser: ParserJSON},
			want: "must define at least one host_pattern",
		},
		{
			name: "empty host pattern",
			spec: ProviderSpec{HostPatterns: []string{""}, Parser: ParserJSON},
			want: "empty",
		},
		{
			name: "path with query",
			spec: ProviderSpec{HostPatterns: []string{"api.provider.example"}, PathPrefixes: []string{"/v1?debug=true"}, Parser: ParserJSON},
			want: "absolute path prefix without query or fragment",
		},
		{
			name: "relative path",
			spec: ProviderSpec{HostPatterns: []string{"api.provider.example"}, PathPrefixes: []string{"v1/messages"}, Parser: ParserJSON},
			want: "absolute path prefix without query or fragment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			providerName := tt.providerName
			if providerName == "" {
				providerName = "provider"
			}
			_, err := NewProviderRegistry(map[string]ProviderSpec{providerName: tt.spec})
			if err == nil {
				t.Fatal("NewProviderRegistry returned nil error, want validation error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("NewProviderRegistry error = %q, want to contain %q", err, tt.want)
			}
		})
	}
}

func TestProviderRegistry_RejectsUnsupportedParser(t *testing.T) {
	t.Parallel()

	_, err := NewProviderRegistry(map[string]ProviderSpec{
		"bad_provider": {
			HostPatterns: []string{"api.bad-provider.example"},
			Parser:       "form",
		},
	})
	if err == nil || !strings.Contains(err.Error(), "parser") {
		t.Fatalf("expected unsupported parser error, got %v", err)
	}
}

func TestProviderRegistry_RejectsNestedWildcardHostPattern(t *testing.T) {
	t.Parallel()

	_, err := NewProviderRegistry(map[string]ProviderSpec{
		"bad_provider": {
			HostPatterns: []string{"*.*.example.com"},
			Parser:       ParserJSON,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("expected wildcard host pattern error, got %v", err)
	}
}

func TestProviderHostMatchPrefersExactAndLongestWildcard(t *testing.T) {
	t.Parallel()

	exact, length, ok := providerHostMatch("api.provider.example", []string{"*.provider.example", "api.provider.example"})
	if !ok {
		t.Fatal("providerHostMatch did not match exact host")
	}
	if !exact {
		t.Fatal("providerHostMatch exact = false, want true")
	}
	if length != len("api.provider.example") {
		t.Fatalf("providerHostMatch length = %d, want %d", length, len("api.provider.example"))
	}

	exact, length, ok = providerHostMatch("deep.api.provider.example", []string{"*.example", "*.provider.example", "*.api.provider.example"})
	if !ok {
		t.Fatal("providerHostMatch did not match wildcard host")
	}
	if exact {
		t.Fatal("providerHostMatch exact = true, want wildcard match")
	}
	if length != len("*.api.provider.example") {
		t.Fatalf("providerHostMatch wildcard length = %d, want %d", length, len("*.api.provider.example"))
	}

	if _, _, ok := providerHostMatch("", []string{"*.provider.example"}); ok {
		t.Fatal("providerHostMatch matched empty host, want no match")
	}
}

func TestProviderMatchLessOrdering(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    providerMatch
		b    providerMatch
		want bool
	}{
		{
			name: "exact host beats wildcard",
			a:    providerMatch{entry: providerEntry{name: "wildcard"}, hostExact: false, hostLength: len("*.provider.example")},
			b:    providerMatch{entry: providerEntry{name: "exact"}, hostExact: true, hostLength: len("api.provider.example")},
			want: true,
		},
		{
			name: "longer path prefix beats shorter",
			a:    providerMatch{entry: providerEntry{name: "short"}, hostExact: true, hostLength: len("api.provider.example"), prefixLength: len("/v1")},
			b:    providerMatch{entry: providerEntry{name: "long"}, hostExact: true, hostLength: len("api.provider.example"), prefixLength: len("/v1/messages")},
			want: true,
		},
		{
			name: "longer wildcard host beats shorter wildcard",
			a:    providerMatch{entry: providerEntry{name: "short"}, hostLength: len("*.example")},
			b:    providerMatch{entry: providerEntry{name: "long"}, hostLength: len("*.provider.example")},
			want: true,
		},
		{
			name: "lexical tie breaker keeps earlier name",
			a:    providerMatch{entry: providerEntry{name: "zzz_provider"}},
			b:    providerMatch{entry: providerEntry{name: "aaa_provider"}},
			want: true,
		},
		{
			name: "current exact beats wildcard candidate",
			a:    providerMatch{entry: providerEntry{name: "exact"}, hostExact: true, hostLength: len("api.provider.example")},
			b:    providerMatch{entry: providerEntry{name: "wildcard"}, hostExact: false, hostLength: len("*.provider.example")},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := providerMatchLess(tt.a, tt.b)
			if got != tt.want {
				t.Fatalf("providerMatchLess(%+v, %+v) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}
