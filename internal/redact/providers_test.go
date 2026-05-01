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
		"acme_llm": {
			HostPatterns: []string{"api.acme-llm.example"},
			PathPrefixes: []string{"/v1/messages"},
			Parser:       ParserJSON,
		},
	})
	if err != nil {
		t.Fatalf("NewProviderRegistry: %v", err)
	}

	body := []byte(`{"input":[{"text":"customer host dc01.corp.local"}]}`)
	out, report, err := RewriteRequestJSON(body, NewDefaultMatcher(), NewRedactor(), Limits{}, RequestMetadata{
		Host: "api.acme-llm.example",
		Path: "/v1/messages",
	}, registry)
	if err != nil {
		t.Fatalf("RewriteRequestJSON: %v", err)
	}
	if report.Provider != "acme_llm" {
		t.Fatalf("provider = %q, want acme_llm", report.Provider)
	}
	if strings.Contains(string(out), "dc01.corp.local") {
		t.Fatalf("custom provider parser leaked FQDN: %s", out)
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
