// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"slices"
	"testing"
)

// matchesPath: host-style globs (no scheme, no path separator) anchor to the
// URL host; path/scheme-qualified patterns keep full-URL matching.
func TestMatchesPath_HostGlobAnchorsToHost(t *testing.T) {
	cases := []struct {
		target, pattern string
		want            bool
	}{
		{"https://api.anthropic.com/v1/messages", "*.anthropic.com*", true},
		{"https://API.AnThRoPiC.COM/v1/messages", "*.anthropic.com*", true},
		{"https://attacker.test/?x=.anthropic.com", "*.anthropic.com*", false},
		{"https://attacker.test/.anthropic.com/x", "*.anthropic.com*", false},
		{"https://api.anthropic.com:80@evil.test/steal", "*.anthropic.com*", false},
		{"https://api.anthropic.com%2f@evil.test/steal", "*.anthropic.com*", false},
		{"https://api.anthropic.com.evil.test/v1/messages", "*.anthropic.com*", false},
		{"https://xanthropic.com/v1/messages", "*.anthropic.com*", false},
		{"https://chatgpt.com/backend-api/codex", "*chatgpt.com*", true},
		// Trailing-dot FQDN must match the bare-domain glob, mirroring what
		// scanner.matchesDomainList exempts on the URL-DLP side (cross-surface
		// parity: never exempt a host for URL DLP but block it for body DLP).
		{"https://api.anthropic.com./v1/messages", "*.anthropic.com*", true},
		{"https://api.anthropic.com.:443/v1/messages", "*.anthropic.com*", true},
		{"https://api.example.com.:8443/v1/messages", "*.example.com:8443*", true},
		// Scheme-qualified full-URL glob still matches its own URL.
		{"https://api.x.com/v1/chat", "https://api.x.com/*", true},
		// Dotted version URL/path globs are not host globs.
		{"https://example.com/downloads/pipelock-v1.2.3/manifest.json", "*v1.2.3*", true},
		// Ambiguous double-sided dotted globs stay host-scoped because
		// extension-looking labels can also be real TLDs.
		{"https://api.example.zip/v1/messages", "*.example.zip*", true},
		{"https://attacker.test/?x=.example.zip", "*.example.zip*", false},
		// Bare relative path patterns are unaffected.
		{"https://example.com/robots.txt", "robots.txt", true},
		{"https://example.com/releases/pipelock.tar.gz", "*.tar.gz", true},
		{"https://example.com/assets/pipelock.min.js", "*.min.js", true},
	}
	for _, c := range cases {
		t.Run(c.pattern+"/"+c.target, func(t *testing.T) {
			if got := matchesPath(c.target, c.pattern); got != c.want {
				t.Errorf("matchesPath(%q, %q) = %v, want %v", c.target, c.pattern, got, c.want)
			}
		})
	}
}

func TestBuiltInCredentialAudienceHosts_ReplaceDerivedProviderDefaults(t *testing.T) {
	cfg := Defaults()
	patternByName := make(map[string]DLPPattern, len(cfg.DLP.Patterns))
	for _, p := range cfg.DLP.Patterns {
		patternByName[p.Name] = p
	}

	// A pattern may legitimately carry more than one audience host when the
	// vendor serves the credential on several domains, so this asserts the
	// exact SET rather than a single value.
	expected := map[string][]string{ // #nosec G101 -- compiled audience host assertions, not credential material
		"Anthropic API Key":     {"*.anthropic.com"},
		"OpenAI API Key":        {"*.openai.com"},
		"OpenAI Service Key":    {"*.openai.com"},
		"Fireworks API Key":     {"*.fireworks.ai"},
		"LLM Router API Key":    {"*.openrouter.ai"},
		"Answer Engine API Key": {"*.perplexity.ai"},
		"Web Research API Key":  {"*.tavily.com"},
		"Google API Key":        {"*.googleapis.com"},
		"Hugging Face Token":    {"*.huggingface.co"},
		"Databricks Token":      {"*.databricks.com"},
		"Replicate API Token":   {"*.replicate.com"},
		"Together AI Key":       {"*.together.ai"},
		"Pinecone API Key":      {"*.pinecone.io"},
		"Groq API Key":          {"*.groq.com"},
		"xAI API Key":           {"*.x.ai"},
		"Discord Bot Token":     {"discord.com", "gateway.discord.gg"},
	}
	for name, hosts := range expected {
		t.Run(name, func(t *testing.T) {
			p, ok := patternByName[name]
			if !ok {
				t.Fatalf("default DLP pattern missing for audience-bound rule %q", name)
			}
			if len(p.ExemptDomains) != 0 {
				t.Fatalf("%q inherited URL-only exempt_domains = %#v", name, p.ExemptDomains)
			}
			if !slices.Equal(p.CredentialAudienceHosts, hosts) {
				t.Fatalf("%q credential audience hosts = %#v, want %#v", name, p.CredentialAudienceHosts, hosts)
			}
		})
	}

	for _, suppression := range cfg.Suppress {
		if suppression.Reason == "provider-bound credential" {
			t.Fatalf("legacy derived suppression remained: %#v", suppression)
		}
	}
}
