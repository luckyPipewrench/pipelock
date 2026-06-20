// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// Standing security tripwire: default provider-key suppressions are scoped to
// the destination HOST, never matched as a substring of the full request URL.
// A full-URL substring match would let an attacker satisfy "*.provider.com*" by
// putting the provider domain in a path or query of an unrelated host, which
// suppresses the body/header DLP finding on an exfil request (allowlist must not
// bypass content scanning). If matchesPath ever regresses to full-URL substring
// matching for host-style globs, this test fails and the change does not ship.
func TestDefaultSuppress_HostScoped_NoURLSubstringBypass(t *testing.T) {
	sup := Defaults().Suppress
	if len(sup) == 0 {
		t.Fatal("expected default provider-key suppressions")
	}

	// Legit: a provider key sent TO its own provider host stays suppressed.
	legit := []struct{ rule, url string }{
		{"Anthropic API Key", "https://api.anthropic.com/v1/messages"},
		{"OpenAI API Key", "https://api.openai.com/v1/responses"},
		{"LLM Router API Key", "https://openrouter.ai/api/v1/chat/completions"},
	}
	for _, c := range legit {
		if !IsSuppressed(c.rule, c.url, sup) {
			t.Errorf("legit provider host should suppress %q on %s", c.rule, c.url)
		}
	}

	// Attack: the provider domain appears in the path/query of an UNRELATED host.
	// These must NOT suppress — the destination host is the attacker's.
	attacks := []string{
		"https://attacker.test/steal?x=.anthropic.com",
		"https://attacker.test/.anthropic.com/exfil",
		"https://evil.example/?ref=https://api.anthropic.com",
		"http://198.51.100.7:9000/collect#.anthropic.com",
		"https://api.anthropic.com@attacker.test/steal", // userinfo smuggling: real host is attacker.test
	}
	for _, a := range attacks {
		if IsSuppressed("Anthropic API Key", a, sup) {
			t.Errorf("BYPASS: anthropic-key DLP suppressed on attacker URL %s", a)
		}
	}

	// Cross-provider: anthropic key to openai host must still block.
	if IsSuppressed("Anthropic API Key", "https://api.openai.com/v1/x", sup) {
		t.Error("cross-provider leak: anthropic key suppressed on openai host")
	}
}

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
		// Bare relative path patterns are unaffected.
		{"https://example.com/robots.txt", "robots.txt", true},
		{"https://example.com/releases/pipelock.tar.gz", "*.tar.gz", true},
		{"https://example.com/assets/pipelock.min.js", "*.min.js", true},
	}
	for _, c := range cases {
		if got := matchesPath(c.target, c.pattern); got != c.want {
			t.Errorf("matchesPath(%q, %q) = %v, want %v", c.target, c.pattern, got, c.want)
		}
	}
}
