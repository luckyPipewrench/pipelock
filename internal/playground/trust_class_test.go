// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package playground

import "testing"

func TestClassifyDestination(t *testing.T) {
	t.Parallel()
	const modelHost = "api.provider.example"

	tests := []struct {
		name      string
		target    string
		modelHost string
		want      string
	}{
		{"model host as bare host", "api.provider.example", modelHost, DestinationClassTrustedModel},
		{"model host with port", "api.provider.example:443", modelHost, DestinationClassTrustedModel},
		{"model host as https url", "https://api.provider.example/v1/chat/completions", modelHost, DestinationClassTrustedModel},
		{"model host trailing dot", "api.provider.example.", modelHost, DestinationClassTrustedModel},
		{"model host uppercase", "API.PROVIDER.EXAMPLE", modelHost, DestinationClassTrustedModel},
		{"lab safe target", "http://safe.target.test:8080/", modelHost, DestinationClassUntrusted},
		{"lab exfil target", "http://intake.lab.test:9090/", modelHost, DestinationClassUntrusted},
		{"lookalike subdomain is not the model host", "https://api.provider.example.evil.test/", modelHost, DestinationClassUntrusted},
		{"empty model host classifies everything untrusted", "https://api.provider.example/v1", "", DestinationClassUntrusted},
		{"empty target untrusted", "", modelHost, DestinationClassUntrusted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := classifyDestination(tt.target, tt.modelHost); got != tt.want {
				t.Errorf("classifyDestination(%q, %q) = %q, want %q", tt.target, tt.modelHost, got, tt.want)
			}
		})
	}
}

func TestHostFromTarget(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"https://h.test:443/p": "h.test",
		"h.test:443":           "h.test",
		"h.test":               "h.test",
		"HTTP://H.TEST/":       "h.test",
		"h.test.":              "h.test",
		"http://[::1]:8080/":   "::1",
		"":                     "",
	}
	for in, want := range tests {
		if got := hostFromTarget(in); got != want {
			t.Errorf("hostFromTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
