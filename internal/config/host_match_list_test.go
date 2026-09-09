// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// A deny list needs SHAPE validation as much as a grant list does, and for a
// worse reason. MatchDomain compares a pattern literally, so a malformed
// blocklist entry matches nothing: "example.com#disabled" was accepted and
// example.com went straight through the blocklist layer. That is a deny rule
// that never denies, and it reads in the config file exactly like one that
// works.
//
// The first repair on these three lists added only the raw-bytes half of the
// contract. This drives real YAML so a validator that exists but is not wired
// to the field cannot pass.
func TestMalformedHostRefusedOnMatchLists(t *testing.T) {
	t.Parallel()

	// Every case is plain ASCII on purpose: the raw-bytes gate must not be
	// what rejects these, or the test would pass without the shape check.
	patterns := map[string]string{
		"a fragment makes the pattern unmatchable": "example.com#disabled",
		"an escape sequence is not a hostname":     "example%2ecom",
		"an underscore is not a legal DNS label":   "bad_host.example.com",
		"a trailing hyphen is not a legal label":   "bad-.example.com",
		"an empty label cannot be matched":         "bad..example.com",
		"a URL is not a hostname pattern":          "https://example.com",
		"a host:port is not a hostname":            "example.com:443",
		"an interior wildcard is not supported":    "example.*.com",
	}

	lists := map[string]func(string) string{
		"api_allowlist": func(p string) string {
			return "mode: strict\napi_allowlist: [\"" + p + "\"]\n"
		},
		"domain blocklist": func(p string) string {
			return "fetch_proxy:\n  monitoring:\n    blocklist: [\"" + p + "\"]\n"
		},
	}

	// NOT in the table, deliberately: "*.8.8.8.8" stays accepted. It is inert
	// for real IP traffic, because MatchDomain takes an equality-only branch as
	// soon as the hostname parses as an IP - but it genuinely matches a domain
	// like "foo.8.8.8.8", verified by calling the matcher rather than reasoning
	// about it. An earlier draft of this test asserted it could never match and
	// was simply wrong.
	for listName, mk := range lists {
		for caseName, pattern := range patterns {
			t.Run(listName+": "+caseName, func(t *testing.T) {
				t.Parallel()
				if _, err := LoadBytes([]byte(mk(pattern))); err == nil {
					t.Fatalf("%q was accepted on %s; MatchDomain compares it literally, so the entry can never match", pattern, listName)
				}
			})
		}
	}
}

// The calibration for the test above. Without it, every case there would pass
// on a validator that refused ALL patterns, which is the over-strict failure
// direction and is nearly as bad on a security product as accepting junk.
// These are the spellings the shipped presets and defaults actually use.
func TestWellFormedHostAcceptedOnMatchLists(t *testing.T) {
	t.Parallel()

	patterns := []string{
		"example.com",             // exact host
		"*.example.com",           // registrable-domain wildcard
		"*.githubusercontent.com", // shipped in a preset
		"*.pastebin.com",          // shipped in the default blocklist
		"*.s3.amazonaws.com",      // private suffix: broad, deliberately allowed
		"8.8.8.8",                 // exact IP: MatchDomain compares an IP hostname for equality
		"xn--bcher-kva.example",   // ASCII A-label form of an internationalized name
		"example.com.",            // trailing dot is DNS-equivalent, not malformed
		"EXAMPLE.com",             // case is folded at match time
	}

	for _, p := range patterns {
		t.Run(p, func(t *testing.T) {
			t.Parallel()
			if _, err := LoadBytes([]byte("mode: strict\napi_allowlist: [\"" + p + "\"]\n")); err != nil {
				t.Errorf("api_allowlist rejected the legitimate pattern %q, which an operator would work around by disabling the check: %v", p, err)
			}
			if _, err := LoadBytes([]byte("fetch_proxy:\n  monitoring:\n    blocklist: [\"" + p + "\"]\n")); err != nil {
				t.Errorf("blocklist rejected the legitimate pattern %q: %v", p, err)
			}
		})
	}
}

// The error must name the field and the offending value. An operator who gets
// "invalid host pattern" and no index cannot find which of forty allowlist
// entries is wrong, and the practical response to that is to stop validating.
func TestMatchListErrorNamesFieldAndValue(t *testing.T) {
	t.Parallel()

	_, err := LoadBytes([]byte("mode: strict\napi_allowlist: [\"ok.example.com\", \"bad_host.example\"]\n"))
	if err == nil {
		t.Fatal("expected the malformed second entry to be refused")
	}
	for _, want := range []string{"api_allowlist", "[1]", "bad_host.example"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not name %q, so the operator cannot locate the entry: %v", want, err)
		}
	}
}
