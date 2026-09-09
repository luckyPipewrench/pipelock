// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

// U+212A KELVIN SIGN lowercases to ASCII "k". A validator that folds case
// before testing for ASCII therefore sees a clean hostname and stores an
// exemption for a DIFFERENT host than the operator typed. The first repair for
// this covered three surfaces and left five entropy-exemption lists and the
// query-parameter host validator still folding first.
//
// These drive real YAML through LoadBytes for every affected field family,
// because a unit test on the predicate agrees with the predicate by
// construction and would not have caught the surfaces that were missed.
func TestKelvinSignRefusedOnValidatedHostLists(t *testing.T) {
	t.Parallel()

	const kelvin = "*.\u212Aexample.com" // U+212A KELVIN SIGN, written as an escape on purpose
	const kelvinExact = "\u212Aexample.com"

	// Premise, load-bearing twice over. The fold must produce a valid-looking
	// ASCII host, or nothing below is a trap; and the rune must still BE
	// non-ASCII. An earlier draft of this file lost the Kelvin sign to a shell
	// heredoc and became a plain ASCII "K", which is legitimately accepted, so
	// the whole test asserted nothing. The escape form above prevents that and
	// the first check proves it.
	if !strings.ContainsFunc(kelvin, func(r rune) bool { return r > 127 }) {
		t.Fatal("the test input is pure ASCII; the Kelvin sign was lost and this test would assert nothing")
	}
	if got := NormalizeHostPattern(kelvin); got != "*.kexample.com" {
		t.Fatalf("premise changed: %q folds to %q, not the ASCII form that makes this a trap", kelvin, got)
	}

	cases := map[string]string{
		"subdomain_entropy_exclusions": `
fetch_proxy:
  monitoring:
    subdomain_entropy_exclusions: ["` + kelvin + `"]
`,
		"query_entropy_exclusions": `
fetch_proxy:
  monitoring:
    query_entropy_exclusions: ["` + kelvin + `"]
`,
		"path_entropy_exclusions host": `
fetch_proxy:
  monitoring:
    path_entropy_exclusions:
      - host: "` + kelvin + `"
        path_prefix: /document/d/
`,
		"websocket content_entropy_exclusions": `
websocket_proxy:
  content_entropy_exclusions: ["` + kelvin + `"]
`,
		"request_body content_entropy_exclusions": `
request_body_scanning:
  content_entropy_exclusions: ["` + kelvin + `"]
`,
		"trusted_domains": `
trusted_domains: ["` + kelvin + `"]
`,
		"query_entropy_param_exclusions host": `
fetch_proxy:
  monitoring:
    query_entropy_param_exclusions:
      - scheme: https
        host: "` + kelvinExact + `"
        path: /v1/search
        param: q
`,
		// The ALLOW and DENY lists get the raw gate too, even though breadth
		// deliberately does not apply to them. Breadth is directional; a
		// retargeted host is wrong in every direction. In strict mode the
		// allowlist decides what may leave at all, so a folded pattern there is
		// an egress grant the operator never wrote.
		"api_allowlist in strict mode": `
mode: strict
api_allowlist: ["` + kelvin + `"]
`,
		"domain blocklist": `
fetch_proxy:
  monitoring:
    blocklist: ["` + kelvin + `"]
`,
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg, err := LoadBytes([]byte(body))
			if err == nil {
				cfg.Internal = nil
				err = cfg.Validate()
			}
			if err == nil {
				t.Fatalf("a KELVIN SIGN host was accepted on %s; it folds to an ASCII host the operator never wrote", name)
			}
			if !strings.Contains(err.Error(), "must be ASCII") {
				t.Fatalf("%s rejected for the wrong reason: %v", name, err)
			}
		})
	}
}

// The ASCII A-label form must keep working on the same lists, or the rule
// refuses the supported way to configure an internationalized domain.
func TestALabelHostsStillAcceptedOnHostLists(t *testing.T) {
	t.Parallel()

	body := `
trusted_domains: ["*.xn--vendr-nsa.example"]
fetch_proxy:
  monitoring:
    subdomain_entropy_exclusions: ["*.xn--vendr-nsa.example"]
    query_entropy_exclusions: ["xn--vendr-nsa.example"]
`
	cfg, err := LoadBytes([]byte(body))
	if err != nil {
		t.Fatalf("LoadBytes: %v", err)
	}
	cfg.Internal = nil
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil; an xn-- A-label is the supported IDN form", err)
	}
}
