// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package reqpolicy_test

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/reqpolicy"
)

// A malformed wildcard in a block rule is a FAIL-OPEN, and validator-level
// tests cannot show that. The runtime matches a hostname against "." plus the
// pattern base, so a base no hostname can contain matches nothing, and a rule
// that matches nothing denies nothing. Two review rounds each found a
// different family of malformed base that config validation admitted:
// interior globs, then "#", "%", "_", empty labels, hyphen placement and
// non-ASCII labels.
//
// This drives the whole path an operator uses, YAML through Load and Validate
// into NewMatcher and Evaluate, so the guarantee is "the block enforces" and
// not merely "the validator returned an error".
func loadPolicy(t *testing.T, hosts string) (*config.Config, error) {
	t.Helper()
	yaml := `
fetch_proxy:
  listen: "127.0.0.1:8888"
request_policy:
  enabled: true
  rules:
    - name: deny-vendor
      action: block
      reason: "blocked by policy"
      route:
        hosts: ` + hosts + `
`
	cfg, err := config.LoadBytes([]byte(yaml))
	if err != nil {
		return nil, err
	}
	cfg.Internal = nil
	return cfg, cfg.Validate()
}

func TestBlockRuleEnforcesAfterLoad(t *testing.T) {
	t.Parallel()

	// A broad block must LOAD and ENFORCE. The breadth rule deliberately does
	// not apply to a deny surface, and this proves the permission is real
	// rather than merely accepted by the validator.
	cfg, err := loadPolicy(t, `["*.co.uk"]`)
	if err != nil {
		t.Fatalf("a broad block rule failed to load: %v", err)
	}
	m, err := reqpolicy.NewMatcher(&cfg.RequestPolicy)
	if err != nil {
		t.Fatalf("NewMatcher: %v", err)
	}
	got := m.Evaluate(reqpolicy.RequestMeta{Host: "shop.co.uk", Method: "GET", Path: "/"})
	if got.Action != config.ActionBlock {
		t.Fatalf("Evaluate(shop.co.uk) action = %q, want %q; a loaded broad block must actually enforce", got.Action, config.ActionBlock)
	}
	if got.RuleName != "deny-vendor" {
		t.Errorf("matched rule = %q, want deny-vendor", got.RuleName)
	}

	// A host outside the pattern is untouched, so the block is scoped and the
	// assertion above is not passing for an unrelated reason.
	if other := m.Evaluate(reqpolicy.RequestMeta{Host: "shop.example", Method: "GET", Path: "/"}); other.Action == config.ActionBlock {
		t.Error("Evaluate(shop.example) blocked; the rule must not match outside its pattern")
	}
}

func TestMalformedBlockRuleIsRefusedAtLoad(t *testing.T) {
	t.Parallel()

	// Each of these would load, compile, and then match nothing, so the block
	// would silently not enforce. Refusing them at load is what makes the
	// operator's policy mean what it says.
	for _, host := range []string{
		"*.vendor.example#disabled",
		"*.example*.com",
		"*.vendor_example.com",
		"*.vendor..example",
		"*.-vendor.example",
	} {
		if _, err := loadPolicy(t, `["`+host+`"]`); err == nil {
			t.Errorf("a block rule with hosts=[%q] loaded; it can never match, so the block would not enforce", host)
		} else if !strings.Contains(err.Error(), "wildcard") && !strings.Contains(err.Error(), "DNS label") && !strings.Contains(err.Error(), "IDNA") {
			t.Errorf("hosts=[%q] rejected for an unexpected reason: %v", host, err)
		}
	}
}
