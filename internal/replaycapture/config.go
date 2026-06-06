// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package replaycapture

import (
	"fmt"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// Fixture hostnames are RFC-reserved .test names that resolve to the local
// httptest backends through dns.host_overrides. The signed receipt records the
// stable synthetic hostname, not a loopback literal.
const (
	labFixtureIP   = "127.0.0.1"
	labDocsHost    = "docs.fixture.test"
	labContentHost = "content.fixture.test"
	labAPIHost     = "api.fixture.test"
)

// awsKeyRegex matches the AWS access key id shape (AKIA + 16 upper/digits). The
// synthetic example key is the only value it will ever see in the lab.
const awsKeyRegex = `AKIA[0-9A-Z]{16}`

// injectionPatternName / injectionRegex detect the stock prompt-injection
// string the lab page returns. The name is a boring public rule id.
const (
	injectionPatternName = "Prompt Injection: ignore-instructions"
	injectionRegex       = `(?i)ignore\s+(all\s+)?previous\s+instructions`
)

// operationPolicyRuleName is a public-safe request_policy rule id surfaced in
// the operation-aware policy scenario's block receipt.
const operationPolicyRuleName = "block-destructive-graphql-mutation"

// labConfig returns a public-safe Pipelock config tuned for one scenario. It
// starts from product defaults and flips only the knobs that scenario exercises,
// so the captured decision comes from the real default pipeline wherever
// possible.
func labConfig(s Scenario) (*config.Config, error) {
	cfg := config.Defaults()

	switch s.ID {
	case "allowed-safe-read":
		allowFixtureHosts(cfg, labDocsHost)
	case "secret-exfil-url-blocked":
		cfg.Internal = nil // blocked at DLP, before any DNS
		ensureAWSPattern(cfg)
	case "prompt-injection-response-blocked":
		allowFixtureHosts(cfg, labContentHost)
		enableResponseInjection(cfg)
	case "ssrf-internal-target-blocked":
		// Leave SSRF active (cfg.Internal stays at defaults) so the link-local
		// metadata target is blocked by the SSRF layer.
	case "operation-aware-policy":
		allowFixtureHosts(cfg, labAPIHost)
		enableOperationPolicy(cfg)
	default:
		return nil, fmt.Errorf("unknown scenario id %q", s.ID)
	}

	cfg.ApplyDefaults()
	return cfg, nil
}

// allowFixtureHosts lets the proxy reach local httptest fixtures through stable
// reserved names. Raw loopback IP targets still hit the normal SSRF controls.
func allowFixtureHosts(cfg *config.Config, hosts ...string) {
	cfg.TrustedDomains = append(cfg.TrustedDomains, hosts...)
	if cfg.DNS.HostOverrides == nil {
		cfg.DNS.HostOverrides = make(map[string][]string, len(hosts))
	}
	for _, host := range hosts {
		cfg.DNS.HostOverrides[host] = []string{labFixtureIP}
	}
}

// ensureAWSPattern guarantees the synthetic AWS example key is detected and
// surfaced under a boring, public rule id regardless of default drift.
func ensureAWSPattern(cfg *config.Config) {
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name:     awsKeyPatternName,
		Regex:    awsKeyRegex,
		Severity: config.SeverityCritical,
	})
}

// enableResponseInjection turns on response scanning in block mode with an
// explicit injection pattern so the lab page's hijack attempt is blocked.
func enableResponseInjection(cfg *config.Config) {
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = config.ActionBlock
	cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, config.ResponseScanPattern{
		Name:  injectionPatternName,
		Regex: injectionRegex,
	})
}

// enableOperationPolicy blocks a destructive GraphQL mutation while allowing
// safe queries on the same synthetic API route.
func enableOperationPolicy(cfg *config.Config) {
	cfg.ForwardProxy.Enabled = true
	cfg.RequestPolicy.Enabled = true
	cfg.RequestPolicy.Rules = []config.RequestPolicyRule{{
		Name:   operationPolicyRuleName,
		Action: config.ActionBlock,
		Route: config.RequestPolicyRoute{
			Hosts:        []string{labAPIHost},
			Methods:      []string{http.MethodPost},
			PathPrefixes: []string{"/graphql"},
			ContentTypes: []string{"application/json"},
		},
		GraphQL: &config.RequestPolicyGraphQL{
			OperationTypes:    []string{"mutation"},
			RootFieldPatterns: []string{`^deleteRecord$`},
		},
		Reason: "destructive mutations require review",
	}}
}
