// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/redact"
)

// Test-local constants for envelope signing field values that repeat
// across sensitivity / reload tests. goconst fires at 3+ occurrences
// per repo policy; extract here rather than inline.
const (
	testEnvelopeKeyIDV1 = "pipelock-mediation-v1"
	testEnvelopeKeyIDV2 = "pipelock-mediation-v2"
)

// canonicalHashOf builds a fresh Config from Defaults(), applies mut, and
// returns the canonical policy hash computed on that value. Using a fresh
// value every time avoids any interaction with the atomic cache — that
// way each subtest observes a true recomputation.
func canonicalHashOf(t *testing.T, mut func(*Config)) string {
	t.Helper()
	cfg := Defaults()
	if mut != nil {
		mut(cfg)
	}
	// Use the uncached computation path so tests exercise the full
	// marshal + hash pipeline on every call. The cached wrapper is
	// tested separately in TestCanonicalPolicyHash_Cached.
	return cfg.computeCanonicalPolicyHash()
}

func TestCanonicalPolicyHash_Deterministic(t *testing.T) {
	t.Parallel()

	h1 := canonicalHashOf(t, nil)
	h2 := canonicalHashOf(t, nil)
	if h1 != h2 {
		t.Errorf("Defaults() canonical hash not deterministic:\n  h1 = %s\n  h2 = %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Errorf("canonical hash length = %d, want 64 (hex-encoded SHA-256)", len(h1))
	}
}

func TestCanonicalPolicyHash_Cached(t *testing.T) {
	t.Parallel()

	cfg := Defaults()
	h1 := cfg.CanonicalPolicyHash()
	h2 := cfg.CanonicalPolicyHash()
	if h1 != h2 {
		t.Errorf("cached canonical hash diverged: %s vs %s", h1, h2)
	}
	// The cache must return the same value as an uncached compute for
	// the same Config shape.
	if want := cfg.computeCanonicalPolicyHash(); h1 != want {
		t.Errorf("cached = %s, uncached = %s; should match", h1, want)
	}
}

func TestCanonicalPolicyHash_ConcurrentFirstTouch(t *testing.T) {
	cfg := Defaults()
	want := cfg.computeCanonicalPolicyHash()

	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 64 {
				if got := cfg.CanonicalPolicyHash(); got != want {
					t.Errorf("CanonicalPolicyHash() = %s, want %s", got, want)
				}
			}
		}()
	}
	wg.Wait()
}

func TestCanonicalPolicyHash_NoiseFieldsDoNotAffect(t *testing.T) {
	t.Parallel()

	base := canonicalHashOf(t, nil)

	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{
			name: "metrics_listen",
			mut:  func(c *Config) { c.MetricsListen = ":19997" },
		},
		{
			// fetch_proxy.listen is operational plumbing — rebinding the
			// port does not change any enforcement decision. Explicitly
			// excluded in policySemanticView so ops can move the listen
			// address without shifting ph. See canonical.go.
			name: "fetch_proxy.listen",
			mut:  func(c *Config) { c.FetchProxy.Listen = ":19999" },
		},
		{
			name: "reverse_proxy.listen",
			mut:  func(c *Config) { c.ReverseProxy.Listen = ":19998" },
		},
		{
			name: "reverse_proxy.upstream",
			mut:  func(c *Config) { c.ReverseProxy.Upstream = "http://other-upstream:9000" },
		},
		{
			name: "logging.include_allowed",
			mut:  func(c *Config) { c.Logging.IncludeAllowed = !c.Logging.IncludeAllowed },
		},
		{
			name: "license_key",
			mut:  func(c *Config) { c.LicenseKey = "test-token-value" },
		},
		{
			name: "mediation_envelope.signing_key_path",
			mut: func(c *Config) {
				c.MediationEnvelope.SigningKeyPath = "/etc/pipelock/envelope.key"
			},
		},
		{
			name: "flight_recorder.dir",
			mut:  func(c *Config) { c.FlightRecorder.Dir = "/var/lib/pipelock/fr" },
		},
		{
			name: "agents map (global view omits agents)",
			mut: func(c *Config) {
				c.Agents = map[string]AgentProfile{"test": {Mode: ModeStrict}}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := canonicalHashOf(t, tc.mut)
			if got != base {
				t.Errorf("%s changed canonical hash (noise field should not affect):\n  base = %s\n  got  = %s",
					tc.name, base, got)
			}
		})
	}
}

func TestCanonicalPolicyHash_PolicyFieldsDoAffect(t *testing.T) {
	t.Parallel()

	base := canonicalHashOf(t, nil)

	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{
			name: "mode changes",
			mut:  func(c *Config) { c.Mode = ModeStrict },
		},
		{
			name: "enforce flipped to false",
			mut: func(c *Config) {
				f := false
				c.Enforce = &f
			},
		},
		{
			name: "mediation_envelope.sign enabled",
			mut: func(c *Config) {
				c.MediationEnvelope.Enabled = true
				c.MediationEnvelope.Sign = true
			},
		},
		{
			name: "mediation_envelope.key_id changed",
			mut: func(c *Config) {
				c.MediationEnvelope.Enabled = true
				c.MediationEnvelope.Sign = true
				c.MediationEnvelope.KeyID = testEnvelopeKeyIDV2
			},
		},
		{
			name: "mediation_envelope.signed_components changed",
			mut: func(c *Config) {
				c.MediationEnvelope.Enabled = true
				c.MediationEnvelope.Sign = true
				c.MediationEnvelope.SignedComponents = []string{"@method", "@authority"}
			},
		},
		{
			name: "redaction provider profile changed",
			mut: func(c *Config) {
				c.RequestBodyScanning.Enabled = true
				c.Redaction = redact.Config{
					Enabled:        true,
					DefaultProfile: "code",
					Profiles: map[string]redact.ProfileSpec{
						"code": {Classes: []string{string(redact.ClassAWSAccessKey)}},
					},
					Providers: map[string]redact.ProviderSpec{
						"custom": {
							HostPatterns: []string{"api.custom-llm.example"},
							PathPrefixes: []string{"/v1/messages"},
							Parser:       redact.ParserJSON,
						},
					},
					Limits: redact.DefaultLimits(),
				}
			},
		},
		{
			name: "redaction route-scoped non-json exception changed",
			mut: func(c *Config) {
				c.RequestBodyScanning.Enabled = true
				c.Redaction = redact.Config{
					Enabled:        true,
					DefaultProfile: "code",
					Profiles: map[string]redact.ProfileSpec{
						"code": {Classes: []string{string(redact.ClassAWSAccessKey)}},
					},
					AllowlistUnparseableRoutes: []redact.UnparseableRouteSpec{{
						Host:         "login.microsoftonline.com",
						Methods:      []string{"POST"},
						PathSuffixes: []string{"/oauth2/v2.0/token"},
						ContentTypes: []string{"application/x-www-form-urlencoded"},
					}},
					Limits: redact.DefaultLimits(),
				}
			},
		},
		{
			// Transport timeouts are enforcement-relevant (DoS
			// exposure bound, tunnel lifetime) so they must flip ph.
			// Listen / Upstream addresses are separately excluded as
			// operational plumbing. See canonical.go:policySemanticView.
			name: "forward_proxy.idle_timeout",
			mut:  func(c *Config) { c.ForwardProxy.IdleTimeoutSeconds = 9999 },
		},
		{
			name: "fetch_proxy.monitoring.blocklist (actual policy)",
			mut:  func(c *Config) { c.FetchProxy.Monitoring.Blocklist = []string{"evil.example.com"} },
		},
		{
			name: "forward_proxy.sni_verification disabled",
			mut: func(c *Config) {
				f := false
				c.ForwardProxy.SNIVerification = &f
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := canonicalHashOf(t, tc.mut)
			if got == base {
				t.Errorf("%s did not change canonical hash (policy field should shift ph):\n  base = %s\n  got  = %s",
					tc.name, base, got)
			}
		})
	}
}

func TestCanonicalPolicyHash_RedactionProviderOrderCanonical(t *testing.T) {
	t.Parallel()

	first := canonicalHashOf(t, func(c *Config) {
		c.RequestBodyScanning.Enabled = true
		c.Redaction = canonicalProviderTestRedaction([]string{"b.example", "a.example"}, []string{"/v1/messages", "/v1/responses"})
	})
	second := canonicalHashOf(t, func(c *Config) {
		c.RequestBodyScanning.Enabled = true
		c.Redaction = canonicalProviderTestRedaction([]string{"a.example", "b.example"}, []string{"/v1/responses", "/v1/messages"})
	})
	if first != second {
		t.Fatalf("redaction provider host/path order should canonicalize:\nfirst:  %s\nsecond: %s", first, second)
	}
}

func TestCanonicalPolicyHash_RedactionUnparseableRouteOrderCanonical(t *testing.T) {
	t.Parallel()

	mkRedaction := func(routes []redact.UnparseableRouteSpec) redact.Config {
		return redact.Config{
			Enabled:        true,
			DefaultProfile: "code",
			Profiles: map[string]redact.ProfileSpec{
				"code": {Classes: []string{string(redact.ClassAWSAccessKey)}},
			},
			AllowlistUnparseable:       []string{"b.example", "a.example"},
			AllowlistUnparseableRoutes: routes,
			Limits:                     redact.DefaultLimits(),
		}
	}
	routeA := redact.UnparseableRouteSpec{
		Host:         "login.microsoftonline.com",
		Methods:      []string{"POST"},
		PathSuffixes: []string{"/oauth2/v2.0/token"},
		ContentTypes: []string{"application/x-www-form-urlencoded"},
	}
	routeB := redact.UnparseableRouteSpec{
		Host:         "graph.microsoft.com",
		Methods:      []string{"PUT"},
		PathPrefixes: []string{"/v1.0/drives/", "/v1.0/me/drive/"},
		PathSuffixes: []string{":/content"},
		ContentTypes: []string{"application/octet-stream", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
	}

	first := canonicalHashOf(t, func(c *Config) {
		c.RequestBodyScanning.Enabled = true
		c.Redaction = mkRedaction([]redact.UnparseableRouteSpec{routeA, routeB})
	})
	second := canonicalHashOf(t, func(c *Config) {
		c.RequestBodyScanning.Enabled = true
		routeBReordered := routeB
		routeBReordered.PathPrefixes = []string{"/v1.0/me/drive/", "/v1.0/drives/"}
		routeBReordered.ContentTypes = []string{"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/octet-stream"}
		c.Redaction = mkRedaction([]redact.UnparseableRouteSpec{routeBReordered, routeA})
	})
	if first != second {
		t.Fatalf("redaction unparseable route order should canonicalize:\nfirst:  %s\nsecond: %s", first, second)
	}
}

func TestCanonicalPolicyHash_DisabledRedactionProviderIsInert(t *testing.T) {
	t.Parallel()

	base := canonicalHashOf(t, nil)
	got := canonicalHashOf(t, func(c *Config) {
		c.Redaction.Providers = map[string]redact.ProviderSpec{
			"custom": {
				HostPatterns: []string{"api.custom-llm.example"},
				Parser:       redact.ParserJSON,
			},
		}
	})
	if got != base {
		t.Fatalf("disabled redaction provider profile changed canonical hash:\nbase: %s\ngot:  %s", base, got)
	}
}

func TestCanonicalPolicyHash_DisabledRedactionUnparseableRoutesAreInert(t *testing.T) {
	t.Parallel()

	base := canonicalHashOf(t, nil)
	got := canonicalHashOf(t, func(c *Config) {
		c.Redaction.AllowlistUnparseable = []string{"api.example.com"}
		c.Redaction.AllowlistUnparseableRoutes = []redact.UnparseableRouteSpec{{
			Host:         "login.microsoftonline.com",
			Methods:      []string{"POST"},
			PathSuffixes: []string{"/oauth2/v2.0/token"},
			ContentTypes: []string{"application/x-www-form-urlencoded"},
		}}
	})
	if got != base {
		t.Fatalf("disabled redaction unparseable allowlists changed canonical hash:\nbase: %s\ngot:  %s", base, got)
	}
}

func canonicalProviderTestRedaction(hosts, paths []string) redact.Config {
	return redact.Config{
		Enabled:        true,
		DefaultProfile: "code",
		Profiles: map[string]redact.ProfileSpec{
			"code": {Classes: []string{string(redact.ClassAWSAccessKey)}},
		},
		Providers: map[string]redact.ProviderSpec{
			"custom": {
				HostPatterns: hosts,
				PathPrefixes: paths,
				Parser:       redact.ParserJSON,
			},
		},
		Limits: redact.DefaultLimits(),
	}
}

func TestCanonicalPolicyHash_SetLikeSlicesSortedIntoCanonicalOrder(t *testing.T) {
	t.Parallel()

	a := canonicalHashOf(t, func(c *Config) {
		c.APIAllowlist = []string{"foo.example", "bar.example", "baz.example"}
	})
	b := canonicalHashOf(t, func(c *Config) {
		c.APIAllowlist = []string{"baz.example", "foo.example", "bar.example"}
	})
	if a != b {
		t.Errorf("api_allowlist order should not affect hash:\n  a = %s\n  b = %s", a, b)
	}

	// Internal (SSRF private-IP allowlist) is set-like too.
	a2 := canonicalHashOf(t, func(c *Config) {
		c.Internal = []string{"10.0.0.0/8", "192.168.0.0/16"}
	})
	b2 := canonicalHashOf(t, func(c *Config) {
		c.Internal = []string{"192.168.0.0/16", "10.0.0.0/8"}
	})
	if a2 != b2 {
		t.Errorf("internal allowlist order should not affect hash:\n  a = %s\n  b = %s", a2, b2)
	}
}

func TestCanonicalPolicyHash_BehavioralSlicesPreserveOrder(t *testing.T) {
	t.Parallel()

	// DLP.Patterns is ordered — first-match-wins enforcement. Two
	// otherwise-identical configs with the same patterns in different
	// order MUST produce different canonical hashes, because they can
	// produce different enforcement decisions on the same input.
	a := canonicalHashOf(t, func(c *Config) {
		c.DLP.Patterns = []DLPPattern{
			{Name: "pat-a", Regex: "secret-[0-9]+"},
			{Name: "pat-b", Regex: "token-[a-z]+"},
		}
	})
	b := canonicalHashOf(t, func(c *Config) {
		c.DLP.Patterns = []DLPPattern{
			{Name: "pat-b", Regex: "token-[a-z]+"},
			{Name: "pat-a", Regex: "secret-[0-9]+"},
		}
	})
	if a == b {
		t.Errorf("DLP pattern order MUST affect canonical hash (first-match wins)\n  a = b = %s", a)
	}

	// MCPToolPolicy.Rules is first-match-wins too.
	a2 := canonicalHashOf(t, func(c *Config) {
		c.MCPToolPolicy.Rules = []ToolPolicyRule{
			{Name: "rule-a", ToolPattern: "^read_.*$", Action: ActionAllow},
			{Name: "rule-b", ToolPattern: "^write_.*$", Action: ActionBlock},
		}
	})
	b2 := canonicalHashOf(t, func(c *Config) {
		c.MCPToolPolicy.Rules = []ToolPolicyRule{
			{Name: "rule-b", ToolPattern: "^write_.*$", Action: ActionBlock},
			{Name: "rule-a", ToolPattern: "^read_.*$", Action: ActionAllow},
		}
	})
	if a2 == b2 {
		t.Errorf("MCP tool policy rule order MUST affect canonical hash (first-match wins)\n  a = b = %s", a2)
	}
}

func TestCanonicalPolicyHash_RawBytesInvariance(t *testing.T) {
	t.Parallel()

	// Two Config values with identical semantic shape but different
	// rawBytes (from different whitespace / comment styles) must hash
	// equally. rawBytes is an unexported field that json.Marshal skips,
	// so this is true by construction — test is a guard against someone
	// adding rawBytes to the canonical view by accident.
	a := canonicalHashOf(t, func(c *Config) {
		c.rawBytes = []byte("# a comment\nmode: balanced\n")
	})
	b := canonicalHashOf(t, func(c *Config) {
		c.rawBytes = []byte("mode:   balanced\n\n\n")
	})
	if a != b {
		t.Errorf("rawBytes must not affect canonical hash (whitespace / comments only):\n  a = %s\n  b = %s", a, b)
	}
}

func TestCanonicalPolicyHash_SortedCopyNilSafe(t *testing.T) {
	t.Parallel()

	// Nil in, nil out — documented so that an omitted-slice and an
	// empty-slice hash identically.
	if got := sortedCopy(nil); got != nil {
		t.Errorf("sortedCopy(nil) = %v, want nil", got)
	}
	if got := sortedCopy([]string{}); got != nil {
		t.Errorf("sortedCopy([]string{}) = %v, want nil (len-0 should normalise)", got)
	}

	got := sortedCopy([]string{"c", "a", "b"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("sortedCopy len = %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("sortedCopy[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
