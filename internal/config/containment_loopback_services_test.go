// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func validLoopbackService(now time.Time) ContainmentLoopbackService {
	return ContainmentLoopbackService{
		Host:      "127.0.0.1",
		Port:      9200,
		Owner:     "search-team",
		Reason:    "agent needs a local search index for retrieval",
		ExpiresAt: now.Add(24 * time.Hour).UTC().Format(time.RFC3339),
	}
}

// TestValidateContainmentLoopbackServices pins every way a declared loopback
// exception is unusable or unsafe: a config-owned exception that cannot name
// who accepted it, why, when it ends, or which single loopback port it
// covers is not a reviewable exception.
func TestValidateContainmentLoopbackServices(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	const proxyPort = 8888

	tests := []struct {
		name     string
		services []ContainmentLoopbackService
		want     string // substring of the error, or "" for nil (valid)
	}{
		{
			name:     "omitted list",
			services: nil,
			want:     "",
		},
		{
			name:     "empty list",
			services: []ContainmentLoopbackService{},
			want:     "",
		},
		{
			name:     "valid single entry",
			services: []ContainmentLoopbackService{validLoopbackService(now)},
			want:     "",
		},
		{
			name: "valid multiple distinct entries",
			services: []ContainmentLoopbackService{
				validLoopbackService(now),
				func() ContainmentLoopbackService {
					s := validLoopbackService(now)
					s.Port = 9201
					return s
				}(),
			},
			want: "",
		},
		{
			name: "non-loopback host",
			services: []ContainmentLoopbackService{
				func() ContainmentLoopbackService {
					s := validLoopbackService(now)
					s.Host = "10.20.0.20"
					return s
				}(),
			},
			want: "must be a loopback literal",
		},
		{
			name: "hostname",
			services: []ContainmentLoopbackService{
				func() ContainmentLoopbackService {
					s := validLoopbackService(now)
					s.Host = "localhost"
					return s
				}(),
			},
			want: "must be a loopback literal",
		},
		{
			name: "wildcard host",
			services: []ContainmentLoopbackService{
				func() ContainmentLoopbackService {
					s := validLoopbackService(now)
					s.Host = "0.0.0.0"
					return s
				}(),
			},
			want: "must be a loopback literal",
		},
		{
			name: "CIDR host",
			services: []ContainmentLoopbackService{
				func() ContainmentLoopbackService {
					s := validLoopbackService(now)
					s.Host = "127.0.0.0/8"
					return s
				}(),
			},
			want: "must be a loopback literal",
		},
		{
			name: "ipv6 loopback allowed",
			services: []ContainmentLoopbackService{
				func() ContainmentLoopbackService {
					s := validLoopbackService(now)
					s.Host = "::1"
					return s
				}(),
			},
			want: "",
		},
		{
			name: "port zero",
			services: []ContainmentLoopbackService{
				func() ContainmentLoopbackService {
					s := validLoopbackService(now)
					s.Port = 0
					return s
				}(),
			},
			want: "must be between 1 and 65535",
		},
		{
			name: "port too large",
			services: []ContainmentLoopbackService{
				func() ContainmentLoopbackService {
					s := validLoopbackService(now)
					s.Port = 65536
					return s
				}(),
			},
			want: "must be between 1 and 65535",
		},
		{
			name: "proxy port collision",
			services: []ContainmentLoopbackService{
				func() ContainmentLoopbackService {
					s := validLoopbackService(now)
					s.Port = proxyPort
					return s
				}(),
			},
			want: "collides with the agent-accessible proxy port",
		},
		{
			name: "duplicate entry",
			services: []ContainmentLoopbackService{
				validLoopbackService(now),
				validLoopbackService(now),
			},
			want: "duplicates an already-declared loopback service",
		},
		{
			name: "missing owner",
			services: []ContainmentLoopbackService{
				func() ContainmentLoopbackService {
					s := validLoopbackService(now)
					s.Owner = ""
					return s
				}(),
			},
			want: "owner is required",
		},
		{
			name: "missing reason",
			services: []ContainmentLoopbackService{
				func() ContainmentLoopbackService {
					s := validLoopbackService(now)
					s.Reason = ""
					return s
				}(),
			},
			want: "reason is required",
		},
		{
			name: "missing expires_at",
			services: []ContainmentLoopbackService{
				func() ContainmentLoopbackService {
					s := validLoopbackService(now)
					s.ExpiresAt = ""
					return s
				}(),
			},
			want: "must use RFC3339",
		},
		{
			name: "expired entry",
			services: []ContainmentLoopbackService{
				func() ContainmentLoopbackService {
					s := validLoopbackService(now)
					s.ExpiresAt = now.Add(-time.Hour).UTC().Format(time.RFC3339)
					return s
				}(),
			},
			want: "expired at",
		},
		{
			name: "expiry far in the future is still just a normal bound the caller enforces at parse time",
			services: []ContainmentLoopbackService{
				func() ContainmentLoopbackService {
					s := validLoopbackService(now)
					s.ExpiresAt = now.Add(24 * 365 * time.Hour).UTC().Format(time.RFC3339)
					return s
				}(),
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateContainmentLoopbackServices(tt.services, proxyPort, now)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("ValidateContainmentLoopbackServices() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("ValidateContainmentLoopbackServices() = %v, want substring %q", err, tt.want)
			}
		})
	}
}

// TestValidateContainmentLoopbackServicesRejectsYAMLNull mirrors the omitted
// vs explicit-null vs empty-list distinction the metrics exposure policy
// already exercises: a nil slice (key omitted or explicit YAML null) and an
// explicit empty list must both validate as "no declared exception," never
// as an error, so an operator cannot be blocked by declaring nothing.
func TestContainmentLoopbackServicesEmptyYAMLShapesDecodeToNoDeclarations(t *testing.T) {
	// Handing the validator a nil Go slice, as this test once did, cannot
	// see a decoder disagreement at all: it skips the decode entirely and
	// asserts only that the empty case is legal, under a name that claimed
	// the opposite. Decode the YAML instead, so a change in how the key is
	// read is what the assertion actually covers.
	for _, tc := range []struct {
		name string
		yaml string
	}{
		{"key omitted", "containment: {}\n"},
		{"explicit null", "containment:\n  loopback_services: null\n"},
		{"explicit tilde", "containment:\n  loopback_services: ~\n"},
		{"explicit empty list", "containment:\n  loopback_services: []\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Defaults()
			if err := yaml.Unmarshal([]byte(tc.yaml), &cfg); err != nil {
				t.Fatalf("decode %q: %v", tc.yaml, err)
			}
			if len(cfg.Containment.LoopbackServices) != 0 {
				t.Fatalf("decoded %+v, want no declared services", cfg.Containment.LoopbackServices)
			}
			if err := cfg.validateContainmentLoopbackServices(); err != nil {
				t.Fatalf("an empty declaration must validate: %v", err)
			}
		})
	}
}

// TestContainmentLoopbackServicesYAMLDecodesADeclaration is the positive
// control for the shapes above: a real declared entry must survive the same
// decode, so "decodes to nothing" cannot pass by decoding nothing ever.
func TestContainmentLoopbackServicesYAMLDecodesADeclaration(t *testing.T) {
	body := "containment:\n  loopback_services:\n  - host: 127.0.0.1\n    port: 9222\n" +
		"    owner: platform\n    reason: browser automation control port\n" +
		"    expires_at: \"" + time.Now().Add(24*time.Hour).UTC().Format(time.RFC3339) + "\"\n"
	cfg := Defaults()
	if err := yaml.Unmarshal([]byte(body), &cfg); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(cfg.Containment.LoopbackServices) != 1 || cfg.Containment.LoopbackServices[0].Port != 9222 {
		t.Fatalf("decoded %+v, want one entry on port 9222", cfg.Containment.LoopbackServices)
	}
	if err := cfg.validateContainmentLoopbackServices(); err != nil {
		t.Fatalf("decoded declaration must validate: %v", err)
	}
}

// TestConfigValidateContainmentLoopbackServices proves containment.loopback_services
// participates in the ordinary Config.Validate() path (fail-closed at config
// load), not only in the standalone ValidateContainmentLoopbackServices helper.
func TestConfigValidateContainmentLoopbackServices(t *testing.T) {
	cfg := Defaults()
	cfg.Containment.LoopbackServices = []ContainmentLoopbackService{
		{
			Host:      "10.20.0.20",
			Port:      9200,
			Owner:     "x",
			Reason:    "y",
			ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "loopback literal") {
		t.Fatalf("Config.Validate() = %v, want a loopback_services error", err)
	}

	cfg.Containment.LoopbackServices[0].Host = "127.0.0.1"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Config.Validate() unexpected error for a valid declared service: %v", err)
	}
}

// TestConfigValidateContainmentLoopbackServicesEmptyIsNoOp confirms the
// common case -- no declared loopback services -- never touches
// fetch_proxy.listen parsing.
func TestConfigValidateContainmentLoopbackServicesEmptyIsNoOp(t *testing.T) {
	cfg := Defaults()
	cfg.FetchProxy.Listen = "not-a-valid-listen-address"
	cfg.Containment.LoopbackServices = nil
	if err := cfg.validateContainmentLoopbackServices(); err != nil {
		t.Fatalf("empty loopback_services must short-circuit before parsing fetch_proxy.listen: %v", err)
	}
}

// TestValidateContainmentLoopbackServicesRejectsPaddedHost pins the
// declaration/render agreement: nftLoopbackAcceptLine renders Host verbatim
// and selects its address family by exact literal match, so a padded
// " ::1 " that validated would render as an IPv4 rule. Validation must
// therefore reject non-canonical spacing rather than trim it, which keeps
// the validated value and the rendered value identical by construction
// instead of relying on two separate places trimming the same way.
func TestValidateContainmentLoopbackServicesRejectsPaddedHost(t *testing.T) {
	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	for _, host := range []string{" ::1 ", "::1 ", " ::1", " 127.0.0.1", "127.0.0.1 ", "\t127.0.0.1"} {
		t.Run(fmt.Sprintf("%q", host), func(t *testing.T) {
			err := ValidateContainmentLoopbackServices([]ContainmentLoopbackService{{
				Host:      host,
				Port:      9222,
				Owner:     "platform",
				Reason:    "browser automation control port",
				ExpiresAt: future,
			}}, 8888, time.Now())
			if err == nil {
				t.Fatalf("host %q was accepted; a padded literal renders a different rule than it declares", host)
			}
			if !strings.Contains(err.Error(), "no surrounding whitespace") {
				t.Errorf("error = %v, want it to explain that surrounding whitespace is refused", err)
			}
		})
	}
}

// TestValidateContainmentLoopbackServicesAcceptsCanonicalHosts is the
// positive control for the test above: the exact literals must still pass,
// so the whitespace refusal cannot be satisfied by rejecting everything.
func TestValidateContainmentLoopbackServicesAcceptsCanonicalHosts(t *testing.T) {
	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	for _, host := range []string{"127.0.0.1", "::1"} {
		t.Run(host, func(t *testing.T) {
			if err := ValidateContainmentLoopbackServices([]ContainmentLoopbackService{{
				Host:      host,
				Port:      9222,
				Owner:     "platform",
				Reason:    "browser automation control port",
				ExpiresAt: future,
			}}, 8888, time.Now()); err != nil {
				t.Fatalf("canonical host %q was refused: %v", host, err)
			}
		})
	}
}
