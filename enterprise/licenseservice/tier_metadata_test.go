//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"slices"
	"testing"
	"time"
)

func TestTierMetadataContract(t *testing.T) {
	handler := &WebhookHandler{cfg: &Config{}}
	if got := len(validTiers); got != 7 {
		t.Fatalf("accepted tier count = %d, want 7", got)
	}
	tests := []struct {
		tier     string
		features []string
		days     int
		founding bool
	}{
		{"founding_pro", []string{"agents"}, 45, true},
		{"pro", []string{"agents"}, 45, false},
		{"enterprise", []string{"agents", "fleet"}, 45, false},
		{"enterprise_eval", []string{"agents", "fleet"}, 60, false},
		{"enterprise_trial", []string{"agents", "fleet"}, 60, false},
		{"trial", []string{"agents"}, 30, false},
		{"assess", []string{"assess"}, 45, false},
	}
	for _, tt := range tests {
		t.Run(tt.tier, func(t *testing.T) {
			sub := &PolarSubscription{}
			sub.Product.Metadata = map[string]string{"pipelock_tier": tt.tier}
			tier, founding, err := handler.mapProductToTier(sub)
			if err != nil || tier != tt.tier || founding != tt.founding {
				t.Fatalf("mapProductToTier() = (%q, %v, %v), want (%q, %v, nil)", tier, founding, err, tt.tier, tt.founding)
			}
			features := handler.tierToFeatures(tier)
			if !slices.Equal(features, tt.features) {
				t.Fatalf("tierToFeatures(%q) = %v, want ordered features %v", tier, features, tt.features)
			}
			if got, want := handler.tokenLifetimeForTier(tier), time.Duration(tt.days)*24*time.Hour; got != want {
				t.Errorf("tokenLifetimeForTier(%q) = %v, want %v", tier, got, want)
			}

			// A caller owns its returned slice. Editing every element must not
			// alter later issuance, including tiers sharing the same features.
			for i := range features {
				features[i] = "caller-owned"
			}
			for _, other := range tests {
				if got := handler.tierToFeatures(other.tier); !slices.Equal(got, other.features) {
					t.Errorf("mutating %q features changed %q to %v, want %v", tier, other.tier, got, other.features)
				}
			}
		})
	}
}

func TestTierMetadataUnknownContract(t *testing.T) {
	handler := &WebhookHandler{cfg: &Config{}}
	for _, value := range []string{"", "unknown", "Pro", " pro", "pro ", "enterprise-eval"} {
		t.Run(value, func(t *testing.T) {
			sub := &PolarSubscription{}
			sub.Product.Metadata = map[string]string{"pipelock_tier": value}
			tier, founding, err := handler.mapProductToTier(sub)
			if err == nil || tier != "" || founding {
				t.Errorf("mapProductToTier() = (%q, %v, %v), want empty tier, false, error", tier, founding, err)
			}
			if got := handler.tierToFeatures(value); got != nil {
				t.Errorf("unknown tier features = %v, want nil", got)
			}
			if got, want := handler.tokenLifetimeForTier(value), 45*24*time.Hour; got != want {
				t.Errorf("unknown tier lifetime = %v, want existing fallback %v", got, want)
			}
		})
	}

	tier, founding, err := handler.mapProductToTier(&PolarSubscription{})
	if err == nil || tier != "" || founding {
		t.Errorf("missing metadata returned (%q, %v, %v), want empty tier, false, error", tier, founding, err)
	}
}
