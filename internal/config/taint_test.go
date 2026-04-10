// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

func TestDefaults_Taint(t *testing.T) {
	cfg := Defaults()

	if !cfg.Taint.Enabled {
		t.Fatal("expected taint to default enabled")
	}
	if cfg.Taint.Policy != ModeBalanced {
		t.Fatalf("policy = %q, want %q", cfg.Taint.Policy, ModeBalanced)
	}
	if cfg.Taint.RecentSources != 10 {
		t.Fatalf("recent_sources = %d, want 10", cfg.Taint.RecentSources)
	}
	if len(cfg.Taint.AllowlistedDomains) == 0 {
		t.Fatal("expected allowlisted domains defaults")
	}
	if len(cfg.Taint.ProtectedPaths) == 0 {
		t.Fatal("expected protected path defaults")
	}
	if len(cfg.Taint.ElevatedPaths) == 0 {
		t.Fatal("expected elevated path defaults")
	}
}

func TestValidateTaint(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{
			name: "invalid policy",
			mutate: func(cfg *Config) {
				cfg.Taint.Policy = "aggressive"
			},
			wantErr: "taint.policy",
		},
		{
			name: "invalid allowlisted domain",
			mutate: func(cfg *Config) {
				cfg.Taint.AllowlistedDomains = []string{"*.com"}
			},
			wantErr: "taint.allowlisted_domains",
		},
		{
			name: "invalid protected path glob",
			mutate: func(cfg *Config) {
				cfg.Taint.ProtectedPaths = []string{"[broken"}
			},
			wantErr: "taint.protected_paths",
		},
		{
			name: "trust override missing expiry",
			mutate: func(cfg *Config) {
				cfg.Taint.TrustOverrides = []TaintTrustOverride{{
					Scope:       "action",
					ActionMatch: "write:*/auth/*",
				}}
			},
			wantErr: "expires_at",
		},
		{
			name: "trust override invalid scope",
			mutate: func(cfg *Config) {
				cfg.Taint.TrustOverrides = []TaintTrustOverride{{
					Scope:       "task",
					ActionMatch: "write:*/auth/*",
					ExpiresAt:   time.Now().UTC().Add(time.Hour),
				}}
			},
			wantErr: "must be action or source",
		},
		{
			name: "scope action requires action match",
			mutate: func(cfg *Config) {
				cfg.Taint.TrustOverrides = []TaintTrustOverride{{
					Scope:     "action",
					ExpiresAt: time.Now().UTC().Add(time.Hour),
				}}
			},
			wantErr: "action_match is required",
		},
		{
			name: "scope source requires source match",
			mutate: func(cfg *Config) {
				cfg.Taint.TrustOverrides = []TaintTrustOverride{{
					Scope:     "source",
					ExpiresAt: time.Now().UTC().Add(time.Hour),
				}}
			},
			wantErr: "source_match is required",
		},
		{
			name: "valid trust override",
			mutate: func(cfg *Config) {
				cfg.Taint.TrustOverrides = []TaintTrustOverride{{
					Scope:       "action",
					ActionMatch: "write:*/auth/*",
					ExpiresAt:   time.Now().UTC().Add(time.Hour),
					GrantedBy:   "operator",
					Reason:      "temporary migration",
				}}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			tt.mutate(cfg)
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
			}
		})
	}
}
