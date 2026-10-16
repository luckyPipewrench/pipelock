// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestConductorRejectsInvalidIdentityAndSafetyBounds(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name string
		edit func(*Conductor)
		want string
	}{
		{name: "valid follower", edit: func(*Conductor) {}},
		{name: "negative major skew", edit: func(c *Conductor) { c.MaxMinVersionMajorSkew = -1 }, want: "conductor.max_min_version_major_skew"},
		{name: "negative minor skew", edit: func(c *Conductor) { c.MaxMinVersionMinorSkew = -1 }, want: "conductor.max_min_version_minor_skew"},
		{name: "malformed poll duration", edit: func(c *Conductor) { c.PollInterval = "later" }, want: "conductor.poll_interval must be a duration"},
		{name: "negative timestamp skew", edit: func(c *Conductor) { c.CreatedSkewSeconds = -1 }, want: "conductor.created_skew_seconds must be > 0"},
		{name: "negative grace multiplier", edit: func(c *Conductor) { c.StalePolicy.GraceMultiplier = -1 }, want: "conductor.stale_policy.grace_multiplier must be > 0"},
		{name: "malformed server URL", edit: func(c *Conductor) { c.ConductorURL = "https://%" }, want: "conductor.conductor_url:"},
		{name: "missing instance identity", edit: func(c *Conductor) { c.InstanceID = "" }, want: "conductor.instance_id required"},
		{name: "overlong instance identity", edit: func(c *Conductor) { c.InstanceID = strings.Repeat("a", 129) }, want: "conductor.instance_id must be <= 128 bytes"},
		{name: "non ASCII instance identity", edit: func(c *Conductor) { c.InstanceID = "node-é" }, want: "conductor.instance_id contains non-ASCII"},
		{name: "instance identity delimiter", edit: func(c *Conductor) { c.InstanceID = "node/other" }, want: "conductor.instance_id contains invalid character"},
		{name: "noncanonical trust path", edit: func(c *Conductor) {
			c.TrustRosterPath = filepath.Dir(c.TrustRosterPath) + string(filepath.Separator) + "." + string(filepath.Separator) + "roster.json"
		}, want: "conductor.trust_roster_path must be in canonical form"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Defaults()
			cfg.Conductor = validConductorConfig(t)
			configureConductorRecorder(t, cfg)
			tt.edit(&cfg.Conductor)
			err := cfg.Validate()
			if tt.want == "" {
				if err != nil {
					t.Fatalf("valid follower configuration: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestConductorRejectsUnusableEnrollmentParents(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"directory", "regular file", "symlink cycle"} {
		t.Run(kind, func(t *testing.T) {
			if kind == "symlink cycle" && runtime.GOOS == "windows" {
				t.Skip("creating symlinks requires additional privileges on Windows")
			}
			cfg := Defaults()
			cfg.Conductor = validConductorConfig(t)
			configureConductorRecorder(t, cfg)
			parent := filepath.Join(filepath.Dir(cfg.Conductor.TrustRosterPath), "enrollment")
			want := ""
			switch kind {
			case "directory":
				if err := os.Mkdir(parent, 0o750); err != nil {
					t.Fatal(err)
				}
			case "regular file":
				if err := os.WriteFile(parent, []byte("not a directory"), 0o600); err != nil {
					t.Fatal(err)
				}
				want = "is not a directory"
			case "symlink cycle":
				if err := os.Symlink(parent, parent); err != nil {
					t.Fatal(err)
				}
				want = "resolve parent"
			}
			cfg.Conductor.EnrollmentTokenPath = filepath.Join(parent, "token")
			err := cfg.Validate()
			if want == "" {
				if err != nil {
					t.Fatalf("private enrollment directory refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "conductor.enrollment_token_path") || !strings.Contains(err.Error(), want) {
				t.Fatalf("Validate() = %v, want enrollment parent refusal containing %q", err, want)
			}
		})
	}
}
