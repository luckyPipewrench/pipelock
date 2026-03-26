// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func boolPtrCfg(b bool) *bool { return &b }

func TestFileSentryChanged(t *testing.T) {
	t.Parallel()

	base := func() *Config {
		c := Defaults()
		c.FileSentry.Enabled = true
		c.FileSentry.BestEffort = false
		c.FileSentry.WatchPaths = []string{"/tmp/watch"}
		c.FileSentry.ScanContent = boolPtrCfg(true)
		c.FileSentry.IgnorePatterns = []string{"*.log"}
		return c
	}

	tests := []struct {
		name    string
		modify  func(c *Config)
		changed bool
	}{
		{
			name:    "identical configs",
			modify:  func(_ *Config) {},
			changed: false,
		},
		{
			name:    "enabled changed",
			modify:  func(c *Config) { c.FileSentry.Enabled = false },
			changed: true,
		},
		{
			name:    "best_effort changed",
			modify:  func(c *Config) { c.FileSentry.BestEffort = true },
			changed: true,
		},
		{
			name:    "watch_paths changed",
			modify:  func(c *Config) { c.FileSentry.WatchPaths = []string{"/tmp/other"} },
			changed: true,
		},
		{
			name:    "watch_paths added",
			modify:  func(c *Config) { c.FileSentry.WatchPaths = append(c.FileSentry.WatchPaths, "/tmp/extra") },
			changed: true,
		},
		{
			name:    "scan_content changed true to false",
			modify:  func(c *Config) { c.FileSentry.ScanContent = boolPtrCfg(false) },
			changed: true,
		},
		{
			name:    "scan_content changed to nil",
			modify:  func(c *Config) { c.FileSentry.ScanContent = nil },
			changed: true,
		},
		{
			name:    "ignore_patterns changed",
			modify:  func(c *Config) { c.FileSentry.IgnorePatterns = []string{"*.tmp"} },
			changed: true,
		},
		{
			name:    "ignore_patterns added",
			modify:  func(c *Config) { c.FileSentry.IgnorePatterns = append(c.FileSentry.IgnorePatterns, "*.tmp") },
			changed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			old := base()
			updated := base()
			tt.modify(updated)
			got := fileSentryChanged(old, updated)
			if got != tt.changed {
				t.Errorf("fileSentryChanged() = %v, want %v", got, tt.changed)
			}
		})
	}
}
