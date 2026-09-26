// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestContainmentDisplayBooleanStates(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		enabled bool
		number  int
	}{
		{name: "omitted", yaml: "mode: balanced\n", number: 99},
		{name: "explicit null", yaml: "containment:\n  display: null\n", number: 99},
		{name: "explicit false", yaml: "containment:\n  display:\n    enabled: false\n", number: 99},
		{name: "explicit display zero", yaml: "containment:\n  display:\n    enabled: true\n    number: 0\n", enabled: true, number: 0},
		{name: "explicit true", yaml: "containment:\n  display:\n    enabled: true\n    number: 77\n", enabled: true, number: 77},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			// IsEnabled resolves the tri-state. Passing false for the host
			// check isolates the CONFIG's own answer: an omitted value
			// defers to the host, and only an explicit true overrides a
			// host with no Xvfb installed.
			if got := cfg.Containment.Display.IsEnabled(false); got != tc.enabled {
				t.Fatalf("IsEnabled(no xvfb) = %v, want %v", got, tc.enabled)
			}
			// An omitted or null value must follow the host; an explicit
			// false must not, even when the host has an X server.
			wantWithXvfb := tc.enabled || strings.Contains(tc.name, "omitted") || strings.Contains(tc.name, "null")
			if got := cfg.Containment.Display.IsEnabled(true); got != wantWithXvfb {
				t.Fatalf("IsEnabled(xvfb present) = %v, want %v", got, wantWithXvfb)
			}
			if got := cfg.Containment.Display.EffectiveNumber(); got != tc.number {
				t.Fatalf("effective number = %d, want %d", got, tc.number)
			}
		})
	}
}

func TestContainmentDisplayReloadStates(t *testing.T) {
	off, err := LoadBytes([]byte("containment:\n  display:\n    enabled: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	on, err := LoadBytes([]byte("containment:\n  display:\n    enabled: true\n    number: 88\n"))
	if err != nil {
		t.Fatal(err)
	}
	onAgain, err := LoadBytes([]byte("containment:\n  display:\n    enabled: true\n    number: 88\n"))
	if err != nil {
		t.Fatal(err)
	}
	if off.Containment.Display.IsEnabled(true) || !on.Containment.Display.IsEnabled(false) ||
		on.Containment.Display.EffectiveNumber() != 88 {
		t.Fatal("reload with change did not apply display configuration")
	}
	if onAgain.Containment.Display.IsEnabled(false) != on.Containment.Display.IsEnabled(false) ||
		onAgain.Containment.Display.EffectiveNumber() != on.Containment.Display.EffectiveNumber() {
		t.Fatal("reload without change drifted display configuration")
	}
}

func TestContainmentDisplayRejectsInvalidNumber(t *testing.T) {
	for _, yaml := range []string{
		"containment:\n  display:\n    enabled: true\n    number: 1000\n",
		"containment:\n  display:\n    enabled: true\n    number: -1\n",
	} {
		if _, err := LoadBytes([]byte(yaml)); err == nil {
			t.Fatalf("invalid display number accepted for %q", yaml)
		}
	}
	if _, err := LoadBytes([]byte("containment:\n  display:\n    enabled: true\n    number: 999\n")); err != nil {
		t.Fatalf("boundary display number 999 rejected: %v", err)
	}
}

func TestContainmentDisplayGeometry(t *testing.T) {
	for _, tc := range []struct {
		geometry string
		valid    bool
	}{
		{"", true},
		{"1280x1024", true},
		{"320x200", true},
		{"65535x65535", true},
		{"319x200", false},
		{"320x199", false},
		{"65536x200", false},
		{"320x65536", false},
		{"0x200", false},
		{"320x0", false},
		{"320", false},
		{"320X200", false},
		{" 320x200", false},
		{"320x200 ", false},
		{"1600x900 -ac", false},
	} {
		t.Run(tc.geometry, func(t *testing.T) {
			cfg, err := LoadBytes([]byte("containment:\n  display:\n    geometry: '" + tc.geometry + "'\n"))
			if (err == nil) != tc.valid {
				t.Fatalf("geometry %q: err = %v, valid = %v", tc.geometry, err, tc.valid)
			}
			if err == nil && tc.geometry == "" && cfg.Containment.Display.EffectiveGeometry() != "1280x1024" {
				t.Fatal("omitted geometry default changed")
			}
		})
	}
}

func TestContainmentDisplayViewerConfig(t *testing.T) {
	tests := []struct {
		name, yaml, backend string
		enabled             bool
		bad                 bool
	}{
		{"omitted", "mode: balanced\n", "xvfb", false, false},
		{"null", "containment:\n  display: null\n", "xvfb", false, false},
		{"viewer false", "containment:\n  display:\n    viewer:\n      enabled: false\n", "xvfb", false, false},
		{"viewer null", "containment:\n  display:\n    viewer:\n      enabled: null\n", "xvfb", false, false},
		{"viewer true", "containment:\n  display:\n    viewer:\n      enabled: true\n      public_origin: https://viewer.example\n", "xvnc", true, false},
		{"viewer missing origin", "containment:\n  display:\n    viewer:\n      enabled: true\n", "", false, true},
		{"viewer HTTP origin", "containment:\n  display:\n    viewer:\n      enabled: true\n      public_origin: http://viewer.example\n", "", false, true},
		{"viewer path origin", "containment:\n  display:\n    viewer:\n      enabled: true\n      public_origin: https://viewer.example/path\n", "", false, true},
		{"viewer bad host", "containment:\n  display:\n    viewer:\n      enabled: true\n      public_origin: https://\n", "", false, true},
		{"explicit xvnc", "containment:\n  display:\n    backend: xvnc\n", "xvnc", true, false},
		{"conflict", "containment:\n  display:\n    backend: xvfb\n    viewer:\n      enabled: true\n", "", false, true},
		{"bad backend", "containment:\n  display:\n    backend: other\n", "", false, true},
		{"bad socket", "containment:\n  display:\n    viewer:\n      host_socket: ../viewer.sock\n", "", false, true},
		{"bad user", "containment:\n  display:\n    viewer:\n      operator_user: 'a b'\n", "", false, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadBytes([]byte(tc.yaml))
			if tc.bad {
				if err == nil {
					t.Fatal("invalid display viewer config accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			d := cfg.Containment.Display
			if d.EffectiveBackend() != tc.backend || d.IsEnabled(false) != tc.enabled {
				t.Fatalf("backend=%s enabled=%t, want %s/%t", d.EffectiveBackend(), d.IsEnabled(false), tc.backend, tc.enabled)
			}
		})
	}
}
