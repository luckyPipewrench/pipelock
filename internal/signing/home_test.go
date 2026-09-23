// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"path/filepath"
	"testing"
)

// withPipelockHome saves and restores the package-level PipelockHome var so
// tests can mutate it without leaking state into other tests.
func withPipelockHome(t *testing.T, value string) {
	t.Helper()
	old := PipelockHome
	PipelockHome = value
	t.Cleanup(func() { PipelockHome = old })
}

func TestResolvedHome_Precedence(t *testing.T) {
	tests := []struct {
		name string
		flag string
		env  string
		want string
	}{
		{name: "neither set", flag: "", env: "", want: ""},
		{name: "env only", flag: "", env: "/env-home", want: "/env-home"},
		{name: "flag only", flag: "/flag-home", env: "", want: "/flag-home"},
		{name: "flag and env both set: flag wins", flag: "/flag-home", env: "/env-home", want: "/flag-home"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withPipelockHome(t, tt.flag)
			t.Setenv("PIPELOCK_HOME", tt.env)

			if got := ResolvedHome(); got != tt.want {
				t.Errorf("ResolvedHome() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveKeystoreDir_Precedence(t *testing.T) {
	home := t.TempDir()
	flagDir := filepath.Join(home, "flag-home")
	envDir := filepath.Join(home, "env-home")

	tests := []struct {
		name     string
		explicit string
		flag     string
		env      string
		want     string // "" means "default keystore path"
	}{
		{name: "explicit wins over everything", explicit: "/explicit", flag: flagDir, env: envDir, want: "/explicit"},
		{name: "flag wins over env when no explicit", explicit: "", flag: flagDir, env: envDir, want: flagDir},
		{name: "env used when no explicit or flag", explicit: "", flag: "", env: envDir, want: envDir},
		{name: "default when nothing set", explicit: "", flag: "", env: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HOME", home)
			withPipelockHome(t, tt.flag)
			t.Setenv("PIPELOCK_HOME", tt.env)

			got, err := ResolveKeystoreDir(tt.explicit)
			if err != nil {
				t.Fatalf("ResolveKeystoreDir(%q): %v", tt.explicit, err)
			}
			want := tt.want
			if want == "" {
				def, defErr := DefaultKeystorePath()
				if defErr != nil {
					t.Fatalf("DefaultKeystorePath: %v", defErr)
				}
				want = def
			}
			if got != want {
				t.Errorf("ResolveKeystoreDir(%q) = %q, want %q", tt.explicit, got, want)
			}
		})
	}
}
