// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// fakeFileInfo is a minimal fs.FileInfo implementation used by the
// resolver tests to emulate different permission modes.
type fakeFileInfo struct {
	name string
	mode fs.FileMode
	size int64
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return f.size }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

// emptyEnv is an os.Getenv stub that returns the empty string for all
// keys. Used when a test wants to exercise the "nothing set" path.
func emptyEnv(string) string { return "" }

func fakeDepsWithEnv(env map[string]string, cfg *config.Config, statErr error) resolverDeps {
	return resolverDeps{
		userHomeDir: func() (string, error) { return "", errors.New("no home in tests") },
		stat: func(string) (os.FileInfo, error) {
			if statErr != nil {
				return nil, statErr
			}
			return fakeFileInfo{name: "pipelock.yaml", mode: 0o600}, nil
		},
		loadConfig: func(string) (*config.Config, error) {
			if cfg == nil {
				return nil, errors.New("no config")
			}
			return cfg, nil
		},
		getenv: func(k string) string { return env[k] },
	}
}

func TestResolveEndpoint_FlagsWin(t *testing.T) {
	flags := &rootFlags{apiURL: "http://localhost:9090", apiToken: "tkn"}
	ep, err := resolveEndpoint(flags, fakeDepsWithEnv(nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if ep.URL != "http://localhost:9090" {
		t.Errorf("URL: got %q, want http://localhost:9090", ep.URL)
	}
	if ep.Token != "tkn" {
		t.Errorf("Token: got %q, want tkn", ep.Token)
	}
}

func TestResolveEndpoint_EnvFallback(t *testing.T) {
	env := map[string]string{
		envAPIURL:              "http://127.0.0.1:9091",
		killswitch.EnvAPIToken: "env-token",
	}
	ep, err := resolveEndpoint(&rootFlags{}, fakeDepsWithEnv(env, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if ep.URL != "http://127.0.0.1:9091" || ep.Token != "env-token" {
		t.Errorf("got %+v", ep)
	}
}

func TestResolveEndpoint_MissingToken(t *testing.T) {
	// No flags, no env, no config → error about token.
	_, err := resolveEndpoint(&rootFlags{apiURL: "http://x:1"}, fakeDepsWithEnv(nil, nil, os.ErrNotExist))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestResolveEndpoint_ConfigFallback(t *testing.T) {
	cfg := config.Defaults()
	cfg.KillSwitch.APIListen = "127.0.0.1:9090"
	cfg.KillSwitch.APIToken = "yaml-token"

	deps := fakeDepsWithEnv(map[string]string{envConfigVar: "/fake/pipelock.yaml"}, cfg, nil)
	ep, err := resolveEndpoint(&rootFlags{}, deps)
	if err != nil {
		t.Fatal(err)
	}
	if ep.Token != "yaml-token" {
		t.Errorf("Token: got %q, want yaml-token", ep.Token)
	}
	if ep.URL != "http://127.0.0.1:9090" {
		t.Errorf("URL: got %q, want http://127.0.0.1:9090", ep.URL)
	}
}

func TestResolveEndpoint_ConfigMissingFields(t *testing.T) {
	cfg := config.Defaults()
	cfg.KillSwitch.APIListen = ""
	cfg.KillSwitch.APIToken = ""

	deps := fakeDepsWithEnv(map[string]string{envConfigVar: "/fake/pipelock.yaml"}, cfg, nil)
	if _, err := resolveEndpoint(&rootFlags{}, deps); err == nil {
		t.Error("expected error when config has neither listen nor token")
	}
}

func TestCheckConfigPerms(t *testing.T) {
	tests := []struct {
		name    string
		mode    fs.FileMode
		wantErr bool
	}{
		{"0600 OK", 0o600, false},
		{"0644 rejected", 0o644, true},
		{"0666 rejected", 0o666, true},
		{"0700 OK (owner-only)", 0o700, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkConfigPerms("fake", func(string) (os.FileInfo, error) {
				return fakeFileInfo{name: "pipelock.yaml", mode: tt.mode}, nil
			})
			if tt.wantErr && err == nil {
				t.Error("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestCheckConfigPerms_StatError(t *testing.T) {
	err := checkConfigPerms("missing", func(string) (os.FileInfo, error) {
		return nil, errors.New("stat boom")
	})
	if err == nil {
		t.Error("expected error from stat failure")
	}
}

func TestResolveConfigPath_Priority(t *testing.T) {
	explicit := "/explicit/pipelock.yaml"
	got := resolveConfigPath(explicit, func() (string, error) { return "", nil }, func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }, emptyEnv)
	if got != explicit {
		t.Errorf("explicit: got %q, want %q", got, explicit)
	}
}

func TestResolveConfigPath_EnvFallback(t *testing.T) {
	env := map[string]string{envConfigVar: "/env/pipelock.yaml"}
	got := resolveConfigPath("", func() (string, error) { return "", nil }, func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }, func(k string) string { return env[k] })
	if got != "/env/pipelock.yaml" {
		t.Errorf("env path: got %q", got)
	}
}

func TestResolveConfigPath_HomeCandidate(t *testing.T) {
	dir := t.TempDir()
	want := filepath.Join(dir, ".config", "pipelock", "pipelock.yaml")
	if err := os.MkdirAll(filepath.Dir(want), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(want, []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	got := resolveConfigPath("",
		func() (string, error) { return dir, nil },
		func(p string) (os.FileInfo, error) {
			if p == want {
				return fakeFileInfo{name: "pipelock.yaml", mode: 0o600}, nil
			}
			return nil, os.ErrNotExist
		},
		emptyEnv,
	)
	if got != want {
		t.Errorf("home candidate: got %q, want %q", got, want)
	}
}

func TestResolveConfigPath_NoCandidate(t *testing.T) {
	got := resolveConfigPath("",
		func() (string, error) { return "", errors.New("no home") },
		func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		emptyEnv,
	)
	if got != "" {
		t.Errorf("no candidate: got %q, want empty", got)
	}
}

func TestEnsureScheme(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"127.0.0.1:9090", "http://127.0.0.1:9090"},
		{"http://localhost:9090", "http://localhost:9090"},
		{"https://api.internal", "https://api.internal"},
	}
	for _, tt := range tests {
		if got := ensureScheme(tt.in); got != tt.want {
			t.Errorf("ensureScheme(%q): got %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestNormalizeEndpoint_StripsTrailingSlashes(t *testing.T) {
	got := normalizeEndpoint(endpoint{URL: "http://x:1///", Token: "t"})
	if got.URL != "http://x:1" {
		t.Errorf("URL: got %q, want http://x:1", got.URL)
	}
}

func TestDefaultResolverDeps_Wiring(t *testing.T) {
	deps := defaultResolverDeps()
	if deps.userHomeDir == nil || deps.stat == nil || deps.loadConfig == nil || deps.getenv == nil {
		t.Error("defaultResolverDeps should populate every field")
	}
}

func TestResolveEndpoint_NoTokenNoConfig(t *testing.T) {
	deps := resolverDeps{
		userHomeDir: func() (string, error) { return "", errors.New("no home") },
		stat:        func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		loadConfig:  func(string) (*config.Config, error) { return nil, errors.New("never called") },
		getenv:      func(string) string { return "" },
	}
	_, err := resolveEndpoint(&rootFlags{apiURL: "http://x:1"}, deps)
	if err == nil {
		t.Error("expected error when token cannot be sourced")
	}
}

func TestResolveEndpoint_ConfigLoadFailure(t *testing.T) {
	deps := resolverDeps{
		userHomeDir: func() (string, error) { return "", errors.New("no home") },
		stat:        func(string) (os.FileInfo, error) { return fakeFileInfo{mode: 0o600}, nil },
		loadConfig:  func(string) (*config.Config, error) { return nil, errors.New("yaml blew up") },
		getenv:      func(k string) string { return map[string]string{envConfigVar: "/fake"}[k] },
	}
	_, err := resolveEndpoint(&rootFlags{}, deps)
	if err == nil {
		t.Error("expected error when config load fails")
	}
}

func TestResolveEndpoint_ConfigPermsRejected(t *testing.T) {
	cfg := config.Defaults()
	cfg.KillSwitch.APIToken = "t"
	cfg.KillSwitch.APIListen = "127.0.0.1:9090"
	deps := resolverDeps{
		userHomeDir: func() (string, error) { return "", errors.New("no home") },
		stat:        func(string) (os.FileInfo, error) { return fakeFileInfo{mode: 0o644}, nil },
		loadConfig:  func(string) (*config.Config, error) { return cfg, nil },
		getenv:      func(k string) string { return map[string]string{envConfigVar: "/fake"}[k] },
	}
	_, err := resolveEndpoint(&rootFlags{}, deps)
	if err == nil {
		t.Error("expected rejection for world-readable config")
	}
}

func TestResolveEndpoint_NoURLNoFlagsNoConfig(t *testing.T) {
	deps := resolverDeps{
		userHomeDir: func() (string, error) { return "", errors.New("no home") },
		stat:        func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		loadConfig:  func(string) (*config.Config, error) { return nil, nil },
		getenv:      func(string) string { return "" },
	}
	// Provide token but not URL — should fail with URL-specific message.
	_, err := resolveEndpoint(&rootFlags{apiToken: "only-token"}, deps)
	if err == nil {
		t.Error("expected error for missing URL")
	}
}
