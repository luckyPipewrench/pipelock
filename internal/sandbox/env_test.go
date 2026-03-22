// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyntheticEnv_CreatesDirectories(t *testing.T) {
	sandboxDir := t.TempDir()
	workspace := t.TempDir()

	_, err := SyntheticEnv(sandboxDir, workspace, nil)
	if err != nil {
		t.Fatalf("SyntheticEnv error: %v", err)
	}

	expectedDirs := []string{
		filepath.Join(sandboxDir, SandboxHome),
		filepath.Join(sandboxDir, SandboxHome, "config"),
		filepath.Join(sandboxDir, SandboxHome, "cache"),
		filepath.Join(sandboxDir, SandboxHome, "data"),
		filepath.Join(sandboxDir, "tmp"),
	}
	for _, d := range expectedDirs {
		fi, err := os.Stat(d)
		if err != nil {
			t.Errorf("expected directory %s to exist: %v", d, err)
			continue
		}
		if !fi.IsDir() {
			t.Errorf("expected %s to be a directory", d)
		}
	}
}

func TestSyntheticEnv_OverridesHOME(t *testing.T) {
	sandboxDir := t.TempDir()
	workspace := t.TempDir()

	env, err := SyntheticEnv(sandboxDir, workspace, nil)
	if err != nil {
		t.Fatalf("SyntheticEnv error: %v", err)
	}

	homeVal := envValue(env, "HOME")
	expectedHome := filepath.Join(sandboxDir, SandboxHome)
	if homeVal != expectedHome {
		t.Errorf("HOME = %q, want %q", homeVal, expectedHome)
	}
}

func TestSyntheticEnv_SetsXDG(t *testing.T) {
	sandboxDir := t.TempDir()
	workspace := t.TempDir()

	env, err := SyntheticEnv(sandboxDir, workspace, nil)
	if err != nil {
		t.Fatalf("SyntheticEnv error: %v", err)
	}

	checks := map[string]string{
		"XDG_CONFIG_HOME": filepath.Join(sandboxDir, SandboxHome, "config"),
		"XDG_CACHE_HOME":  filepath.Join(sandboxDir, SandboxHome, "cache"),
		"XDG_DATA_HOME":   filepath.Join(sandboxDir, SandboxHome, "data"),
		"TMPDIR":          filepath.Join(sandboxDir, "tmp"),
		"PWD":             workspace,
		"SHELL":           "/bin/sh",
	}
	for key, want := range checks {
		got := envValue(env, key)
		if got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestSyntheticEnv_DropsSecrets(t *testing.T) {
	// Set env vars that should NOT pass through the allowlist.
	t.Setenv("OPENAI_API_KEY", "sk-secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
	t.Setenv("LD_PRELOAD", "/tmp/evil.so")
	t.Setenv("HTTP_PROXY", "http://attacker:8080")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")

	sandboxDir := t.TempDir()
	workspace := t.TempDir()

	env, err := SyntheticEnv(sandboxDir, workspace, nil)
	if err != nil {
		t.Fatalf("SyntheticEnv error: %v", err)
	}

	// None of these should appear in the sandbox env.
	forbidden := []string{
		"OPENAI_API_KEY", "AWS_SECRET_ACCESS_KEY",
		"LD_PRELOAD", "HTTP_PROXY", "SSH_AUTH_SOCK",
	}
	for _, key := range forbidden {
		if val := envValue(env, key); val != "" {
			t.Errorf("secret env var %s leaked into sandbox: %q", key, val)
		}
	}
}

func TestSyntheticEnv_PassesSafeVars(t *testing.T) {
	t.Setenv("USER", "testuser")
	t.Setenv("LANG", "en_US.UTF-8")
	t.Setenv("TZ", "America/New_York")

	sandboxDir := t.TempDir()
	workspace := t.TempDir()

	env, err := SyntheticEnv(sandboxDir, workspace, nil)
	if err != nil {
		t.Fatalf("SyntheticEnv error: %v", err)
	}

	if got := envValue(env, "USER"); got != "testuser" {
		t.Errorf("USER = %q, want %q", got, "testuser")
	}
	if got := envValue(env, "LANG"); got != "en_US.UTF-8" {
		t.Errorf("LANG = %q, want %q", got, "en_US.UTF-8")
	}
	if got := envValue(env, "TZ"); got != "America/New_York" {
		t.Errorf("TZ = %q, want %q", got, "America/New_York")
	}
}

func TestSyntheticEnv_AddsTelemetrySuppression(t *testing.T) {
	sandboxDir := t.TempDir()
	workspace := t.TempDir()

	env, err := SyntheticEnv(sandboxDir, workspace, nil)
	if err != nil {
		t.Fatalf("SyntheticEnv error: %v", err)
	}

	for key, want := range telemetrySuppression {
		got := envValue(env, key)
		if got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestSyntheticEnv_ExtraEnvPassthrough(t *testing.T) {
	sandboxDir := t.TempDir()
	workspace := t.TempDir()

	extra := []string{"MY_TOOL_KEY=abc123", "CUSTOM_FLAG=true"}
	env, err := SyntheticEnv(sandboxDir, workspace, extra)
	if err != nil {
		t.Fatalf("SyntheticEnv error: %v", err)
	}

	if got := envValue(env, "MY_TOOL_KEY"); got != "abc123" {
		t.Errorf("MY_TOOL_KEY = %q, want %q", got, "abc123")
	}
	if got := envValue(env, "CUSTOM_FLAG"); got != "true" {
		t.Errorf("CUSTOM_FLAG = %q, want %q", got, "true")
	}
}

func TestSyntheticEnv_SetsPATH(t *testing.T) {
	sandboxDir := t.TempDir()
	workspace := t.TempDir()

	env, err := SyntheticEnv(sandboxDir, workspace, nil)
	if err != nil {
		t.Fatalf("SyntheticEnv error: %v", err)
	}

	path := envValue(env, "PATH")
	if !strings.Contains(path, "/usr/bin") {
		t.Errorf("PATH missing /usr/bin: %q", path)
	}
	if !strings.Contains(path, "/usr/local/bin") {
		t.Errorf("PATH missing /usr/local/bin: %q", path)
	}
}

func TestSyntheticEnv_DoesNotInheritUnlistedVars(t *testing.T) {
	// Set a var that is NOT in the safe passthrough list and NOT in overrides.
	t.Setenv("TOTALLY_RANDOM_UNLIKELY_VAR_XYZ", "should-not-appear")

	sandboxDir := t.TempDir()
	workspace := t.TempDir()

	env, err := SyntheticEnv(sandboxDir, workspace, nil)
	if err != nil {
		t.Fatalf("SyntheticEnv error: %v", err)
	}

	if val := envValue(env, "TOTALLY_RANDOM_UNLIKELY_VAR_XYZ"); val != "" {
		t.Errorf("unlisted env var leaked through: %q", val)
	}
}

func TestSyntheticEnv_BlocksDangerousExtraEnv(t *testing.T) {
	dir := t.TempDir()
	for key := range dangerousEnvKeys {
		_, err := SyntheticEnv(dir, dir, []string{key + "=/tmp/evil"})
		if err == nil {
			t.Errorf("expected error for dangerous env key %q, got nil", key)
		}
	}
}

func TestSyntheticEnv_AllowsSafeExtraEnv(t *testing.T) {
	dir := t.TempDir()
	env, err := SyntheticEnv(dir, dir, []string{"MY_APP_CONFIG=/etc/app.conf"})
	if err != nil {
		t.Fatalf("unexpected error for safe env key: %v", err)
	}
	if envValue(env, "MY_APP_CONFIG") != "/etc/app.conf" {
		t.Error("expected MY_APP_CONFIG in env")
	}
}

// envValue extracts the value of a key from an env slice.
func envValue(env []string, key string) string {
	prefix := key + "="
	for _, e := range env {
		if strings.HasPrefix(e, prefix) {
			return e[len(prefix):]
		}
	}
	return ""
}
