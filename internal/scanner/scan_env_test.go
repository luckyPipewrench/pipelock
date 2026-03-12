// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
)

func TestScan_EnvLeakDetection_Disabled(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = nil // disable regex DLP so only env leak would fire

	t.Setenv("TEST_SECRET_DISABLED", "my-super-secret-token-value-disabled-1234")
	s := New(cfg)

	result := s.Scan(context.Background(), "https://evil.com/?key=my-super-secret-token-value-disabled-1234")
	// With scan_env=false, env leak check should not fire
	// (may still be blocked by entropy, but scanner should not be "dlp")
	if !result.Allowed && result.Scanner == ScannerDLP && strings.Contains(result.Reason, "environment variable") {
		t.Error("expected env leak check to be disabled when scan_env=false")
	}
}

func TestScan_EnvLeakDetection_RawValue(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	cfg.DLP.Patterns = nil

	t.Setenv("PIPELOCK_TEST_SECRET", "sk-ant-abcdefghijklmnopqrstu1234567890")
	s := New(cfg)

	result := s.Scan(context.Background(), "https://evil.com/?key=sk-ant-abcdefghijklmnopqrstu1234567890")
	if result.Allowed {
		t.Error("expected URL blocked due to env var leak")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
	if !strings.Contains(result.Reason, "environment variable leak") {
		t.Errorf("expected generic leak message, got: %s", result.Reason)
	}
}

func TestScan_EnvLeakDetection_Base64Encoded(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	cfg.DLP.Patterns = nil

	secret := "my-secret-token-value-12345"
	t.Setenv("PIPELOCK_TEST_B64", secret)
	s := New(cfg)

	encoded := base64.StdEncoding.EncodeToString([]byte(secret))
	result := s.Scan(context.Background(), "https://evil.com/?data="+encoded)
	if result.Allowed {
		t.Error("expected URL blocked due to base64-encoded env var leak")
	}
	if !strings.Contains(result.Reason, "base64") {
		t.Errorf("expected base64 mention in reason, got: %s", result.Reason)
	}
}

func TestScan_EnvLeakDetection_Base64URLEncoded(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	cfg.DLP.Patterns = nil

	// A tilde at position mod 3 == 2 produces '+' in standard base64
	// and '-' in URL base64, so the encodings differ.
	secret := "xR~4kP8mZj9nFqW2Ls" //nolint:gosec // test value
	t.Setenv("PIPELOCK_TEST_B64URL", secret)
	s := New(cfg)

	encoded := base64.URLEncoding.EncodeToString([]byte(secret))
	result := s.Scan(context.Background(), "https://evil.com/?data="+encoded)
	if result.Allowed {
		t.Error("expected URL blocked due to base64url-encoded env var leak")
	}
	if !strings.Contains(result.Reason, "base64url") {
		t.Errorf("expected base64url mention in reason, got: %s", result.Reason)
	}
}

func TestScan_EnvLeakDetection_ShortValueIgnored(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	cfg.DLP.Patterns = nil

	t.Setenv("PIPELOCK_SHORT", "abc123")
	s := New(cfg)

	result := s.Scan(context.Background(), "https://example.com/?val=abc123")
	if !result.Allowed {
		t.Errorf("expected short env var (<16 chars) to be ignored, got blocked: %s", result.Reason)
	}
}

func TestScan_EnvLeakDetection_LowEntropyIgnored(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	cfg.DLP.Patterns = nil

	t.Setenv("PIPELOCK_PATH", "aaaaaaaaaaaaaaaaaaa")
	s := New(cfg)

	result := s.Scan(context.Background(), "https://example.com/?path=aaaaaaaaaaaaaaaaaaa")
	if !result.Allowed {
		t.Errorf("expected low-entropy env var to be ignored, got blocked: %s", result.Reason)
	}
}

func TestScan_EnvLeakDetection_InPath(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	cfg.DLP.Patterns = nil

	t.Setenv("PIPELOCK_PATH_SECRET", "sk-ant-abcdefghijklmnopqrstu1234567890")
	s := New(cfg)

	result := s.Scan(context.Background(), "https://evil.com/upload/sk-ant-abcdefghijklmnopqrstu1234567890/file")
	if result.Allowed {
		t.Error("expected secret in path to be blocked")
	}
}

func TestScan_EnvLeakDetection_NoSecretsInEnv(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	cfg.DLP.Patterns = nil
	s := New(cfg)

	result := s.Scan(context.Background(), "https://example.com/?key=anything")
	if !result.Allowed {
		t.Errorf("expected URL allowed when no env secrets match, got: %s", result.Reason)
	}
}

func TestExtractEnvSecrets_FiltersCorrectly(t *testing.T) {
	t.Setenv("PIPELOCK_SHORT_VAL", "abc")
	t.Setenv("PIPELOCK_LOW_ENTROPY", "aaaaaaaaaaaaaaaaaaa")
	t.Setenv("PIPELOCK_HIGH_ENTROPY", "sk-ant-high-entropy-value-12345")

	secrets := extractEnvSecrets(16)

	// The high-entropy value should be included
	found := false
	for _, s := range secrets {
		if s == "sk-ant-high-entropy-value-12345" {
			found = true
		}
		if s == "abc" || s == "aaaaaaaaaaaaaaaaaaa" {
			t.Errorf("expected short/low-entropy values to be filtered out, got: %s", s)
		}
	}
	if !found {
		t.Error("expected high-entropy value to be included in secrets")
	}
}

func TestExtractEnvSecrets_SkipsNonSecretNames(t *testing.T) {
	// Set well-known non-secret vars with values that would otherwise
	// pass length and entropy filters.
	highEntropyPath := "/home/testuser/dev/pipelock-project"
	t.Setenv("PWD", highEntropyPath)
	t.Setenv("HOME", "/home/testuser/complex-dirname")
	t.Setenv("PATH", "/usr/local/bin:/usr/bin:/home/testuser/.local/bin:/opt/go/bin")
	t.Setenv("LS_COLORS", "rs=0:di=01;34:ln=01;36:mh=00:pi=40;33")
	t.Setenv("XDG_DATA_HOME", "/home/testuser/.local/share/data")
	t.Setenv("LC_ALL", "en_US.UTF-8-something-long-enough")

	// Also set a real secret to confirm those still get collected.
	// Split at regex boundary to avoid self-scan false positive.
	realSecret := "sk-" + "ant-realkey-abcdefghij12345"
	t.Setenv("PIPELOCK_REAL_SECRET", realSecret)

	secrets := extractEnvSecrets(16)

	for _, s := range secrets {
		if s == highEntropyPath {
			t.Error("PWD value should be skipped (non-secret env var name)")
		}
		if s == "/home/testuser/complex-dirname" {
			t.Error("HOME value should be skipped")
		}
		if strings.Contains(s, "/usr/local/bin") {
			t.Error("PATH value should be skipped")
		}
		if strings.Contains(s, "rs=0:di=01") {
			t.Error("LS_COLORS value should be skipped")
		}
		if strings.Contains(s, ".local/share/data") {
			t.Error("XDG_DATA_HOME value should be skipped (XDG_ prefix)")
		}
		if strings.Contains(s, "UTF-8-something") {
			t.Error("LC_ALL value should be skipped (LC_ prefix)")
		}
	}

	// The real secret must still be collected.
	found := false
	for _, s := range secrets {
		if s == realSecret {
			found = true
		}
	}
	if !found {
		t.Error("real secret should still be collected after skipping non-secret names")
	}
}

func TestIsNonSecretEnvName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"PWD", true},
		{"HOME", true},
		{"PATH", true},
		{"LS_COLORS", true},
		{"SHELL", true},
		{"USER", true},
		{"DISPLAY", true},
		{"GOPATH", true},
		{"EDITOR", true},
		// Prefix matches
		{"LC_ALL", true},
		{"LC_CTYPE", true},
		{"XDG_DATA_HOME", true},
		{"XDG_RUNTIME_DIR", true},
		// Mixed-case variants (Windows-style)
		{"Path", true},
		{"UserProfile", true},
		{"Pwd", true},
		{"Home", true},
		{"Shell", true},
		{"xdg_data_home", true},
		{"lc_all", true},
		// Actual secrets should NOT match
		{"API_KEY", false},
		{"AWS_SECRET_ACCESS_KEY", false},
		{"DATABASE_URL", false},
		{"ANTHROPIC_API_KEY", false},
		{"PIPELOCK_TOKEN", false},
		{"GITHUB_TOKEN", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNonSecretEnvName(tt.name)
			if got != tt.want {
				t.Errorf("isNonSecretEnvName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestScan_EnvLeakDetection_PWDNotBlocked(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	cfg.DLP.Patterns = nil
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0 // isolate test to env-name filter

	// Simulate the exact scenario: PWD value appears in MCP tool argument.
	pwdValue := "/home/testuser/dev/pipelock-project"
	t.Setenv("PWD", pwdValue)
	s := New(cfg)

	// The PWD value should NOT trigger env leak detection.
	result := s.Scan(context.Background(), "https://example.com/?cwd="+pwdValue)
	if !result.Allowed {
		t.Errorf("PWD value in URL should not be blocked, got: scanner=%s reason=%s",
			result.Scanner, result.Reason)
	}
}

func TestScan_EnvLeakDetection_GenericMessage(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	cfg.DLP.Patterns = nil

	secret := "super-secret-api-key-value-12345"
	t.Setenv("PIPELOCK_GENERIC", secret)
	s := New(cfg)

	result := s.Scan(context.Background(), "https://evil.com/?key="+secret)
	if result.Allowed {
		t.Fatal("expected blocked")
	}
	// Reason must NOT contain the actual secret value
	if strings.Contains(result.Reason, secret) {
		t.Error("reason message must not contain the actual secret value")
	}
}

func TestScan_EnvLeakDetection_ZeroWidthBypass(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	cfg.DLP.Patterns = nil

	secret := "sk-ant-abcdefghijklmnopqrstu1234567890"
	t.Setenv("PIPELOCK_ZW", secret)
	s := New(cfg)

	// Insert zero-width space into the secret to attempt bypass.
	bypassed := "sk-ant-abcdefghijk\u200Blmnopqrstu1234567890"
	result := s.Scan(context.Background(), "https://evil.com/?key="+bypassed)
	if result.Allowed {
		t.Error("zero-width char insertion should not bypass env leak detection")
	}
	if result.Scanner != ScannerDLP {
		t.Errorf("expected scanner=dlp, got %s", result.Scanner)
	}
}
