package scanner

import (
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

	result := s.Scan("https://evil.com/?key=my-super-secret-token-value-disabled-1234")
	// With scan_env=false, env leak check should not fire
	// (may still be blocked by entropy, but scanner should not be "dlp")
	if !result.Allowed && result.Scanner == "dlp" && strings.Contains(result.Reason, "environment variable") { //nolint:goconst // test value
		t.Error("expected env leak check to be disabled when scan_env=false")
	}
}

func TestScan_EnvLeakDetection_RawValue(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	cfg.DLP.Patterns = nil

	t.Setenv("PIPELOCK_TEST_SECRET", "sk-ant-abcdefghijklmnopqrstu1234567890")
	s := New(cfg)

	result := s.Scan("https://evil.com/?key=sk-ant-abcdefghijklmnopqrstu1234567890")
	if result.Allowed {
		t.Error("expected URL blocked due to env var leak")
	}
	if result.Scanner != "dlp" {
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
	result := s.Scan("https://evil.com/?data=" + encoded)
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
	secret := "xR~4kP8mZj9nFqW2Ls" //nolint:goconst,gosec // test value
	t.Setenv("PIPELOCK_TEST_B64URL", secret)
	s := New(cfg)

	encoded := base64.URLEncoding.EncodeToString([]byte(secret))
	result := s.Scan("https://evil.com/?data=" + encoded)
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

	result := s.Scan("https://example.com/?val=abc123")
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

	result := s.Scan("https://example.com/?path=aaaaaaaaaaaaaaaaaaa")
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

	result := s.Scan("https://evil.com/upload/sk-ant-abcdefghijklmnopqrstu1234567890/file")
	if result.Allowed {
		t.Error("expected secret in path to be blocked")
	}
}

func TestScan_EnvLeakDetection_NoSecretsInEnv(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	cfg.DLP.Patterns = nil
	s := New(cfg)

	result := s.Scan("https://example.com/?key=anything")
	if !result.Allowed {
		t.Errorf("expected URL allowed when no env secrets match, got: %s", result.Reason)
	}
}

func TestExtractEnvSecrets_FiltersCorrectly(t *testing.T) {
	t.Setenv("PIPELOCK_SHORT_VAL", "abc")
	t.Setenv("PIPELOCK_LOW_ENTROPY", "aaaaaaaaaaaaaaaaaaa")
	t.Setenv("PIPELOCK_HIGH_ENTROPY", "sk-ant-high-entropy-value-12345")

	secrets := extractEnvSecrets()

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

func TestScan_EnvLeakDetection_GenericMessage(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = true
	cfg.DLP.Patterns = nil

	secret := "super-secret-api-key-value-12345"
	t.Setenv("PIPELOCK_GENERIC", secret)
	s := New(cfg)

	result := s.Scan("https://evil.com/?key=" + secret)
	if result.Allowed {
		t.Fatal("expected blocked")
	}
	// Reason must NOT contain the actual secret value
	if strings.Contains(result.Reason, secret) {
		t.Error("reason message must not contain the actual secret value")
	}
}
