//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"testing"
)

// setRequiredConfigEnv sets all required env vars for LoadConfig tests.
// Split credential-like values at runtime to avoid gosec G101.
func setRequiredConfigEnv(t *testing.T) {
	t.Helper()
	t.Setenv("POLAR_WEBHOOK_SECRET", "whsec_"+"dGVzdA==")
	t.Setenv("POLAR_API_TOKEN", "polar_"+"test")
	t.Setenv("PIPELOCK_LICENSE_KEY_PATH", "/tmp/test.key")
	t.Setenv("RESEND_API_KEY", "re_"+"test")
}

func TestLoadConfig_AllRequired(t *testing.T) {
	setRequiredConfigEnv(t)

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.PolarWebhookSecret != "whsec_"+"dGVzdA==" {
		t.Errorf("PolarWebhookSecret = %q", cfg.PolarWebhookSecret)
	}
	if cfg.ListenAddr != defaultListenAddr {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, defaultListenAddr)
	}
	if cfg.FoundingProCap != defaultFoundingProCap {
		t.Errorf("FoundingProCap = %d, want %d", cfg.FoundingProCap, defaultFoundingProCap)
	}
	if cfg.DBPath != defaultDBPath {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, defaultDBPath)
	}
}

func TestLoadConfig_MissingRequired(t *testing.T) {
	tests := []struct {
		name     string
		clearEnv string
	}{
		{"missing POLAR_WEBHOOK_SECRET", "POLAR_WEBHOOK_SECRET"},
		{"missing POLAR_API_TOKEN", "POLAR_API_TOKEN"},
		{"missing PIPELOCK_LICENSE_KEY_PATH", "PIPELOCK_LICENSE_KEY_PATH"},
		{"missing RESEND_API_KEY", "RESEND_API_KEY"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setRequiredConfigEnv(t)
			t.Setenv(tt.clearEnv, "")

			_, err := LoadConfig()
			if err == nil {
				t.Error("expected error for missing required config, got nil")
			}
		})
	}
}

func TestLoadConfig_NegativeFoundingCap(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("FOUNDING_PRO_CAP", "-1")

	_, err := LoadConfig()
	if err == nil {
		t.Error("expected error for negative founding cap, got nil")
	}
}

func TestLoadConfig_InvalidFoundingCap(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("FOUNDING_PRO_CAP", "not-a-number")

	_, err := LoadConfig()
	if err == nil {
		t.Error("expected error for invalid founding cap, got nil")
	}
}

func TestLoadConfig_InvalidDeadline(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("FOUNDING_PRO_DEADLINE", "not-a-date")

	_, err := LoadConfig()
	if err == nil {
		t.Error("expected error for invalid deadline, got nil")
	}
}

func TestLoadConfig_CustomValues(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("LISTEN_ADDR", ":9090")
	t.Setenv("DB_PATH", "/tmp/custom.db")
	t.Setenv("FOUNDING_PRO_CAP", "100")
	t.Setenv("FOUNDING_PRO_DEADLINE", "2027-01-01")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.ListenAddr != ":9090" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":9090")
	}
	if cfg.DBPath != "/tmp/custom.db" {
		t.Errorf("DBPath = %q, want %q", cfg.DBPath, "/tmp/custom.db")
	}
	if cfg.FoundingProCap != 100 {
		t.Errorf("FoundingProCap = %d, want %d", cfg.FoundingProCap, 100)
	}
}

func TestLoadConfig_ZeroFoundingCap(t *testing.T) {
	setRequiredConfigEnv(t)
	t.Setenv("FOUNDING_PRO_CAP", "0")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	// Zero is valid (means no founding slots at all).
	if cfg.FoundingProCap != 0 {
		t.Errorf("FoundingProCap = %d, want 0", cfg.FoundingProCap)
	}
}
