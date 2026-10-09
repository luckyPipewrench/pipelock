// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const (
	doctorIdentityDigest  = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
	doctorIdentityModHash = "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22"
)

func doctorIdentityConfig() *config.Config {
	cfg := config.Defaults()
	cfg.MCPIdentities = []config.MCPIdentity{
		{
			Name: "vendor-indexer",
			VerifiedLocalService: &config.MCPVerifiedLocalService{
				Scheme:           config.MCPIdentitySchemeHTTP,
				Host:             config.MCPIdentityHostIPv4Loopback,
				Path:             "/rpc/v1",
				ExecutableSHA256: doctorIdentityDigest,
				MappedFiles:      []config.MCPIdentityFilePin{{Path: "/opt/vendor/lib/native.so", SHA256: doctorIdentityModHash}},
				SessionHeader:    &config.MCPIdentitySessionHeader{Name: "Authorization", Scheme: config.MCPIdentitySessionScheme, Carrier: "PIPELOCK_VSCODE_INDEXER_AUTH"},
			},
		},
		{
			Name: "native-bridge",
			VerifiedLocalService: &config.MCPVerifiedLocalService{
				Scheme:           config.MCPIdentitySchemeWS,
				Host:             config.MCPIdentityHostIPv6Loopback,
				Path:             "/bridge",
				ExecutableSHA256: doctorIdentityDigest,
				ControlEnvironment: map[string]string{
					"VENDOR_MODE": "local",
				},
			},
		},
	}
	return cfg
}

func TestCheckDoctorMCPIdentities(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		cfg        func() *config.Config
		goos       string
		wantStatus string
		wantConfig bool
		wantDetail []string
		wantNext   string
	}{
		{
			name:       "no registrations is informational",
			cfg:        config.Defaults,
			goos:       goosLinux,
			wantStatus: doctorStatusInfo,
			wantDetail: []string{"no verified local services registered"},
			wantNext:   "pipelock mcp identity register",
		},
		{
			name:       "registered on linux is ok and lists each shape and binding",
			cfg:        doctorIdentityConfig,
			goos:       goosLinux,
			wantStatus: doctorStatusOK,
			wantConfig: true,
			wantDetail: []string{
				"2 registered",
				"vendor-indexer (http://127.0.0.1/rpc/v1, session header Authorization, 1 mapped files, 0 control env, binding verified-local-session)",
				"native-bridge (ws://::1/bridge, no session header, 0 mapped files, 1 control env, binding verified-local-session)",
			},
			wantNext: "pipelock mcp identity inspect",
		},
		{
			name:       "registered off linux warns that matched registrations refuse to start",
			cfg:        doctorIdentityConfig,
			goos:       "windows",
			wantStatus: doctorStatusWarn,
			wantConfig: true,
			wantDetail: []string{"requires Linux", "will refuse to start on windows", "vendor-indexer", "native-bridge"},
			wantNext:   "only on Linux hosts",
		},
		{
			name: "a registration without a verified service block is still named",
			cfg: func() *config.Config {
				cfg := config.Defaults()
				cfg.MCPIdentities = []config.MCPIdentity{{Name: "bare"}}
				return cfg
			},
			goos:       goosLinux,
			wantStatus: doctorStatusOK,
			wantConfig: true,
			wantDetail: []string{"bare (no verified_local_service)"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			check := checkDoctorMCPIdentities(tt.cfg(), tt.goos)
			if check.Name != doctorCheckMCPIdentities || check.Surface != doctorSurfaceMCP {
				t.Errorf("name/surface = %q/%q", check.Name, check.Surface)
			}
			if check.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q (detail %q)", check.Status, tt.wantStatus, check.Detail)
			}
			if check.Configured != tt.wantConfig {
				t.Errorf("configured = %v, want %v", check.Configured, tt.wantConfig)
			}
			for _, w := range tt.wantDetail {
				if !strings.Contains(check.Detail, w) {
					t.Errorf("detail %q missing %q", check.Detail, w)
				}
			}
			if !strings.Contains(check.Next, tt.wantNext) {
				t.Errorf("next %q missing %q", check.Next, tt.wantNext)
			}
		})
	}
}

func TestBuildDoctorReport_IncludesMCPIdentitiesCheck(t *testing.T) {
	t.Parallel()
	report := buildDoctorReport(doctorIdentityConfig(), "test")
	var found *doctorReportCheck
	for i := range report.Checks {
		if report.Checks[i].Name == doctorCheckMCPIdentities {
			found = &report.Checks[i]
		}
	}
	if found == nil {
		t.Fatalf("mcp_identities check missing from the doctor report")
	}
	wantStatus := doctorStatusOK
	if runtime.GOOS != goosLinux {
		wantStatus = doctorStatusWarn
	}
	if found.Status != wantStatus {
		t.Errorf("status = %q, want %q on %s", found.Status, wantStatus, runtime.GOOS)
	}
}
