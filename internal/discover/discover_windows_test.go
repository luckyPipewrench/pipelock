// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverClaudeWindowsLayouts(t *testing.T) {
	const serverConfig = `{"mcpServers":{"ordinary":{"command":"node","args":["server.js"]}}}`
	for _, tt := range []struct {
		name          string
		classic       string
		packaged      string
		wantServers   int
		wantClients   int
		wantParseErrs int
	}{
		{name: "absent"},
		{name: "classic", classic: serverConfig, wantServers: 1, wantClients: 1},
		{name: "packaged", packaged: serverConfig, wantServers: 1, wantClients: 1},
		{name: "both retain source", classic: serverConfig, packaged: serverConfig, wantServers: 2, wantClients: 2},
		{name: "packaged parse error", packaged: "{", wantClients: 1, wantParseErrs: 1},
		{name: "classic survives packaged error", classic: serverConfig, packaged: "{", wantServers: 1, wantClients: 2, wantParseErrs: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			classic := filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json")
			packaged := filepath.Join(home, "AppData", "Local", "Packages", "Claude_pzs8sxrjxfjjc",
				"LocalCache", "Roaming", "Claude", "claude_desktop_config.json")
			for path, content := range map[string]string{classic: tt.classic, packaged: tt.packaged} {
				if content == "" {
					continue
				}
				if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			report, err := Discover(home)
			if err != nil {
				t.Fatal(err)
			}
			if report.Summary.TotalServers != tt.wantServers || report.Summary.TotalClients != tt.wantClients || report.Summary.ParseErrors != tt.wantParseErrs {
				t.Fatalf("summary = %+v, want servers=%d clients=%d parse errors=%d", report.Summary, tt.wantServers, tt.wantClients, tt.wantParseErrs)
			}
			seen := make(map[string]bool)
			for _, server := range report.Servers {
				if server.ConfigPath != classic && server.ConfigPath != packaged {
					t.Errorf("unexpected config path %q", server.ConfigPath)
				}
				if seen[server.ConfigPath] {
					t.Errorf("duplicate config path %q", server.ConfigPath)
				}
				seen[server.ConfigPath] = true
				if server.Client != clientClaudeDesktop || server.Protection != Unprotected {
					t.Errorf("unexpected server classification: %+v", server)
				}
			}
		})
	}
}
