// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestRedactReportForOutput_RemovesSensitiveValues(t *testing.T) {
	report := &Report{
		Servers: []MCPServer{{
			ServerName: "db",
			Command:    testCmdNpx,
			Args: []string{
				"postgresql://postgres:postgres@127.0.0.1:5432/app",
				"--token=abc123",
				"--api-key",
				"split-secret",
				"--header",
				"Authorization: Bearer header-secret",
				"https://api.example.com/mcp?" + "api_key=secret&safe=value#frag",
				"DATABASE_URL=postgresql://app:db-secret@db.internal:5432/app",
			},
			Env: map[string]string{
				"API_TOKEN": "secret-token",
				"BRAIN_DIR": testDataDir,
			},
			URL: "https://token@example.com/mcp?" + "bearer=secret",
		}},
	}

	redacted := RedactReportForOutput(report)
	if redacted == report {
		t.Fatal("redaction should return a copy")
	}
	got := redacted.Servers[0]
	joined := strings.Join(append(append([]string{got.URL}, got.Args...), got.Env["API_TOKEN"], got.Env["BRAIN_DIR"]), " ")

	for _, leaked := range []string{"postgres:postgres", "postgres@", "app:db-secret", "abc123", "split-secret", "header-secret", "secret-token", testDataDir, "api_key=secret", "bearer=secret", "#frag"} {
		if strings.Contains(joined, leaked) {
			t.Fatalf("redacted output leaked %q in %q", leaked, joined)
		}
	}
	for _, want := range []string{"postgresql://127.0.0.1:5432/app", "DATABASE_URL=postgresql://db.internal:5432/app", "--token=[REDACTED]", "--api-key [REDACTED]", "--header [REDACTED]", "api_key=[REDACTED]", "bearer=%5BREDACTED%5D"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("redacted output missing %q in %q", want, joined)
		}
	}
}

func TestRedactReportForOutput_RedactsSensitiveCommandURL(t *testing.T) {
	report := &Report{
		Servers: []MCPServer{{
			Command: "https://user:" + "pass@example.com/tool?" + "token=secret",
		}},
	}

	redacted := RedactReportForOutput(report)
	got := redacted.Servers[0].Command
	for _, leaked := range []string{"user:pass", "token=secret"} {
		if strings.Contains(got, leaked) {
			t.Fatalf("redacted command leaked %q in %q", leaked, got)
		}
	}
	if !strings.Contains(got, "token=%5BREDACTED%5D") {
		t.Fatalf("redacted command missing query redaction marker: %q", got)
	}
}

func TestRedactReportForOutput_DoesNotMutateInput(t *testing.T) {
	rawURL := "postgresql://u:" + "p@127.0.0.1:5432/db"
	report := &Report{
		Servers: []MCPServer{{
			Args: []string{rawURL},
			Env:  map[string]string{"TOKEN": secretMarker},
			URL:  "https://example.com/mcp?" + "token=secret",
		}},
	}

	_ = RedactReportForOutput(report)

	if report.Servers[0].Args[0] != rawURL {
		t.Fatalf("input args mutated: %q", report.Servers[0].Args[0])
	}
	if report.Servers[0].Env["TOKEN"] != secretMarker {
		t.Fatalf("input env mutated: %q", report.Servers[0].Env["TOKEN"])
	}
	if report.Servers[0].URL != "https://example.com/mcp?"+"token=secret" {
		t.Fatalf("input url mutated: %q", report.Servers[0].URL)
	}
}

func TestRedactReportForOutput_RedactsStandaloneAuthorizationArgs(t *testing.T) {
	bearer := "bearer-" + "canary-value"
	basic := base64.StdEncoding.EncodeToString([]byte("example:" + "canary-value"))
	tests := []struct {
		name string
		args []string
		want []string
		leak string
	}{
		{
			name: "mixed case bearer",
			args: []string{"serve", "aUtHoRiZaTiOn: BeArEr " + bearer, "--mode", "safe"},
			want: []string{"serve", redactedValue, "--mode", "safe"},
			leak: bearer,
		},
		{
			name: "mixed case basic",
			args: []string{"serve", "BaSiC " + basic, "--mode", "safe"},
			want: []string{"serve", redactedValue, "--mode", "safe"},
			leak: basic,
		},
		{
			name: "standalone bearer",
			args: []string{"serve", "BeArEr " + bearer, "--mode", "safe"},
			want: []string{"serve", redactedValue, "--mode", "safe"},
			leak: bearer,
		},
		{
			name: "unrecognized header flag",
			args: []string{"serve", "-H", "Authorization: Bearer " + bearer, "--mode", "safe"},
			want: []string{"serve", "-H", redactedValue, "--mode", "safe"},
			leak: bearer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{
				"auth": map[string]any{"command": "node", "args": tt.args},
			})
			if err != nil {
				t.Fatalf("marshal server config: %v", err)
			}
			servers, err := parseServerMap(raw, "config.json", clientClaudeCode)
			if err != nil {
				t.Fatalf("parseServerMap: %v", err)
			}
			report := &Report{Servers: servers}

			redacted := RedactReportForOutput(report)
			serialized, err := json.Marshal(redacted)
			if err != nil {
				t.Fatalf("marshal redacted report: %v", err)
			}
			if strings.Contains(string(serialized), tt.leak) {
				t.Fatalf("serialized output leaked %q: %s", tt.leak, serialized)
			}
			if got := redacted.Servers[0].Args; !slices.Equal(got, tt.want) {
				t.Errorf("redacted args = %q, want %q", got, tt.want)
			}
			if got := report.Servers[0].Args; !slices.Equal(got, tt.args) {
				t.Errorf("raw parsed args changed: got %q, want %q", got, tt.args)
			}
		})
	}
}
