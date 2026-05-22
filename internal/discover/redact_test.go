// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package discover

import (
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
