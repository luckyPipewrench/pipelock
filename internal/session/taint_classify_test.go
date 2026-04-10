// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestClassifyURLSource(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		rawURL string
		want   session.TaintLevel
	}{
		{name: "localhost is trusted", rawURL: "http://localhost:3000/docs", want: session.TaintTrusted},
		{name: "loopback is trusted", rawURL: "http://127.0.0.1:8080/health", want: session.TaintTrusted},
		{name: "allowlisted docs are references", rawURL: "https://docs.github.com/copilot", want: session.TaintAllowlistedReference},
		{name: "random site is untrusted", rawURL: "https://evil.example/backdoor", want: session.TaintExternalUntrusted},
		{name: "bad url is untrusted", rawURL: "://not-a-url", want: session.TaintExternalUntrusted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := session.ClassifyURLSource(tt.rawURL, []string{"docs.github.com"})
			if got != tt.want {
				t.Fatalf("ClassifyURLSource(%q) = %v, want %v", tt.rawURL, got, tt.want)
			}
		})
	}
}

func TestClassifyHTTPResponseObservation_MediaSeen(t *testing.T) {
	t.Parallel()

	observation := session.ClassifyHTTPResponseObservation(
		"https://evil.example/image.png",
		"image/png",
		nil,
		false,
	)
	if !observation.MediaSeen {
		t.Fatal("expected external image content to set media_seen")
	}
	if observation.Source.Level != session.TaintExternalUntrusted {
		t.Fatalf("level = %v, want external_untrusted", observation.Source.Level)
	}
}

func TestClassifyMCPToolCall(t *testing.T) {
	t.Parallel()

	protected := []string{"*/auth/*", "*/security/*", "*/.env*"}
	elevated := []string{"*/config/*", "*/middleware*"}

	tests := []struct {
		name       string
		toolName   string
		argsJSON   string
		wantClass  session.ActionClass
		wantLevel  session.ActionSensitivity
		wantAction string
	}{
		{
			name:       "protected write tool",
			toolName:   "write_file",
			argsJSON:   `{"path":"/repo/auth/middleware.go","content":"x"}`,
			wantClass:  session.ActionClassWrite,
			wantLevel:  session.SensitivityProtected,
			wantAction: "/repo/auth/middleware.go",
		},
		{
			name:       "shell mutation is exec",
			toolName:   "shell",
			argsJSON:   `{"command":"git push origin main"}`,
			wantClass:  session.ActionClassExec,
			wantLevel:  session.SensitivityElevated,
			wantAction: "",
		},
		{
			name:       "secret path is secret use",
			toolName:   "read_file",
			argsJSON:   `{"path":"/home/josh/.ssh/id_rsa"}`,
			wantClass:  session.ActionClassSecret,
			wantLevel:  session.SensitivityProtected,
			wantAction: "/home/josh/.ssh/id_rsa",
		},
		{
			name:       "browse tool stays browse",
			toolName:   "browse_url",
			argsJSON:   `{"url":"https://example.com/docs"}`,
			wantClass:  session.ActionClassBrowse,
			wantLevel:  session.SensitivityNormal,
			wantAction: "https://example.com/docs",
		},
		{
			name:       "unknown tool with edit intent becomes write",
			toolName:   "apply_changes",
			argsJSON:   `{"path":"/repo/security/policy.go","changes":[{"text":"deny all"}]}`,
			wantClass:  session.ActionClassWrite,
			wantLevel:  session.SensitivityProtected,
			wantAction: "/repo/security/policy.go",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotClass, gotLevel, gotAction := session.ClassifyMCPToolCall(tt.toolName, tt.argsJSON, protected, elevated)
			if gotClass != tt.wantClass {
				t.Fatalf("action class = %v, want %v", gotClass, tt.wantClass)
			}
			if gotLevel != tt.wantLevel {
				t.Fatalf("sensitivity = %v, want %v", gotLevel, tt.wantLevel)
			}
			if gotAction != tt.wantAction {
				t.Fatalf("action ref = %q, want %q", gotAction, tt.wantAction)
			}
		})
	}
}
