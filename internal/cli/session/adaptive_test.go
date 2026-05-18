// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

func TestAdaptiveCmd_RegistersSubcommands(t *testing.T) {
	cmd := AdaptiveCmd()
	for _, name := range []string{"status", "flush", "whoami"} {
		if _, _, err := cmd.Find([]string{name}); err != nil {
			t.Errorf("adaptive subcommand %q not registered: %v", name, err)
		}
	}
	if cmd.Use != "adaptive" {
		t.Errorf("Use: got %q, want adaptive", cmd.Use)
	}
}

func TestAdaptiveStatusCmd_HumanAndJSON(t *testing.T) {
	status := makeAdaptiveStatus()
	for _, tt := range []struct {
		name     string
		args     []string
		validate func(*testing.T, string)
	}{
		{
			name: "human",
			validate: func(t *testing.T, out string) {
				t.Helper()
				for _, want := range []string{"adaptive status:", "sessions=2", "domain_burst 2"} {
					if !strings.Contains(out, want) {
						t.Errorf("output missing %q: %s", want, out)
					}
				}
			},
		},
		{
			name: "json",
			args: []string{"--json"},
			validate: func(t *testing.T, out string) {
				t.Helper()
				var got proxy.AdaptiveStatus
				if err := json.Unmarshal([]byte(out), &got); err != nil {
					t.Fatalf("json output not parseable: %v; out=%s", err, out)
				}
				if got.ActiveSessions != status.ActiveSessions {
					t.Errorf("active_sessions: got %d, want %d", got.ActiveSessions, status.ActiveSessions)
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertBearer(t, r)
				if r.Method != http.MethodGet {
					t.Errorf("method: got %s, want GET", r.Method)
				}
				if r.URL.Path != "/api/v1/adaptive/status" {
					t.Errorf("path: got %q", r.URL.Path)
				}
				writeJSONResponse(w, http.StatusOK, status)
			}))
			overrideClientFactory(t, flags)

			out, err := runCommand(adaptiveStatusCmd(&rootFlags{}), tt.args...)
			if err != nil {
				t.Fatalf("execute: %v; out=%s", err, out)
			}
			tt.validate(t, out)
		})
	}
}

func TestAdaptiveFlushCmd_HumanAndJSON(t *testing.T) {
	resp := proxy.AdaptiveFlushResult{
		Flushed:              true,
		IdentitySessions:     2,
		SkippedInvocations:   1,
		IPDomainStateCleared: true,
	}
	for _, tt := range []struct {
		name     string
		args     []string
		validate func(*testing.T, string)
	}{
		{
			name: "human",
			validate: func(t *testing.T, out string) {
				t.Helper()
				for _, want := range []string{"flushed adaptive state", "identity_sessions=2", "skipped_invocations=1"} {
					if !strings.Contains(out, want) {
						t.Errorf("output missing %q: %s", want, out)
					}
				}
			},
		},
		{
			name: "json",
			args: []string{"--json"},
			validate: func(t *testing.T, out string) {
				t.Helper()
				var got proxy.AdaptiveFlushResult
				if err := json.Unmarshal([]byte(out), &got); err != nil {
					t.Fatalf("json output not parseable: %v; out=%s", err, out)
				}
				if !got.Flushed || got.IdentitySessions != 2 {
					t.Errorf("unexpected flush result: %+v", got)
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertBearer(t, r)
				if r.Method != http.MethodPost {
					t.Errorf("method: got %s, want POST", r.Method)
				}
				if r.URL.Path != "/api/v1/adaptive/flush" {
					t.Errorf("path: got %q", r.URL.Path)
				}
				writeJSONResponse(w, http.StatusOK, resp)
			}))
			overrideClientFactory(t, flags)

			out, err := runCommand(adaptiveFlushCmd(&rootFlags{}), tt.args...)
			if err != nil {
				t.Fatalf("execute: %v; out=%s", err, out)
			}
			tt.validate(t, out)
		})
	}
}

func TestAdaptiveWhoamiCmd_HumanAndJSON(t *testing.T) {
	resp := proxy.AdaptiveWhoami{
		ClientIP:           "203.0.113.9",
		Agent:              "agent-a",
		SessionKey:         "agent-a|203.0.113.9",
		Exists:             true,
		Classification:     "observe",
		EscalationLevel:    "elevated",
		EscalationLevelInt: 1,
		ThreatScore:        3.5,
		AirlockTier:        "soft",
		LockdownTTLSeconds: 120,
	}
	for _, tt := range []struct {
		name     string
		args     []string
		validate func(*testing.T, string)
	}{
		{
			name: "human",
			validate: func(t *testing.T, out string) {
				t.Helper()
				for _, want := range []string{"client_ip=203.0.113.9", "classification=observe", "score=3.50"} {
					if !strings.Contains(out, want) {
						t.Errorf("output missing %q: %s", want, out)
					}
				}
			},
		},
		{
			name: "json",
			args: []string{"--json"},
			validate: func(t *testing.T, out string) {
				t.Helper()
				var got proxy.AdaptiveWhoami
				if err := json.Unmarshal([]byte(out), &got); err != nil {
					t.Fatalf("json output not parseable: %v; out=%s", err, out)
				}
				if got.SessionKey != resp.SessionKey || got.Classification != resp.Classification {
					t.Errorf("unexpected whoami response: %+v", got)
				}
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertBearer(t, r)
				if r.Method != http.MethodGet {
					t.Errorf("method: got %s, want GET", r.Method)
				}
				if r.URL.Path != "/api/v1/adaptive/whoami" {
					t.Errorf("path: got %q", r.URL.Path)
				}
				writeJSONResponse(w, http.StatusOK, resp)
			}))
			overrideClientFactory(t, flags)

			out, err := runCommand(adaptiveWhoamiCmd(&rootFlags{}), tt.args...)
			if err != nil {
				t.Fatalf("execute: %v; out=%s", err, out)
			}
			tt.validate(t, out)
		})
	}
}

func TestRenderAdaptiveStatus_EmptyAnomalies(t *testing.T) {
	var buf bytes.Buffer
	if err := renderAdaptiveStatus(&buf, proxy.AdaptiveStatus{
		SessionsByLevel:    map[string]int{"normal": 1},
		AirlockTiers:       map[string]int{"none": 1},
		RecentSignalCounts: map[string]int{},
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "top_anomalies: none") {
		t.Errorf("empty anomaly output: %s", buf.String())
	}
}

func makeAdaptiveStatus() proxy.AdaptiveStatus {
	return proxy.AdaptiveStatus{
		ActiveSessions:     2,
		MaxEscalationLevel: "high",
		MaxEscalationInt:   2,
		SessionsByLevel:    map[string]int{"normal": 1, "high": 1},
		AirlockTiers:       map[string]int{"none": 1, "soft": 1},
		RecentSignalCounts: map[string]int{"anomaly": 2, "block": 1},
		TopAnomalies:       []proxy.AdaptiveTopAnomaly{{Name: "domain_burst", Count: 2}},
		LockdownTTLSeconds: 30,
	}
}
