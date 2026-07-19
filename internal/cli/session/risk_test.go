// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

func TestRiskCmd_WithKeyHumanAndJSON(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		json bool
	}{
		{name: "human", args: []string{testKeyIdent}},
		{name: "json", args: []string{testKeyIdent, "--json"}, json: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertBearer(t, r)
				if r.URL.Path != "/api/v1/sessions/"+testKeyIdent {
					t.Fatalf("path = %q", r.URL.Path)
				}
				writeJSONResponse(w, http.StatusOK, makeDetail())
			}))
			overrideClientFactory(t, flags)

			out, err := runCommand(riskCmd(&rootFlags{}), tt.args...)
			if err != nil {
				t.Fatalf("execute: %v; out=%s", err, out)
			}
			if tt.json {
				var detail proxy.SessionDetail
				if err := json.Unmarshal([]byte(out), &detail); err != nil {
					t.Fatalf("json output not parseable: %v; out=%s", err, out)
				}
				if detail.AutoRecoverAt.IsZero() {
					t.Fatal("json risk output missing auto_recover_at")
				}
				return
			}
			for _, want := range []string{"level=critical", "score=0.75", "auto_recover_at=", `hint="wait for auto-recovery"`} {
				if !strings.Contains(out, want) {
					t.Fatalf("risk output missing %q: %s", want, out)
				}
			}
		})
	}
}

func TestRiskCmd_WithKeyHumanEmptyRecoveryFields(t *testing.T) {
	detail := makeDetail()
	detail.AutoRecoverAt = time.Time{}
	detail.RecoverHint = ""
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		writeJSONResponse(w, http.StatusOK, detail)
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(riskCmd(&rootFlags{}), testKeyIdent)
	if err != nil {
		t.Fatalf("execute: %v; out=%s", err, out)
	}
	for _, want := range []string{"auto_recover_at=-", `hint="-"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("risk output missing %q: %s", want, out)
		}
	}
}

func TestRiskCmd_NoKeyUsesWhoami(t *testing.T) {
	resp := proxy.AdaptiveWhoami{
		Exists:             true,
		ClientIP:           "10.0.0.42",
		SessionKey:         testKeyIdent,
		Classification:     "identity",
		ThreatScore:        0.75,
		EscalationLevel:    "high",
		AirlockTier:        "none",
		LockdownTTLSeconds: 123,
	}
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		if r.URL.Path != "/api/v1/adaptive/whoami" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		writeJSONResponse(w, http.StatusOK, resp)
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(riskCmd(&rootFlags{}))
	if err != nil {
		t.Fatalf("execute: %v; out=%s", err, out)
	}
	for _, want := range []string{"session=" + testKeyIdent, "level=high", "ttl_seconds=123"} {
		if !strings.Contains(out, want) {
			t.Fatalf("risk whoami output missing %q: %s", want, out)
		}
	}
}

func TestRiskCmd_NoKeyJSONAndErrors(t *testing.T) {
	t.Run("whoami_json", func(t *testing.T) {
		resp := proxy.AdaptiveWhoami{
			Exists:             true,
			ClientIP:           "10.0.0.42",
			SessionKey:         testKeyIdent,
			Classification:     "identity",
			ThreatScore:        0.75,
			EscalationLevel:    "high",
			LockdownTTLSeconds: 123,
		}
		flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assertBearer(t, r)
			writeJSONResponse(w, http.StatusOK, resp)
		}))
		overrideClientFactory(t, flags)

		out, err := runCommand(riskCmd(&rootFlags{}), "--json")
		if err != nil {
			t.Fatalf("execute: %v; out=%s", err, out)
		}
		var got proxy.AdaptiveWhoami
		if err := json.Unmarshal([]byte(out), &got); err != nil {
			t.Fatalf("json output not parseable: %v; out=%s", err, out)
		}
		if got.SessionKey != testKeyIdent {
			t.Fatalf("session key = %q, want %q", got.SessionKey, testKeyIdent)
		}
	})

	for _, tt := range []struct {
		name string
		args []string
		path string
	}{
		{name: "whoami_error", path: "/api/v1/adaptive/whoami"},
		{name: "inspect_error", args: []string{testKeyIdent}, path: "/api/v1/sessions/" + testKeyIdent},
	} {
		t.Run(tt.name, func(t *testing.T) {
			flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertBearer(t, r)
				if r.URL.Path != tt.path {
					t.Fatalf("path = %q, want %q", r.URL.Path, tt.path)
				}
				http.Error(w, "boom", http.StatusInternalServerError)
			}))
			overrideClientFactory(t, flags)

			out, err := runCommand(riskCmd(&rootFlags{}), tt.args...)
			if err == nil {
				t.Fatalf("expected error; out=%s", out)
			}
		})
	}
}
