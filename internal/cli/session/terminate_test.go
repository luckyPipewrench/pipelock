// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

func TestTerminateCmd_HappyPath(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		if r.Method != http.MethodPost {
			t.Errorf("method: %s", r.Method)
		}
		writeJSONResponse(w, http.StatusOK, proxy.SessionTerminateResult{
			Key: testKeyIdent, Terminated: true, PreviousTier: "hard",
			PreviousLevel: "critical", PreviousScore: 0.9,
			CEEStateCleared: true,
		})
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(terminateCmd(), testKeyIdent)
	if err != nil {
		t.Fatal(err)
	}
	// Warning line is non-negotiable.
	if !strings.Contains(out, "WARNING") {
		t.Errorf("expected WARNING line in output: %s", out)
	}
	wantContains := []string{"terminated", "previous_tier=hard", "cee_cleared=true"}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in: %s", w, out)
		}
	}
}

func TestTerminateCmd_InvocationRejected(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invocation key"})
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(terminateCmd(), testKeyInvoc)
	if err == nil || !strings.Contains(err.Error(), "bad request") {
		t.Errorf("expected bad request, got %v", err)
	}
}

func TestTerminateCmd_JSON(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, proxy.SessionTerminateResult{
			Key: testKeyIdent, Terminated: true,
		})
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(terminateCmd(), testKeyIdent, "--json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "WARNING") {
		t.Fatalf("json output should not include warning banner: %s", out)
	}
	var parsed proxy.SessionTerminateResult
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !parsed.Terminated {
		t.Error("Terminated should be true")
	}
}

func TestTerminateCmd_NotFound(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "ghost", http.StatusNotFound)
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(terminateCmd(), testKeyIdent)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found, got %v", err)
	}
}

func TestTerminateCmd_RateLimited(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limit", http.StatusTooManyRequests)
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(terminateCmd(), testKeyIdent)
	if err == nil || !strings.Contains(err.Error(), "rate") {
		t.Errorf("expected rate limited error, got %v", err)
	}
}
