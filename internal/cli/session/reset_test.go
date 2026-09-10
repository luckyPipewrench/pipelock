// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

func TestResetCmd_HappyPath(t *testing.T) {
	key := "agent/z|10.0.0.42"
	wantPath := "/api/v1/sessions/" + url.PathEscape(key) + "/reset"
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		if r.Method != http.MethodPost {
			t.Errorf("method: %s", r.Method)
		}
		if r.URL.EscapedPath() != wantPath {
			t.Errorf("path: %s, want %s", r.URL.EscapedPath(), wantPath)
		}
		writeJSONResponse(w, http.StatusOK, proxy.SessionResetResult{
			Key:             key,
			Reset:           true,
			PreviousLevel:   "critical",
			PreviousScore:   12,
			IPStateCleared:  true,
			CEEStateCleared: true,
		})
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(resetCmd(&rootFlags{}), key)
	if err != nil {
		t.Fatal(err)
	}
	wantContains := []string{"reset", "previous_level=critical", "previous_score=12.00", "ip_cleared=true", "cee_cleared=true"}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in: %s", w, out)
		}
	}
}

func TestResetCmd_JSON(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, proxy.SessionResetResult{
			Key: testKeyIdent, Reset: true, PreviousLevel: "high", PreviousScore: 6,
		})
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(resetCmd(&rootFlags{}), testKeyIdent, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var parsed proxy.SessionResetResult
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !parsed.Reset || parsed.PreviousLevel != "high" {
		t.Errorf("unexpected reset result: %+v", parsed)
	}
}

func TestResetCmd_InvocationRejected(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusBadRequest, map[string]string{"error": "invocation key"})
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(resetCmd(&rootFlags{}), testKeyInvoc)
	if err == nil || !strings.Contains(err.Error(), "bad request") {
		t.Errorf("expected bad request, got %v", err)
	}
}

func TestResetCmd_NotFound(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "ghost", http.StatusNotFound)
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(resetCmd(&rootFlags{}), testKeyIdent)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found, got %v", err)
	}
}
