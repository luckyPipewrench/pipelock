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

func TestInspectCmd_HappyPathHuman(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		writeJSONResponse(w, http.StatusOK, makeDetail())
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(inspectCmd(), testKeyIdent)
	if err != nil {
		t.Fatalf("execute: %v; out=%s", err, out)
	}
	wantContains := []string{testKeyIdent, "hard", "in_flight", "dlp secret"}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in: %s", w, out)
		}
	}
}

func TestInspectCmd_JSON(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, makeDetail())
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(inspectCmd(), testKeyIdent, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var parsed proxy.SessionDetail
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("json parse: %v; out=%s", err, out)
	}
	if parsed.Key != testKeyIdent {
		t.Errorf("Key: got %q", parsed.Key)
	}
}

func TestInspectCmd_RequiresArg(t *testing.T) {
	overrideClientFactory(t, &rootFlags{apiURL: "http://ignored:1", apiToken: testToken})
	_, err := runCommand(inspectCmd())
	if err == nil {
		t.Error("expected error without key argument")
	}
}

func TestInspectCmd_NotFound(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(inspectCmd(), testKeyIdent)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found, got %v", err)
	}
}

func TestInspectCmd_Unauthorized(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad token", http.StatusUnauthorized)
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(inspectCmd(), testKeyIdent)
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("expected unauthorized, got %v", err)
	}
}
