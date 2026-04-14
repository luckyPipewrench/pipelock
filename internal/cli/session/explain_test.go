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

func TestExplainCmd_HappyPath(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		writeJSONResponse(w, http.StatusOK, makeExplanation())
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(explainCmd(), testKeyIdent)
	if err != nil {
		t.Fatal(err)
	}
	wantContains := []string{"on_critical", "evidence", "dlp secret", "next_deescalation"}
	for _, w := range wantContains {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in: %s", w, out)
		}
	}
}

func TestExplainCmd_JSON(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, makeExplanation())
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(explainCmd(), testKeyIdent, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var exp proxy.SessionExplanation
	if err := json.Unmarshal([]byte(out), &exp); err != nil {
		t.Fatalf("parse: %v; out=%s", err, out)
	}
	if exp.Trigger != "on_critical" {
		t.Errorf("Trigger: got %q", exp.Trigger)
	}
}

func TestExplainCmd_NoneTierSession(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, proxy.SessionExplanation{
			Key: testKeyIdent, Tier: "none", Reason: "session not quarantined",
		})
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(explainCmd(), testKeyIdent)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "not quarantined") {
		t.Errorf("none tier: expected reason text, got %s", out)
	}
}

func TestExplainCmd_NotFound(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "ghost", http.StatusNotFound)
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(explainCmd(), testKeyIdent)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not found, got %v", err)
	}
}

func TestExplainCmd_RequiresArg(t *testing.T) {
	overrideClientFactory(t, &rootFlags{apiURL: "http://x:1", apiToken: testToken})
	_, err := runCommand(explainCmd())
	if err == nil {
		t.Error("expected error without key argument")
	}
}
