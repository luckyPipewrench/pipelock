// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestReleaseCmd_DefaultToNone(t *testing.T) {
	var tier string
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]string
		_ = json.Unmarshal(body, &parsed)
		tier = parsed["tier"]
		writeJSONResponse(w, http.StatusOK, airlockResponse{
			Key: testKeyIdent, PreviousTier: tierHard, NewTier: tierNone, Changed: true,
		})
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(releaseCmd(&rootFlags{}), testKeyIdent)
	if err != nil {
		t.Fatal(err)
	}
	if tier != tierNone {
		t.Errorf("default --to: got %q, want %s", tier, tierNone)
	}
	if !strings.Contains(out, "released") {
		t.Errorf("output: %s", out)
	}
}

func TestReleaseCmd_ToSoft(t *testing.T) {
	var tier string
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]string
		_ = json.Unmarshal(body, &parsed)
		tier = parsed["tier"]
		writeJSONResponse(w, http.StatusOK, airlockResponse{Key: testKeyIdent, NewTier: tierSoft})
	}))
	overrideClientFactory(t, flags)

	if _, err := runCommand(releaseCmd(&rootFlags{}), testKeyIdent, "--to", tierSoft); err != nil {
		t.Fatal(err)
	}
	if tier != tierSoft {
		t.Errorf("tier: got %q, want %s", tier, tierSoft)
	}
}

func TestReleaseCmd_InvalidTo(t *testing.T) {
	overrideClientFactory(t, &rootFlags{apiURL: "http://x:1", apiToken: testToken})
	_, err := runCommand(releaseCmd(&rootFlags{}), testKeyIdent, "--to", "hard")
	if err == nil {
		t.Error("expected error for upward transition")
	}
}

func TestReleaseCmd_JSON(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, airlockResponse{
			Key: testKeyIdent, PreviousTier: tierHard, NewTier: tierNone, Changed: true,
		})
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(releaseCmd(&rootFlags{}), testKeyIdent, "--json")
	if err != nil {
		t.Fatal(err)
	}
	var parsed airlockResponse
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !parsed.Changed {
		t.Error("Changed should be true")
	}
}

func TestReleaseCmd_Unauthorized(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad", http.StatusUnauthorized)
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(releaseCmd(&rootFlags{}), testKeyIdent)
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Errorf("expected unauthorized, got %v", err)
	}
}
