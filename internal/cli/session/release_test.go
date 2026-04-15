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

// releaseStub multiplexes the GET /sessions/{key} (inspect) and POST
// .../airlock (release) endpoints that release.go now hits. currentTier
// is the tier returned from inspect; captureTier is written when the
// release POST body is parsed.
func releaseStub(t *testing.T, currentTier string, captureTier *string, airlockResp airlockResponse) *rootFlags {
	t.Helper()
	return stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		if r.Method == http.MethodGet {
			detail := makeDetail()
			detail.AirlockTier = currentTier
			writeJSONResponse(w, http.StatusOK, detail)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]string
		_ = json.Unmarshal(body, &parsed)
		if captureTier != nil {
			*captureTier = parsed["tier"]
		}
		writeJSONResponse(w, http.StatusOK, airlockResp)
	}))
}

func TestReleaseCmd_DefaultToNone(t *testing.T) {
	var tier string
	flags := releaseStub(t, tierHard, &tier, airlockResponse{
		Key: testKeyIdent, PreviousTier: tierHard, NewTier: tierNone, Changed: true,
	})
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
	// Session is at hard; downward to soft is valid.
	flags := releaseStub(t, tierHard, &tier, airlockResponse{Key: testKeyIdent, NewTier: tierSoft})
	overrideClientFactory(t, flags)

	if _, err := runCommand(releaseCmd(&rootFlags{}), testKeyIdent, "--to", tierSoft); err != nil {
		t.Fatal(err)
	}
	if tier != tierSoft {
		t.Errorf("tier: got %q, want %s", tier, tierSoft)
	}
}

// Regression: release --to soft on a normal-tier session must be rejected
// client-side without making a POST to /airlock, or it would escalate the
// session (contract says release is downward-only).
func TestReleaseCmd_RefusesUpwardFromNone(t *testing.T) {
	var releaseBodyPosted bool
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		if r.Method == http.MethodGet {
			detail := makeDetail()
			detail.AirlockTier = tierNone
			writeJSONResponse(w, http.StatusOK, detail)
			return
		}
		releaseBodyPosted = true
		writeJSONResponse(w, http.StatusOK, airlockResponse{})
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(releaseCmd(&rootFlags{}), testKeyIdent, "--to", tierSoft)
	if err == nil {
		t.Fatal("expected rejection for upward transition")
	}
	if !strings.Contains(err.Error(), "downward-only") {
		t.Errorf("error message: got %q, want substring 'downward-only'", err.Error())
	}
	if releaseBodyPosted {
		t.Error("release POST should not be issued when the client rejects the transition")
	}
}

// TestReleaseCmd_SameTierAllowed confirms release is idempotent: releasing
// to the current tier is a no-op but not an error.
func TestReleaseCmd_SameTierAllowed(t *testing.T) {
	flags := releaseStub(t, tierSoft, nil, airlockResponse{Key: testKeyIdent, NewTier: tierSoft})
	overrideClientFactory(t, flags)
	if _, err := runCommand(releaseCmd(&rootFlags{}), testKeyIdent, "--to", tierSoft); err != nil {
		t.Fatalf("same-tier release should succeed: %v", err)
	}
}

func TestEnsureDownward(t *testing.T) {
	cases := []struct {
		name    string
		current string
		target  string
		wantErr bool
	}{
		{"hard to none", tierHard, tierNone, false},
		{"soft to none", tierSoft, tierNone, false},
		{"hard to soft", tierHard, tierSoft, false},
		{"same tier", tierSoft, tierSoft, false},
		{"empty current to none", "", tierNone, false},
		{"none to soft rejected", tierNone, tierSoft, true},
		{"empty to soft rejected", "", tierSoft, true},
		{"soft to hard rejected", tierSoft, tierHard, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ensureDownward(tc.current, tc.target)
			if tc.wantErr && err == nil {
				t.Errorf("expected error for %s -> %s", tc.current, tc.target)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
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
