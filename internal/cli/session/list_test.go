// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func TestListCmd_HappyPathHuman(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		writeJSONResponse(w, http.StatusOK, listResponse{Sessions: makeSnapshotList(), Count: 1})
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(listCmd(&rootFlags{}))
	if err != nil {
		t.Fatalf("execute: %v; out=%s", err, out)
	}
	if !strings.Contains(out, testKeyIdent) {
		t.Errorf("output missing key: %s", out)
	}
	if !strings.Contains(out, tierHard) {
		t.Errorf("output missing tier: %s", out)
	}
}

func TestListCmd_JSONOutput(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, listResponse{Sessions: makeSnapshotList(), Count: 1})
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(listCmd(&rootFlags{}), "--json")
	if err != nil {
		t.Fatalf("execute: %v; out=%s", err, out)
	}
	var parsed listResponse
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("json output not parseable: %v; out=%s", err, out)
	}
	if parsed.Count != 1 {
		t.Errorf("Count: got %d, want 1", parsed.Count)
	}
}

func TestListCmd_TierFilterForwarded(t *testing.T) {
	var gotTier string
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTier = r.URL.Query().Get("tier")
		writeJSONResponse(w, http.StatusOK, listResponse{})
	}))
	overrideClientFactory(t, flags)

	if _, err := runCommand(listCmd(&rootFlags{}), "--tier", tierHard); err != nil {
		t.Fatal(err)
	}
	if gotTier != tierHard {
		t.Errorf("tier forwarded: got %q", gotTier)
	}
}

func TestListCmd_InvalidTierFailsLocally(t *testing.T) {
	// Don't stand up a server — local validation catches this first.
	overrideClientFactory(t, &rootFlags{apiURL: "http://ignored:1", apiToken: testToken})
	_, err := runCommand(listCmd(&rootFlags{}), "--tier", "moist")
	if err == nil {
		t.Error("expected error for bogus tier")
	}
}

func TestListCmd_404Maps_SessionNotFound(t *testing.T) {
	// List returns 404 rarely, but the path is validated for robustness.
	// Also pins the mapped exit code (1 = operational failure) so a
	// regression that collapses 404 into exit 0 or exit 2 fails the
	// test even if the error text is preserved.
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(listCmd(&rootFlags{}))
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected not-found text, got %v", err)
	}
	if code := cliutil.ExitCodeOf(err); code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
}

func TestListCmd_401Maps_Unauthorized(t *testing.T) {
	// 401 is a setup error; exit code 2 signals scripts that the
	// token/url should be fixed before retrying.
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "bad token", http.StatusUnauthorized)
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(listCmd(&rootFlags{}))
	if err == nil || !strings.Contains(err.Error(), "unauthorized") {
		t.Fatalf("expected unauthorized error, got %v", err)
	}
	if code := cliutil.ExitCodeOf(err); code != 2 {
		t.Errorf("exit code: got %d, want 2", code)
	}
}

func TestListCmd_429Maps_RateLimited(t *testing.T) {
	// 429 is retry-able; exit code 1 signals scripts that a backoff
	// retry is the right response.
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "slow down", http.StatusTooManyRequests)
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(listCmd(&rootFlags{}))
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("expected rate limited error, got %v", err)
	}
	if code := cliutil.ExitCodeOf(err); code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
}

func TestListCmd_500Maps_ServerError(t *testing.T) {
	// 500 is an operational failure on the server side. Scripts get
	// exit code 1 so they can retry or escalate — same class as 404.
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "internal boom", http.StatusInternalServerError)
	}))
	overrideClientFactory(t, flags)

	_, err := runCommand(listCmd(&rootFlags{}))
	if err == nil || !strings.Contains(err.Error(), "server error") {
		t.Fatalf("expected server error wrapper, got %v", err)
	}
	if code := cliutil.ExitCodeOf(err); code != 1 {
		t.Errorf("exit code: got %d, want 1", code)
	}
}

func TestListCmd_EmptyResultPrintsPlaceholder(t *testing.T) {
	flags := stubServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSONResponse(w, http.StatusOK, listResponse{Count: 0})
	}))
	overrideClientFactory(t, flags)

	out, err := runCommand(listCmd(&rootFlags{}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "No sessions") {
		t.Errorf("expected no-sessions placeholder: %s", out)
	}
}
