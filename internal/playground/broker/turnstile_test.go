// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestTurnstileVerifier_Verify(t *testing.T) {
	t.Parallel()
	var got url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if gotCT := r.Header.Get("Content-Type"); gotCT != "application/x-www-form-urlencoded" {
			t.Fatalf("content-type = %q", gotCT)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		got = r.PostForm
		_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
	}))
	t.Cleanup(ts.Close)

	verifier := TurnstileVerifier{Secret: "secret", VerifyURL: ts.URL, Client: ts.Client()}
	if err := verifier.Verify(context.Background(), "token", "198.51.100.7"); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if got.Get("secret") != "secret" || got.Get("response") != "token" || got.Get("remoteip") != "198.51.100.7" {
		t.Fatalf("siteverify form = %v", got)
	}
}

func TestTurnstileVerifier_FailsClosed(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		token   string
		handler http.HandlerFunc
	}{
		{
			name:  "rejected",
			token: "token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"success":     false,
					"error-codes": []string{"timeout-or-duplicate"},
				})
			},
		},
		{
			name:  "bad_status",
			token: "token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "bad gateway", http.StatusBadGateway)
			},
		},
		{
			name:  "bad_json",
			token: "token",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("{"))
			},
		},
		{
			name:  "empty_token",
			token: "",
			handler: func(http.ResponseWriter, *http.Request) {
				t.Fatal("siteverify should not be called for an empty token")
			},
		},
		{
			name:  "oversized_token",
			token: strings.Repeat("x", maxTurnstileTokenBytes+1),
			handler: func(http.ResponseWriter, *http.Request) {
				t.Fatal("siteverify should not be called for an oversized token")
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := httptest.NewServer(tc.handler)
			t.Cleanup(ts.Close)
			verifier := TurnstileVerifier{Secret: "secret", VerifyURL: ts.URL, Client: ts.Client()}
			if err := verifier.Verify(context.Background(), tc.token, "198.51.100.7"); err == nil {
				t.Fatal("Verify succeeded, want fail closed")
			}
		})
	}
}

func TestTurnstileVerifier_EmptySecretFailsClosed(t *testing.T) {
	t.Parallel()
	if err := (TurnstileVerifier{}).Verify(context.Background(), "token", "198.51.100.7"); err == nil {
		t.Fatal("Verify with empty secret succeeded, want fail closed")
	}
}
