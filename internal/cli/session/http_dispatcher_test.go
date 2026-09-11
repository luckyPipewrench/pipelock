// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

// The recover command's other tests stub recoverDispatcher, so httpDispatcher's
// own methods never execute. These drive the real dispatcher against a fake
// admin API, because the operator-visible text those methods print is the whole
// point of the surface: `release` in particular has to say plainly that it did
// NOT clear destination adaptive scores, or an operator reads a successful
// release as "the session is unstuck" when its score is untouched.

func TestHTTPDispatcher_Reset_ReportsPreviousState(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method: got %q, want POST", r.Method)
		}
		if !strings.HasSuffix(r.URL.Path, "/reset") {
			t.Errorf("path: got %q, want a /reset suffix", r.URL.Path)
		}
		writeJSONResponse(w, http.StatusOK, proxy.SessionResetResult{
			Key:           "agent|10.0.0.1",
			PreviousLevel: "block_all",
			PreviousScore: 12.5,
		})
	}))
	defer srv.Close()

	var out bytes.Buffer
	client := newClient(endpoint{URL: srv.URL, Token: testToken})
	if err := (httpDispatcher{}).Reset(context.Background(), client, "agent|10.0.0.1", &out); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	got := out.String()
	for _, want := range []string{"agent|10.0.0.1", "previous_level=block_all", "previous_score=12.50"} {
		if !strings.Contains(got, want) {
			t.Errorf("reset output missing %q; got %q", want, got)
		}
	}
}

func TestHTTPDispatcher_Release_WarnsWhenAirlockDidNotChange(t *testing.T) {
	for _, tt := range []struct {
		name      string
		changed   bool
		wantWarn  bool
		wantParts []string
	}{
		{
			name:      "changed release stays quiet about scores",
			changed:   true,
			wantWarn:  false,
			wantParts: []string{"released agent|10.0.0.1", "hard -> none", "changed=true"},
		},
		{
			// The no-op case is the one that misleads: the command succeeded,
			// nothing moved, and the adaptive score that is actually holding
			// the session down is still there.
			name:      "unchanged release must point at reset",
			changed:   false,
			wantWarn:  true,
			wantParts: []string{"changed=false"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !strings.HasSuffix(r.URL.Path, "/airlock") {
					t.Errorf("path: got %q, want an /airlock suffix", r.URL.Path)
				}
				writeJSONResponse(w, http.StatusOK, airlockResponse{
					Key:          "agent|10.0.0.1",
					PreviousTier: "hard",
					NewTier:      "none",
					Changed:      tt.changed,
				})
			}))
			defer srv.Close()

			var out bytes.Buffer
			client := newClient(endpoint{URL: srv.URL, Token: testToken})
			if err := (httpDispatcher{}).Release(context.Background(), client, "agent|10.0.0.1", "none", &out); err != nil {
				t.Fatalf("Release: %v", err)
			}
			got := out.String()
			for _, want := range tt.wantParts {
				if !strings.Contains(got, want) {
					t.Errorf("release output missing %q; got %q", want, got)
				}
			}
			mentionsReset := strings.Contains(got, "use reset")
			if mentionsReset != tt.wantWarn {
				t.Errorf("reset guidance present=%t, want %t; got %q", mentionsReset, tt.wantWarn, got)
			}
		})
	}
}

func TestHTTPDispatcher_PropagatesTransportErrors(t *testing.T) {
	// A failing admin API must surface as an error rather than printing a
	// success line an operator would believe.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	client := newClient(endpoint{URL: srv.URL, Token: testToken})
	for _, tt := range []struct {
		name string
		call func(out *bytes.Buffer) error
	}{
		{"reset", func(out *bytes.Buffer) error {
			return (httpDispatcher{}).Reset(context.Background(), client, "agent|10.0.0.1", out)
		}},
		{"release", func(out *bytes.Buffer) error {
			return (httpDispatcher{}).Release(context.Background(), client, "agent|10.0.0.1", "none", out)
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := tt.call(&out); err == nil {
				t.Fatalf("%s accepted a 500 response; output=%q", tt.name, out.String())
			}
			if out.Len() != 0 {
				t.Errorf("%s printed on failure: %q", tt.name, out.String())
			}
		})
	}
}
