// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/proxy"
)

const deferredCLIID = "0193defer00000000000000000001"

func TestDeferredCmd_RegistersSubcommands(t *testing.T) {
	// deferred is registered under `session`.
	if _, _, err := Cmd().Find([]string{"deferred", "list"}); err != nil {
		t.Fatalf("session deferred list not registered: %v", err)
	}
	cmd := deferredCmd(&rootFlags{})
	for _, name := range []string{"list", "approve", "deny"} {
		if _, _, err := cmd.Find([]string{name}); err != nil {
			t.Errorf("subcommand %q not registered: %v", name, err)
		}
	}
	if !strings.Contains(cmd.Long, "admin API") {
		t.Errorf("long help should mention admin API: %q", cmd.Long)
	}
}

func TestClient_DeferredMethods(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertBearer(t, r)
		paths = append(paths, r.Method+" "+r.URL.EscapedPath())
		switch r.URL.EscapedPath() {
		case "/api/v1/deferred":
			writeJSONResponse(w, http.StatusOK, proxy.DeferredListResponse{
				Held:  []proxy.DeferredHeldView{{DeferID: deferredCLIID, Surface: "mcp_stdio", Method: "tools/call", Target: "shell.exec", SessionID: "sess-1"}},
				Count: 1,
			})
		case "/api/v1/deferred/" + url.PathEscape(deferredCLIID) + "/approve":
			writeJSONResponse(w, http.StatusOK, proxy.DeferredResolveResult{DeferID: deferredCLIID, Action: "approve", FinalDecision: "allow", Resolved: true})
		case "/api/v1/deferred/" + url.PathEscape(deferredCLIID) + "/deny":
			writeJSONResponse(w, http.StatusOK, proxy.DeferredResolveResult{DeferID: deferredCLIID, Action: "deny", FinalDecision: "block", Resolved: true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := newClient(endpoint{URL: srv.URL, Token: testToken})
	if _, err := c.DeferredList(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeferredApprove(context.Background(), deferredCLIID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeferredDeny(context.Background(), deferredCLIID); err != nil {
		t.Fatal(err)
	}

	want := []string{
		"GET /api/v1/deferred",
		"POST /api/v1/deferred/" + url.PathEscape(deferredCLIID) + "/approve",
		"POST /api/v1/deferred/" + url.PathEscape(deferredCLIID) + "/deny",
	}
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Fatalf("paths:\ngot:\n%s\nwant:\n%s", strings.Join(paths, "\n"), strings.Join(want, "\n"))
	}
}

func TestClient_DeferredMethods_ErrorPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		call       func(*Client) error
		statusCode int
		body       string
		wantStatus int
	}{
		{
			name:       "list non-200",
			call:       func(c *Client) error { _, err := c.DeferredList(context.Background()); return err },
			statusCode: http.StatusInternalServerError,
			body:       `{"error":"list failed"}`,
			wantStatus: http.StatusInternalServerError,
		},
		{
			name:       "list invalid JSON",
			call:       func(c *Client) error { _, err := c.DeferredList(context.Background()); return err },
			statusCode: http.StatusOK,
			body:       `not-json`,
		},
		{
			name:       "approve unknown id",
			call:       func(c *Client) error { _, err := c.DeferredApprove(context.Background(), deferredCLIID); return err },
			statusCode: http.StatusNotFound,
			body:       `{"error":"unknown defer id"}`,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "approve already resolved",
			call:       func(c *Client) error { _, err := c.DeferredApprove(context.Background(), deferredCLIID); return err },
			statusCode: http.StatusConflict,
			body:       `{"error":"already resolved"}`,
			wantStatus: http.StatusConflict,
		},
		{
			name:       "approve invalid JSON",
			call:       func(c *Client) error { _, err := c.DeferredApprove(context.Background(), deferredCLIID); return err },
			statusCode: http.StatusOK,
			body:       `not-json`,
		},
		{
			name:       "deny unknown id",
			call:       func(c *Client) error { _, err := c.DeferredDeny(context.Background(), deferredCLIID); return err },
			statusCode: http.StatusNotFound,
			body:       `{"error":"unknown defer id"}`,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "deny already resolved",
			call:       func(c *Client) error { _, err := c.DeferredDeny(context.Background(), deferredCLIID); return err },
			statusCode: http.StatusConflict,
			body:       `{"error":"already resolved"}`,
			wantStatus: http.StatusConflict,
		},
		{
			name:       "deny invalid JSON",
			call:       func(c *Client) error { _, err := c.DeferredDeny(context.Background(), deferredCLIID); return err },
			statusCode: http.StatusOK,
			body:       `not-json`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertBearer(t, r)
				w.Header().Set("Content-Type", contentTypeJSON)
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			c := newClient(endpoint{URL: srv.URL, Token: testToken})
			err := tt.call(c)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if tt.wantStatus == 0 {
				if !strings.Contains(err.Error(), "decode response") {
					t.Fatalf("error = %q, want decode failure", err)
				}
				return
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("error type = %T, want *APIError", err)
			}
			if apiErr.StatusCode != tt.wantStatus {
				t.Fatalf("status = %d, want %d", apiErr.StatusCode, tt.wantStatus)
			}
		})
	}
}

func TestDeferredRenderers(t *testing.T) {
	// List with one held action surfaces the identifying fields, never the payload.
	listOut := &strings.Builder{}
	if err := renderDeferredList(listOut, proxy.DeferredListResponse{
		Held:  []proxy.DeferredHeldView{{DeferID: deferredCLIID, Surface: "mcp_stdio", Method: "tools/call", Target: "shell.exec", SessionID: "sess-1", CascadeDepth: 0, Reason: "tool policy: defer"}},
		Count: 1,
	}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{deferredCLIID, "mcp_stdio", "shell.exec", "DEFER_ID"} {
		if !strings.Contains(listOut.String(), want) {
			t.Errorf("list output missing %q: %s", want, listOut.String())
		}
	}

	// Empty list.
	emptyOut := &strings.Builder{}
	if err := renderDeferredList(emptyOut, proxy.DeferredListResponse{Count: 0}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(emptyOut.String(), "no held actions") {
		t.Errorf("empty list output = %q", emptyOut.String())
	}

	// Resolve output reports the ACTUAL decision: a forbidden approve prints
	// "approve <id> -> block", never a misleading success.
	resolveOut := &strings.Builder{}
	if err := renderDeferredResolve(resolveOut, proxy.DeferredResolveResult{DeferID: deferredCLIID, Action: "approve", FinalDecision: "block", Resolved: true}); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(resolveOut.String()); got != "approve "+deferredCLIID+" -> block" {
		t.Errorf("resolve output = %q, want honest block decision", got)
	}
}
