// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
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
