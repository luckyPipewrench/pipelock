// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
)

// blockedBundleServer answers every request with status and the given headers,
// standing in for a Pipelock proxy that refused to release a bundle.
func blockedBundleServer(t *testing.T, status int, set func(http.Header)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if set != nil {
			set(w.Header())
		}
		http.Error(w, "blocked: response contains injection", status)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestFetchNamesPipelockOnBlockedResponse: the reason a bundle install fails
// has to reach the operator. A Pipelock 403 arriving as a bare "status 403" is
// indistinguishable from the registry being down.
func TestFetchNamesPipelockOnBlockedResponse(t *testing.T) {
	srv := blockedBundleServer(t, http.StatusForbidden, func(h http.Header) {
		info, err := blockreason.NewForReason(blockreason.PromptInjection)
		if err != nil {
			t.Fatalf("NewForReason: %v", err)
		}
		info, err = info.WithLayer("response_scan")
		if err != nil {
			t.Fatalf("WithLayer: %v", err)
		}
		info.SetHeaders(h)
	})

	_, err := httpGetWithClient(context.Background(), srv.URL+"/rules/pipelock-community/bundle.yaml", srv.Client())
	if err == nil {
		t.Fatal("expected an error from a 403")
	}
	msg := err.Error()

	for _, want := range []string{
		"Pipelock",
		"not by the server",
		"prompt_injection",
		"response_scan",
		"response_scanning",
		"authenticated_artifacts",
		"bundle_name",
		`path: "/rules/pipelock-community/bundle.yaml"`,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message omits %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "blocked: response contains injection") {
		t.Errorf("error message echoed the response body:\n%s", msg)
	}
}

// TestFetchDoesNotMislabelOrdinaryUpstreamError is the negative direction. An
// upstream 403 with no Pipelock headers must stay a plain status error, or the
// CLI blames the operator's proxy for something it never did.
func TestFetchDoesNotMislabelOrdinaryUpstreamError(t *testing.T) {
	tests := []struct {
		name   string
		status int
		set    func(http.Header)
	}{
		{"plain 403", http.StatusForbidden, nil},
		{"plain 404", http.StatusNotFound, nil},
		{"502 from a CDN", http.StatusBadGateway, func(h http.Header) {
			h.Set("Server", "cloudflare")
		}},
		{"unknown reason code", http.StatusForbidden, func(h http.Header) {
			h.Set(blockreason.HeaderReason, "something_else_entirely")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := blockedBundleServer(t, tc.status, tc.set)
			_, err := httpGetWithClient(context.Background(), srv.URL+"/bundle.yaml", srv.Client())
			if err == nil {
				t.Fatal("expected an error")
			}
			msg := err.Error()
			if strings.Contains(msg, "Pipelock") || strings.Contains(msg, "authenticated_artifacts") {
				t.Fatalf("an ordinary upstream error was reported as a Pipelock block:\n%s", msg)
			}
			if !strings.Contains(msg, "status") {
				t.Fatalf("lost the status code:\n%s", msg)
			}
		})
	}
}

// TestRemedyOnlyOfferedForTheLayerItGoverns: authenticated_artifacts is
// consulted only on the response-injection path. Offering it for a block from
// any other layer would be an inert remedy - it would not have changed the
// outcome, so it teaches the operator that policy changed when nothing did.
func TestRemedyOnlyOfferedForTheLayerItGoverns(t *testing.T) {
	t.Parallel()
	bundleURL := "https://pipelab.org/rules/pipelock-community/bundle.yaml"

	if got := authenticatedArtifactRemedy(bundleURL, blockreason.PromptInjection); got == "" {
		t.Fatal("prompt_injection is exactly the block this exception governs; remedy must be offered")
	}

	for _, reason := range blockreason.AllReasons() {
		if reason == blockreason.PromptInjection {
			continue
		}
		if got := authenticatedArtifactRemedy(bundleURL, reason); got != "" {
			t.Errorf("offered the authenticated_artifacts remedy for %q, which it would not have unblocked", reason)
		}
	}
}

func TestRemedyUsesTheStringsTheProxyCompares(t *testing.T) {
	t.Parallel()
	// The proxy matches on URL.Hostname() and URL.EscapedPath(), so a remedy
	// quoting anything else sends the operator to a config that will not match.
	got := authenticatedArtifactRemedy("https://PipeLab.org:443/rules/a%2Bb/bundle.yaml", blockreason.PromptInjection)
	if !strings.Contains(got, `host: "PipeLab.org"`) {
		t.Errorf("remedy lost the host:\n%s", got)
	}
	if !strings.Contains(got, `path: "/rules/a%2Bb/bundle.yaml"`) {
		t.Errorf("remedy did not use the escaped path:\n%s", got)
	}
}

func TestRemedyAbsentForAnUnparseableURL(t *testing.T) {
	t.Parallel()
	if got := authenticatedArtifactRemedy("://not a url", blockreason.PromptInjection); got != "" {
		t.Errorf("invented a remedy for an unparseable URL:\n%s", got)
	}
}
