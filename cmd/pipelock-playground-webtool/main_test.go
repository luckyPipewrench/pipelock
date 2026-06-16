// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// canaryPart1 + canaryPart2 compose the synthetic canary; split so the full
// literal never appears as a single string constant (OPSEC guard).
const (
	canaryPart1 = "AKIA"
	canaryPart2 = "IOSFODNN7EXAMPLE"
)

func canaryValue() string { return canaryPart1 + canaryPart2 }

// TestWebTool_PostIncludesCanaryFromEnv asserts that when --include-canary is
// set, the web tool reads the canary VALUE from the environment and places it
// in the POST body, NOT from argv.  We verify that no argv passed to
// runWebTool contains the canary value.
func TestWebTool_PostIncludesCanaryFromEnv(t *testing.T) {
	cv := canaryValue()
	t.Setenv("PLAYGROUND_CANARY_VALUE", cv)

	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBody = b
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	// argv must NOT contain the canary value.
	args := []string{"post", srv.URL, "--include-canary"}
	for _, a := range args {
		if strings.Contains(a, cv) {
			t.Fatalf("argv must not contain canary value; found in: %q", a)
		}
	}

	var buf bytes.Buffer
	err := runWebTool(t.Context(), &buf, args, func(key string) string {
		if key == "PLAYGROUND_CANARY_VALUE" {
			return cv
		}
		return ""
	})
	if err != nil {
		t.Fatalf("runWebTool: %v", err)
	}

	body := string(receivedBody)
	if !strings.Contains(body, cv) {
		t.Fatalf("POST body should contain canary value; got: %q", body)
	}
}

// TestWebTool_GetDoesNotSendCanary verifies that a plain GET never sends the
// canary value.
func TestWebTool_GetDoesNotSendCanary(t *testing.T) {
	cv := canaryValue()
	t.Setenv("PLAYGROUND_CANARY_VALUE", cv)

	var receivedURL string
	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedURL = r.RequestURI
		b, _ := io.ReadAll(r.Body)
		receivedBody = b
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("safe"))
	}))
	defer srv.Close()

	var buf bytes.Buffer
	err := runWebTool(t.Context(), &buf, []string{"get", srv.URL}, func(key string) string {
		if key == "PLAYGROUND_CANARY_VALUE" {
			return cv
		}
		return ""
	})
	if err != nil {
		t.Fatalf("runWebTool GET: %v", err)
	}

	if strings.Contains(receivedURL, cv) {
		t.Fatalf("canary must not appear in GET URL; got: %q", receivedURL)
	}
	if strings.Contains(string(receivedBody), cv) {
		t.Fatalf("canary must not appear in GET body; got: %q", string(receivedBody))
	}
}

func TestWebTool_GetSendsAgentHeaderWhenConfigured(t *testing.T) {
	var gotAgent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAgent = r.Header.Get(agentHeader)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	err := runWebTool(t.Context(), &buf, []string{"get", srv.URL}, func(key string) string {
		if key == agentIDEnvVar {
			return "lab-agent"
		}
		return ""
	})
	if err != nil {
		t.Fatalf("runWebTool GET: %v", err)
	}
	if gotAgent != "lab-agent" {
		t.Fatalf("agent header = %q", gotAgent)
	}
}

// TestWebTool_PostWithoutCanaryFlagOmitsCanary verifies that without
// --include-canary the POST body does NOT contain the canary, even if the env
// var is set.
func TestWebTool_PostWithoutCanaryFlagOmitsCanary(t *testing.T) {
	cv := canaryValue()
	t.Setenv("PLAYGROUND_CANARY_VALUE", cv)

	var receivedBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		receivedBody = b
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	var buf bytes.Buffer
	err := runWebTool(t.Context(), &buf, []string{"post", srv.URL}, func(key string) string {
		if key == "PLAYGROUND_CANARY_VALUE" {
			return cv
		}
		return ""
	})
	if err != nil {
		t.Fatalf("runWebTool POST without flag: %v", err)
	}

	if strings.Contains(string(receivedBody), cv) {
		t.Fatalf("canary must NOT appear in body when --include-canary is absent; got: %q", string(receivedBody))
	}
}

// TestWebTool_GetPrintsStatusLine checks that the GET output includes an HTTP
// status indicator.
func TestWebTool_GetPrintsStatusLine(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	var buf bytes.Buffer
	err := runWebTool(t.Context(), &buf, []string{"get", srv.URL}, func(_ string) string { return "" })
	if err != nil {
		t.Fatalf("runWebTool GET: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "200") {
		t.Fatalf("expected status 200 in output; got: %q", out)
	}
}

// TestWebTool_UnknownSubcommand returns an error for an unknown subcommand.
func TestWebTool_UnknownSubcommand(t *testing.T) {
	var buf bytes.Buffer
	err := runWebTool(t.Context(), &buf, []string{"delete", "http://x.example"}, func(_ string) string { return "" })
	if err == nil {
		t.Fatal("expected error for unknown subcommand")
	}
}

// TestWebTool_MissingURL returns an error when no URL is given.
func TestWebTool_MissingURL(t *testing.T) {
	var buf bytes.Buffer
	err := runWebTool(t.Context(), &buf, []string{"get"}, func(_ string) string { return "" })
	if err == nil {
		t.Fatal("expected error for missing URL")
	}
}

func TestWebTool_PostMissingURL(t *testing.T) {
	var buf bytes.Buffer
	err := runWebTool(t.Context(), &buf, []string{"post"}, func(_ string) string { return "" })
	if err == nil {
		t.Fatal("expected error for missing POST URL")
	}
}

func TestWebTool_GetRejectsExtraArgs(t *testing.T) {
	var buf bytes.Buffer
	err := runWebTool(t.Context(), &buf, []string{"get", "http://x.example", "--include-canary"}, func(_ string) string { return "" })
	if err == nil {
		t.Fatal("expected error for extra GET argument")
	}
}

func TestWebTool_PostRejectsUnknownArg(t *testing.T) {
	var buf bytes.Buffer
	err := runWebTool(t.Context(), &buf, []string{"post", "http://x.example", "--include-canery"}, func(_ string) string { return "" })
	if err == nil {
		t.Fatal("expected error for unknown POST argument")
	}
}

func TestWebTool_RequestBuildErrors(t *testing.T) {
	for _, args := range [][]string{
		{"get", "http://[::1"},
		{"post", "http://[::1"},
	} {
		var buf bytes.Buffer
		err := runWebTool(t.Context(), &buf, args, func(_ string) string { return "" })
		if err == nil {
			t.Fatalf("expected request build error for args %v", args)
		}
	}
}

func TestWebTool_HTTPDoErrors(t *testing.T) {
	for _, args := range [][]string{
		{"get", "ftp://example.test/resource"},
		{"post", "ftp://example.test/resource"},
	} {
		var buf bytes.Buffer
		err := runWebTool(t.Context(), &buf, args, func(_ string) string { return "" })
		if err == nil {
			t.Fatalf("expected HTTP client error for args %v", args)
		}
	}
}

func TestWebTool_HTTPClientHasTimeout(t *testing.T) {
	if webToolHTTPClient().Timeout != 5*time.Second {
		t.Fatalf("web tool HTTP timeout = %s", webToolHTTPClient().Timeout)
	}
}
