// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildLLMAgentConfig(t *testing.T) {
	t.Parallel()

	// No model flags: deterministic agent (nil config, no error).
	if cfg, err := buildLLMAgentConfig(&serveFlags{}); err != nil || cfg != nil {
		t.Fatalf("no flags: got cfg=%v err=%v, want nil,nil", cfg, err)
	}

	// Partial: a single model flag set must fail loudly, not silently fall back.
	partials := []struct {
		name string
		in   serveFlags
	}{
		{name: "base_url_only", in: serveFlags{modelBaseURL: "http://provider.example/v1"}},
		{name: "max_steps_only", in: serveFlags{modelMaxSteps: 4}},
		{name: "timeout_only", in: serveFlags{modelTimeout: 20 * time.Second}},
		{name: "tuning_only", in: serveFlags{modelMaxSteps: 4, modelTimeout: 20 * time.Second}},
	}
	for _, tc := range partials {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildLLMAgentConfig(&tc.in); err == nil {
				t.Fatal("partial model flags should error")
			}
		})
	}

	// Full set: builds the config. keyPath is a filesystem path (not a credential);
	// assigning via a variable avoids a gosec G101 false positive on the field name.
	keyPath := filepath.Join(t.TempDir(), "model.key")
	cfg, err := buildLLMAgentConfig(&serveFlags{
		llmAgentBin:     "/usr/local/bin/pipelock-playground-llm-agent",
		modelBaseURL:    "http://provider.example/v1",
		model:           "test-model",
		modelSecretFile: keyPath,
		modelMaxSteps:   4,
		modelTimeout:    20 * time.Second,
	})
	if err != nil {
		t.Fatalf("full flags: %v", err)
	}
	if cfg == nil || cfg.Model != "test-model" || cfg.Bin == "" || cfg.SecretFile == "" {
		t.Fatalf("full flags: unexpected cfg %+v", cfg)
	}

	credentialModelURL := "http://user:" + strings.ToLower("PASS") + "@provider.example/v1"
	queryModelURL := "http://provider.example/v1?api_key=" + strings.ToLower("SECRET")
	fragmentModelURL := "http://provider.example/v1#" + strings.ToLower("SECRET")
	for _, raw := range []string{
		credentialModelURL,
		queryModelURL,
		fragmentModelURL,
	} {
		t.Run("bad_model_url_"+raw, func(t *testing.T) {
			_, err := buildLLMAgentConfig(&serveFlags{
				llmAgentBin:     "/usr/local/bin/pipelock-playground-llm-agent",
				modelBaseURL:    raw,
				model:           "test-model",
				modelSecretFile: keyPath,
			})
			if err == nil {
				t.Fatal("want error for unsafe model base URL")
			}
		})
	}
}

func TestResolveSecret_Generated(t *testing.T) {
	t.Parallel()
	got, err := resolveSecret("", "")
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if len(got) < 32 {
		t.Errorf("generated secret len = %d, want >= 32", len(got))
	}
}

func TestResolveSecret_Base64(t *testing.T) {
	t.Parallel()
	want := []byte("0123456789abcdef0123456789abcdef")
	b64 := base64.StdEncoding.EncodeToString(want)
	got, err := resolveSecret(b64, "")
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("decoded secret mismatch")
	}
}

func TestResolveSecret_BadBase64(t *testing.T) {
	t.Parallel()
	if _, err := resolveSecret("!!!not base64!!!", ""); err == nil {
		t.Error("expected error on bad base64 --secret")
	}
}

func TestResolveSecret_File(t *testing.T) {
	t.Parallel()
	want := []byte("fedcba9876543210fedcba9876543210")
	dir := t.TempDir()
	path := filepath.Join(dir, "secret.b64")
	// Trailing newline must be tolerated (echo/redirect adds one).
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(want)+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	// File takes precedence over an (also-set) inline secret.
	got, err := resolveSecret(base64.StdEncoding.EncodeToString([]byte("ignored-inline-secret-value-32by")), path)
	if err != nil {
		t.Fatalf("resolveSecret: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("file secret mismatch; file should take precedence")
	}
}

func TestResolveSecret_MissingFile(t *testing.T) {
	t.Parallel()
	if _, err := resolveSecret("", filepath.Join(t.TempDir(), "nope.b64")); err == nil {
		t.Error("expected error on missing --secret-file")
	}
}

func TestResolveCodes_Explicit(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	f := &serveFlags{codes: []string{"alpha", "beta"}, maxPerCode: 25}
	specs, err := resolveCodes(&out, f)
	if err != nil {
		t.Fatalf("resolveCodes: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("specs = %d, want 2", len(specs))
	}
	for _, s := range specs {
		if s.MaxSessions != 25 {
			t.Errorf("MaxSessions = %d, want 25 (finite default applied)", s.MaxSessions)
		}
	}
}

func TestResolveCodes_NoCodesNotDev(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	if _, err := resolveCodes(&out, &serveFlags{}); err == nil {
		t.Error("expected error: no codes and not --dev")
	}
}

func TestResolveCodes_BlankCodeRejected(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	if _, err := resolveCodes(&out, &serveFlags{codes: []string{" \t"}, maxPerCode: defaultMaxPerCode}); err == nil {
		t.Error("expected error: blank invite code")
	}
}

func TestResolveCodes_DevGenerates(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	f := &serveFlags{dev: true, maxPerCode: defaultMaxPerCode}
	specs, err := resolveCodes(&out, f)
	if err != nil {
		t.Fatalf("resolveCodes: %v", err)
	}
	if len(specs) != 1 || specs[0].Code == "" {
		t.Fatalf("expected one generated code, got %+v", specs)
	}
	if !strings.Contains(out.String(), specs[0].Code) {
		t.Error("generated dev code should be printed to the operator")
	}
}

func TestContainVerifier_NonRootFailsClosed(t *testing.T) {
	t.Parallel()
	if os.Geteuid() == 0 {
		t.Skip("running as root; non-root refusal path not exercised")
	}
	if err := (containVerifier{}).Verify(context.Background()); err == nil {
		t.Error("non-root containment verify should fail closed")
	}
}

func TestGenSecretCmd(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	cmd := newGenSecretCmd()
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("gen-secret: %v", err)
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(out.String()))
	if err != nil || len(dec) < 32 {
		t.Errorf("gen-secret output not a >=32-byte base64 secret: %q (%v)", out.String(), err)
	}
}

func TestNewRootCmd_HasSubcommands(t *testing.T) {
	t.Parallel()
	root := newRootCmd()
	want := map[string]bool{"serve": false, "gen-secret": false, "gen-code": false}
	for _, c := range root.Commands() {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("root missing subcommand %q", name)
		}
	}
}

func TestNewServeCmd_RegistersFlags(t *testing.T) {
	t.Parallel()
	cmd := newServeCmd()
	for _, name := range []string{"listen", "code", "max-per-code", "dev", "require-containment", "secret", "secret-file", "static-dir", "session-ttl", "daily-turn-budget", "max-messages-per-session"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("serve missing --%s flag", name)
		}
	}
}

func TestRunServe_NoCodesErrorsBeforeListen(t *testing.T) {
	t.Parallel()
	cmd := newServeCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	// No codes and not --dev: runServe must error out before ever binding a port.
	if err := runServe(cmd, &serveFlags{listen: "127.0.0.1:0", sessionTTL: time.Minute}); err == nil {
		t.Error("runServe should error before ListenAndServe when no codes are configured")
	}
}

func devServeFlags() *serveFlags {
	return &serveFlags{
		listen: "127.0.0.1:0", dev: true, maxPerCode: defaultMaxPerCode,
		concurrency: 3, sessionTTL: 90 * time.Second, maxInputBytes: 2048,
		ipRate: 1, ipBurst: 5, codeRate: 1, codeBurst: 10,
	}
}

func TestBuildServer_DevDefault(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	srv, handler, err := buildServer(&out, devServeFlags())
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	if srv == nil || handler == nil {
		t.Fatal("nil server/handler")
	}
	defer srv.Close()
	if !strings.Contains(out.String(), "UNCONTAINED") {
		t.Error("--dev must print the uncontained warning")
	}
}

func TestBuildServer_StaticDirMux(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<!doctype html>hi"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	f := devServeFlags()
	f.staticDir = dir
	var out bytes.Buffer
	srv, handler, err := buildServer(&out, f)
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	if srv == nil || handler == nil {
		t.Fatal("nil server/handler")
	}
	defer srv.Close()

	// The static index is served at /, and the API is still mounted.
	ctx := context.Background()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "hi") {
		t.Errorf("static index not served: code=%d body=%q", rec.Code, rec.Body.String())
	}
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/live/health", nil))
	if rec2.Code != http.StatusOK {
		t.Errorf("api/live/health under static mux: code=%d", rec2.Code)
	}
}

func TestBuildServer_PublicModelRequiresDailyBudget(t *testing.T) {
	t.Parallel()
	f := devServeFlags()
	f.dev = false
	f.requireContainment = true
	f.codes = []string{"good"}
	f.llmAgentBin = "/usr/local/bin/pipelock-playground-llm-agent"
	f.modelBaseURL = "http://provider.example/v1"
	f.model = "test-model"
	f.modelSecretFile = filepath.Join(t.TempDir(), "model.key")

	var out bytes.Buffer
	if _, _, err := buildServer(&out, f); err == nil {
		t.Fatal("model-backed non-dev server without daily budget should fail closed")
	}

	f.dailyTurnBudget = 10
	srv, handler, err := buildServer(&out, f)
	if err != nil {
		t.Fatalf("model-backed non-dev server with daily budget: %v", err)
	}
	if srv == nil || handler == nil {
		t.Fatal("nil server/handler")
	}
	defer srv.Close()
}

func TestBuildServer_NonDevRequiresContainment(t *testing.T) {
	t.Parallel()
	f := devServeFlags()
	f.dev = false
	f.requireContainment = false
	f.codes = []string{"good"}
	var out bytes.Buffer
	if _, _, err := buildServer(&out, f); err == nil {
		t.Fatal("non-dev uncontained server should fail closed")
	}
}

func TestValidateServeSafety_RejectsNegativeCaps(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		f    serveFlags
	}{
		{name: "max_per_code", f: serveFlags{maxPerCode: -1}},
		{name: "daily_budget", f: serveFlags{dailyTurnBudget: -1}},
		{name: "session_messages", f: serveFlags{maxMessagesPerSession: -1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateServeSafety(&tc.f, false); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestValidateServeSafety_AllowOrigin(t *testing.T) {
	t.Parallel()
	if err := validateServeSafety(&serveFlags{allowOrigin: "https://pipelab.org", dev: true}, false); err != nil {
		t.Fatalf("exact origin rejected: %v", err)
	}
	if err := validateServeSafety(&serveFlags{allowOrigin: "*", dev: true}, false); err != nil {
		t.Fatalf("dev wildcard rejected: %v", err)
	}
	for _, tc := range []struct {
		name string
		f    serveFlags
	}{
		{name: "wildcard_nondev", f: serveFlags{allowOrigin: "*", requireContainment: true}},
		{name: "path", f: serveFlags{allowOrigin: "https://pipelab.org/app", dev: true}},
		{name: "query", f: serveFlags{allowOrigin: "https://pipelab.org?x=1", dev: true}},
		{name: "fragment", f: serveFlags{allowOrigin: "https://pipelab.org#x", dev: true}},
		{name: "whitespace", f: serveFlags{allowOrigin: " https://pipelab.org", dev: true}},
		{name: "non_http", f: serveFlags{allowOrigin: "file:///tmp/viewer", dev: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateServeSafety(&tc.f, false); err == nil {
				t.Fatal("expected unsafe allow-origin to be rejected")
			}
		})
	}
}

func TestBuildServer_NoCodesNotDevErrors(t *testing.T) {
	t.Parallel()
	f := devServeFlags()
	f.dev = false // not dev + no codes -> error
	var out bytes.Buffer
	if _, _, err := buildServer(&out, f); err == nil {
		t.Error("expected error: no codes and not --dev")
	}
}

func TestGenCodeCmd(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	cmd := newGenCodeCmd()
	cmd.SetOut(&out)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("gen-code: %v", err)
	}
	if len(strings.TrimSpace(out.String())) < 16 {
		t.Errorf("gen-code output too short: %q", out.String())
	}
}
