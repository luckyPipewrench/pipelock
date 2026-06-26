// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/luckyPipewrench/pipelock/internal/playground/broker"
	"github.com/luckyPipewrench/pipelock/internal/playground/livechat"
)

type fakeProvider struct{}

func (fakeProvider) CreateMachine(_ context.Context, _ broker.MachineSpec) (*broker.Machine, error) {
	return nil, errors.New("not used")
}

func (fakeProvider) WaitReady(_ context.Context, _ string) error {
	return nil
}

func (fakeProvider) DestroyMachine(_ context.Context, _ string) error {
	return nil
}

func (fakeProvider) ListManagedMachines(_ context.Context) ([]broker.Machine, error) {
	return nil, nil
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func TestRootCommandHasServe(t *testing.T) {
	root := newRootCmd()
	if root.Use != "pipelock-playground-broker" {
		t.Fatalf("root Use = %q", root.Use)
	}
	for _, cmd := range root.Commands() {
		if cmd.Name() == "serve" {
			return
		}
	}
	t.Fatal("serve subcommand missing")
}

func TestBuildServerWithInjectedProvider(t *testing.T) {
	dir := t.TempDir()
	flyTokenFile := writeTestFile(t, dir, "fly.token", "fly-file-token\n")
	gateSecret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	gateSecretFile := writeTestFile(t, dir, "gate.b64", gateSecret+"\n")
	modelFile := writeTestFile(t, dir, "model.key", "model-file-value\n")
	orchestratorFile := writeTestFile(t, dir, "orchestrator.key", "orchestrator-file-value\n")

	var gotProvider string
	var gotToken string
	oldFactory := newMachineProvider
	newMachineProvider = func(_ context.Context, f *serveFlags, token string) (broker.MachineProvider, error) {
		gotProvider = f.provider
		gotToken = token
		return fakeProvider{}, nil
	}
	t.Cleanup(func() { newMachineProvider = oldFactory })

	var out bytes.Buffer
	srv, handler, _, _, err := buildServer(context.Background(), &out, &serveFlags{
		listen:                defaultListen,
		provider:              "fake",
		flyApp:                "playground-test",
		flyTokenFile:          flyTokenFile,
		image:                 "registry.example/playground:test",
		internalPort:          8080,
		concurrency:           2,
		codes:                 []string{"outer-code"},
		maxPerCode:            defaultMaxPerCode,
		gateSecretFile:        gateSecretFile,
		ipRate:                defaultIPRate,
		ipBurst:               defaultIPBurst,
		codeRate:              defaultCodeRate,
		codeBurst:             defaultCodeBurst,
		globalDailyBudget:     10,
		unsafeNoHumanGate:     true,
		sessionTTL:            defaultSessionTTL,
		deadlineGrace:         defaultGrace,
		vmDailyTurnBudget:     10,
		modelKeyFile:          modelFile,
		orchestratorKeyFile:   orchestratorFile,
		requireSessionSecrets: true,
	})
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	t.Cleanup(srv.Close)
	if handler == nil {
		t.Fatal("handler is nil")
	}
	if gotProvider != "fake" || gotToken != "fly-file-token" {
		t.Fatalf("provider args = %q %q", gotProvider, gotToken)
	}
	if strings.Contains(out.String(), gotToken) || strings.Contains(out.String(), "model-file-value") {
		t.Fatalf("operator output leaked secret material: %q", out.String())
	}
}

func TestBuildServerStaticDir(t *testing.T) {
	dir := t.TempDir()
	uiDir := filepath.Join(dir, "ui")
	if err := os.MkdirAll(uiDir, 0o750); err != nil {
		t.Fatalf("mkdir ui: %v", err)
	}
	writeTestFile(t, uiDir, "index.html", "<html><body>live demo ui</body></html>")
	flyTokenFile := writeTestFile(t, dir, "fly.token", "fly-file-token\n")
	gateSecret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	gateSecretFile := writeTestFile(t, dir, "gate.b64", gateSecret+"\n")

	oldFactory := newMachineProvider
	newMachineProvider = func(_ context.Context, _ *serveFlags, _ string) (broker.MachineProvider, error) {
		return fakeProvider{}, nil
	}
	t.Cleanup(func() { newMachineProvider = oldFactory })

	flags := func(staticDir string) *serveFlags {
		return &serveFlags{
			listen: defaultListen, provider: "fake", flyApp: "playground-test",
			flyTokenFile: flyTokenFile, image: "registry.example/playground:test",
			staticDir: staticDir, internalPort: 8080, concurrency: 2,
			codes: []string{"outer-code"}, maxPerCode: defaultMaxPerCode,
			gateSecretFile: gateSecretFile, ipRate: defaultIPRate, ipBurst: defaultIPBurst,
			codeRate: defaultCodeRate, codeBurst: defaultCodeBurst,
			globalDailyBudget: 10,
			unsafeNoHumanGate: true,
			sessionTTL:        defaultSessionTTL, deadlineGrace: defaultGrace,
			vmDailyTurnBudget:     10,
			requireSessionSecrets: false,
		}
	}

	// With --static-dir: / serves the UI AND the API still routes on the same origin.
	srv, handler, _, _, err := buildServer(context.Background(), &bytes.Buffer{}, flags(uiDir))
	if err != nil {
		t.Fatalf("buildServer(static): %v", err)
	}
	t.Cleanup(srv.Close)
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	if body, status := httpGetStatus(t, ts.URL+"/"); status != http.StatusOK || !strings.Contains(body, "live demo ui") {
		t.Fatalf("GET / = %d %q, want 200 serving the UI", status, body)
	}
	if _, status := httpGetStatus(t, ts.URL+livechat.RouteHealth); status != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200 (API served alongside static)", livechat.RouteHealth, status)
	}

	// Without --static-dir: / is 404 (broker is API-only).
	srv2, handler2, _, _, err := buildServer(context.Background(), &bytes.Buffer{}, flags(""))
	if err != nil {
		t.Fatalf("buildServer(no static): %v", err)
	}
	t.Cleanup(srv2.Close)
	ts2 := httptest.NewServer(handler2)
	t.Cleanup(ts2.Close)
	if _, status := httpGetStatus(t, ts2.URL+"/"); status != http.StatusNotFound {
		t.Fatalf("GET / without --static-dir = %d, want 404", status)
	}
}

func TestBuildServerHostGuardFromAllowOrigin(t *testing.T) {
	dir := t.TempDir()
	uiDir := filepath.Join(dir, "ui")
	if err := os.MkdirAll(uiDir, 0o750); err != nil {
		t.Fatalf("mkdir ui: %v", err)
	}
	writeTestFile(t, uiDir, "index.html", "<html><body>live demo ui</body></html>")
	flyTokenFile := writeTestFile(t, dir, "fly.token", "fly-file-token\n")
	gateSecret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	gateSecretFile := writeTestFile(t, dir, "gate.b64", gateSecret+"\n")

	oldFactory := newMachineProvider
	newMachineProvider = func(_ context.Context, _ *serveFlags, _ string) (broker.MachineProvider, error) {
		return fakeProvider{}, nil
	}
	t.Cleanup(func() { newMachineProvider = oldFactory })

	srv, handler, _, _, err := buildServer(context.Background(), &bytes.Buffer{}, &serveFlags{
		listen: defaultListen, provider: "fake", flyApp: "playground-test",
		flyTokenFile: flyTokenFile, image: "registry.example/playground:test",
		staticDir: uiDir, internalPort: 8080, concurrency: 2,
		codes: []string{"outer-code"}, maxPerCode: defaultMaxPerCode,
		gateSecretFile: gateSecretFile, ipRate: defaultIPRate, ipBurst: defaultIPBurst,
		codeRate: defaultCodeRate, codeBurst: defaultCodeBurst,
		globalDailyBudget: 10,
		unsafeNoHumanGate: true,
		sessionTTL:        defaultSessionTTL, deadlineGrace: defaultGrace,
		vmDailyTurnBudget:     10,
		allowOrigin:           "https://playground.pipelab.org",
		requireSessionSecrets: false,
	})
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	t.Cleanup(srv.Close)

	rr := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://pipelab-playground.fly.dev/", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("direct Fly host status = %d, want 404", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://playground.pipelab.org/", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "live demo ui") {
		t.Fatalf("public host status/body = %d %q, want UI", rr.Code, rr.Body.String())
	}
}

func TestBuildServerCFAccessGuard(t *testing.T) {
	dir := t.TempDir()
	uiDir := filepath.Join(dir, "ui")
	if err := os.MkdirAll(uiDir, 0o750); err != nil {
		t.Fatalf("mkdir ui: %v", err)
	}
	writeTestFile(t, uiDir, "index.html", "<html><body>live demo ui</body></html>")
	flyTokenFile := writeTestFile(t, dir, "fly.token", "fly-file-token\n")
	gateSecret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	gateSecretFile := writeTestFile(t, dir, "gate.b64", gateSecret+"\n")

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	const kid = "cf-access-test-key"
	issuer := "https://team.cloudflareaccess.com"
	aud := "playground-aud"
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &priv.PublicKey,
		KeyID:     kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}
	keyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			t.Fatalf("encode jwks: %v", err)
		}
	}))
	t.Cleanup(keyServer.Close)

	oldFactory := newMachineProvider
	newMachineProvider = func(_ context.Context, _ *serveFlags, _ string) (broker.MachineProvider, error) {
		return fakeProvider{}, nil
	}
	t.Cleanup(func() { newMachineProvider = oldFactory })

	srv, handler, _, _, err := buildServer(context.Background(), &bytes.Buffer{}, &serveFlags{
		listen: defaultListen, provider: "fake", flyApp: "playground-test",
		flyTokenFile: flyTokenFile, image: "registry.example/playground:test",
		staticDir: uiDir, internalPort: 8080, concurrency: 2,
		codes: []string{"outer-code"}, maxPerCode: defaultMaxPerCode,
		gateSecretFile: gateSecretFile, ipRate: defaultIPRate, ipBurst: defaultIPBurst,
		codeRate: defaultCodeRate, codeBurst: defaultCodeBurst,
		globalDailyBudget: 10,
		sessionTTL:        defaultSessionTTL, deadlineGrace: defaultGrace,
		vmDailyTurnBudget:     10,
		allowOrigin:           "https://playground.pipelab.org",
		cfAccessTeamDomain:    issuer,
		cfAccessAUD:           aud,
		cfAccessCertsURL:      keyServer.URL,
		requireSessionSecrets: false,
	})
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	t.Cleanup(srv.Close)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://playground.pipelab.org/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("missing Access JWT status = %d, want 403", rr.Code)
	}

	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://playground.pipelab.org/", nil)
	req.Header.Set(cfAccessJWTHeader, "not-a-jwt")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("bad Access JWT status = %d, want 403", rr.Code)
	}

	token := signedCFAccessTestJWT(t, priv, kid, issuer, aud, time.Now())
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://playground.pipelab.org/", nil)
	req.Header.Set(cfAccessJWTHeader, token)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "live demo ui") {
		t.Fatalf("valid Access JWT status/body = %d %q, want UI", rr.Code, rr.Body.String())
	}
}

func TestBuildServerTurnstileRejectsMissingToken(t *testing.T) {
	dir := t.TempDir()
	flyTokenFile := writeTestFile(t, dir, "fly.token", "fly-file-token\n")
	gateSecret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	gateSecretFile := writeTestFile(t, dir, "gate.b64", gateSecret+"\n")
	turnstileSecretFile := writeTestFile(t, dir, "turnstile.secret", "turnstile-secret\n")
	verifyServer := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("missing-token rejection should not call Turnstile Siteverify")
	}))
	t.Cleanup(verifyServer.Close)

	oldFactory := newMachineProvider
	newMachineProvider = func(_ context.Context, _ *serveFlags, _ string) (broker.MachineProvider, error) {
		return fakeProvider{}, nil
	}
	t.Cleanup(func() { newMachineProvider = oldFactory })

	srv, handler, _, _, err := buildServer(context.Background(), &bytes.Buffer{}, &serveFlags{
		listen:                defaultListen,
		provider:              "fake",
		flyApp:                "playground-test",
		flyTokenFile:          flyTokenFile,
		image:                 "registry.example/playground:test",
		internalPort:          8080,
		concurrency:           2,
		codes:                 []string{"outer-code"},
		maxPerCode:            defaultMaxPerCode,
		gateSecretFile:        gateSecretFile,
		ipRate:                defaultIPRate,
		ipBurst:               defaultIPBurst,
		codeRate:              defaultCodeRate,
		codeBurst:             defaultCodeBurst,
		globalDailyBudget:     10,
		turnstileSecretFile:   turnstileSecretFile,
		turnstileVerifyURL:    verifyServer.URL,
		sessionTTL:            defaultSessionTTL,
		deadlineGrace:         defaultGrace,
		vmDailyTurnBudget:     10,
		requireSessionSecrets: false,
	})
	if err != nil {
		t.Fatalf("buildServer: %v", err)
	}
	t.Cleanup(srv.Close)

	rr := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, livechat.RouteSession, strings.NewReader(`{"code":"outer-code"}`))
	req.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("missing Turnstile token status = %d, want 403", rr.Code)
	}
}

func signedCFAccessTestJWT(t *testing.T, priv *rsa.PrivateKey, kid, issuer, aud string, now time.Time) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	raw, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:    issuer,
		Subject:   "dylan@example.com",
		Audience:  jwt.Audience{aud},
		IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
		NotBefore: jwt.NewNumericDate(now.Add(-time.Minute)),
		Expiry:    jwt.NewNumericDate(now.Add(time.Minute)),
	}).Serialize()
	if err != nil {
		t.Fatalf("sign access jwt: %v", err)
	}
	return raw
}

func TestNormalizePublicHost(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "Playground.Pipelab.Org.", want: "playground.pipelab.org"},
		{in: "playground.pipelab.org:443", want: "playground.pipelab.org"},
		{in: "[2001:db8::1]:443", want: "2001:db8::1"},
		{in: "https://playground.pipelab.org", wantErr: true},
		{in: "bad/host", wantErr: true},
		{in: "bad host", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := normalizePublicHost(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatal("normalizePublicHost succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizePublicHost: %v", err)
			}
			if got != tt.want {
				t.Fatalf("normalizePublicHost = %q, want %q", got, tt.want)
			}
		})
	}
}

func httpGetStatus(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b), resp.StatusCode
}

func TestBuildServerValidation(t *testing.T) {
	dir := t.TempDir()
	tokenFile := writeTestFile(t, dir, "fly.token", "fly-file-token")
	base := serveFlags{
		listen:                defaultListen,
		provider:              "fly",
		flyApp:                "playground-test",
		flyTokenFile:          tokenFile,
		image:                 "registry.example/playground:test",
		internalPort:          8080,
		concurrency:           1,
		codes:                 []string{"outer-code"},
		maxPerCode:            defaultMaxPerCode,
		ipRate:                defaultIPRate,
		ipBurst:               defaultIPBurst,
		codeRate:              defaultCodeRate,
		codeBurst:             defaultCodeBurst,
		globalDailyBudget:     10,
		unsafeNoHumanGate:     true,
		sessionTTL:            defaultSessionTTL,
		deadlineGrace:         defaultGrace,
		vmDailyTurnBudget:     10,
		requireSessionSecrets: false,
	}
	tests := []struct {
		name   string
		mutate func(*serveFlags)
	}{
		{name: "missing_image", mutate: func(f *serveFlags) { f.image = "" }},
		{name: "missing_code", mutate: func(f *serveFlags) { f.codes = nil }},
		{name: "bad_origin", mutate: func(f *serveFlags) { f.allowOrigin = "*" }},
		{name: "bad_port", mutate: func(f *serveFlags) { f.internalPort = 0 }},
		{name: "negative_budget", mutate: func(f *serveFlags) { f.globalDailyBudget = -1 }},
		{name: "missing_global_budget", mutate: func(f *serveFlags) { f.globalDailyBudget = 0 }},
		{name: "missing_vm_budget", mutate: func(f *serveFlags) { f.vmDailyTurnBudget = 0 }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := base
			f.codes = append([]string(nil), base.codes...)
			tc.mutate(&f)
			if err := validateFlags(&f); err == nil {
				t.Fatal("validateFlags succeeded, want error")
			}
		})
	}
}

func TestValidateDefaultCode(t *testing.T) {
	t.Parallel()
	const pub = "pub-code"
	mk := func(mut func(*serveFlags)) *serveFlags {
		f := &serveFlags{codes: []string{pub, "other"}}
		mut(f)
		return f
	}
	cases := []struct {
		name    string
		f       *serveFlags
		wantErr bool
	}{
		{"empty_is_noop", mk(func(f *serveFlags) {}), false},
		{"turnstile_gate_ok", mk(func(f *serveFlags) { f.defaultCode = pub; f.turnstileSecretEnv = "TS_SECRET" }), false},
		{"cfaccess_gate_ok", mk(func(f *serveFlags) {
			f.defaultCode = pub
			f.cfAccessTeamDomain = "https://x.cloudflareaccess.com"
			f.cfAccessAUD = "aud-tag"
		}), false},
		// The security guardrail: a default code with NO human gate would let
		// anyone create sessions code-free. Must fail closed.
		{"no_gate_rejected", mk(func(f *serveFlags) { f.defaultCode = pub }), true},
		{"unsafe_no_human_gate_rejected", mk(func(f *serveFlags) { f.defaultCode = pub; f.unsafeNoHumanGate = true }), true},
		{"unknown_code_rejected", mk(func(f *serveFlags) { f.defaultCode = "ghost"; f.turnstileSecretEnv = "TS_SECRET" }), true},
		{"conflicting_flags_rejected", mk(func(f *serveFlags) {
			f.defaultCode = pub
			f.cfAccessDefaultCode = "other"
			f.turnstileSecretEnv = "TS_SECRET"
		}), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateDefaultCode(tc.f)
			if tc.wantErr && err == nil {
				t.Fatal("validateDefaultCode succeeded, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateDefaultCode failed: %v", err)
			}
		})
	}
}

func TestEffectiveDefaultCode(t *testing.T) {
	t.Parallel()
	if got := effectiveDefaultCode(&serveFlags{defaultCode: "general"}); got != "general" {
		t.Fatalf("general wins: got %q", got)
	}
	if got := effectiveDefaultCode(&serveFlags{cfAccessDefaultCode: "cf"}); got != "cf" {
		t.Fatalf("cf fallback: got %q", got)
	}
	if got := effectiveDefaultCode(&serveFlags{}); got != "" {
		t.Fatalf("empty: got %q", got)
	}
}

func TestRunServeListenErrorAfterBuild(t *testing.T) {
	dir := t.TempDir()
	flyTokenFile := writeTestFile(t, dir, "fly.token", "fly-file-token\n")
	gateSecret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	gateSecretFile := writeTestFile(t, dir, "gate.b64", gateSecret+"\n")

	oldFactory := newMachineProvider
	newMachineProvider = func(_ context.Context, _ *serveFlags, _ string) (broker.MachineProvider, error) {
		return fakeProvider{}, nil
	}
	t.Cleanup(func() { newMachineProvider = oldFactory })

	cmd := newServeCmd()
	var out lockedBuffer
	cmd.SetOut(&out)
	err := runServe(cmd, &serveFlags{
		listen:                "127.0.0.1:bad-port",
		provider:              "fake",
		flyApp:                "playground-test",
		flyTokenFile:          flyTokenFile,
		image:                 "registry.example/playground:test",
		internalPort:          8080,
		concurrency:           1,
		codes:                 []string{"outer-code"},
		maxPerCode:            defaultMaxPerCode,
		gateSecretFile:        gateSecretFile,
		ipRate:                defaultIPRate,
		ipBurst:               defaultIPBurst,
		codeRate:              defaultCodeRate,
		codeBurst:             defaultCodeBurst,
		globalDailyBudget:     10,
		unsafeNoHumanGate:     true,
		sessionTTL:            defaultSessionTTL,
		deadlineGrace:         defaultGrace,
		vmDailyTurnBudget:     10,
		requireSessionSecrets: false,
	})
	if err == nil || !strings.Contains(err.Error(), "listen 127.0.0.1:bad-port") {
		t.Fatalf("runServe error = %v, want listen failure", err)
	}
	if !strings.Contains(out.String(), "broker configured") {
		t.Fatalf("runServe should build before listen error, output = %q", out.String())
	}
}

func TestRunServeContextCancelledShutsDown(t *testing.T) {
	dir := t.TempDir()
	flyTokenFile := writeTestFile(t, dir, "fly.token", "fly-file-token\n")
	gateSecret := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	gateSecretFile := writeTestFile(t, dir, "gate.b64", gateSecret+"\n")

	oldFactory := newMachineProvider
	newMachineProvider = func(_ context.Context, _ *serveFlags, _ string) (broker.MachineProvider, error) {
		return fakeProvider{}, nil
	}
	t.Cleanup(func() { newMachineProvider = oldFactory })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := newServeCmd()
	cmd.SetContext(ctx)
	var out lockedBuffer
	cmd.SetOut(&out)
	err := runServe(cmd, &serveFlags{
		listen:                "127.0.0.1:0",
		provider:              "fake",
		flyApp:                "playground-test",
		flyTokenFile:          flyTokenFile,
		image:                 "registry.example/playground:test",
		internalPort:          8080,
		concurrency:           1,
		codes:                 []string{"outer-code"},
		maxPerCode:            defaultMaxPerCode,
		gateSecretFile:        gateSecretFile,
		ipRate:                defaultIPRate,
		ipBurst:               defaultIPBurst,
		codeRate:              defaultCodeRate,
		codeBurst:             defaultCodeBurst,
		globalDailyBudget:     10,
		unsafeNoHumanGate:     true,
		sessionTTL:            defaultSessionTTL,
		deadlineGrace:         defaultGrace,
		vmDailyTurnBudget:     10,
		requireSessionSecrets: false,
	})
	if err != nil {
		t.Fatalf("runServe with canceled context: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "broker shutting down: context canceled") {
		t.Fatalf("runServe output = %q, want context-canceled shutdown", got)
	}
}

func TestStartSignalControlLoopContextCancelled(t *testing.T) {
	srv := newBrokerControlTestServer(t)
	httpSrv := &http.Server{
		Handler:           http.NewServeMux(),
		ReadHeaderTimeout: time.Second,
	}
	shutdownDone := make(chan struct{})
	httpSrv.RegisterOnShutdown(func() { close(shutdownDone) })
	ctx, cancel := context.WithCancel(context.Background())
	var out lockedBuffer
	stop := startSignalControlLoop(ctx, &out, srv, httpSrv)
	cancel()
	select {
	case <-shutdownDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for signal loop shutdown")
	}
	stop()

	if got := out.String(); !strings.Contains(got, "broker shutting down: context canceled") {
		t.Fatalf("signal loop output = %q, want context-canceled shutdown", got)
	}
}

func TestApplyControlSignalShutdown(t *testing.T) {
	srv := newBrokerControlTestServer(t)

	var out bytes.Buffer
	if shutdown := applyControlSignal(&out, srv, os.Interrupt); !shutdown {
		t.Fatal("interrupt did not request graceful shutdown")
	}
}

func newBrokerControlTestServer(t *testing.T) *broker.Server {
	t.Helper()
	gate, err := livechat.NewGate(livechat.GateConfig{
		Secret: []byte("0123456789abcdef0123456789abcdef"),
		Codes:  []livechat.CodeSpec{{Code: "outer-code"}},
	})
	if err != nil {
		t.Fatalf("new gate: %v", err)
	}
	lm, err := broker.NewLeaseManager(broker.LeaseConfig{
		Provider:    fakeProvider{},
		Concurrency: livechat.NewConcurrencyLimiter(1),
		Image:       "registry.example/playground:test",
	})
	if err != nil {
		t.Fatalf("new lease manager: %v", err)
	}
	srv, err := broker.NewServer(broker.ServerConfig{
		Leases:            lm,
		Gate:              gate,
		GlobalDailyBudget: 1,
	})
	if err != nil {
		t.Fatalf("new broker server: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv
}

func TestAdminHandlerAuthAndPauseResume(t *testing.T) {
	srv := newBrokerControlTestServer(t)
	handler := adminHandler(srv, "operator-value")

	rr := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/admin/pause", nil)
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth status = %d, want 401", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/admin/pause", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("bad auth status = %d, want 403", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin/pause", nil)
	req.Header.Set("Authorization", "Bearer operator-value")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET pause status = %d, want 405", rr.Code)
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/admin/pause", nil)
	req.Header.Set("Authorization", "Bearer operator-value")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !srv.Killed() {
		t.Fatalf("pause status/killed = %d/%v, want 200/true", rr.Code, srv.Killed())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/admin/resume", nil)
	req.Header.Set("Authorization", "Bearer operator-value")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || srv.Killed() {
		t.Fatalf("resume status/killed = %d/%v, want 200/false", rr.Code, srv.Killed())
	}

	rr = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/admin/health", nil)
	req.Header.Set("Authorization", "Bearer operator-value")
	handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"killed":false`) {
		t.Fatalf("health status/body = %d/%q, want killed false", rr.Code, rr.Body.String())
	}
}

func TestStartAdminServerValidationBranches(t *testing.T) {
	srv := newBrokerControlTestServer(t)
	if stop, err := startAdminServer(context.Background(), io.Discard, &serveFlags{}, srv); err != nil {
		t.Fatalf("startAdminServer disabled: %v", err)
	} else {
		stop()
	}
	if _, err := startAdminServer(context.Background(), io.Discard, &serveFlags{
		adminListen:   "127.0.0.1:0",
		adminTokenEnv: "BROKER_TEST_EMPTY_" + "ADMIN",
	}, srv); err == nil {
		t.Fatal("startAdminServer with empty token env succeeded, want error")
	}
}

func TestResolveGateSecret(t *testing.T) {
	dir := t.TempDir()
	want := []byte("fedcba9876543210fedcba9876543210")
	path := writeTestFile(t, dir, "gate.b64", base64.StdEncoding.EncodeToString(want)+"\n")
	got, err := resolveGateSecret(path, "")
	if err != nil {
		t.Fatalf("resolveGateSecret file: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("file gate secret mismatch")
	}

	t.Setenv("BROKER_TEST_GATE", base64.StdEncoding.EncodeToString(want))
	got, err = resolveGateSecret("", "BROKER_TEST_GATE")
	if err != nil {
		t.Fatalf("resolveGateSecret env: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("env gate secret mismatch")
	}
	if _, err := resolveGateSecret(writeTestFile(t, dir, "bad.b64", "not base64"), ""); err == nil {
		t.Fatal("bad base64 should error")
	}
}

func TestResolveTurnstileVerifier(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "turnstile.secret", "file-secret\n")
	got, err := resolveTurnstileVerifier(&serveFlags{turnstileSecretFile: path})
	if err != nil {
		t.Fatalf("resolveTurnstileVerifier file: %v", err)
	}
	fileGuard, ok := got.(*broker.ReplayGuardVerifier)
	if !ok {
		t.Fatalf("verifier type = %T, want *broker.ReplayGuardVerifier", got)
	}
	fileInner, ok := fileGuard.Inner.(broker.TurnstileVerifier)
	if !ok {
		t.Fatalf("inner type = %T, want broker.TurnstileVerifier", fileGuard.Inner)
	}
	if fileInner.Secret != "file-secret" {
		t.Fatal("file turnstile secret mismatch")
	}

	t.Setenv("BROKER_TEST_TURNSTILE", "env-secret")
	got, err = resolveTurnstileVerifier(&serveFlags{turnstileSecretEnv: "BROKER_TEST_TURNSTILE"})
	if err != nil {
		t.Fatalf("resolveTurnstileVerifier env: %v", err)
	}
	envGuard, ok := got.(*broker.ReplayGuardVerifier)
	if !ok {
		t.Fatalf("verifier type = %T, want *broker.ReplayGuardVerifier", got)
	}
	envInner, ok := envGuard.Inner.(broker.TurnstileVerifier)
	if !ok {
		t.Fatalf("inner type = %T, want broker.TurnstileVerifier", envGuard.Inner)
	}
	if envInner.Secret != "env-secret" {
		t.Fatal("env turnstile secret mismatch")
	}
	if got, err := resolveTurnstileVerifier(&serveFlags{}); err != nil || got != nil {
		t.Fatalf("resolveTurnstileVerifier empty = %T %v, want nil nil", got, err)
	}
	// Split literal: this is an (unset) env var NAME, not a credential; the split
	// keeps gosec G101 from flagging a string literal assigned to a *Env field.
	if _, err := resolveTurnstileVerifier(&serveFlags{turnstileSecretEnv: "BROKER_TEST_" + "EMPTY_VALUE"}); err == nil {
		t.Fatal("empty turnstile env should error")
	}
}

func TestResolveAdminToken(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "admin.token", "file-token\n")
	got, err := resolveAdminToken(&serveFlags{adminTokenFile: path})
	if err != nil {
		t.Fatalf("resolveAdminToken file: %v", err)
	}
	if got != "file-token" {
		t.Fatal("file admin token mismatch")
	}

	t.Setenv("BROKER_TEST_ADMIN_VALUE", "env-token")
	got, err = resolveAdminToken(&serveFlags{adminTokenEnv: "BROKER_TEST_ADMIN_VALUE"})
	if err != nil {
		t.Fatalf("resolveAdminToken env: %v", err)
	}
	if got != "env-token" {
		t.Fatal("env admin token mismatch")
	}
	// Split literal (see above): unset env var NAME, not a credential.
	if _, err := resolveAdminToken(&serveFlags{adminTokenEnv: "BROKER_TEST_" + "EMPTY_VALUE"}); err == nil {
		t.Fatal("empty admin token env should error")
	}
}

func TestDefaultMachineProvider(t *testing.T) {
	provider, err := defaultMachineProvider(context.Background(), &serveFlags{
		provider: "fly",
		flyApp:   "playground-test",
	}, "fly-token")
	if err != nil {
		t.Fatalf("defaultMachineProvider fly: %v", err)
	}
	fly, ok := provider.(*broker.FlyMachines)
	if !ok {
		t.Fatalf("provider type = %T, want *broker.FlyMachines", provider)
	}
	if fly.AppName != "playground-test" || fly.Token != "fly-token" {
		t.Fatalf("fly config = %+v", fly)
	}
	if _, err := defaultMachineProvider(context.Background(), &serveFlags{provider: "fake"}, "token"); err == nil {
		t.Fatal("unsupported provider should error")
	}
}

func TestValidateFlagsBranches(t *testing.T) {
	base := serveFlags{
		provider:          "fly",
		flyApp:            "playground-test",
		flyTokenEnv:       "BROKER_TEST_FLY_TOKEN",
		image:             "registry.example/playground:test",
		internalPort:      8080,
		concurrency:       1,
		codes:             []string{"outer-code"},
		maxPerCode:        defaultMaxPerCode,
		ipRate:            defaultIPRate,
		ipBurst:           defaultIPBurst,
		codeRate:          defaultCodeRate,
		codeBurst:         defaultCodeBurst,
		globalDailyBudget: 10,
		unsafeNoHumanGate: true,
		sessionTTL:        defaultSessionTTL,
		deadlineGrace:     defaultGrace,
		vmDailyTurnBudget: 10,
	}
	if err := validateFlags(&base); err != nil {
		t.Fatalf("base validateFlags: %v", err)
	}
	if err := validateFlags(nil); err == nil {
		t.Fatal("nil flags should error")
	}
	noHumanGate := base
	noHumanGate.unsafeNoHumanGate = false
	if err := validateFlags(&noHumanGate); err == nil {
		t.Fatal("broker without Turnstile, Cloudflare Access, or --unsafe-no-human-gate should fail")
	}
	turnstileGate := noHumanGate
	turnstileGate.turnstileSecretEnv = "BROKER_TEST_TURNSTILE"
	turnstileGate.turnstileExpectedHostname = "playground.example"
	turnstileGate.turnstileExpectedAction = "playground-session"
	if err := validateFlags(&turnstileGate); err != nil {
		t.Fatalf("turnstile gate should validate: %v", err)
	}
	cfAccessGate := noHumanGate
	cfAccessGate.cfAccessTeamDomain = "team.cloudflareaccess.com"
	cfAccessGate.cfAccessAUD = "aud"
	if err := validateFlags(&cfAccessGate); err != nil {
		t.Fatalf("Cloudflare Access gate should validate: %v", err)
	}
	unsafeUnlimited := base
	unsafeUnlimited.globalDailyBudget = 0
	unsafeUnlimited.vmDailyTurnBudget = 0
	unsafeUnlimited.unsafeUnlimited = true
	if err := validateFlags(&unsafeUnlimited); err != nil {
		t.Fatalf("unsafe unlimited budgets should validate: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*serveFlags)
	}{
		{name: "missing_fly_app", mutate: func(f *serveFlags) { f.flyApp = "" }},
		{name: "missing_token_source", mutate: func(f *serveFlags) { f.flyTokenEnv = "" }},
		{name: "admin_token_without_listen", mutate: func(f *serveFlags) { f.adminTokenEnv = "BROKER_ADMIN_VALUE" }},
		{name: "admin_listen_without_token", mutate: func(f *serveFlags) { f.adminListen = "127.0.0.1:0" }},
		{name: "bad_concurrency", mutate: func(f *serveFlags) { f.concurrency = 0 }},
		{name: "bad_max_per_code", mutate: func(f *serveFlags) { f.maxPerCode = -1 }},
		{name: "bad_memory", mutate: func(f *serveFlags) { f.memoryMB = -1 }},
		{name: "bad_cpus", mutate: func(f *serveFlags) { f.cpus = -1 }},
		{name: "bad_deadline_grace", mutate: func(f *serveFlags) { f.deadlineGrace = -1 }},
		{name: "turnstile_url_without_secret", mutate: func(f *serveFlags) { f.turnstileVerifyURL = "https://turnstile.example/verify" }},
		{name: "bad_turnstile_verify_url", mutate: func(f *serveFlags) {
			f.turnstileSecretEnv = "BROKER_TEST_TURNSTILE"
			f.turnstileVerifyURL = "file:///tmp/siteverify"
		}},
		{name: "bad_turnstile_max_age", mutate: func(f *serveFlags) {
			f.turnstileSecretEnv = "BROKER_TEST_TURNSTILE"
			f.turnstileVerifyURL = "https://turnstile.example/verify"
			f.turnstileMaxAge = -1
		}},
		{name: "turnstile_production_missing_hostname_action", mutate: func(f *serveFlags) {
			// Turnstile against Cloudflare (no --turnstile-verify-url) must bind
			// hostname + action; omitting them is rejected.
			f.turnstileSecretEnv = "BROKER_TEST_TURNSTILE"
		}},
		{name: "turnstile_explicit_cloudflare_url_missing_bindings", mutate: func(f *serveFlags) {
			// Explicitly pointing at the real Cloudflare Siteverify URL must NOT
			// escape the hostname/action binding requirement.
			f.turnstileSecretEnv = "BROKER_TEST_TURNSTILE"
			f.turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
		}},
		{name: "turnstile_explicit_cloudflare_url_with_port_missing_bindings", mutate: func(f *serveFlags) {
			// A port on the real Cloudflare host is still the production
			// Siteverify endpoint, so hostname/action binding remains required.
			f.turnstileSecretEnv = "BROKER_TEST_TURNSTILE"
			f.turnstileVerifyURL = "https://challenges.cloudflare.com:443/turnstile/v0/siteverify"
		}},
		{name: "turnstile_explicit_cloudflare_url_trailing_dot_missing_bindings", mutate: func(f *serveFlags) {
			// A DNS-root trailing dot is still the real Cloudflare host, so it
			// must not bypass hostname/action binding.
			f.turnstileSecretEnv = "BROKER_TEST_TURNSTILE"
			f.turnstileVerifyURL = "https://challenges.cloudflare.com./turnstile/v0/siteverify"
		}},
		{name: "bad_cf_combo", mutate: func(f *serveFlags) { f.cfAccessCertsURL = "https://keys.example/certs" }},
		{name: "bad_cf_aud", mutate: func(f *serveFlags) {
			f.cfAccessTeamDomain = "team.cloudflareaccess.com"
			f.cfAccessAUD = "bad aud"
		}},
		{name: "bad_cf_certs_scheme", mutate: func(f *serveFlags) {
			f.cfAccessTeamDomain = "team.cloudflareaccess.com"
			f.cfAccessAUD = "aud"
			f.cfAccessCertsURL = "file:///tmp/certs"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := base
			f.codes = append([]string(nil), base.codes...)
			tc.mutate(&f)
			if err := validateFlags(&f); err == nil {
				t.Fatal("validateFlags succeeded, want error")
			}
		})
	}
}

func TestBrokerPublicHosts(t *testing.T) {
	hosts, err := brokerPublicHosts(&serveFlags{
		publicHosts: []string{"Playground.Pipelab.Org.", "playground.pipelab.org:443", ""},
	})
	if err != nil {
		t.Fatalf("brokerPublicHosts explicit: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "playground.pipelab.org" {
		t.Fatalf("hosts = %#v, want one normalized host", hosts)
	}
	hosts, err = brokerPublicHosts(&serveFlags{allowOrigin: "https://playground.pipelab.org"})
	if err != nil {
		t.Fatalf("brokerPublicHosts allowOrigin: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "playground.pipelab.org" {
		t.Fatalf("hosts from origin = %#v", hosts)
	}
	hosts, err = brokerPublicHosts(&serveFlags{turnstileExpectedHostname: "Playground.Pipelab.Org."})
	if err != nil {
		t.Fatalf("brokerPublicHosts turnstile hostname: %v", err)
	}
	if len(hosts) != 1 || hosts[0] != "playground.pipelab.org" {
		t.Fatalf("hosts from turnstile hostname = %#v", hosts)
	}
	if _, err := brokerPublicHosts(&serveFlags{publicHosts: []string{"https://bad.example"}}); err == nil {
		t.Fatal("URL-shaped public host should error")
	}
}

func TestValidateAllowOriginBranches(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
	}{
		{name: "empty", raw: "", wantErr: false},
		{name: "valid", raw: "https://playground.pipelab.org", wantErr: false},
		{name: "surrounding_space", raw: " https://playground.pipelab.org", wantErr: true},
		{name: "wildcard", raw: "*", wantErr: true},
		{name: "bad_scheme", raw: "ftp://playground.pipelab.org", wantErr: true},
		{name: "missing_host", raw: "https:///path", wantErr: true},
		{name: "path_not_origin", raw: "https://playground.pipelab.org/path", wantErr: true},
		{name: "query_not_origin", raw: "https://playground.pipelab.org?x=1", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAllowOrigin(tc.raw)
			if tc.wantErr && err == nil {
				t.Fatal("validateAllowOrigin succeeded, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateAllowOrigin: %v", err)
			}
		})
	}
}

func TestResolveCodesBranches(t *testing.T) {
	specs, err := resolveCodes([]string{"outer", "inner"}, 3)
	if err != nil {
		t.Fatalf("resolveCodes: %v", err)
	}
	if len(specs) != 2 || specs[0].Code != "outer" || specs[0].MaxSessions != 3 || specs[1].Code != "inner" {
		t.Fatalf("specs = %+v, want two code specs with max sessions", specs)
	}
	if _, err := resolveCodes(nil, 3); err == nil {
		t.Fatal("missing codes should error")
	}
	if _, err := resolveCodes([]string{"outer", " \t"}, 3); err == nil {
		t.Fatal("blank code should error")
	}
}

func TestNormalizeCFAccessTeamDomain(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "team.cloudflareaccess.com.", want: "https://team.cloudflareaccess.com"},
		{in: "https://TEAM.cloudflareaccess.com/", want: "https://team.cloudflareaccess.com"},
		{in: "", wantErr: true},
		{in: "http://team.cloudflareaccess.com", wantErr: true},
		{in: "https://team.cloudflareaccess.com/path", wantErr: true},
		{in: "https://user@team.cloudflareaccess.com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := normalizeCFAccessTeamDomain(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatal("normalizeCFAccessTeamDomain succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeCFAccessTeamDomain: %v", err)
			}
			if got != tt.want {
				t.Fatalf("normalizeCFAccessTeamDomain = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveSessionEnv(t *testing.T) {
	dir := t.TempDir()
	modelFile := writeTestFile(t, dir, "model.key", "model-file-value\n")
	t.Setenv(envOrchestratorKey, "orchestrator-env-value")
	env, err := resolveSessionEnv(&serveFlags{
		modelKeyFile:          modelFile,
		requireSessionSecrets: true,
	})
	if err != nil {
		t.Fatalf("resolveSessionEnv: %v", err)
	}
	if env[envModelKey] != "model-file-value" {
		t.Fatalf("model env = %q", env[envModelKey])
	}
	if env[envOrchestratorKey] != "orchestrator-env-value" {
		t.Fatalf("orchestrator env = %q", env[envOrchestratorKey])
	}
}

func TestResolveFlyToken(t *testing.T) {
	dir := t.TempDir()
	tokenFile := writeTestFile(t, dir, "fly.token", "fly-file-token\n")
	t.Setenv("BROKER_TEST_FLY_TOKEN", "fly-env-token")
	got, err := resolveFlyToken(&serveFlags{flyTokenFile: tokenFile, flyTokenEnv: "BROKER_TEST_FLY_TOKEN"})
	if err != nil {
		t.Fatalf("resolveFlyToken file: %v", err)
	}
	if got != "fly-file-token" {
		t.Fatalf("file token = %q", got)
	}
	got, err = resolveFlyToken(&serveFlags{flyTokenEnv: "BROKER_TEST_FLY_TOKEN"})
	if err != nil {
		t.Fatalf("resolveFlyToken env: %v", err)
	}
	if got != "fly-env-token" {
		t.Fatalf("env token = %q", got)
	}
	emptyEnv := "BROKER_TEST_EMPTY"
	if _, err := resolveFlyToken(&serveFlags{flyTokenEnv: emptyEnv}); err == nil {
		t.Fatal("empty env token should error")
	}
}

func TestResolveSessionSecretBranches(t *testing.T) {
	dir := t.TempDir()
	path := writeTestFile(t, dir, "session.secret", "file-value\n")
	t.Setenv("BROKER_TEST_SESSION_SECRET", "env-value")
	t.Setenv(envModelKey, "default-env-value")

	if got, err := resolveSessionSecret(path, "BROKER_TEST_SESSION_SECRET", "--model-key-file", envModelKey, true); err != nil || got != "file-value" {
		t.Fatalf("file secret = %q err=%v", got, err)
	}
	if got, err := resolveSessionSecret("", "BROKER_TEST_SESSION_SECRET", "--model-key-file", envModelKey, true); err != nil || got != "env-value" {
		t.Fatalf("named env secret = %q err=%v", got, err)
	}
	if got, err := resolveSessionSecret("", "", "--model-key-file", envModelKey, true); err != nil || got != "default-env-value" {
		t.Fatalf("default env secret = %q err=%v", got, err)
	}
	t.Setenv(envModelKey, "")
	if got, err := resolveSessionSecret("", "", "--model-key-file", envModelKey, false); err != nil || got != "" {
		t.Fatalf("optional missing secret = %q err=%v", got, err)
	}
	if _, err := resolveSessionSecret("", "", "--model-key-file", envModelKey, true); err == nil {
		t.Fatal("required missing secret should error")
	}
	if _, err := readRequiredFile(writeTestFile(t, dir, "empty", " \n"), "--empty"); err == nil {
		t.Fatal("empty required file should error")
	}
}

func TestCFAccessVerifierErrorsAndCache(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(srv.Close)

	verifier, err := newCFAccessVerifier(&serveFlags{
		cfAccessTeamDomain: "team.cloudflareaccess.com",
		cfAccessAUD:        "aud",
		cfAccessCertsURL:   srv.URL,
	})
	if err != nil {
		t.Fatalf("newCFAccessVerifier: %v", err)
	}
	if err := verifier.verify(context.Background(), "not-a-jwt"); err == nil {
		t.Fatal("invalid JWT should error before JWKS fetch")
	}
	if hits != 0 {
		t.Fatalf("invalid JWT fetched JWKS %d times, want 0", hits)
	}
	if _, err := verifier.keySet(context.Background()); err == nil {
		t.Fatal("empty JWKS should error")
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	const kid = "cache-key"
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &priv.PublicKey,
		KeyID:     kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}
	hits = 0
	goodJWKS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(goodJWKS.Close)
	verifier.certsURL = goodJWKS.URL
	verifier.keys = nil
	verifier.keysExp = time.Time{}
	token := signedCFAccessTestJWT(t, priv, kid, verifier.issuer, verifier.audience, time.Now())
	if err := verifier.verify(context.Background(), token); err != nil {
		t.Fatalf("valid Access JWT: %v", err)
	}
	if err := verifier.verify(context.Background(), token); err != nil {
		t.Fatalf("cached Access JWT: %v", err)
	}
	if hits != 1 {
		t.Fatalf("JWKS fetches = %d, want 1 cached fetch", hits)
	}

	wrongIssuer := signedCFAccessTestJWT(t, priv, kid, "https://wrong.cloudflareaccess.com", verifier.audience, time.Now())
	if err := verifier.verify(context.Background(), wrongIssuer); err == nil {
		t.Fatal("wrong issuer should fail claim validation")
	}
}

func TestCFAccessJWKS_NegativeCache(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	const kid = "neg-cache-key"
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       &priv.PublicKey,
		KeyID:     kid,
		Algorithm: string(jose.RS256),
		Use:       "sig",
	}}}

	var fetchCount int
	fetchFailing := false
	keySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetchCount++
		if fetchFailing {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	t.Cleanup(keySrv.Close)

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	verifier := &cfAccessVerifier{
		issuer:   "https://team.cloudflareaccess.com",
		audience: "aud",
		certsURL: keySrv.URL,
		client:   keySrv.Client(),
		now:      func() time.Time { return now },
	}

	// Initial fetch succeeds and caches.
	jwt := signedCFAccessTestJWT(t, priv, kid, verifier.issuer, verifier.audience, now)
	if err := verifier.verify(context.Background(), jwt); err != nil {
		t.Fatalf("initial verify: %v", err)
	}
	if fetchCount != 1 {
		t.Fatalf("fetches = %d, want 1", fetchCount)
	}

	// Expire the cache and make fetch fail.
	now = now.Add(cfAccessKeysTTL + time.Second)
	fetchFailing = true
	fetchesBefore := fetchCount
	jwt = signedCFAccessTestJWT(t, priv, kid, verifier.issuer, verifier.audience, now)
	if err := verifier.verify(context.Background(), jwt); err != nil {
		t.Fatalf("verify with stale keys after fetch failure: %v", err)
	}
	if fetchCount != fetchesBefore+1 {
		t.Fatalf("expected exactly 1 refetch attempt, got %d", fetchCount-fetchesBefore)
	}

	// Within the negative-cache window, no new fetch is attempted.
	fetchesBefore = fetchCount
	jwt = signedCFAccessTestJWT(t, priv, kid, verifier.issuer, verifier.audience, now)
	if err := verifier.verify(context.Background(), jwt); err != nil {
		t.Fatalf("verify within negative-cache window: %v", err)
	}
	if fetchCount != fetchesBefore {
		t.Fatalf("fetch during negative-cache window: got %d additional fetches", fetchCount-fetchesBefore)
	}
}

func TestCFAccessJWKS_NoCacheFailsClosed(t *testing.T) {
	t.Parallel()
	keySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusServiceUnavailable)
	}))
	t.Cleanup(keySrv.Close)

	verifier := &cfAccessVerifier{
		issuer:   "https://team.cloudflareaccess.com",
		audience: "aud",
		certsURL: keySrv.URL,
		client:   keySrv.Client(),
		now:      time.Now,
	}

	if _, err := verifier.keySet(context.Background()); err == nil {
		t.Fatal("keySet with no cache and failing fetch should error (fail-closed)")
	}
}

func writeTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

// TestBuildVMBaseEnv pins the PLAYGROUND_* env contract that the deploy
// entrypoint (deploy/fly-playground/entrypoint.sh) consumes into serve flags. A
// rename here without updating the entrypoint silently breaks the per-VM config,
// so this test is the producer-side guard for that string-coupled contract.
// deadlineRecorder is an http.ResponseWriter that captures the write deadline
// the middleware sets, so the test can assert exempt-vs-bounded routing. A
// plain httptest.ResponseRecorder does not implement SetWriteDeadline, so
// http.ResponseController could not otherwise apply (or reveal) the deadline.
type deadlineRecorder struct {
	http.ResponseWriter
	deadline time.Time
	set      bool
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.deadline = t
	d.set = true
	return nil
}

// writeDeadliner mirrors the (anonymous in net/http) interface
// http.ResponseController uses to apply a write deadline. The assertion makes
// unparam recognize deadlineRecorder as an interface implementation — the
// always-nil error return is required by that contract, not dead code.
type writeDeadliner interface{ SetWriteDeadline(time.Time) error }

var _ writeDeadliner = (*deadlineRecorder)(nil)

func TestNoCacheStatic(t *testing.T) {
	t.Parallel()
	var served bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		served = true
		w.WriteHeader(http.StatusOK)
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/viewer-live.js", nil)
	noCacheStatic(inner).ServeHTTP(rec, req)
	if !served {
		t.Fatal("inner static handler was not called")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
		t.Fatalf("Cache-Control = %q, want no-cache (so the viewer revalidates after a redeploy)", got)
	}
}

func TestWriteDeadlineMiddleware(t *testing.T) {
	t.Parallel()
	const (
		defaultTimeout = 30 * time.Second
		longTimeout    = 90 * time.Second
		routeHealth    = "/api/live/health"
		routeSession   = "/api/live/session"
		routeStream    = "/api/live/stream"
		routeMessage   = "/api/live/message"
	)
	overrides := map[string]time.Duration{
		routeStream:  0,           // exempt: SSE writes indefinitely
		routeMessage: 0,           // exempt: held open for the whole model turn
		routeSession: longTimeout, // bounded long: cold VM boot+proof
	}

	const (
		kindExempt  = "exempt"  // no deadline
		kindDefault = "default" // ~defaultTimeout
		kindLong    = "long"    // ~longTimeout (bounded, but > default)
	)
	tests := []struct {
		name string
		path string
		kind string
	}{
		{name: "health_default", path: routeHealth, kind: kindDefault},
		// session-create boots+proves a cold microVM (can exceed 30s): a longer
		// but still BOUNDED deadline, not a full exemption (a slow reader must
		// not pin the goroutine). 30s here made cold starts fail closed (PU02/502).
		{name: "session_long_bounded", path: routeSession, kind: kindLong},
		{name: "stream_exempt", path: routeStream, kind: kindExempt},
		{name: "message_exempt_held_open_for_turn", path: routeMessage, kind: kindExempt},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var ran bool
			inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				ran = true
				w.WriteHeader(http.StatusOK)
			})
			mw := writeDeadlineMiddleware(inner, defaultTimeout, overrides)
			rec := &deadlineRecorder{ResponseWriter: httptest.NewRecorder()}
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, tc.path, nil)
			before := time.Now()
			mw.ServeHTTP(rec, req)

			if !ran {
				t.Fatal("inner handler did not run")
			}
			if !rec.set {
				t.Fatal("middleware never called SetWriteDeadline")
			}
			switch tc.kind {
			case kindExempt:
				if !rec.deadline.IsZero() {
					t.Fatalf("exempt path %s: deadline = %v, want zero (cleared)", tc.path, rec.deadline)
				}
			case kindDefault:
				// ~defaultTimeout out, and clearly shorter than the long budget.
				if !rec.deadline.After(before) || rec.deadline.After(before.Add(defaultTimeout+5*time.Second)) {
					t.Fatalf("default path %s: deadline = %v, want ~%s out", tc.path, rec.deadline, defaultTimeout)
				}
			case kindLong:
				// Bounded (not zero) AND longer than the default deadline, so a
				// cold VM boot completes but a slow reader is still capped.
				if rec.deadline.IsZero() {
					t.Fatalf("long path %s: deadline = zero, want a bounded future deadline", tc.path)
				}
				if !rec.deadline.After(before.Add(defaultTimeout)) {
					t.Fatalf("long path %s: deadline = %v, want > default (%s) out", tc.path, rec.deadline, defaultTimeout)
				}
			}
		})
	}
}

func TestValidateAdminListenScope(t *testing.T) {
	tests := []struct {
		name         string
		listen       string
		unsafePublic bool
		wantErr      bool
	}{
		{name: "loopback_ok", listen: "127.0.0.1:9090", wantErr: false},
		{name: "loopback_v6_ok", listen: "[::1]:9090", wantErr: false},
		{name: "private_rfc1918_ok", listen: "10.0.0.5:9090", wantErr: false},
		{name: "private_172_ok", listen: "172.16.0.1:9090", wantErr: false},
		{name: "private_192_ok", listen: "192.168.1.1:9090", wantErr: false},
		{name: "link_local_ok", listen: "169.254.1.1:9090", wantErr: false},
		{name: "ula_ok", listen: "[fd00::1]:9090", wantErr: false},
		{name: "localhost_ok", listen: "localhost:9090", wantErr: false},
		{name: "unspecified_rejected", listen: "0.0.0.0:9090", wantErr: true},
		{name: "unspecified_v6_rejected", listen: "[::]:9090", wantErr: true},
		{name: "empty_host_rejected", listen: ":9090", wantErr: true},
		{name: "public_ip_rejected", listen: "203.0.113.5:9090", wantErr: true},
		{name: "public_v6_rejected", listen: "[2001:db8::1]:9090", wantErr: true},
		{name: "unspecified_with_unsafe_ok", listen: "0.0.0.0:9090", unsafePublic: true, wantErr: false},
		{name: "public_with_unsafe_ok", listen: "203.0.113.5:9090", unsafePublic: true, wantErr: false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAdminListenScope(tc.listen, tc.unsafePublic)
			if tc.wantErr && err == nil {
				t.Fatal("validateAdminListenScope succeeded, want error")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateAdminListenScope: %v", err)
			}
			// Public rejections must name the escape flag.
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), "--unsafe-admin-listen-public") {
				t.Fatalf("error %q does not name the escape flag", err)
			}
		})
	}
}

func TestBuildVMBaseEnv(t *testing.T) {
	f := &serveFlags{
		internalPort:      8080,
		vmModelBaseURL:    "https://api.provider.example/v1",
		vmModel:           "demo-model",
		vmModelMaxSteps:   4,
		vmDailyTurnBudget: 2000,
		vmSessionTTL:      90 * time.Second,
		vmMaxMessages:     12,
	}
	want := map[string]string{
		"PLAYGROUND_LISTEN":            "0.0.0.0:8080",
		"PLAYGROUND_MODEL_BASE_URL":    "https://api.provider.example/v1",
		"PLAYGROUND_MODEL":             "demo-model",
		"PLAYGROUND_MODEL_MAX_STEPS":   "4",
		"PLAYGROUND_DAILY_TURN_BUDGET": "2000",
		"PLAYGROUND_SESSION_TTL":       "1m30s",
		"PLAYGROUND_MAX_MESSAGES":      "12",
	}
	env := buildVMBaseEnv(f)
	for k, v := range want {
		if env[k] != v {
			t.Errorf("env[%s] = %q, want %q", k, env[k], v)
		}
	}
	// Zero-valued optionals are omitted so the VM falls back to its own defaults.
	empty := buildVMBaseEnv(&serveFlags{internalPort: 8080})
	if len(empty) != 1 || empty["PLAYGROUND_LISTEN"] != "0.0.0.0:8080" {
		t.Errorf("empty config should yield only PLAYGROUND_LISTEN, got %v", empty)
	}
}
