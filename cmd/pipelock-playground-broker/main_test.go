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
	srv, handler, err := buildServer(context.Background(), &out, &serveFlags{
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
		sessionTTL:            defaultSessionTTL,
		deadlineGrace:         defaultGrace,
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
			sessionTTL: defaultSessionTTL, deadlineGrace: defaultGrace,
			requireSessionSecrets: false,
		}
	}

	// With --static-dir: / serves the UI AND the API still routes on the same origin.
	srv, handler, err := buildServer(context.Background(), &bytes.Buffer{}, flags(uiDir))
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
	srv2, handler2, err := buildServer(context.Background(), &bytes.Buffer{}, flags(""))
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

	srv, handler, err := buildServer(context.Background(), &bytes.Buffer{}, &serveFlags{
		listen: defaultListen, provider: "fake", flyApp: "playground-test",
		flyTokenFile: flyTokenFile, image: "registry.example/playground:test",
		staticDir: uiDir, internalPort: 8080, concurrency: 2,
		codes: []string{"outer-code"}, maxPerCode: defaultMaxPerCode,
		gateSecretFile: gateSecretFile, ipRate: defaultIPRate, ipBurst: defaultIPBurst,
		codeRate: defaultCodeRate, codeBurst: defaultCodeBurst,
		sessionTTL: defaultSessionTTL, deadlineGrace: defaultGrace,
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

	srv, handler, err := buildServer(context.Background(), &bytes.Buffer{}, &serveFlags{
		listen: defaultListen, provider: "fake", flyApp: "playground-test",
		flyTokenFile: flyTokenFile, image: "registry.example/playground:test",
		staticDir: uiDir, internalPort: 8080, concurrency: 2,
		codes: []string{"outer-code"}, maxPerCode: defaultMaxPerCode,
		gateSecretFile: gateSecretFile, ipRate: defaultIPRate, ipBurst: defaultIPBurst,
		codeRate: defaultCodeRate, codeBurst: defaultCodeBurst,
		sessionTTL: defaultSessionTTL, deadlineGrace: defaultGrace,
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
		sessionTTL:            defaultSessionTTL,
		deadlineGrace:         defaultGrace,
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
	var out bytes.Buffer
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
		sessionTTL:            defaultSessionTTL,
		deadlineGrace:         defaultGrace,
		requireSessionSecrets: false,
	})
	if err == nil || !strings.Contains(err.Error(), "listen 127.0.0.1:bad-port") {
		t.Fatalf("runServe error = %v, want listen failure", err)
	}
	if !strings.Contains(out.String(), "broker configured") {
		t.Fatalf("runServe should build before listen error, output = %q", out.String())
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
		provider:      "fly",
		flyApp:        "playground-test",
		flyTokenEnv:   "BROKER_TEST_FLY_TOKEN",
		image:         "registry.example/playground:test",
		internalPort:  8080,
		concurrency:   1,
		codes:         []string{"outer-code"},
		maxPerCode:    defaultMaxPerCode,
		ipRate:        defaultIPRate,
		ipBurst:       defaultIPBurst,
		codeRate:      defaultCodeRate,
		codeBurst:     defaultCodeBurst,
		sessionTTL:    defaultSessionTTL,
		deadlineGrace: defaultGrace,
	}
	if err := validateFlags(&base); err != nil {
		t.Fatalf("base validateFlags: %v", err)
	}
	if err := validateFlags(nil); err == nil {
		t.Fatal("nil flags should error")
	}
	tests := []struct {
		name   string
		mutate func(*serveFlags)
	}{
		{name: "missing_fly_app", mutate: func(f *serveFlags) { f.flyApp = "" }},
		{name: "missing_token_source", mutate: func(f *serveFlags) { f.flyTokenEnv = "" }},
		{name: "bad_concurrency", mutate: func(f *serveFlags) { f.concurrency = 0 }},
		{name: "bad_max_per_code", mutate: func(f *serveFlags) { f.maxPerCode = -1 }},
		{name: "bad_memory", mutate: func(f *serveFlags) { f.memoryMB = -1 }},
		{name: "bad_cpus", mutate: func(f *serveFlags) { f.cpus = -1 }},
		{name: "bad_deadline_grace", mutate: func(f *serveFlags) { f.deadlineGrace = -1 }},
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
	if _, err := brokerPublicHosts(&serveFlags{publicHosts: []string{"https://bad.example"}}); err == nil {
		t.Fatal("URL-shaped public host should error")
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
