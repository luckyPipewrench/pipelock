// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground/broker"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestBrokerMainRejectsInvalidProcessInvocation(t *testing.T) {
	if os.Getenv("PIPELOCK_TEST_BROKER_MAIN") == "1" {
		os.Args = []string{"pipelock-playground-broker", "not-a-command"}
		main()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	cmd := exec.CommandContext( // #nosec G204 -- fixed self-test binary and test name.
		ctx,
		executable,
		"-test.run=^TestBrokerMainRejectsInvalidProcessInvocation$",
	)
	cmd.Env = append(os.Environ(), "PIPELOCK_TEST_BROKER_MAIN=1")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("broker helper process did not exit: %v", ctx.Err())
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("broker helper error = %v, output = %q; want exit status 1", err, output)
	}
	if !bytes.Contains(output, []byte(`unknown command "not-a-command"`)) {
		t.Fatalf("broker helper output = %q, want unknown-command error", output)
	}
}

func TestServeCommandParsesFlagsBeforeProviderFailure(t *testing.T) {
	t.Setenv("BROKER_INCREMENTAL_FLY_TOKEN", "fly-token")
	wantErr := errors.New("provider creation stopped")
	oldFactory := newMachineProvider
	newMachineProvider = func(_ context.Context, f *serveFlags, token string) (broker.MachineProvider, error) {
		if f.listen != "127.0.0.1:0" || f.image != "registry.example/playground:test" {
			t.Fatalf("parsed flags = %+v", f)
		}
		if token != "fly-token" {
			t.Fatalf("resolved provider token = %q", token)
		}
		return nil, wantErr
	}
	t.Cleanup(func() { newMachineProvider = oldFactory })

	cmd := newServeCmd()
	cmd.SetArgs([]string{
		"--listen", "127.0.0.1:0",
		"--image", "registry.example/playground:test",
		"--fly-app", "playground-test",
		"--fly-token-env", "BROKER_INCREMENTAL_FLY_TOKEN",
		"--code", "outer-code",
		"--global-daily-budget", "4",
		"--vm-daily-turn-budget", "8",
		"--unsafe-no-human-gate",
		"--require-session-secrets=false",
	})
	if err := cmd.Execute(); !errors.Is(err, wantErr) {
		t.Fatalf("serve command error = %v, want injected provider error", err)
	}
}

func TestMergeSessionAndBaseEnvPrecedenceAndIsolation(t *testing.T) {
	base := map[string]string{
		"PLAYGROUND_LISTEN":    "0.0.0.0:8080",
		"PLAYGROUND_MODEL_KEY": "base-must-not-win",
	}
	session := map[string]string{
		"PLAYGROUND_MODEL_KEY":        "session-value",
		"PLAYGROUND_ORCHESTRATOR_KEY": "orchestrator-value",
	}
	got := mergeSessionAndBaseEnv(session, base, "vm-code")
	if got["PLAYGROUND_LISTEN"] != "0.0.0.0:8080" ||
		got["PLAYGROUND_MODEL_KEY"] != "session-value" ||
		got["PLAYGROUND_ORCHESTRATOR_KEY"] != "orchestrator-value" ||
		got["PLAYGROUND_CODE"] != "vm-code" {
		t.Fatalf("merged environment = %#v", got)
	}

	got["PLAYGROUND_LISTEN"] = "changed"
	got["PLAYGROUND_MODEL_KEY"] = "changed"
	if base["PLAYGROUND_LISTEN"] != "0.0.0.0:8080" || session["PLAYGROUND_MODEL_KEY"] != "session-value" {
		t.Fatalf("merge mutated inputs: base=%#v session=%#v", base, session)
	}

	onlyCode := mergeSessionAndBaseEnv(nil, nil, "standalone-code")
	if len(onlyCode) != 1 || onlyCode["PLAYGROUND_CODE"] != "standalone-code" {
		t.Fatalf("nil-map merge = %#v, want only VM code", onlyCode)
	}
}

func TestBrokerValidationFailClosedEdges(t *testing.T) {
	base := serveFlags{ // #nosec G101 -- environment variable names, not credentials.
		adminListen:           "127.0.0.1:0",
		adminTokenEnv:         "BROKER_INCREMENTAL_ADMIN_TOKEN",
		image:                 "registry.example/playground:test",
		flyApp:                "playground-test",
		flyTokenEnv:           "BROKER_INCREMENTAL_FLY_TOKEN",
		concurrency:           1,
		codes:                 []string{"outer-code"},
		maxPerCode:            1,
		internalPort:          8080,
		globalDailyBudget:     4,
		vmDailyTurnBudget:     8,
		unsafeNoHumanGate:     true,
		sessionTTL:            time.Minute,
		requireSessionSecrets: false,
	}
	if err := validateFlags(&base); err != nil {
		t.Fatalf("valid baseline flags rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*serveFlags)
	}{
		{"zero_session_ttl", func(f *serveFlags) { f.sessionTTL = 0 }},
		{"malformed_allow_origin", func(f *serveFlags) { f.allowOrigin = "https://%" }},
		{"malformed_turnstile_url", func(f *serveFlags) {
			f.turnstileSecretEnv = "TURNSTILE_SECRET"
			f.turnstileExpectedHostname = "playground.example"
			f.turnstileExpectedAction = "session"
			f.turnstileVerifyURL = "https://%"
		}},
		{"turnstile_url_without_host", func(f *serveFlags) {
			f.turnstileSecretEnv = "TURNSTILE_SECRET"
			f.turnstileExpectedHostname = "playground.example"
			f.turnstileExpectedAction = "session"
			f.turnstileVerifyURL = "https:"
		}},
		{"cf_access_team_without_audience", func(f *serveFlags) {
			f.cfAccessTeamDomain = "team.cloudflareaccess.com"
		}},
		{"cf_access_malformed_team", func(f *serveFlags) {
			f.cfAccessTeamDomain = "https://%"
			f.cfAccessAUD = "audience"
		}},
		{"cf_access_malformed_certs_url", func(f *serveFlags) {
			f.cfAccessTeamDomain = "team.cloudflareaccess.com"
			f.cfAccessAUD = "audience"
			f.cfAccessCertsURL = "https://%"
		}},
		{"cf_access_certs_url_without_host", func(f *serveFlags) {
			f.cfAccessTeamDomain = "team.cloudflareaccess.com"
			f.cfAccessAUD = "audience"
			f.cfAccessCertsURL = "https:"
		}},
		{"cf_access_default_without_gate", func(f *serveFlags) {
			f.cfAccessDefaultCode = "outer-code"
		}},
		{"cf_access_default_unknown_code", func(f *serveFlags) {
			f.cfAccessTeamDomain = "team.cloudflareaccess.com"
			f.cfAccessAUD = "audience"
			f.cfAccessDefaultCode = "missing-code"
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := base
			f.codes = append([]string(nil), base.codes...)
			tc.mutate(&f)
			if err := validateFlags(&f); err == nil {
				t.Fatal("validateFlags succeeded, want fail-closed error")
			}
		})
	}

	withDefault := base
	withDefault.cfAccessTeamDomain = "team.cloudflareaccess.com"
	withDefault.cfAccessAUD = "audience"
	withDefault.cfAccessDefaultCode = "outer-code"
	if err := validateFlags(&withDefault); err != nil {
		t.Fatalf("valid Access default code rejected: %v", err)
	}
}

func TestRejectAmbiguousCompactJWTEdges(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"wrong_segment_count", "one.two"},
		{"invalid_base64", "!e30.e30.signature"},
		{"duplicate_header_key", "eyJhbGciOiJSUzI1NiIsImFsZyI6IlJTMjU2In0.e30.signature"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := rejectAmbiguousCompactJWT(tc.raw); err == nil {
				t.Fatal("rejectAmbiguousCompactJWT succeeded, want error")
			}
		})
	}
	if err := rejectAmbiguousCompactJWT("e30.e30.signature"); err != nil {
		t.Fatalf("unambiguous compact JWT rejected: %v", err)
	}
}

type securityRoundTripFunc func(*http.Request) (*http.Response, error)

func (f securityRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type trackingReadCloser struct {
	reader io.Reader
	closed atomic.Bool
}

func (r *trackingReadCloser) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *trackingReadCloser) Close() error {
	r.closed.Store(true)
	return nil
}

type alwaysErrorReader struct{}

func (alwaysErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("body read failed")
}

func TestFetchCFAccessKeysHTTPFailuresCloseBodies(t *testing.T) {
	transportErr := errors.New("transport unavailable")
	tests := []struct {
		name       string
		certsURL   string
		status     int
		body       io.Reader
		transport  error
		wantClosed bool
	}{
		{name: "request_build_error", certsURL: "https://%"},
		{name: "transport_error", certsURL: "https://keys.example/jwks", transport: transportErr},
		{name: "http_status", certsURL: "https://keys.example/jwks", status: http.StatusBadGateway, body: strings.NewReader("upstream failure"), wantClosed: true},
		{name: "body_read_error", certsURL: "https://keys.example/jwks", status: http.StatusOK, body: alwaysErrorReader{}, wantClosed: true},
		{name: "oversized_body", certsURL: "https://keys.example/jwks", status: http.StatusOK, body: strings.NewReader(strings.Repeat("x", (1<<20)+1)), wantClosed: true},
		{name: "duplicate_json_key", certsURL: "https://keys.example/jwks", status: http.StatusOK, body: strings.NewReader(`{"keys":[],"keys":[]}`), wantClosed: true},
		{name: "malformed_json", certsURL: "https://keys.example/jwks", status: http.StatusOK, body: strings.NewReader(`{"keys":`), wantClosed: true},
		{name: "empty_key_set", certsURL: "https://keys.example/jwks", status: http.StatusOK, body: strings.NewReader(`{"keys":[]}`), wantClosed: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var body *trackingReadCloser
			client := &http.Client{Transport: securityRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.Method != http.MethodGet {
					t.Fatalf("JWKS method = %s, want GET", req.Method)
				}
				if tc.transport != nil {
					return nil, tc.transport
				}
				body = &trackingReadCloser{reader: tc.body}
				return &http.Response{
					StatusCode: tc.status,
					Body:       body,
					Header:     make(http.Header),
					Request:    req,
				}, nil
			})}
			verifier := &cfAccessVerifier{certsURL: tc.certsURL, client: client}
			if _, err := verifier.fetchKeys(context.Background()); err == nil {
				t.Fatal("fetchKeys succeeded, want error")
			}
			if tc.wantClosed && (body == nil || !body.closed.Load()) {
				t.Fatal("fetchKeys did not close the HTTP response body")
			}
		})
	}
}

func TestAdminServerStartsAndCleansUpLoopbackListener(t *testing.T) {
	t.Setenv("BROKER_INCREMENTAL_ADMIN_TOKEN", "operator-token")
	srv := newBrokerControlTestServer(t)
	var out bytes.Buffer
	stop, err := startAdminServer(context.Background(), &out, &serveFlags{ // #nosec G101 -- environment variable name.
		adminListen:   "127.0.0.1:0",
		adminTokenEnv: "BROKER_INCREMENTAL_ADMIN_TOKEN",
	}, srv)
	if err != nil {
		t.Fatalf("startAdminServer: %v", err)
	}
	line := strings.TrimSpace(out.String())
	const prefix = "broker admin serving on "
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("admin startup output = %q", line)
	}
	addr := strings.TrimPrefix(line, prefix)
	dialer := &net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatalf("admin listener %s was not reachable: %v", addr, err)
	}
	_ = conn.Close()
	stop()

	dialer.Timeout = 50 * time.Millisecond
	testwait.For(t, 2*time.Second, func() bool {
		conn, dialErr := dialer.DialContext(context.Background(), "tcp", addr)
		if dialErr != nil {
			return true
		}
		_ = conn.Close()
		return false
	}, "admin listener %s to close after stop", addr)
}
