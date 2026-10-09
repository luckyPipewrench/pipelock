// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/localservice"
)

const (
	testIdentityName      = "local-tools"
	testIdentityDigest    = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"
	testIdentityModDigest = "bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22"
	testIdentityOtherHash = "cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33cc33"
	testIdentityCarrier   = "PIPELOCK_VSCODE_TEST_AUTH"
	testIdentityModule    = "/opt/vendor/lib/native.so"
	testIdentityUpstream  = "http://127.0.0.1:43111/mcp"
)

// fakeIdentityConn is a connection whose only purpose is to be handed to the
// injected probe functions.
func fakeIdentityProbe(t *testing.T, obs localservice.Observation, observeErr, verifyErr error) (identityProbe, *[]string) {
	t.Helper()
	var dialed []string
	return identityProbe{
		dial: func(_ context.Context, network, addr string) (net.Conn, error) {
			dialed = append(dialed, network+" "+addr)
			client, server := net.Pipe()
			t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
			return client, nil
		},
		observe: func(context.Context, net.Conn) (localservice.Observation, error) {
			return obs, observeErr
		},
		verify: func(_ context.Context, _ net.Conn, _ localservice.Pin) (localservice.Evidence, error) {
			if verifyErr != nil {
				return localservice.Evidence{}, verifyErr
			}
			return localservice.Evidence{PID: 4242, UID: 1000, ExecutableSHA256: testIdentityDigest}, nil
		},
	}, &dialed
}

func writeIdentityConfig(t *testing.T, sessionHeader bool) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("version: 1\nmcp_identities:\n  - name: " + testIdentityName + "\n    verified_local_service:\n")
	b.WriteString("      scheme: http\n      host: 127.0.0.1\n      path: /mcp\n      principal_uid: 1000\n")
	b.WriteString("      executable_sha256: " + testIdentityDigest + "\n")
	b.WriteString("      mapped_files:\n        - path: " + testIdentityModule + "\n          sha256: " + testIdentityModDigest + "\n")
	if sessionHeader {
		b.WriteString("      session_header:\n        name: Authorization\n        scheme: Bearer\n        carrier: " + testIdentityCarrier + "\n")
	}
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func runIdentityCmd(t *testing.T, probe identityProbe, args ...string) (string, error) {
	t.Helper()
	cmd := newMCPIdentityCmd(probe)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(context.Background())
	return out.String(), err
}

func TestMCPIdentityInspect_Unregistered(t *testing.T) {
	t.Parallel()
	cfgPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		args     []string
		wantOut  []string
		wantErr  string
		wantDial bool
	}{
		{
			name:    "unnamed server is a legacy binding",
			args:    []string{"inspect", "--config", cfgPath, "--upstream", "https://api.vendor.example/mcp"},
			wantOut: []string{"server=(unnamed)", "source=unnamed", "binding=transport-v2", "registration: none", "scope: an acknowledgment is bound to this launch's exact upstream"},
		},
		{
			name:    "operator label is not an identity",
			args:    []string{"inspect", "--config", cfgPath, "--upstream", "https://api.vendor.example/mcp", "--server-name", "docs"},
			wantOut: []string{"server=docs", "source=explicit", "binding=transport-v2"},
		},
		{
			name:    "websocket upstream",
			args:    []string{"inspect", "--config", cfgPath, "--upstream", "wss://api.vendor.example/mcp"},
			wantOut: []string{"source=unnamed"},
		},
		{
			name:    "missing upstream flag",
			args:    []string{"inspect", "--config", cfgPath},
			wantErr: "upstream",
		},
		{
			name:    "bad scheme",
			args:    []string{"inspect", "--config", cfgPath, "--upstream", "ftp://api.vendor.example/mcp"},
			wantErr: "scheme must be",
		},
		{
			name:    "no host",
			args:    []string{"inspect", "--config", cfgPath, "--upstream", "http:///mcp"},
			wantErr: "must include a scheme and host",
		},
		{
			name:    "invalid server name",
			args:    []string{"inspect", "--config", cfgPath, "--upstream", "https://api.vendor.example/mcp", "--server-name", "bad name!"},
			wantErr: "--server-name",
		},
		{
			name:    "unreadable config",
			args:    []string{"inspect", "--config", filepath.Join(t.TempDir(), "absent.yaml"), "--upstream", "https://api.vendor.example/mcp"},
			wantErr: "absent.yaml",
		},
		{
			name:    "unreadable header file",
			args:    []string{"inspect", "--config", cfgPath, "--upstream", "https://api.vendor.example/mcp", "--header-file", filepath.Join(t.TempDir(), "absent.hdr")},
			wantErr: "absent.hdr",
		},
		{
			name:    "header carrier that is not set",
			args:    []string{"inspect", "--config", cfgPath, "--upstream", "https://api.vendor.example/mcp", "--header-carrier", "Authorization=" + testIdentityCarrier + "_UNSET"},
			wantErr: testIdentityCarrier + "_UNSET",
		},
		{
			name:    "malformed header",
			args:    []string{"inspect", "--config", cfgPath, "--upstream", "https://api.vendor.example/mcp", "--header", "no-colon"},
			wantErr: "header",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			probe, dialed := fakeIdentityProbe(t, localservice.Observation{}, nil, nil)
			out, err := runIdentityCmd(t, probe, tt.args...)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q (output %q)", err, tt.wantErr, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v\n%s", err, out)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q:\n%s", want, out)
				}
			}
			if len(*dialed) != 0 {
				t.Errorf("an unregistered upstream must not be dialed, got %v", *dialed)
			}
		})
	}
}

func TestMCPIdentityInspect_Registered(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("registered resolution requires Linux")
	}
	verifyFail := errors.New("owner is not the pinned executable")
	tests := []struct {
		name          string
		sessionHeader bool
		extraArgs     []string
		verifyErr     error
		wantOut       []string
		wantErr       string
		wantDial      string
	}{
		{
			name:     "verified without a session header",
			wantOut:  []string{"source=verified-local-service", "registration: " + testIdentityName, "binding=verified-local-session", "verification: verified pid=4242 uid=1000"},
			wantDial: "tcp 127.0.0.1:43111",
		},
		{
			name:          "verified with a session header binds the session",
			sessionHeader: true,
			extraArgs:     []string{"--header-carrier", "Authorization=" + testIdentityCarrier},
			wantOut:       []string{"binding=verified-local-session", "scope: an acknowledgment bound to this identity covers every session"},
			wantDial:      "tcp 127.0.0.1:43111",
		},
		{
			name:      "verification failure exits non-zero",
			verifyErr: verifyFail,
			wantOut:   []string{"verification: refused: " + verifyFail.Error()},
			wantErr:   "verified local service " + testIdentityName,
			wantDial:  "tcp 127.0.0.1:43111",
		},
		{
			name:          "session header registration without the carrier refuses",
			sessionHeader: true,
			wantOut:       []string{"refused:"},
			wantErr:       "identity refused",
		},
		{
			name:      "explicit name that conflicts with the match refuses",
			extraArgs: []string{"--server-name", "other"},
			wantOut:   []string{"refused:"},
			wantErr:   "identity refused",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(testIdentityCarrier, "Bearer session-credential-value")
			if strings.Contains(tt.name, "without the carrier") {
				if err := os.Unsetenv(testIdentityCarrier); err != nil {
					t.Fatal(err)
				}
			}
			probe, dialed := fakeIdentityProbe(t, localservice.Observation{}, nil, tt.verifyErr)
			args := []string{"inspect", "--config", writeIdentityConfig(t, tt.sessionHeader), "--upstream", testIdentityUpstream}
			out, err := runIdentityCmd(t, probe, append(args, tt.extraArgs...)...)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q\n%s", err, tt.wantErr, out)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v\n%s", err, out)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q:\n%s", want, out)
				}
			}
			if strings.Contains(out, "session-credential-value") {
				t.Errorf("output leaked the session credential:\n%s", out)
			}
			if tt.wantDial == "" {
				if len(*dialed) != 0 {
					t.Errorf("unexpected dial %v", *dialed)
				}
				return
			}
			if len(*dialed) != 1 || (*dialed)[0] != tt.wantDial {
				t.Errorf("dialed %v, want [%s]", *dialed, tt.wantDial)
			}
		})
	}
}

func TestMCPIdentityInspect_RegisteredRefusesOffLinux(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("covered by the Linux table")
	}
	probe, dialed := fakeIdentityProbe(t, localservice.Observation{}, nil, nil)
	out, err := runIdentityCmd(t, probe, "inspect", "--config", writeIdentityConfig(t, false), "--upstream", testIdentityUpstream)
	if err == nil || !strings.Contains(err.Error(), "identity refused") {
		t.Fatalf("error = %v, want a refusal\n%s", err, out)
	}
	if len(*dialed) != 0 {
		t.Errorf("a refused resolution must not dial, got %v", *dialed)
	}
}

func TestMCPIdentityInspect_DialFailure(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("registered resolution requires Linux")
	}
	probe := identityProbe{
		dial: func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("connection refused") },
	}
	out, err := runIdentityCmd(t, probe, "inspect", "--config", writeIdentityConfig(t, false), "--upstream", testIdentityUpstream)
	if err == nil || !strings.Contains(err.Error(), "dial upstream") {
		t.Fatalf("error = %v, want a dial failure\n%s", err, out)
	}
}

func TestMCPIdentityRegister(t *testing.T) {
	t.Parallel()
	obs := localservice.Observation{
		PID: 4242, UID: 1000, ExecutableSHA256: testIdentityDigest,
		Files: []localservice.ObservedFile{
			{Path: "/lib/x86_64-linux-gnu/libc.so.6", SHA256: testIdentityOtherHash},
			{Path: testIdentityModule, SHA256: testIdentityModDigest},
			{Path: "/opt/vendor/bin/service", SHA256: testIdentityDigest},
			{Path: "/opt/vendor/data/blob.bin"},
			{Path: "/opt/vendor/lib/other.so", SHA256: testIdentityOtherHash},
		},
		ControlEnvironment: []string{"LD_PRELOAD"},
	}
	tests := []struct {
		name      string
		args      []string
		obs       localservice.Observation
		observeEr error
		wantOut   []string
		notOut    []string
		wantErr   string
	}{
		{
			name: "pins the chosen file and comments the rest with system libraries last",
			args: []string{"register", "--upstream", testIdentityUpstream, "--name", testIdentityName, "--mapped-file", testIdentityModule},
			obs:  obs,
			wantOut: []string{
				"name: " + testIdentityName, "scheme: http", "host: 127.0.0.1", "path: /mcp",
				"principal_uid: 1000", "executable_sha256: " + testIdentityDigest,
				"mapped_files:", "path: " + testIdentityModule, "sha256: " + testIdentityModDigest,
				"#   /opt/vendor/lib/other.so sha256=" + testIdentityOtherHash,
				"#   /opt/vendor/data/blob.bin (digest unavailable",
				"control_environment:", "LD_PRELOAD: " + yamlScalar(identityControlEnvHint),
			},
			notOut: []string{"session_header", "/opt/vendor/bin/service"},
		},
		{
			name:    "session header from the carrier",
			args:    []string{"register", "--upstream", testIdentityUpstream, "--name", testIdentityName, "--session-header", "Authorization", "--carrier", testIdentityCarrier},
			obs:     localservice.Observation{UID: 1, ExecutableSHA256: testIdentityDigest},
			wantOut: []string{"session_header:", "name: Authorization", "scheme: Bearer", "carrier: " + testIdentityCarrier},
			notOut:  []string{"mapped_files:", "control_environment:"},
		},
		{name: "mapped file the process does not hold", args: []string{"register", "--upstream", testIdentityUpstream, "--name", testIdentityName, "--mapped-file", "/opt/vendor/lib/absent.so"}, obs: obs, wantErr: "not held open or mapped"},
		{name: "mapped file with no tied digest", args: []string{"register", "--upstream", testIdentityUpstream, "--name", testIdentityName, "--mapped-file", "/opt/vendor/data/blob.bin"}, obs: obs, wantErr: "cannot be pinned"},
		{name: "mapped file twice", args: []string{"register", "--upstream", testIdentityUpstream, "--name", testIdentityName, "--mapped-file", testIdentityModule, "--mapped-file", testIdentityModule}, obs: obs, wantErr: "more than once"},
		{name: "session header without carrier", args: []string{"register", "--upstream", testIdentityUpstream, "--name", testIdentityName, "--session-header", "Authorization"}, obs: obs, wantErr: "must be given together"},
		{name: "carrier without session header", args: []string{"register", "--upstream", testIdentityUpstream, "--name", testIdentityName, "--carrier", testIdentityCarrier}, obs: obs, wantErr: "must be given together"},
		{name: "session header on a websocket upstream", args: []string{"register", "--upstream", "ws://127.0.0.1:43111/mcp", "--name", testIdentityName, "--session-header", "Authorization", "--carrier", testIdentityCarrier}, obs: obs, wantErr: "WebSocket"},
		{name: "non canonical header", args: []string{"register", "--upstream", testIdentityUpstream, "--name", testIdentityName, "--session-header", "authorization", "--carrier", testIdentityCarrier}, obs: obs, wantErr: "canonical form"},
		{name: "carrier outside the namespace", args: []string{"register", "--upstream", testIdentityUpstream, "--name", testIdentityName, "--session-header", "Authorization", "--carrier", "HOME"}, obs: obs, wantErr: "--carrier"},
		{name: "non loopback host", args: []string{"register", "--upstream", "http://api.vendor.example:43111/mcp", "--name", testIdentityName}, obs: obs, wantErr: "literal"},
		{name: "no port", args: []string{"register", "--upstream", "http://127.0.0.1/mcp", "--name", testIdentityName}, obs: obs, wantErr: "explicit port"},
		{name: "no path", args: []string{"register", "--upstream", "http://127.0.0.1:43111", "--name", testIdentityName}, obs: obs, wantErr: "path"},
		{name: "query string", args: []string{"register", "--upstream", "http://127.0.0.1:43111/mcp?k=v", "--name", testIdentityName}, obs: obs, wantErr: "query"},
		{name: "userinfo", args: []string{"register", "--upstream", "http://u:p@127.0.0.1:43111/mcp", "--name", testIdentityName}, obs: obs, wantErr: "credentials"},
		{name: "bad name", args: []string{"register", "--upstream", testIdentityUpstream, "--name", "bad name!"}, obs: obs, wantErr: "--name"},
		{name: "bad scheme", args: []string{"register", "--upstream", "ftp://127.0.0.1:1/mcp", "--name", testIdentityName}, obs: obs, wantErr: "scheme must be"},
		{name: "observe failure", args: []string{"register", "--upstream", testIdentityUpstream, "--name", testIdentityName}, obs: obs, observeEr: localservice.ErrOwnerNotVisible, wantErr: "observe the owner"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			probe, _ := fakeIdentityProbe(t, tt.obs, tt.observeEr, nil)
			out, err := runIdentityCmd(t, probe, tt.args...)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want containing %q\n%s", err, tt.wantErr, out)
				}
				if strings.Contains(out, "mcp_identities:") {
					t.Errorf("a failed registration must not print an entry:\n%s", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v\n%s", err, out)
			}
			for _, want := range tt.wantOut {
				if !strings.Contains(out, want) {
					t.Errorf("output missing %q:\n%s", want, out)
				}
			}
			for _, not := range tt.notOut {
				if strings.Contains(out, not) {
					t.Errorf("output must not contain %q:\n%s", not, out)
				}
			}
		})
	}
}

func TestMCPIdentityRegister_SystemLibrariesComeLast(t *testing.T) {
	t.Parallel()
	obs := localservice.Observation{
		UID: 1, ExecutableSHA256: testIdentityDigest,
		Files: []localservice.ObservedFile{
			{Path: "/etc/ssl/certs/ca.pem", SHA256: testIdentityOtherHash},
			{Path: "/usr/lib/libz.so.1", SHA256: testIdentityOtherHash},
			{Path: "/opt/vendor/a.so", SHA256: testIdentityModDigest},
		},
	}
	probe, _ := fakeIdentityProbe(t, obs, nil, nil)
	out, err := runIdentityCmd(t, probe, "register", "--upstream", testIdentityUpstream, "--name", testIdentityName)
	if err != nil {
		t.Fatal(err)
	}
	vendor, etc, usr := strings.Index(out, "/opt/vendor/a.so"), strings.Index(out, "/etc/ssl"), strings.Index(out, "/usr/lib")
	if vendor < 0 || etc < 0 || usr < 0 || vendor > etc || vendor > usr {
		t.Errorf("vendor file must precede system libraries:\n%s", out)
	}
}

// TestMCPIdentityRegister_OutputLoads feeds the printed entry back through the
// config loader, so the printed shape cannot drift from what the loader accepts.
func TestMCPIdentityRegister_OutputLoads(t *testing.T) {
	t.Parallel()
	obs := localservice.Observation{
		PID: 1, UID: 1000, ExecutableSHA256: testIdentityDigest,
		Files: []localservice.ObservedFile{{Path: testIdentityModule, SHA256: testIdentityModDigest}},
	}
	probe, _ := fakeIdentityProbe(t, obs, nil, nil)
	out, err := runIdentityCmd(t, probe, "register", "--upstream", testIdentityUpstream, "--name", testIdentityName,
		"--mapped-file", testIdentityModule, "--session-header", "Authorization", "--carrier", testIdentityCarrier)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"+out), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("printed entry does not load: %v\n%s", err, out)
	}
	if len(cfg.MCPIdentities) != 1 {
		t.Fatalf("loaded %d identities, want 1", len(cfg.MCPIdentities))
	}
	v := cfg.MCPIdentities[0].VerifiedLocalService
	if v == nil || v.ExecutableSHA256 != testIdentityDigest || len(v.MappedFiles) != 1 || v.SessionHeader == nil || v.SessionHeader.Carrier != testIdentityCarrier {
		t.Errorf("loaded entry = %+v", v)
	}
}

// TestMCPIdentityRegister_ObservedPathCannotInjectYAML: the observed service
// names its own files, so a path with a newline must not end a comment or a
// scalar and add live YAML to the entry the operator copies into a config.
func TestMCPIdentityRegister_ObservedPathCannotInjectYAML(t *testing.T) {
	t.Parallel()
	injected := "/opt/vendor/x.so\n  - name: injected-identity\n    verified_local_service: {}"
	pinnedPath := "/opt/vendor/odd\nname.so"
	obs := localservice.Observation{
		PID: 1, UID: 1000, ExecutableSHA256: testIdentityDigest,
		Files: []localservice.ObservedFile{
			{Path: injected, SHA256: testIdentityOtherHash},
			{Path: pinnedPath, SHA256: testIdentityModDigest},
		},
	}
	probe, _ := fakeIdentityProbe(t, obs, nil, nil)
	out, err := runIdentityCmd(t, probe, "register", "--upstream", testIdentityUpstream, "--name", testIdentityName,
		"--mapped-file", pinnedPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "\n  - name: injected-identity") {
		t.Fatalf("an observed path added live YAML:\n%s", out)
	}
	path := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(path, []byte("version: 1\n"+out), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("printed entry does not load: %v\n%s", err, out)
	}
	if len(cfg.MCPIdentities) != 1 || cfg.MCPIdentities[0].Name != testIdentityName {
		t.Fatalf("loaded identities = %+v, want only %s", cfg.MCPIdentities, testIdentityName)
	}
	v := cfg.MCPIdentities[0].VerifiedLocalService
	if v == nil || len(v.MappedFiles) != 1 || v.MappedFiles[0].Path != pinnedPath {
		t.Fatalf("pinned path did not round-trip: %+v", v)
	}
}

func TestMCPIdentityRegister_ControlEnvironmentPlaceholder(t *testing.T) {
	t.Parallel()
	obs := localservice.Observation{UID: 1, ExecutableSHA256: testIdentityDigest, ControlEnvironment: []string{"LD_PRELOAD"}}
	probe, _ := fakeIdentityProbe(t, obs, nil, nil)
	out, err := runIdentityCmd(t, probe, "register", "--upstream", testIdentityUpstream, "--name", testIdentityName)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "LD_PRELOAD: "+yamlScalar(identityControlEnvHint)) {
		t.Fatalf("placeholder missing:\n%s", out)
	}
	if !strings.Contains(out, "Fill in the exact reviewed value") {
		t.Errorf("review instruction missing:\n%s", out)
	}
}

func TestDefaultIdentityProbe(t *testing.T) {
	t.Parallel()
	p := defaultIdentityProbe()
	if p.dial == nil || p.observe == nil || p.verify == nil {
		t.Fatal("default probe must be fully populated")
	}
	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	conn, err := p.dial(context.Background(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if runtime.GOOS != "linux" {
		if _, err := p.observe(context.Background(), conn); !errors.Is(err, localservice.ErrUnsupportedPlatform) {
			t.Errorf("observe err = %v, want ErrUnsupportedPlatform", err)
		}
		if _, err := p.verify(context.Background(), conn, localservice.Pin{}); !errors.Is(err, localservice.ErrUnsupportedPlatform) {
			t.Errorf("verify err = %v, want ErrUnsupportedPlatform", err)
		}
	}
}

func TestYAMLScalarQuotesWhenNeeded(t *testing.T) {
	t.Parallel()
	tests := []struct{ in, want string }{
		{"plain", "plain"},
		{"has: colon", `'has: colon'`},
		{"/opt/vendor/x", "/opt/vendor/x"},
		{"true", `"true"`},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			if got := yamlScalar(tt.in); got != tt.want {
				t.Errorf("yamlScalar(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
