// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

const (
	e2eIdentityName   = "e2e-vendor"
	e2eIdentityPath   = "/rpc"
	e2eSessionCarrier = "PIPELOCK_VSCODE_E2E_AUTH"
	e2eAckServer      = "vault"
	e2eToolsListLine  = `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	e2eStoreSecret    = `store_secret`
	e2eFakeDigest     = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12"
	e2eFakeModuleHash = "cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34"
	e2eLoopbackHost   = "127.0.0.1"
	e2eKeyEnv         = "PIPELOCK_E2E_ACK_KEY"

	e2eSessionBindingDomain = "pipelock-mcp-ack-binding-verified-local-session-v1"
)

// e2eRegistration is a verified local service registration written into a test
// configuration. The pins are real values for the helper process the Linux
// tests start, and fixed placeholders where no process is involved.
type e2eRegistration struct {
	Scheme        string
	UID           uint32
	ExecSHA       string
	MappedPath    string
	MappedSHA     string
	SessionHeader bool
}

func (r e2eRegistration) yaml() string {
	var b strings.Builder
	_, _ = fmt.Fprintf(&b, "mcp_identities:\n  - name: %s\n    verified_local_service:\n", e2eIdentityName)
	_, _ = fmt.Fprintf(&b, "      scheme: %s\n      host: %s\n      path: %s\n", r.Scheme, e2eLoopbackHost, e2eIdentityPath)
	_, _ = fmt.Fprintf(&b, "      principal_uid: %d\n      executable_sha256: %s\n", r.UID, r.ExecSHA)
	_, _ = fmt.Fprintf(&b, "      mapped_files:\n        - path: %s\n          sha256: %s\n", r.MappedPath, r.MappedSHA)
	if r.SessionHeader {
		_, _ = fmt.Fprintf(&b, "      session_header:\n        name: Authorization\n        scheme: Bearer\n        carrier: %s\n", e2eSessionCarrier)
	}
	return b.String()
}

func e2ePlaceholderRegistration(scheme string) e2eRegistration {
	return e2eRegistration{
		Scheme:        scheme,
		UID:           1000,
		ExecSHA:       e2eFakeDigest,
		MappedPath:    "/opt/vendor/lib/module.bin",
		MappedSHA:     e2eFakeModuleHash,
		SessionHeader: true,
	}
}

// e2eToolSHA is the digest an acknowledgment names for ackListenerTool.
func e2eToolSHA(t *testing.T) string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(ackListenerTool), &v); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return ackListenerSHA(string(canonical))
}

// e2eAckBlock is the acknowledged_findings entry for ackListenerTool, keyed to
// binding. An empty mode leaves the entry in the default transport-v2 mode.
func e2eAckBlock(t *testing.T, server, binding, mode string) string {
	t.Helper()
	var b strings.Builder
	keyed := ackListenerKeyed(ackListenerKey, binding)
	if mode == config.MCPAckBindingModeVerifiedLocalSession {
		keyed = ackListenerKeyedDomain(ackListenerKey, e2eSessionBindingDomain, binding)
	}
	_, _ = fmt.Fprintf(&b, "  acknowledged_findings:\n    - server: %s\n      server_binding_hmac: %s\n", server, keyed)
	if mode != "" {
		_, _ = fmt.Fprintf(&b, "      server_binding_mode: %s\n", mode)
	}
	_, _ = fmt.Fprintf(&b, "      tool: store_secret\n      finding: Credential Request Directive\n      family_revision: 2\n      tool_sha256: %s\n", e2eToolSHA(t))
	_, _ = fmt.Fprintf(&b, "      occurrences:\n        - field: /inputSchema/properties/key/description\n          field_text_sha256: %s\n", ackListenerSHA(ackListenerKeyDesc))
	_, _ = fmt.Fprintf(&b, "          pattern: 0\n          ordinal: 0\n          start: 0\n          end: %d\n          match_sha256: %s\n", len(ackListenerKeyDesc), ackListenerSHA(ackListenerKeyDesc))
	_, _ = fmt.Fprintf(&b, "      owner: platform team\n      reason: reviewed placeholder\n      expires: %q\n", time.Now().UTC().AddDate(0, 0, 30).Format("2006-01-02"))
	return b.String()
}

// writeE2EConfig writes a blocking tool-scanning configuration with the given
// acknowledgment block and registration (either may be empty).
func writeE2EConfig(t *testing.T, ackBlock, registration string) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(e2eKeyEnv, ackListenerKey)
	text := fmt.Sprintf("version: 1\nmode: balanced\nmcp_tool_scanning:\n  enabled: true\n  action: block\n  detect_drift: false\n  acknowledgment_key: \"${%s}\"\n", e2eKeyEnv) + ackBlock + registration
	path := filepath.Join(dir, "pipelock.yaml")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// e2eProxy is one running pipelock mcp proxy session whose stdin and stdout
// the test drives line by line.
type e2eProxy struct {
	t      *testing.T
	in     *io.PipeWriter
	lines  chan string
	stderr *syncBuffer
	done   chan error
	cancel context.CancelFunc
	once   sync.Once
}

func startE2EProxy(t *testing.T, args []string) *e2eProxy {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	p := &e2eProxy{t: t, in: inW, lines: make(chan string, 64), stderr: &syncBuffer{}, done: make(chan error, 1), cancel: cancel}

	cmd := McpCmd()
	cmd.SetContext(ctx)
	cmd.SetIn(inR)
	cmd.SetOut(outW)
	cmd.SetErr(p.stderr)
	cmd.SetArgs(args)

	go func() {
		err := cmd.Execute()
		_ = outW.Close()
		_ = inR.Close()
		p.done <- err
	}()
	go func() {
		sc := bufio.NewScanner(outR)
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			p.lines <- sc.Text()
		}
		close(p.lines)
	}()
	t.Cleanup(p.stop)
	return p
}

func (p *e2eProxy) stop() {
	p.once.Do(func() {
		p.cancel()
		_ = p.in.Close()
	})
}

// recv returns the next response line, or false when the proxy closed its
// output or none arrived within the deadline.
func (p *e2eProxy) recv() (string, bool) {
	select {
	case line, ok := <-p.lines:
		return line, ok
	case <-time.After(testwait.Deadline(15 * time.Second)):
		return "", false
	}
}

// call sends a tools/list request and returns the response, failing the test
// if none arrives.
func (p *e2eProxy) call() string {
	p.t.Helper()
	line := e2eToolsListLine
	if _, err := io.WriteString(p.in, line+"\n"); err != nil {
		p.t.Fatalf("write to proxy stdin: %v (stderr: %s)", err, p.stderr.String())
	}
	got, ok := p.recv()
	if !ok {
		p.t.Fatalf("no response to %s (stderr: %s)", line, p.stderr.String())
	}
	return got
}

// tryCall is call for a request the proxy may refuse without answering; ok is
// false when no response line arrived.
func (p *e2eProxy) tryCall(line string) (string, bool) {
	p.t.Helper()
	if _, err := io.WriteString(p.in, line+"\n"); err != nil {
		return "", false
	}
	return p.recv()
}

// finish closes stdin, waits for the proxy to exit and returns its error and
// stderr.
func (p *e2eProxy) finish() (string, error) {
	p.t.Helper()
	_ = p.in.Close()
	select {
	case err := <-p.done:
		return p.stderr.String(), err
	case <-time.After(testwait.Deadline(30 * time.Second)):
		p.stop()
		p.t.Fatalf("proxy did not exit after stdin closed (stderr: %s)", p.stderr.String())
		return "", nil
	}
}

func e2eToolsListUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Errorf("decode upstream request: %v", err)
			return
		}
		if len(request.ID) == 0 {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[%s]}}`, request.ID, ackListenerTool)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// An unregistered server keeps the transport-v2 binding, which covers its
// configured headers: a real upstream credential change still invalidates the
// acknowledgment, and the verified-service machinery does not weaken that.
func TestMCPProxyUnregisteredCredentialChangeStillInvalidatesAck(t *testing.T) {
	upstream := e2eToolsListUpstream(t)
	binding := mcpServerBinding(mcpBindingInputs{UpstreamURL: upstream.URL, Headers: http.Header{"X-Tenant": {"alpha"}}})
	cfgPath := writeE2EConfig(t, e2eAckBlock(t, e2eAckServer, binding, ""), "")

	tests := []struct {
		name        string
		header      []string
		wantAllowed bool
	}{
		{"acknowledged credential passes", []string{"--header", "X-Tenant: alpha"}, true},
		{"changed credential is refused", []string{"--header", "X-Tenant: beta"}, false},
		{"missing credential is refused", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := append([]string{"proxy", "--config", cfgPath, "--upstream", upstream.URL, "--server-name", e2eAckServer}, tt.header...)
			p := startE2EProxy(t, args)
			got := p.call()
			if stderr, err := p.finish(); err != nil {
				t.Fatalf("proxy exit: %v (stderr: %s)", err, stderr)
			}
			if allowed := strings.Contains(got, e2eStoreSecret); allowed != tt.wantAllowed {
				t.Fatalf("store_secret present = %v, want %v: %s", allowed, tt.wantAllowed, got)
			}
			if !tt.wantAllowed && !strings.Contains(got, `"error"`) {
				t.Fatalf("refused tools/list carries no JSON-RPC error: %s", got)
			}
		})
	}
}

// A launch that claims a registered name must match the registration, and a
// launch that matches one must not claim another name. Both fail at startup,
// before any connection.
func TestMCPProxyRefusesRegisteredNameClaims(t *testing.T) {
	reg := e2ePlaceholderRegistration("http")
	cfgPath := writeE2EConfig(t, "", reg.yaml())
	matching := fmt.Sprintf("http://%s:4100%s", e2eLoopbackHost, e2eIdentityPath)
	elsewhere := fmt.Sprintf("http://%s:4100/other", e2eLoopbackHost)

	tests := []struct {
		name     string
		upstream string
		explicit string
		want     string
	}{
		{"registered name with a non-matching upstream", elsewhere, e2eIdentityName, "is registered as a verified local service"},
		{"different explicit name on a matching upstream", matching, e2eAckServer, "conflicts with mcp_identities"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stderr, err := runMCPProxyStdin(t, "", []string{"proxy", "--config", cfgPath, "--upstream", tt.upstream, "--server-name", tt.explicit})
			if err == nil {
				t.Fatalf("startup succeeded; stderr: %s", stderr)
			}
			if !strings.Contains(err.Error(), tt.want) && !strings.Contains(stderr, tt.want) {
				t.Fatalf("error %q (stderr %q) does not name %q", err, stderr, tt.want)
			}
		})
	}
}
