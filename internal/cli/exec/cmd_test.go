// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/launchcontract"
)

const healthyState = `{"status":"healthy","forward_proxy_enabled":true,"tls_interception_enabled":true,"kill_switch_active":false}`

func TestPublicCommand(t *testing.T) {
	t.Parallel()
	cmd := Cmd()
	cmd.SetArgs([]string{})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); err == nil {
		t.Fatal("public command accepted missing arguments")
	}
}

func testCA(t *testing.T) (string, []byte) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, data
}

func healthServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("path=%s", r.URL.Path)
		}
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(server.Close)
	return server
}

func TestFailClosedNeverLaunches(t *testing.T) {
	t.Parallel()
	ca, roots := testCA(t)
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("bad CA"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name   string
		status int
		body   string
		ca     string
		extra  []string
		want   string
	}{
		{"health unhealthy", 503, healthyState, ca, nil, "proxy unhealthy"},
		{"forward disabled", 200, strings.Replace(healthyState, `"forward_proxy_enabled":true`, `"forward_proxy_enabled":false`, 1), ca, nil, "forward proxy is disabled"},
		{"intercept disabled with CA", 200, strings.Replace(healthyState, `"tls_interception_enabled":true`, `"tls_interception_enabled":false`, 1), ca, nil, "TLS interception is required"},
		{"intercept explicitly required", 200, strings.Replace(healthyState, `"tls_interception_enabled":true`, `"tls_interception_enabled":false`, 1), ca, []string{"--require-intercept"}, "TLS interception is required"},
		{"kill switch", 200, strings.Replace(healthyState, `"kill_switch_active":false`, `"kill_switch_active":true`, 1), ca, nil, "kill switch is active"},
		{"missing CA", 200, healthyState, filepath.Join(t.TempDir(), "missing.pem"), nil, "fix the path"},
		{"bad CA", 200, healthyState, bad, nil, "invalid --ca"},
		{"CA required without path", 200, healthyState, "", []string{"--require-intercept"}, "requires a CA file"},
		{"invalid JSON", 200, "not JSON", ca, nil, "invalid proxy health"},
		{"incomplete JSON", 200, `{"status":"healthy","forward_proxy_enabled":true}`, ca, nil, "incomplete"},
		{"unknown status", 200, strings.Replace(healthyState, "healthy", "unknown", 1), ca, nil, "unhealthy or incomplete"},
		{"null kill switch", 200, strings.Replace(healthyState, `"kill_switch_active":false`, `"kill_switch_active":null`, 1), ca, nil, "incomplete"},
		{"wrong boolean type", 200, strings.Replace(healthyState, `"kill_switch_active":false`, `"kill_switch_active":"false"`, 1), ca, nil, "invalid proxy health"},
		{"duplicate flag", 200, strings.Replace(healthyState, `"forward_proxy_enabled":true`, `"forward_proxy_enabled":false,"forward_proxy_enabled":true`, 1), ca, nil, "duplicate health field"},
		{"case folded flag", 200, strings.Replace(healthyState, `"forward_proxy_enabled":true`, `"FORWARD_PROXY_ENABLED":true`, 1), ca, nil, "incomplete"},
		{"case folded override cannot enable", 200, strings.Replace(healthyState, `"forward_proxy_enabled":true`, `"forward_proxy_enabled":false,"FORWARD_PROXY_ENABLED":true`, 1), ca, nil, "forward proxy is disabled"},
		{"trailing JSON", 200, healthyState + `{}`, ca, nil, "trailing data"},
		{"oversized health", 200, strings.Repeat(" ", 65<<10) + healthyState, ca, nil, "too large"},
		{"redirect", 302, healthyState, ca, nil, "status 302"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := healthServer(t, tt.status, tt.body)
			launched := false
			cmd := newCmd(dependencies{
				launch:      func(_ *cobra.Command, _, _ []string) error { launched = true; return nil },
				systemRoots: func() ([]byte, error) { return roots, nil },
				cacheDir:    func() (string, error) { return t.TempDir(), nil },
			})
			args := []string{"--proxy-url", server.URL}
			if tt.ca != "" {
				args = append(args, "--ca", tt.ca)
			}
			args = append(args, tt.extra...)
			args = append(args, "--", "must-never-start")
			cmd.SetArgs(args)
			cmd.SetErr(&bytes.Buffer{})
			err := cmd.Execute()
			if launched || err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("launched=%v err=%v want=%q", launched, err, tt.want)
			}
		})
	}
}

func TestHealthDown(t *testing.T) {
	t.Parallel()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	launched := false
	cmd := newCmd(dependencies{launch: func(_ *cobra.Command, _, _ []string) error { launched = true; return nil }})
	cmd.SetArgs([]string{"--proxy-url", "http://" + addr, "--", "must-never-start"})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); launched || err == nil || !strings.Contains(err.Error(), "start pipelock run") {
		t.Fatalf("launched=%v err=%v", launched, err)
	}
}

func TestHealthRedirectRefusesLaunch(t *testing.T) {
	t.Parallel()
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("health probe followed a redirect")
		_, _ = fmt.Fprint(w, healthyState)
	}))
	t.Cleanup(destination.Close)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/health", http.StatusFound)
	}))
	t.Cleanup(server.Close)
	launched := false
	cmd := newCmd(dependencies{launch: func(_ *cobra.Command, _, _ []string) error { launched = true; return nil }})
	cmd.SetArgs([]string{"--proxy-url", server.URL, "--", "must-never-start"})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); launched || err == nil || !strings.Contains(err.Error(), "status 302") {
		t.Fatalf("launched=%v err=%v", launched, err)
	}
}

func TestSuccessContractAndInheritance(t *testing.T) {
	// Environment changes forbid Parallel; the siblings use isolated injected dependencies.
	t.Setenv("CUSTOM_PROXY", "http://old.invalid")
	t.Setenv("Http_Proxy", "http://old.invalid")
	t.Setenv("NO_PROXY", "*")
	t.Setenv("CODEX_CA_CERTIFICATE", "stale")
	t.Setenv("EXEC_UNRELATED", "preserved")
	ca, roots := testCA(t)
	server := healthServer(t, 200, healthyState)
	launched := false
	cmd := newCmd(dependencies{
		launch: func(_ *cobra.Command, args, env []string) error {
			launched = true
			if !reflect.DeepEqual(args, []string{"command", "--child-flag"}) {
				t.Fatalf("args=%v", args)
			}
			values := make(map[string]string)
			for _, entry := range env {
				k, v, _ := strings.Cut(entry, "=")
				values[k] = v
			}
			bundle := values["SSL_CERT_FILE"]
			if values["ALL_PROXY"] != server.URL || values["all_proxy"] != server.URL || values["CODEX_CA_CERTIFICATE"] != ca || values["DENO_CERT"] != bundle || values["npm_config_noproxy"] != "localhost" || values["npm_config_cafile"] != bundle {
				t.Fatal("missing ALL_PROXY, the npm overrides, or the runtime-specific CA overrides")
			}
			got, err := os.ReadFile(filepath.Clean(bundle))
			if err != nil || bytes.Count(got, []byte("-----BEGIN CERTIFICATE-----")) != 2 {
				t.Fatalf("combined bundle err=%v cert count=%d", err, bytes.Count(got, []byte("-----BEGIN CERTIFICATE-----")))
			}
			want := launchcontract.Merge(os.Environ(), launchcontract.Vars(launchcontract.Exec, server.URL, "localhost", bundle, ca))
			if !reflect.DeepEqual(env, want) || values["CUSTOM_PROXY"] != "" || values["Http_Proxy"] != "" || values["EXEC_UNRELATED"] != "preserved" {
				t.Fatalf("launch environment differs from shared contract")
			}
			return nil
		},
		systemRoots: func() ([]byte, error) { return roots, nil },
		cacheDir:    func() (string, error) { return t.TempDir(), nil },
	})
	cmd.SetArgs([]string{"--proxy-url", server.URL, "--ca", ca, "--no-proxy", "localhost", "--", "command", "--child-flag"})
	if err := cmd.Execute(); err != nil || !launched {
		t.Fatalf("launched=%v err=%v", launched, err)
	}
}

func TestNoCAAndPrintModes(t *testing.T) {
	t.Parallel()
	server := healthServer(t, 200, strings.Replace(healthyState, `"tls_interception_enabled":true`, `"tls_interception_enabled":false`, 1))
	for _, mode := range []string{"--dry-run", "sh", "pwsh", "cmd", "json"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()
			cmd := newCmd(dependencies{launch: func(_ *cobra.Command, _, _ []string) error { t.Fatal("print launched"); return nil }})
			args := []string{"--proxy-url", server.URL}
			if mode == "--dry-run" {
				args = append(args, mode)
			} else {
				args = append(args, "--print-env", mode)
			}
			cmd.SetArgs(args)
			var out bytes.Buffer
			cmd.SetOut(&out)
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), server.URL) {
				t.Fatalf("missing selected proxy in %s", out.String())
			}
			if mode == "json" || mode == "--dry-run" {
				var result struct {
					Set   map[string]string `json:"set"`
					Unset []string          `json:"unset"`
				}
				if err := json.Unmarshal(out.Bytes(), &result); err != nil || len(result.Set) != 10 {
					t.Fatalf("JSON=%s err=%v", out.String(), err)
				}
			}
		})
	}
}

func TestArgumentAndURLValidation(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{},
		{"command"},
		{"--dry-run", "command"},
		{"--print-env", "fish"},
		{"--dry-run", "--proxy-url", "http://user:pass@example.com"},
		{"--dry-run", "--proxy-url", "ftp://example.com"},
		{"--dry-run", "--proxy-url", "http://example.com/path"},
		{"--dry-run", "--proxy-url", "http://example.com?q=1"},
		{"--dry-run", "--proxy-url", "http://example.com#fragment"},
		{"--dry-run", "--proxy-url", "http://[broken"},
		{"--dry-run", "--no-proxy", "bad\nvalue"},
		{"--dry-run", "--config", filepath.Join(t.TempDir(), "missing.yaml")},
	} {
		t.Run(fmt.Sprint(args), func(t *testing.T) {
			t.Parallel()
			cmd := newCmd(dependencies{})
			cmd.SetArgs(args)
			cmd.SetErr(&bytes.Buffer{})
			if err := cmd.Execute(); err == nil {
				t.Fatal("invalid args accepted")
			}
		})
	}
}

func TestCABundleFailuresRefuseLaunch(t *testing.T) {
	t.Parallel()
	ca, roots := testCA(t)
	server := healthServer(t, 200, healthyState)
	for _, tt := range []struct {
		name  string
		roots func() ([]byte, error)
		cache func() (string, error)
		want  string
	}{
		{"root read", func() ([]byte, error) { return nil, errors.New("root read failure") }, nil, "root read failure"},
		{"invalid roots", func() ([]byte, error) { return []byte("bad"), nil }, nil, "system CA bundle"},
		{"cache location", func() ([]byte, error) { return roots, nil }, func() (string, error) { return "", errors.New("no cache") }, "find CA cache"},
		{"cache write", func() ([]byte, error) { return roots, nil }, func() (string, error) { return ca, nil }, "create CA cache"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cmd := newCmd(dependencies{systemRoots: tt.roots, cacheDir: tt.cache, launch: func(_ *cobra.Command, _, _ []string) error { t.Fatal("launched after bundle failure"); return nil }})
			cmd.SetArgs([]string{"--proxy-url", server.URL, "--ca", ca, "--", "must-never-start"})
			cmd.SetErr(&bytes.Buffer{})
			if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err=%v want=%s", err, tt.want)
			}
		})
	}
}

func TestConfigDefaultsAndOverrides(t *testing.T) {
	t.Parallel()
	ca, _ := testCA(t)
	file := filepath.Join(filepath.Dir(ca), "pipelock.yaml")
	if err := os.WriteFile(file, []byte("fetch_proxy:\n  listen: '0.0.0.0:9876'\ntls_interception:\n  ca_cert: ca.pem\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := resolveOptions(options{configFile: file}, false, false)
	if err != nil || got.proxyURL != "http://127.0.0.1:9876" || got.caFile != ca {
		t.Fatalf("resolved=%+v err=%v", got, err)
	}
	for _, listen := range []string{"':9876'", "'[::]:9876'", "'[::0]:9876'", "'[0:0:0:0:0:0:0:0]:9876'"} {
		alt := filepath.Join(filepath.Dir(ca), "unspecified.yaml")
		if err := os.WriteFile(alt, []byte("fetch_proxy:\n  listen: "+listen+"\ntls_interception:\n  ca_cert: ca.pem\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got, err := resolveOptions(options{configFile: alt}, false, false); err != nil || got.proxyURL != "http://127.0.0.1:9876" {
			t.Fatalf("listen %s resolved=%+v err=%v", listen, got, err)
		}
	}
	got, err = resolveOptions(options{configFile: file, proxyURL: "http://localhost:4321/", caFile: "override"}, true, true)
	if err != nil || got.proxyURL != "http://localhost:4321" || got.caFile != "override" {
		t.Fatalf("overrides=%+v err=%v", got, err)
	}
}

func TestConfigDefaultHomeCAWithoutServiceKey(t *testing.T) {
	ca, roots := testCA(t)
	t.Setenv("PIPELOCK_HOME", filepath.Dir(ca))
	server := healthServer(t, http.StatusOK, healthyState)
	file := filepath.Join(t.TempDir(), "pipelock.yaml")
	content := "fetch_proxy:\n  listen: '" + strings.TrimPrefix(server.URL, "http://") + "'\ntls_interception:\n  enabled: true\nlicense_file: 'missing-service-license'\n"
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveOptions(options{configFile: file}, false, false)
	if err != nil || resolved.caFile != ca || !resolved.requireIntercept {
		t.Fatalf("resolved=%+v err=%v", resolved, err)
	}
	launched := false
	cmd := newCmd(dependencies{
		launch:      func(_ *cobra.Command, _, _ []string) error { launched = true; return nil },
		systemRoots: func() ([]byte, error) { return roots, nil },
		cacheDir:    func() (string, error) { return t.TempDir(), nil },
	})
	cmd.SetArgs([]string{"--config", file, "--", "command"})
	if err := cmd.Execute(); err != nil || !launched {
		t.Fatalf("default-home launch=%v err=%v", launched, err)
	}
	// A CLI CA override doesn't depend on the service's certificate/key paths.
	staleConfig := strings.Replace(content, "  enabled: true", "  enabled: true\n  ca_cert: missing-service-ca.pem\n  ca_key: missing-service-key.pem", 1)
	if err := os.WriteFile(file, []byte(staleConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	resolved, err = resolveOptions(options{configFile: file, proxyURL: server.URL, caFile: ca}, true, true)
	if err != nil || resolved.caFile != ca {
		t.Fatalf("explicit override=%+v err=%v", resolved, err)
	}
}

func TestConfigHomeMissingRefusesLaunch(t *testing.T) {
	t.Setenv("PIPELOCK_HOME", "")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	file := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(file, []byte("tls_interception:\n  enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	launched := false
	cmd := newCmd(dependencies{launch: func(_ *cobra.Command, _, _ []string) error { launched = true; return nil }})
	cmd.SetArgs([]string{"--config", file, "--", "must-never-start"})
	cmd.SetErr(&bytes.Buffer{})
	if err := cmd.Execute(); launched || err == nil || !strings.Contains(err.Error(), "set --ca explicitly") {
		t.Fatalf("launched=%v err=%v", launched, err)
	}
}
