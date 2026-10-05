// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testCorrelationHeader = "X-Correlation-Id"

func TestValidateEmitCorrelationHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		header  string
		wantErr string
	}{
		{name: "empty is off", header: ""},
		{name: "canonical token", header: testCorrelationHeader},
		{name: "lowercase token", header: "x-correlation-id"},
		{name: "request id", header: "X-Request-Id"},
		{name: "traceparent", header: "Traceparent"},
		{name: "test case tag", header: "X-Test-Case"},
		{name: "tchar punctuation", header: "X-Case!#$%&'*+.^_`|~1"},
		{name: "space in name", header: "X Correlation", wantErr: "valid HTTP header name token"},
		{name: "colon in name", header: "X-Correlation:", wantErr: "valid HTTP header name token"},
		{name: "whitespace only", header: "   ", wantErr: "valid HTTP header name token"},
		{name: "leading space", header: " X-Correlation-Id", wantErr: "valid HTTP header name token"},
		{name: "control char", header: "X-Corr\x01", wantErr: "valid HTTP header name token"},
		{name: "non-ascii", header: "X-Corré", wantErr: "valid HTTP header name token"},
		{name: "authorization", header: "Authorization", wantErr: "credential-bearing"},
		{name: "authorization lowercase", header: "authorization", wantErr: "credential-bearing"},
		{name: "proxy authorization", header: "Proxy-Authorization", wantErr: "credential-bearing"},
		{name: "cookie", header: "Cookie", wantErr: "credential-bearing"},
		{name: "set-cookie", header: "Set-Cookie", wantErr: "credential-bearing"},
		{name: "x-api-key", header: "X-Api-Key", wantErr: "credential-bearing"},
		{name: "connection", header: "Connection", wantErr: "hop-by-hop"},
		{name: "upgrade", header: "Upgrade", wantErr: "hop-by-hop"},
		{name: "transfer-encoding", header: "Transfer-Encoding", wantErr: "hop-by-hop"},
		{name: "te", header: "TE", wantErr: "hop-by-hop"},
		{name: "proxy-connection", header: "Proxy-Connection", wantErr: "hop-by-hop"},
		{name: "host", header: "Host", wantErr: "hop-by-hop"},
		{name: "session token heuristic", header: "X-Session-Token", wantErr: `word "token"`},
		{name: "amz security token heuristic", header: "X-Amz-Security-Token", wantErr: `word "token"`},
		{name: "custom auth heuristic", header: "X-Custom-Auth", wantErr: `word "auth"`},
		{name: "client secret heuristic", header: "X-Client-Secret", wantErr: `word "secret"`},
		{name: "signature heuristic", header: "X-Hub-Signature", wantErr: `word "signature"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := Defaults()
			cfg.Emit.CorrelationHeader = tt.header
			err := cfg.validateEmitCorrelationHeader()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validate(%q) = %v, want nil", tt.header, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validate(%q) = %v, want error containing %q", tt.header, err, tt.wantErr)
			}
		})
	}
}

// A header the operator marked sensitive for request body scanning must not
// be copied into SIEM events either, including one that passes the built-in
// list and name heuristics.
func TestValidateEmitCorrelationHeader_ConfiguredSensitiveHeader(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.RequestBodyScanning.SensitiveHeaders = append(cfg.RequestBodyScanning.SensitiveHeaders, "X-Tenant-Ref")
	cfg.Emit.CorrelationHeader = "x-tenant-ref"
	err := cfg.validateEmitCorrelationHeader()
	if err == nil || !strings.Contains(err.Error(), "sensitive_headers") {
		t.Fatalf("validate = %v, want sensitive_headers rejection", err)
	}
}

// Every default sensitive header must be rejected so a default-config
// operator cannot exfiltrate a credential header into a SIEM by naming it.
func TestValidateEmitCorrelationHeader_RejectsEveryDefaultSensitiveHeader(t *testing.T) {
	t.Parallel()
	base := Defaults()
	base.ApplyDefaults()
	if len(base.RequestBodyScanning.SensitiveHeaders) == 0 {
		t.Fatal("default sensitive_headers is empty; test has nothing to check")
	}
	for _, h := range base.RequestBodyScanning.SensitiveHeaders {
		cfg := Defaults()
		cfg.RequestBodyScanning.SensitiveHeaders = nil // isolate the built-in list
		cfg.Emit.CorrelationHeader = h
		if err := cfg.validateEmitCorrelationHeader(); err == nil {
			t.Errorf("default sensitive header %q accepted as correlation_header", h)
		}
	}
}

func TestEmitCorrelationHeader_DefaultIsOff(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	if cfg.Emit.CorrelationHeader != "" {
		t.Fatalf("Defaults().Emit.CorrelationHeader = %q, want empty (off)", cfg.Emit.CorrelationHeader)
	}
	cfg.ApplyDefaults()
	if cfg.Emit.CorrelationHeader != "" {
		t.Fatalf("ApplyDefaults set CorrelationHeader = %q, want empty (off)", cfg.Emit.CorrelationHeader)
	}
}

func TestEmitCorrelationHeader_NormalizeCanonicalizes(t *testing.T) {
	t.Parallel()
	cfg := Defaults()
	cfg.Emit.CorrelationHeader = "x-correlation-id"
	cfg.ApplyDefaults()
	if cfg.Emit.CorrelationHeader != testCorrelationHeader {
		t.Fatalf("normalized = %q, want %q", cfg.Emit.CorrelationHeader, testCorrelationHeader)
	}

	bad := Defaults()
	bad.Emit.CorrelationHeader = "bad header"
	bad.ApplyDefaults()
	if bad.Emit.CorrelationHeader != "bad header" {
		t.Fatalf("invalid name rewritten to %q; validation must see it verbatim", bad.Emit.CorrelationHeader)
	}
}

func TestEmitCorrelationHeader_LoadYAML(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		yaml    string
		want    string
		wantErr string
	}{
		{name: "omitted", yaml: "emit:\n  instance_id: test\n", want: ""},
		{name: "yaml null", yaml: "emit:\n  correlation_header:\n", want: ""},
		{name: "explicit empty", yaml: "emit:\n  correlation_header: \"\"\n", want: ""},
		{name: "valid", yaml: "emit:\n  correlation_header: x-correlation-id\n", want: testCorrelationHeader},
		{name: "invalid token", yaml: "emit:\n  correlation_header: \"bad header\"\n", wantErr: "valid HTTP header name token"},
		{name: "forbidden", yaml: "emit:\n  correlation_header: Authorization\n", wantErr: "credential-bearing"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(path, []byte("version: 1\nmode: balanced\n"+tt.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Load error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.Emit.CorrelationHeader != tt.want {
				t.Fatalf("CorrelationHeader = %q, want %q", cfg.Emit.CorrelationHeader, tt.want)
			}
		})
	}
}

// correlation_header is telemetry-only and must not move the canonical policy
// hash, matching the other emit output knobs.
func TestEmitCorrelationHeader_ExcludedFromPolicyHash(t *testing.T) {
	t.Parallel()
	a := Defaults()
	a.ApplyDefaults()
	b := Defaults()
	b.Emit.CorrelationHeader = testCorrelationHeader
	b.ApplyDefaults()
	if a.CanonicalPolicyHash() != b.CanonicalPolicyHash() {
		t.Fatal("correlation_header changed the canonical policy hash")
	}
	if a.Emit.Fingerprint() == b.Emit.Fingerprint() {
		t.Fatal("correlation_header did not change the emit fingerprint; reload would not detect the change")
	}
}

// The credential-name heuristic works on words, not substrings: it must reject
// credential-bearing names a substring list misses and must accept harmless
// names that merely contain a credential stem. Every name is checked as
// written, lowercase, and uppercase.
func TestValidateEmitCorrelationHeader_CredentialWords(t *testing.T) {
	t.Parallel()

	rejected := []string{
		"X-Session-Id",
		"X-AccessKey",
		"X-Api_Key",
		"X-Api.Key",
		"X-Bearer",
		"X-Jwt",
		"X-Pwd",
		"X-Pass",
		"Cf-Access-Jwt-Assertion",
		"X-Goog-Iap-Jwt-Assertion",
		"X-Access-Key",
		"X-Secret-Key",
		"X-Private-Key",
		"X-Authn",
		"X-Authz",
		"X-Csrf-Token",
		"X-Xsrf",
		"X-Otp",
		"X-Totp-Code",
		"X-Sig",
		"X-Credentials",
		"X-Pass-Word",
		"X-Sessionid",
		"X-Sessiontoken",
		"X-Apitoken",
		"X-Oauth",
		"X-Tokenid",
	}
	accepted := []string{
		"X-Author",
		"X-Author-Id",
		"X-Authority",
		"X-Request-Id",
		"X-Correlation-Id",
		"X-Test-Case",
		"X-Signal",
		"X-Passthrough-Ref",
		"X-Key-Ref",
		"X-Monkey",
		"Traceparent",
	}
	variants := func(name string) []string {
		return []string{name, strings.ToLower(name), strings.ToUpper(name)}
	}
	for _, base := range rejected {
		for _, name := range variants(base) {
			t.Run("reject/"+name, func(t *testing.T) {
				t.Parallel()
				cfg := Defaults()
				cfg.Emit.CorrelationHeader = name
				err := cfg.validateEmitCorrelationHeader()
				if err == nil || !strings.Contains(err.Error(), "credential-bearing") {
					t.Fatalf("validate(%q) = %v, want credential-bearing rejection", name, err)
				}
			})
		}
	}
	for _, base := range accepted {
		for _, name := range variants(base) {
			t.Run("accept/"+name, func(t *testing.T) {
				t.Parallel()
				cfg := Defaults()
				cfg.Emit.CorrelationHeader = name
				if err := cfg.validateEmitCorrelationHeader(); err != nil {
					t.Fatalf("validate(%q) = %v, want nil", name, err)
				}
			})
		}
	}
}

func TestValidateEmitCorrelationHeader_SubstringFloor(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"X-Tokens", "X-Apikeys", "X-Auth2", "X-Authkey", "X-Myauth", "X-Accesskeys", "X-Sessions", "X-Jwts", "X-Author-Token"} {
		if credentialHeaderWord(name) == "" {
			t.Errorf("%s: want rejected by substring floor", name)
		}
	}
	for _, name := range []string{"X-Author", "X-Authority", "X-Author-Id", "X-Correlation-Id", "X-Request-Id", "X-Trace-Id"} {
		if w := credentialHeaderWord(name); w != "" {
			t.Errorf("%s: want allowed, rejected on %q", name, w)
		}
	}
}
