// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHeaderDiagnosticsOmitSubmittedValues(t *testing.T) {
	t.Parallel()
	const marker = "private-header-value"
	tests := []struct {
		name  string
		lines []string
	}{
		{name: "missing separator", lines: []string{marker}},
		{name: "empty name", lines: []string{": " + marker}},
		{name: "invalid name", lines: []string{marker + " bad: value"}},
		{name: "invalid value", lines: []string{"Authorization: " + marker + "\n"}},
		{name: "managed header", lines: []string{"Host: " + marker}},
		{name: "duplicate credential", lines: []string{"Authorization: first", "authorization: " + marker}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			headers, err := parseHeaderFlags(tt.lines)
			if err == nil || headers != nil {
				t.Fatal("invalid headers must return an error and no headers")
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatal("diagnostic contains submitted header data")
			}
		})
	}
}

func TestMCPHeaderDiagnosticsAcrossSources(t *testing.T) {
	const marker = "private-header-value"
	t.Setenv(testIdentityCarrier, marker+"\n")
	path := filepath.Join(t.TempDir(), "headers")
	if err := os.WriteFile(path, []byte("Authorization: "+marker+"\x7f\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sources := []struct {
		name string
		args []string
	}{
		{name: "flag", args: []string{"--header", "Authorization: " + marker + "\n"}},
		{name: "file", args: []string{"--header-file", path}},
		{name: "carrier", args: []string{"--header-carrier", "Authorization=" + testIdentityCarrier}},
	}
	for _, source := range sources {
		t.Run(source.name, func(t *testing.T) {
			for _, command := range []string{"proxy", "inspect"} {
				t.Run(command, func(t *testing.T) {
					args := append([]string{"--upstream", "https://api.vendor.example/mcp"}, source.args...)
					var stdout, stderr string
					var err error
					if command == "proxy" {
						stdout, stderr, err = runMCPProxyCommandWithArgs(t, append([]string{"proxy"}, args...))
					} else {
						stdout, err = runIdentityCmd(t, identityProbe{}, append([]string{"inspect"}, args...)...)
					}
					if err == nil {
						t.Fatal("invalid headers must refuse before dialing")
					}
					if !strings.Contains(err.Error(), "value contains invalid characters") {
						t.Fatalf("unexpected diagnostic: %v", err)
					}
					if strings.Contains(stdout+stderr+err.Error(), marker) {
						t.Fatal("command diagnostic contains submitted header data")
					}
				})
			}
		})
	}
	valid, err := parseHeaderFlags([]string{"Authorization: " + marker})
	if err != nil || valid.Get("Authorization") != marker || len(valid) != 1 {
		t.Fatal("valid header value must remain intact")
	}
}

func TestMCPIdentityInspectRejectsDuplicateHeadersBeforeDial(t *testing.T) {
	probe := identityProbe{dial: func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("invalid headers must not dial")
		return nil, nil
	}}
	_, err := runIdentityCmd(t, probe, "inspect", "--upstream", "https://api.vendor.example/mcp",
		"--header", "Authorization: first", "--header", "authorization: second")
	if err == nil || !strings.Contains(err.Error(), "duplicate header") {
		t.Fatalf("want duplicate header refusal, got %v", err)
	}
}

func TestCarrierMappingDiagnosticsOmitSubmittedValues(t *testing.T) {
	t.Parallel()
	const marker = "private-carrier-value"
	for _, flag := range []string{"--header-carrier", "--env-carrier"} {
		for _, mapping := range []string{"Authorization: Bearer " + marker, "Authorization=Bearer " + marker, "TOKEN=" + marker + "=extra"} {
			t.Run(flag+mapping, func(t *testing.T) {
				t.Parallel()
				_, _, err := parseCarrierMapping(flag, mapping)
				if err == nil || strings.Contains(err.Error(), marker) {
					t.Fatal("invalid mapping must refuse without submitted data")
				}
			})
		}
	}
}
