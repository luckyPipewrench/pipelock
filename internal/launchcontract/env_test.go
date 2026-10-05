// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package launchcontract

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestProfiles(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		profile Profile
		ca      string
		count   int
	}{
		{"contain", Contain, "bundle", 16},
		{"contain empty CA retains legacy assignments", Contain, "", 16},
		{"sandbox", Sandbox, "", 6},
		{"exec", Exec, "bundle", 20},
		{"exec no CA", Exec, "", 10},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			additive := ""
			if tt.profile == Exec && tt.ca != "" {
				additive = "pipelock-ca"
			}
			vars := Vars(tt.profile, "proxy", "bypass", tt.ca, additive)
			if len(vars) != tt.count {
				t.Fatalf("vars=%v, want %d entries", vars, tt.count)
			}
			seen := make(map[string]bool)
			for _, v := range vars {
				if seen[v.Name] {
					t.Fatalf("duplicate %s", v.Name)
				}
				seen[v.Name] = true
				if v.Value != "proxy" && v.Value != "bypass" && v.Value != tt.ca && v.Value != additive && v.Value != "1" {
					t.Fatalf("unexpected value: %v", v)
				}
			}
		})
	}
}

func TestMerge(t *testing.T) {
	t.Parallel()
	input := []string{"KEEP=secret-not-printed", "HTTP_PROXY=old", "Http_proxy=old", "CUSTOM_PROXY=old", "no_proxy=*", "npm_config_noproxy=*", "NPM_CONFIG_CAFILE=old", "SSL_CERT_FILE=old", "CODEX_CA_CERTIFICATE=old", "DENO_CERT=old", "NODE_USE_ENV_PROXY=0", "NODE_OPTIONS=--trace-warnings", "invalid"}
	vars := Vars(Exec, "proxy", "", "bundle", "pipelock-ca")
	want := append([]string{"KEEP=secret-not-printed", "NODE_OPTIONS=--trace-warnings"}, Entries(vars)...)
	if got := Merge(input, vars); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	got := Merge(input, Vars(Exec, "proxy", "", "", ""))
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, "CA_CERTIFICATE=") || strings.Contains(joined, "noproxy=*") || strings.Contains(joined, "NPM_CONFIG_CAFILE=") {
		t.Fatalf("stale CA override retained: %v", got)
	}
}

func TestDocumentationParity(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		path    string
		profile Profile
		marker  string
	}{
		{"docs/contain-cli.md", Contain, "contain"},
		{"docs/guides/claude-code.md", Exec, "exec"},
		{"docs/cli/exec.md", Exec, "exec"},
	} {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(tt.path)))
			if err != nil {
				t.Fatal(err)
			}
			begin := "<!-- BEGIN launchcontract:" + tt.marker + " -->\n"
			end := "<!-- END launchcontract:" + tt.marker + " -->"
			_, tail, found := strings.Cut(strings.ReplaceAll(string(data), "\r\n", "\n"), begin)
			got, _, ended := strings.Cut(tail, end)
			var want strings.Builder
			want.WriteString("| Variable | Value |\n|---|---|\n")
			additive := ""
			if tt.profile == Exec {
				additive = "Pipelock CA file"
			}
			for _, v := range Vars(tt.profile, "proxy URL", "explicit bypass list", "combined CA bundle", additive) {
				fmt.Fprintf(&want, "| `%s` | %s |\n", v.Name, v.Value)
			}
			if !found || !ended || got != want.String() {
				t.Fatalf("documented %s contract differs from internal/launchcontract: got:\n%s\nwant:\n%s", tt.marker, got, want.String())
			}
		})
	}
}
