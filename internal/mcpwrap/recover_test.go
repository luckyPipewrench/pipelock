// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcpwrap

import (
	"errors"
	"strings"
	"testing"
)

func TestRecoverInner_NotProxyInvocation(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"nil", nil},
		{"empty", []string{}},
		{"too short", []string{"mcp"}},
		{"wrong verb", []string{"mcp", "scan", "--", "srv"}},
		{"wrong subcommand", []string{"proxy", "mcp", "--", "srv"}},
		{"leading flag", []string{"--config", "x", "mcp", "proxy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RecoverInner(tc.args); !errors.Is(err, ErrNotProxyInvocation) {
				t.Fatalf("RecoverInner(%v) err = %v, want ErrNotProxyInvocation", tc.args, err)
			}
		})
	}
}

func TestRecoverInner_Stdio(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		wantCmd  string
		wantArgs []string
	}{
		{
			"bare command and args",
			[]string{"mcp", "proxy", "--", "node", "server.js"},
			"node",
			[]string{"server.js"},
		},
		{
			"command with no args",
			[]string{"mcp", "proxy", "--", "node"},
			"node", nil,
		},
		{
			"all recognized flags are discarded",
			[]string{"mcp", "proxy", "--config", "/c.yaml", "--sandbox", "--workspace", "/w", "--env", "API_KEY", "--", "node", "-x", "y"},
			"node",
			[]string{"-x", "y"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RecoverInner(tc.args)
			if err != nil {
				t.Fatalf("RecoverInner: %v", err)
			}
			if got.Transport != TransportStdio {
				t.Fatalf("transport = %v, want stdio", got.Transport)
			}
			if got.Command != tc.wantCmd {
				t.Fatalf("command = %q, want %q", got.Command, tc.wantCmd)
			}
			if strings.Join(got.Args, "\x00") != strings.Join(tc.wantArgs, "\x00") {
				t.Fatalf("args = %#v, want %#v", got.Args, tc.wantArgs)
			}
		})
	}
}

func TestRecoverInner_ArgsAreCopied(t *testing.T) {
	input := []string{"mcp", "proxy", "--", "node", "server.js"}
	got, err := RecoverInner(input)
	if err != nil {
		t.Fatalf("RecoverInner: %v", err)
	}
	got.Args[0] = "mutated"
	if input[4] != "server.js" {
		t.Fatalf("RecoverInner aliased the input slice: %#v", input)
	}
}

func TestRecoverInner_Upstream(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"bare upstream", []string{"mcp", "proxy", "--upstream", "https://api.vendor.example/mcp"}, "https://api.vendor.example/mcp"},
		{"http upstream", []string{"mcp", "proxy", "--upstream", "http://api.vendor.example/mcp"}, "http://api.vendor.example/mcp"},
		{"ws upstream", []string{"mcp", "proxy", "--upstream", "ws://api.vendor.example/mcp"}, "ws://api.vendor.example/mcp"},
		{"upstream after flags", []string{"mcp", "proxy", "--config", "/c.yaml", "--env", "TOKEN", "--upstream", "wss://api.vendor.example/mcp"}, "wss://api.vendor.example/mcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RecoverInner(tc.args)
			if err != nil {
				t.Fatalf("RecoverInner: %v", err)
			}
			if got.Transport != TransportUpstream {
				t.Fatalf("transport = %v, want upstream", got.Transport)
			}
			if got.UpstreamURL != tc.want {
				t.Fatalf("upstream = %q, want %q", got.UpstreamURL, tc.want)
			}
		})
	}
}

func TestRecoverInner_Refusals(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		wantSub string
	}{
		{"header sidecar credentials", []string{"mcp", "proxy", "--header-file", "/p.headers", "--upstream", "https://h/mcp"}, "header sidecar"},
		{"unknown flag", []string{"mcp", "proxy", "--bogus", "x", "--", "node"}, "does not recognize"},
		{"bare token before separator", []string{"mcp", "proxy", "node"}, "does not recognize"},
		{"empty tail after separator", []string{"mcp", "proxy", "--"}, "no child command after"},
		{"empty first tail element", []string{"mcp", "proxy", "--", ""}, "no child command after"},
		{"mixes upstream and separator", []string{"mcp", "proxy", "--upstream", "https://h/mcp", "--", "node"}, "mixes --upstream"},
		{"upstream missing value", []string{"mcp", "proxy", "--upstream"}, "--upstream with no URL"},
		{"empty upstream value", []string{"mcp", "proxy", "--upstream", ""}, "empty --upstream"},
		{"value flag missing value", []string{"mcp", "proxy", "--config"}, "has no value"},
		{"no child or upstream", []string{"mcp", "proxy", "--config", "/c.yaml"}, "no child command or upstream"},
		{"nested proxy", []string{"mcp", "proxy", "--", "older-proxy", "mcp", "proxy", "--", "node"}, "another proxy invocation"},
		{"repeated upstream", []string{"mcp", "proxy", "--upstream", "https://a.example/mcp", "--upstream", "https://b.example/mcp"}, "repeats --upstream"},
		{"flag instead of upstream", []string{"mcp", "proxy", "--upstream", "--header-file"}, "invalid --upstream URL"},
		{"malformed upstream", []string{"mcp", "proxy", "--upstream", "https://%/mcp"}, "invalid --upstream URL"},
		{"upstream without host", []string{"mcp", "proxy", "--upstream", "https:///mcp"}, "invalid --upstream URL"},
		{"unsupported upstream scheme", []string{"mcp", "proxy", "--upstream", "file://example/mcp"}, "unsupported --upstream URL scheme"},
		{"flag instead of config", []string{"mcp", "proxy", "--config", "--header-file", "--", "node"}, "has no value"},
		{"empty env value", []string{"mcp", "proxy", "--env", "", "--", "node"}, "has no value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := RecoverInner(tc.args)
			if err == nil {
				t.Fatalf("RecoverInner(%v) = nil error, want refusal", tc.args)
			}
			if !errors.Is(err, ErrCannotNormalize) {
				t.Fatalf("refusal lost its typed signal: %v", err)
			}
			if errors.Is(err, ErrNotProxyInvocation) {
				t.Fatalf("refusal misclassified as not-a-proxy: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("err = %q, want it to mention %q", err.Error(), tc.wantSub)
			}
			if !strings.Contains(err.Error(), "cannot normalize wrapper") {
				t.Fatalf("err = %q, want the refusal prefix", err.Error())
			}
		})
	}
}

func TestRecoverInnerRefusalOmitsArgumentValues(t *testing.T) {
	const opaqueValue = "--unsupported=private-value"
	_, err := RecoverInner([]string{"mcp", "proxy", opaqueValue, "--", "node"})
	if !errors.Is(err, ErrCannotNormalize) || strings.Contains(err.Error(), opaqueValue) {
		t.Fatalf("refusal must omit unknown argument values: %v", err)
	}
}

func TestWrapServerRecoversForeignInvocation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		command string
		url     string
	}{
		{"stdio", []string{"mcp", "proxy", "--", "node", "server.js"}, "node", ""},
		{"remote", []string{"mcp", "proxy", "--upstream", "https://api.vendor.example/mcp"}, "", "https://api.vendor.example/mcp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := map[string]interface{}{
				FieldCommand:  "/nonexistent/older-proxy",
				FieldArgs:     tc.args,
				FieldPipelock: map[string]interface{}{"original_command": "wrong-command"},
			}
			wrapped, meta, plan, err := WrapServer(server, "/current/proxy", "new.yaml", "config.yaml", "example")
			if err != nil {
				t.Fatal(err)
			}
			if meta.OriginalCommand != tc.command || meta.OriginalURL != tc.url {
				t.Fatalf("metadata did not come from invocation: %+v", meta)
			}
			if wrapped[FieldCommand] != "/current/proxy" || plan != nil {
				t.Fatalf("unexpected wrapper or sidecar: %v %v", wrapped, plan)
			}
			if _, ok := wrapped[FieldPipelock]; ok {
				t.Fatal("stale restoration marker survived")
			}
		})
	}
}

func TestWrapServerForeignRecoveryErrors(t *testing.T) {
	for _, server := range []map[string]interface{}{
		{FieldCommand: "/nonexistent/older-proxy", FieldArgs: []string{"mcp", "proxy", "--header-file", "credentials.headers"}},
		{FieldCommand: []string{"/nonexistent/older-proxy", "mcp", "proxy"}, FieldArgs: []interface{}{false}},
	} {
		wrapped, meta, plan, err := WrapServer(server, "/current/proxy", "new.yaml", "config.yaml", "example")
		if err == nil || wrapped != nil || meta != nil || plan != nil {
			t.Fatalf("invalid foreign wrapper produced a write plan: %v %v %v %v", wrapped, meta, plan, err)
		}
	}
}
