// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestContinueRemoteHeadersRefused(t *testing.T) {
	for _, typ := range []string{"", continueTypeSSE, continueTypeStreamHTTP} {
		for _, tc := range []struct {
			name    string
			headers interface{}
		}{
			{"mapping", map[string]interface{}{"Authorization": "Bearer test-only-value"}},
			{"string mapping", map[string]string{"X-Tenant": "test-only-value"}},
			{"scalar", "test-only-value"},
			{"list", []interface{}{"test-only-value"}},
			{"non-string value", map[string]interface{}{"X-Tenant": 7}},
		} {
			t.Run(typ+"/"+tc.name, func(t *testing.T) {
				server := map[string]interface{}{
					mcpFieldURL:     "https://api.vendor.example/mcp",
					mcpFieldHeaders: tc.headers,
				}
				if typ != "" {
					server[mcpFieldType] = typ
				}
				before, err := yaml.Marshal(server)
				if err != nil {
					t.Fatal(err)
				}
				result, err := wrapContinueServer(server, "/usr/bin/pipelock", "")
				if err == nil || result != nil {
					t.Fatalf("remote headers produced a wrapper: result=%v error=%v", result, err)
				}
				for _, want := range []string{"Continue", "headers", "--header-file"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("refusal %q does not explain %q", err, want)
					}
				}
				if strings.Contains(err.Error(), "test-only-value") {
					t.Fatal("refusal disclosed a header value")
				}
				after, marshalErr := yaml.Marshal(server)
				if marshalErr != nil || !bytes.Equal(before, after) {
					t.Fatalf("refusal mutated the input: error=%v", marshalErr)
				}
			})
		}
	}
}

func TestContinueRemoteWithoutHeadersUnchanged(t *testing.T) {
	for _, typ := range []string{"", continueTypeSSE, continueTypeStreamHTTP} {
		for _, tc := range []struct {
			name    string
			headers interface{}
		}{
			{"null", nil},
			{"empty mapping", map[string]interface{}{}},
			{"empty string mapping", map[string]string{}},
		} {
			t.Run(typ+"/"+tc.name, func(t *testing.T) {
				server := map[string]interface{}{
					mcpFieldURL: "https://api.vendor.example/mcp",
					"env":       map[string]interface{}{"TENANT": "test-only-value"},
				}
				if typ != "" {
					server[mcpFieldType] = typ
				}
				baseline, err := wrapContinueServer(server, "/usr/bin/pipelock", "policy.yaml")
				if err != nil {
					t.Fatal(err)
				}
				server[mcpFieldHeaders] = tc.headers
				wrapped, err := wrapContinueServer(server, "/usr/bin/pipelock", "policy.yaml")
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(wrapped[mcpFieldHeaders], tc.headers) {
					t.Fatal("empty headers field was not preserved")
				}
				delete(wrapped, mcpFieldHeaders)
				if !reflect.DeepEqual(wrapped, baseline) {
					t.Fatalf("empty headers changed the launch: got %v, want %v", wrapped, baseline)
				}
				want := []string{"mcp", "proxy", "--config", "policy.yaml", "--env", "TENANT", "--upstream", "https://api.vendor.example/mcp"}
				if got := commandArgStrings(wrapped[mcpFieldArgs]); !reflect.DeepEqual(got, want) {
					t.Fatalf("launch args = %v, want %v", got, want)
				}
			})
		}
	}
}

func TestContinueInstallHeadersRefusalPreservesEveryFile(t *testing.T) {
	for _, location := range []string{"global", "block"} {
		for _, shape := range []string{"fresh", "self", "foreign", "self-misleading-metadata", "self-unknown-argument"} {
			for _, dryRun := range []bool{false, true} {
				name := location + "/" + shape
				if dryRun {
					name += "/dry-run"
				}
				t.Run(name, func(t *testing.T) {
					home := t.TempDir()
					t.Setenv("HOME", home)
					global := filepath.Join(home, continueDirname, continueConfigName)
					blocks := filepath.Join(home, continueDirname, continueMCPDirname)
					if err := os.MkdirAll(blocks, 0o750); err != nil {
						t.Fatal(err)
					}
					block := filepath.Join(blocks, "remote.yaml")
					for _, path := range []string{global, block} {
						if err := os.WriteFile(path, []byte(continueStdioFixture), 0o600); err != nil {
							t.Fatal(err)
						}
					}
					server := map[string]interface{}{mcpFieldURL: "https://api.vendor.example/mcp"}
					if shape != "fresh" {
						exe, err := resolvePipelockBinary()
						if err != nil {
							t.Fatal(err)
						}
						server, err = wrapContinueServer(server, exe, "")
						if err != nil {
							t.Fatal(err)
						}
						if shape == "foreign" {
							server[mcpFieldCommand] = "/nonexistent/older-proxy"
						}
						if shape == "self-misleading-metadata" {
							server[mcpFieldPipelock] = map[string]interface{}{"original_type": vsTypeStdio, "original_command": "node"}
						}
						if shape == "self-unknown-argument" {
							server[mcpFieldArgs] = append(commandArgStrings(server[mcpFieldArgs]), "--unknown-proxy-option")
						}
					}
					// Match the old installer's output: credentials remain outside
					// argv and are absent from the restoration metadata.
					server[mcpFieldHeaders] = map[string]interface{}{"Authorization": "Bearer test-only-value"}
					data, err := yaml.Marshal(map[string]interface{}{continueServersKey: []interface{}{
						map[string]interface{}{"name": "local", mcpFieldCommand: "node"}, server,
					}})
					if err != nil {
						t.Fatal(err)
					}
					target := global
					if location == "block" {
						target = block
					}
					if err := os.WriteFile(target, data, 0o600); err != nil {
						t.Fatal(err)
					}
					before := snapshotTree(t, home)
					cmd := ContinueCmd()
					var output bytes.Buffer
					cmd.SetOut(&output)
					cmd.SetErr(&output)
					args := []string{"install"}
					if dryRun {
						args = append(args, "--dry-run")
					}
					cmd.SetArgs(args)
					err = cmd.Execute()
					if err == nil {
						t.Fatal("install reported success for an unsupported header entry")
					}
					if !strings.Contains(err.Error(), target) || !strings.Contains(err.Error(), "mcpServers[1]") {
						t.Fatalf("error does not locate refused entry: %v", err)
					}
					if strings.Contains(output.String()+err.Error(), "test-only-value") {
						t.Fatal("refusal disclosed credentials")
					}
					if after := snapshotTree(t, home); !reflect.DeepEqual(before, after) {
						t.Fatal("refusal changed configuration, backup, or sidecar files")
					}
				})
			}
		}
	}
}

func TestContinueStdioHeadersRemainUnchanged(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, continueConfigName)
	server := map[string]interface{}{
		mcpFieldCommand: "node",
		mcpFieldArgs:    []interface{}{"server.js", "--upstream", "https://api.vendor.example/mcp"},
		mcpFieldHeaders: map[string]interface{}{"X-Example": "test-only-value"},
	}
	data, err := yaml.Marshal(map[string]interface{}{continueServersKey: []interface{}{server}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"install", "--path", path, "--mcp-dir", filepath.Join(home, "blocks")}
	if err := runContinueCmd(t, args...); err != nil {
		t.Fatal(err)
	}
	wrapped := readContinueServers(t, path)[0]
	if !reflect.DeepEqual(wrapped[mcpFieldHeaders], server[mcpFieldHeaders]) {
		t.Fatal("stdio install changed an unrelated headers field")
	}
	if got := afterSeparator(commandArgStrings(wrapped[mcpFieldArgs])); !reflect.DeepEqual(got, []string{"node", "server.js", "--upstream", "https://api.vendor.example/mcp"}) {
		t.Fatalf("stdio child invocation changed: %v", got)
	}
	before := snapshotTree(t, home)
	if err := runContinueCmd(t, args...); err != nil {
		t.Fatalf("stdio rerun: %v", err)
	}
	if after := snapshotTree(t, home); !reflect.DeepEqual(before, after) {
		t.Fatal("stdio rerun changed an already wrapped entry")
	}
}
