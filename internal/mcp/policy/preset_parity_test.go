// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
)

func TestPresetToolPoliciesCoverEquivalentProtectedPathOperations(t *testing.T) {
	presets := []string{
		"audit.yaml",
		"balanced.yaml",
		"claude-code.yaml",
		"cursor.yaml",
		"generic-agent.yaml",
		"hostile-model.yaml",
		"strict.yaml",
	}
	for _, preset := range presets {
		t.Run(preset, func(t *testing.T) {
			path, err := filepath.Abs(filepath.Join("..", "..", "..", "configs", preset))
			if err != nil {
				t.Fatal(err)
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("load preset: %v", err)
			}
			pc := New(cfg.MCPToolPolicy)
			if pc == nil {
				t.Fatal("preset tool policy is disabled")
			}

			for _, args := range []any{
				map[string]any{"file": "main.go", "edits": []map[string]string{{"old": "x := 1", "new": "x := 2"}}},
				map[string]any{"path": "main.go", "content": "package main\n"},
				map[string]any{"patch": ""},
				map[string]any{},
				"please update the readme for me",
			} {
				assertPolicyArgsAllowed(t, pc, filePatchToolPattern, args)
			}

			credentialAction := effectiveRuleAction(t, cfg.MCPToolPolicy, "Credential File Access")
			for _, toolName := range strings.Split(fileReadToolPattern, "|") {
				assertPolicyCall(t, pc, toolName, map[string]any{
					"path": "/home/user/.ssh/id_rsa",
				}, "Credential File Access", credentialAction)
			}
			for _, toolName := range strings.Split(fileLinkToolPattern, "|") {
				for _, direction := range []string{"target", "linkPath"} {
					args := map[string]any{"target": "/tmp/target", "linkPath": "/tmp/link"}
					args[direction] = "/home/user/.ssh/id_rsa"
					assertPolicyCall(t, pc, toolName, args, "Credential File Access", credentialAction)
				}
			}

			checks := []struct {
				path         string
				moveRule     string
				copyRule     string
				baselineRule string
			}{
				{path: "/etc/systemd/system/p.service", moveRule: "Persistence Path Write", copyRule: "Protected Path Copy", baselineRule: "Persistence Path Write"},
				{path: "/home/user/.bashrc", moveRule: "Shell Profile Modification", copyRule: "Protected Path Copy", baselineRule: "Shell Profile Modification"},
				{path: "/var/log/audit.log", moveRule: "Audit Log Move", copyRule: "Audit Log Copy", baselineRule: "Audit Log Tampering"},
				{path: "/var/lib/pipelock/evidence/evidence-proxy-1.jsonl", moveRule: "Audit Log Move", copyRule: "Audit Log Copy", baselineRule: "Audit Log Tampering"},
			}
			for _, check := range checks {
				wantAction := effectiveRuleAction(t, cfg.MCPToolPolicy, check.baselineRule)
				protectedPrefix := "Protected Path"
				if check.baselineRule == "Audit Log Tampering" {
					protectedPrefix = "Audit Log"
				}
				for _, class := range []struct {
					pattern string
					suffix  string
				}{
					{pattern: fileDeleteToolPattern, suffix: "Delete"},
					{pattern: fileMetadataToolPattern, suffix: "Metadata Change"},
				} {
					for _, toolName := range strings.Split(class.pattern, "|") {
						assertPolicyCall(t, pc, toolName, map[string]any{
							"path": check.path,
						}, protectedPrefix+" "+class.suffix, wantAction)
					}
				}
				for _, toolName := range strings.Split(fileLinkToolPattern, "|") {
					for _, direction := range []string{"target", "linkPath"} {
						args := map[string]any{"target": "/tmp/target", "linkPath": "/tmp/link"}
						args[direction] = check.path
						assertPolicyCall(t, pc, toolName, args, protectedPrefix+" Link Creation", wantAction)
					}
				}
				for _, toolName := range strings.Split(fileWriteToolPattern, "|") {
					writeArgs := map[string]any{"path": check.path, "content": "replacement"}
					switch {
					case strings.HasPrefix(check.path, "/var/lib/pipelock"):
						assertPolicyCall(t, pc, toolName, writeArgs, "Audit Log Write", wantAction)
					case strings.HasPrefix(check.path, "/var/log"):
						// An application appending to its own log is ordinary.
						assertPolicyAllowed(t, pc, toolName, writeArgs)
					default:
						assertPolicyCall(t, pc, toolName, writeArgs, check.baselineRule, wantAction)
					}
				}
				if check.baselineRule != "Audit Log Tampering" {
					assertPolicyArgs(t, pc, filePatchToolPattern, map[string]any{
						"path": check.path, "content": "replacement",
					}, check.baselineRule, wantAction)
					assertPolicyArgs(t, pc, filePatchToolPattern, map[string]any{
						"patch": "--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-old\n+new\n", "path": check.path,
					}, check.baselineRule, wantAction)
				}
				patchRule := check.baselineRule
				if check.baselineRule == "Audit Log Tampering" {
					patchRule = "Audit Log Patch"
				}
				for _, patch := range protectedPatchTargetFormats(check.path) {
					assertPolicyCall(t, pc, filePatchToolPattern, map[string]any{"patch": patch}, patchRule, wantAction)
				}
				// Alternate spellings the server resolves to the same protected file.
				for _, alias := range []string{
					"/" + check.path,
					"/." + check.path,
					"/tmp/.." + check.path,
					strings.ReplaceAll(check.path, "/", "//"),
					strings.ReplaceAll(check.path, "/", "/./"),
				} {
					assertPolicyCall(t, pc, "delete_file", map[string]any{"path": alias}, protectedPrefix+" Delete", wantAction)
				}
				for _, direction := range []string{"source", "destination"} {
					args := map[string]any{"source": "/tmp/staged", "destination": "/tmp/backup"}
					args[direction] = check.path
					assertPolicyCall(t, pc, "move_file", args, check.moveRule, wantAction)
				}
				for _, toolName := range strings.Split(fileCopyToolPattern, "|") {
					assertPolicyCall(t, pc, toolName, map[string]any{
						"source": "/tmp/staged", "destination": check.path,
					}, check.copyRule, wantAction)
				}
			}

			uninspectableAction := effectiveRuleAction(t, cfg.MCPToolPolicy, "Persistence Path Write")
			for _, args := range []any{
				map[string]any{"patch": "diff --git a/file"},
				map[string]any{"patch": "*** Begin Patch\n*** Update File: README.md\n@@\n-old\n+new\n"},
			} {
				assertPolicyArgs(t, pc, filePatchToolPattern, args, uninspectablePatchTargetsRule, uninspectableAction)
			}

			for _, safe := range []struct {
				toolName string
				args     map[string]any
			}{
				{toolName: "delete_file", args: map[string]any{"path": "/home/v/myapp/app.log"}},
				{toolName: "chmod_file", args: map[string]any{"path": "/tmp/build.log"}},
				{toolName: "delete_file", args: map[string]any{"path": "/home/v/data/train.jsonl"}},
				{toolName: "move_file", args: map[string]any{"source": "app.log", "destination": "app.log.1"}},
				{toolName: filePatchToolPattern, args: map[string]any{"patch": "--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-source ~/.bashrc\n+describe source ~/.bashrc\n"}},
				{toolName: filePatchToolPattern, args: map[string]any{"patch": "diff --git a/.bashrc b/backup.txt\nsimilarity index 100%\ncopy from .bashrc\ncopy to backup.txt\n"}},
				{toolName: filePatchToolPattern, args: map[string]any{"patch": "*** Begin Patch\n*** Update File: migrations/001.sql\n@@\n--- drop the legacy index\n CREATE INDEX i ON t (id);\n*** End Patch"}},
				{toolName: filePatchToolPattern, args: map[string]any{"patch": "--- a/schema.sql\n+++ b/schema.sql\n@@ -1,2 +1,1 @@\n--- old note\n CREATE TABLE t (id int);\n"}},
			} {
				assertPolicyAllowed(t, pc, safe.toolName, safe.args)
			}
		})
	}
}

func assertPolicyArgsAllowed(t *testing.T, pc *Config, toolName string, args any) {
	t.Helper()
	if v := pc.CheckRequest(toolCallRequest(t, toolName, args)); v.Matched {
		t.Fatalf("%s arguments matched rules %v, want allowed", toolName, v.Rules)
	}
}

func assertPolicyArgs(t *testing.T, pc *Config, toolName string, args any, wantRule, wantAction string) {
	t.Helper()
	v := pc.CheckRequest(toolCallRequest(t, toolName, args))
	if !v.Matched || !slices.Equal(v.Rules, []string{wantRule}) {
		t.Fatalf("%s verdict = %+v, want only rule %q", toolName, v, wantRule)
	}
	if v.Action != wantAction {
		t.Fatalf("%s action = %q, want preserved action %q", toolName, v.Action, wantAction)
	}
}

func protectedPatchTargetFormats(target string) []string {
	return []string{
		"diff --git a/file b" + target + "\n--- a/file\n+++ b" + target + "\n@@ -1 +1 @@\n-old\n+new\n",
		"diff --git a/file b" + target + "\nsimilarity index 100%\nrename from file\nrename to " + strings.TrimPrefix(target, "/") + "\n",
		"diff --git a/file b" + target + "\nsimilarity index 100%\ncopy from file\ncopy to " + strings.TrimPrefix(target, "/") + "\n",
		"diff --git a" + target + " b" + target + "\nold mode 100644\nnew mode 100755\n",
		"diff --git a" + target + " b" + target + "\nnew file mode 100644\nindex 0000000..1111111\n--- /dev/null\n+++ b" + target + "\n@@ -0,0 +1 @@\n+new\n",
		"diff --git a" + target + " b" + target + "\ndeleted file mode 100644\nindex 1111111..0000000\n--- a" + target + "\n+++ /dev/null\n@@ -1 +0,0 @@\n-old\n",
		"diff --git a" + target + " b" + target + "\nindex 1111111..2222222 100644\nGIT binary patch\nliteral 1\nAcmZQz\n",
		"diff --git a" + target + " b" + target + "\nindex 1111111..2222222 100644\nBinary files a" + target + " and b" + target + " differ\n",
		"diff --git a" + target + " b" + target + "\nindex 1111111..2222222 100644\n@@ -1 +1 @@\n-old\n+new\n",
		"*** Begin Patch\n*** Update File: file\n*** Move to: " + target + "\n@@\n-old\n+new\n*** End Patch",
	}
}

func assertPolicyAllowed(t *testing.T, pc *Config, toolName string, args map[string]any) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	extracted := jsonrpc.ExtractStringsFromJSONResult(raw)
	if v := pc.CheckToolCallWithArgs(toolName, extracted.Strings, raw); v.Matched {
		t.Fatalf("%s(%s) matched rules %v, want allowed", toolName, raw, v.Rules)
	}
}

func effectiveRuleAction(t *testing.T, cfg config.MCPToolPolicy, name string) string {
	t.Helper()
	for _, rule := range cfg.Rules {
		if rule.Name == name {
			if rule.Action != "" {
				return rule.Action
			}
			return cfg.Action
		}
	}
	t.Fatalf("rule %q not found", name)
	return ""
}

func assertPolicyCall(t *testing.T, pc *Config, toolName string, args map[string]any, wantRule, wantAction string) {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	extracted := jsonrpc.ExtractStringsFromJSONResult(raw)
	v := pc.CheckToolCallWithArgs(toolName, extracted.Strings, raw)
	if !v.Matched || !slices.Contains(v.Rules, wantRule) {
		t.Fatalf("%s(%s) verdict = %+v, want rule %q", toolName, raw, v, wantRule)
	}
	if v.Action != wantAction {
		t.Fatalf("%s(%s) action = %q, want preserved action %q", toolName, raw, v.Action, wantAction)
	}
}
