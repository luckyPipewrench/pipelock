// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

const fileMutationRuleName = "Credential File Write"

func TestCredentialDestinationFileStreams(t *testing.T) {
	for _, preset := range []string{"built-in", "audit", "balanced", "claude-code", "cursor", "generic-agent", "hostile-model", "strict"} {
		t.Run(preset, func(t *testing.T) {
			cfg := config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()}
			if preset != "built-in" {
				loaded, err := config.Load(filepath.Join("..", "..", "..", "configs", preset+".yaml"))
				if err != nil {
					t.Fatal(err)
				}
				cfg = loaded.MCPToolPolicy
			}
			pc := New(cfg)
			wantAction := effectiveRuleAction(t, cfg, "Credential File Access")
			for _, path := range []string{`.ssh\config`, `.ssh\rc`, `.aws\credentials`, `.aws\config`, `.kube\config`, `.docker\config.json`, `.netrc`} {
				for _, stream := range []string{"::$DATA", ":fixture"} {
					target := `C:\Users\demo\` + path + stream
					for _, call := range []struct {
						tool string
						args map[string]any
					}{
						{"write_file", map[string]any{"path": target, "content": "fixture"}},
						{"edit_block", map[string]any{"file_path": target, "old_string": "old", "new_string": "new"}},
						{"move_file", map[string]any{"source": "notes.txt", "destination": target}},
						{"copy_file", map[string]any{"source": "notes.txt", "destination": target}},
						{"apply_patch", map[string]any{"path": target, "content": "fixture"}},
					} {
						assertPolicyCall(t, pc, call.tool, call.args, fileMutationRuleName, wantAction)
					}
				}
			}
			for _, path := range []string{`.kube\config.example::$DATA`, `.docker\config.json.example:fixture`, `notes.txt::$DATA`} {
				assertPolicyAllowed(t, pc, "write_file", map[string]any{"path": `C:\Users\demo\` + path, "content": "fixture"})
			}
		})
	}
}

func TestCredentialDestinationPolicyParity(t *testing.T) {
	for _, preset := range []string{"built-in", "audit", "balanced", "claude-code", "cursor", "generic-agent", "hostile-model", "strict"} {
		t.Run(preset, func(t *testing.T) {
			cfg := config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()}
			if preset != "built-in" {
				loaded, err := config.Load(filepath.Join("..", "..", "..", "configs", preset+".yaml"))
				if err != nil {
					t.Fatal(err)
				}
				cfg = loaded.MCPToolPolicy
			}
			pc := New(cfg)
			wantAction := effectiveRuleAction(t, cfg, "Credential File Access")
			for _, target := range []string{
				"/home/user/.ssh/authorized_keys", "/home/user/.ssh/id_ed25519",
				"/home/user/.kube/config", "/home/user/.docker/config.json",
				"/home/user/.aws/credentials", "/home/user/.netrc", "/etc/shadow",
				"/home/user/.ssh/config", "/home/user/.ssh/rc", "/home/user/.aws/config",
			} {
				t.Run(target, func(t *testing.T) {
					for _, tool := range strings.Split(fileWriteToolPattern, "|") {
						key := "path"
						if tool == "edit_block" {
							key = "file_path"
						}
						args := map[string]any{key: target, "content": "ordinary text", "old_string": "old", "new_string": "new"}
						v := toolCallVerdict(t, pc, tool, args)
						if !v.Matched || v.Action != wantAction || !slices.Contains(v.Rules, fileMutationRuleName) {
							t.Errorf("%s(%q) = %+v, want %s with %s", tool, target, v, fileMutationRuleName, wantAction)
						}
					}
					for _, tool := range append(strings.Split(fileMoveToolPattern, "|"), strings.Split(fileCopyToolPattern, "|")...) {
						v := toolCallVerdict(t, pc, tool, map[string]any{"source": "ordinary.txt", "destination": target})
						if !v.Matched || v.Action != wantAction || !slices.Contains(v.Rules, fileMutationRuleName) {
							t.Errorf("%s destination %q = %+v, want %s with %s", tool, target, v, fileMutationRuleName, wantAction)
						}
					}
					for _, patch := range protectedPatchTargetFormats(target) {
						v := toolCallVerdict(t, pc, filePatchToolPattern, map[string]any{"patch": patch})
						if !v.Matched || v.Action != wantAction || !slices.Contains(v.Rules, fileMutationRuleName) {
							t.Errorf("patch target %q = %+v, want %s with %s", target, v, fileMutationRuleName, wantAction)
						}
					}
				})
			}
			for _, tc := range []struct {
				tool string
				args map[string]any
			}{
				{tool: "write_file", args: map[string]any{"path": "notes.txt", "content": "Use .kube/config or .ssh/authorized_keys"}},
				{tool: "write_file", args: map[string]any{"path": ".env", "content": "LOG_LEVEL=info"}},
				{tool: "write_file", args: map[string]any{"path": "fixtures/.kube/config.example", "content": "ordinary text"}},
				{tool: "write_file", args: map[string]any{"path": "fixtures/.docker/configuration.md", "content": "ordinary text"}},
				{tool: "write_file", args: map[string]any{"path": "fixtures/.netrc.example", "content": "ordinary text"}},
				{tool: "write_file", args: map[string]any{"path": "/home/user/.ssh/id_ed25519.pub", "content": "public text"}},
				{tool: "edit_block", args: map[string]any{"file_path": "notes.txt", "old_string": ".kube/config", "new_string": ".ssh/authorized_keys"}},
				{tool: "apply_patch", args: map[string]any{"path": "notes.txt", "content": "Use .kube/config"}},
				{tool: "apply_patch", args: map[string]any{"patch": "--- a/notes.txt\n+++ b/notes.txt\n@@ -1 +1 @@\n-old\n+Use .kube/config\n"}},
				{tool: "apply_patch", args: map[string]any{"patch": "*** Begin Patch\n*** Update File: notes.txt\n@@\n-old\n+Use .ssh/authorized_keys\n*** End Patch", "description": "Describe .kube/config"}},
			} {
				assertPolicyAllowed(t, pc, tc.tool, tc.args)
			}
			for _, tool := range []string{"copy_file", "move_file"} {
				v := toolCallVerdict(t, pc, tool, map[string]any{"source": "/home/user/.ssh/id_ed25519", "destination": "backup.txt"})
				if !v.Matched || !slices.Contains(v.Rules, "Credential File Access") || v.Action != wantAction {
					t.Errorf("credential relocation with %s = %+v, want preserved source protection", tool, v)
				}
			}
			for _, tool := range strings.Split(fileLinkToolPattern, "|") {
				assertPolicyCall(t, pc, tool, map[string]any{"target": "ordinary.txt", "link_path": "/home/user/.kube/config"}, "Protected Path Link Creation", wantAction)
			}
		})
	}
}

func TestCredentialDestinationPublicKeyIdentity(t *testing.T) {
	f := newLocalPathFixture(t)
	public := filepath.Join(f.home, ".ssh", "id_ed25519.pub")
	private := filepath.Join(f.home, ".ssh", "id_ed25519")
	f.write(t, public)
	f.write(t, private)
	alias := filepath.Join(f.ws, "public-key")
	f.link(t, public, alias)
	pc := f.policy(true)
	assertPolicyAllowed(t, pc, "write_file", map[string]any{"path": alias, "content": "public fixture"})
	assertPolicyAllowed(t, pc, "apply_patch", map[string]any{"path": alias, "patch": "*** Begin Patch\n*** Update File: notes.txt\n@@\n-old\n+new\n*** End Patch"})
	assertPolicyAllowed(t, pc, "write_file", map[string]any{"path": []string{alias, public}, "content": "public fixture"})
	assertPolicyCall(t, pc, "write_file", map[string]any{"path": []string{alias, private}, "content": "fixture"}, fileMutationRuleName, config.ActionBlock)
}

func TestCredentialDestinationCustomMatching(t *testing.T) {
	var shipped config.ToolPolicyRule
	for _, rule := range DefaultToolPolicyRules() {
		if rule.Name == fileMutationRuleName && rule.ArgSource == "" && rule.ArgKey == fileTargetKeyPattern {
			shipped = rule
			break
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*config.ToolPolicyRule)
		tool   string
		key    string
	}{
		{"custom name", func(r *config.ToolPolicyRule) { r.Name = "Operator Credential Rule" }, "write_file", "path"},
		{"custom tool", func(r *config.ToolPolicyRule) { r.ToolPattern = "^operator_write$" }, "operator_write", "path"},
		{"custom key", func(r *config.ToolPolicyRule) { r.ArgKey = "^paths$" }, "write_file", "paths"},
		{"custom pattern", func(r *config.ToolPolicyRule) { r.ArgPattern += "|operator-pattern" }, "write_file", "path"},
		{"unscoped", func(r *config.ToolPolicyRule) { r.ArgKey = "" }, "write_file", "path"},
		{"custom source", func(r *config.ToolPolicyRule) { r.ArgSource = config.ToolPolicyArgSourcePatchTargets }, "write_file", "path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := shipped
			tc.change(&rule)
			pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: []config.ToolPolicyRule{rule}})
			assertPolicyCall(t, pc, tc.tool, map[string]any{tc.key: []string{".ssh/id_ed25519.pub", ".ssh/id_rsa.pub"}}, rule.Name, config.ActionBlock)
		})
	}
}

func TestCredentialDestinationLinkRuleCopiesMatch(t *testing.T) {
	var want string
	for _, rule := range DefaultToolPolicyRules() {
		if rule.Name == "Protected Path Link Creation" {
			want = rule.ArgPattern
		}
	}
	if want == "" {
		t.Fatal("missing built-in link rule")
	}
	for _, preset := range []string{"audit", "balanced", "claude-code", "cursor", "generic-agent", "hostile-model", "strict"} {
		cfg, err := config.Load(filepath.Join("..", "..", "..", "configs", preset+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, rule := range cfg.MCPToolPolicy.Rules {
			if rule.Name == "Protected Path Link Creation" {
				found = true
				// Existing preset spellings of the older path alternatives differ;
				// the added credential destinations must stay byte-identical.
				if !strings.HasSuffix(rule.ArgPattern, "|"+credentialWritePathPattern+")") {
					t.Errorf("%s link destinations differ from built-in", preset)
				}
			}
		}
		if !found {
			t.Errorf("%s missing protected link rule", preset)
		}
	}
}

func TestCredentialDestinationLocalIdentity(t *testing.T) {
	for _, path := range []string{".kube/config", ".docker/config.json", ".ssh/authorized_keys", ".ssh/config", ".ssh/rc", ".aws/config"} {
		t.Run(path, func(t *testing.T) {
			f := newLocalPathFixture(t)
			backing := filepath.Join(f.ws, "backing")
			f.write(t, backing)
			protected := filepath.Join(f.home, filepath.FromSlash(path))
			f.write(t, protected)
			alias := filepath.Join(f.ws, "alias")
			f.link(t, protected, alias)
			pc := f.policy(true)
			v := checkPath(pc, "write_file", "path", alias)
			if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, fileMutationRuleName) {
				t.Fatalf("alias to protected credential = %+v, want block", v)
			}
			v = toolCallVerdict(t, pc, "apply_patch", map[string]any{
				"path": alias, "patch": "*** Begin Patch\n*** Update File: notes.txt\n@@\n-old\n+new\n*** End Patch",
			})
			if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, fileMutationRuleName) {
				t.Fatalf("structured patch target alias = %+v, want block", v)
			}
			if err := os.Remove(protected); err != nil {
				t.Fatal(err)
			}
			f.link(t, backing, protected)
			v = checkPath(pc, "write_file", "path", backing)
			if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, fileMutationRuleName) {
				t.Fatalf("protected credential linked to backing file = %+v, want block", v)
			}
			if v := checkPath(f.policy(false), "write_file", "path", backing); v.Matched {
				t.Fatalf("identity disabled control = %+v, want no lexical match", v)
			}
		})
	}
}

func TestCredentialDestinationScopedPatches(t *testing.T) {
	var rules []config.ToolPolicyRule
	for _, rule := range DefaultToolPolicyRules() {
		if rule.Name == fileMutationRuleName {
			rules = append(rules, rule)
		}
	}
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: rules})
	safePatch := "*** Begin Patch\n*** Update File: notes.txt\n@@\n-old\n+new\n*** End Patch"
	for _, tc := range []struct {
		name     string
		args     map[string]any
		wantRule string
	}{
		{name: "structured target", args: map[string]any{"path": ".kube/config", "content": "ordinary text"}, wantRule: fileMutationRuleName},
		{name: "structured target with patch", args: map[string]any{"file_path": ".kube/config", "patch": safePatch}, wantRule: fileMutationRuleName},
		{name: "patch target with safe structured target", args: map[string]any{"path": "notes.txt", "patch": "*** Begin Patch\n*** Update File: .kube/config\n@@\n-old\n+new\n*** End Patch"}, wantRule: fileMutationRuleName},
		{name: "malformed patch", args: map[string]any{"patch": "--- a/notes.txt"}, wantRule: uninspectablePatchTargetsRule},
		{name: "empty patch target", args: map[string]any{"patch": "*** Begin Patch\n*** Update File: \n*** End Patch"}, wantRule: uninspectablePatchTargetsRule},
		{name: "content reference", args: map[string]any{"path": "notes.txt", "content": ".kube/config"}},
		{name: "patch description", args: map[string]any{"patch": safePatch, "description": ".kube/config"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := toolCallVerdict(t, pc, "apply_patch", tc.args)
			if tc.wantRule == "" {
				if v.Matched {
					t.Fatalf("safe patch = %+v, want allow", v)
				}
			} else if !v.Matched || v.Action != config.ActionBlock || !slices.Contains(v.Rules, tc.wantRule) {
				t.Fatalf("patch = %+v, want %s block", v, tc.wantRule)
			}
		})
	}
}

func TestCredentialDestinationSpellings(t *testing.T) {
	pc := credentialRelocationConfig(t)
	for _, target := range []string{
		".kube/config", "~/.kube/config", "/home/user/.kube//config",
		"/home/user/.kube/./config", "/home/user/.kube/../.kube/config",
		`C:\Users\user\.kube\config`, "/home/user/.ssh/authorized_keys",
	} {
		for _, key := range []string{"path", "file_path", "filePath", "file", "filename", "target_file"} {
			for _, tool := range []string{"write_file", "mcp__filesystem__write_file", "filesystem.write_file", "filesystem:write_file"} {
				v := toolCallVerdict(t, pc, tool, map[string]any{key: target, "content": "ordinary text"})
				if !v.Matched || v.Action != config.ActionBlock {
					t.Errorf("%s(%s=%q) = %+v, want block", tool, key, target, v)
				}
			}
		}
	}
	for _, key := range []string{"destination", "destination_path", "destinationPath", "dest", "new_path", "newPath", "target"} {
		v := toolCallVerdict(t, pc, "rename_file", map[string]any{"source": "ordinary.txt", key: "/home/user/.kube/config"})
		if !v.Matched || v.Action != config.ActionBlock {
			t.Errorf("rename_file(%s) = %+v, want block", key, v)
		}
	}
}

func TestCredentialWriteRuleCopiesMatch(t *testing.T) {
	var want []config.ToolPolicyRule
	for _, rule := range DefaultToolPolicyRules() {
		if rule.Name == fileMutationRuleName {
			want = append(want, rule)
		}
	}
	if len(want) != 3 {
		t.Fatalf("built-in credential write rules = %d, want 3", len(want))
	}
	for _, preset := range []string{"audit", "balanced", "claude-code", "cursor", "generic-agent", "hostile-model", "strict"} {
		cfg, err := config.Load(filepath.Join("..", "..", "..", "configs", preset+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		var got []config.ToolPolicyRule
		for _, rule := range cfg.MCPToolPolicy.Rules {
			if rule.Name == fileMutationRuleName {
				got = append(got, rule)
			}
		}
		if len(got) != len(want) {
			t.Fatalf("%s credential write rules = %d, want %d", preset, len(got), len(want))
		}
		for i := range want {
			if got[i].ToolPattern != want[i].ToolPattern || got[i].ArgPattern != want[i].ArgPattern || got[i].ArgKey != want[i].ArgKey || got[i].ArgSource != want[i].ArgSource {
				t.Errorf("%s rule %d differs from built-in destination protection", preset, i)
			}
		}
	}
}
