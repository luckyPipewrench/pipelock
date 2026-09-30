// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
)

func TestSSHPublicKeySingleArgumentAliases(t *testing.T) {
	f := newLocalPathFixture(t)
	public := filepath.Join(f.home, ".ssh", "id_ed25519.pub")
	private := filepath.Join(f.home, ".ssh", "id_ed25519")
	f.write(t, public)
	f.write(t, private)
	link := filepath.Join(f.ws, "public.pub")
	f.link(t, public, link)
	disguised := filepath.Join(f.home, ".ssh", "id_disguised.pub")
	f.link(t, private, disguised)
	t.Setenv("HOME", f.home)
	pc := f.policy(false)
	pc.EnableLocalPathIdentity(f.ws)
	for _, tc := range []struct {
		name   string
		values []string
		want   bool
	}{
		{"absolute", []string{public}, false},
		{"tilde existing", []string{"~/.ssh/id_ed25519.pub"}, false},
		{"relative existing", []string{"../.ssh/id_ed25519.pub"}, false},
		{"public symlink", []string{link}, false},
		{"private symlink", []string{disguised}, true},
		{"both halves", []string{public, private}, true},
		{"separate note", []string{public, "note"}, true},
		{"shell", []string{"cat ~/.ssh/id_ed25519.pub"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"paths": tc.values})
			for _, keys := range []bool{false, true} {
				args := slices.Clone(tc.values)
				if keys {
					args = append([]string{"paths"}, args...)
				}
				v := pc.CheckToolCallWithArgs(testReadTool, args, raw)
				got := slices.Contains(v.Rules, testKeyReadRule)
				if got != tc.want {
					t.Errorf("keys=%v values=%q expanded=%q verdict=%+v want credential=%v", keys, tc.values, pc.localPaths.expand(tc.values), v, tc.want)
				}
			}
		})
	}
}

func TestSSHPublicKeyOtherRulePairwisePreserved(t *testing.T) {
	f := newLocalPathFixture(t)
	public := filepath.Join(f.home, ".ssh", "id_ed25519.pub")
	f.write(t, public)
	for _, pattern := range []string{`(?i)\.pub\s+path`, `(?i)\.pub\s+/`} {
		pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: []config.ToolPolicyRule{{Name: "Custom pair", ToolPattern: `^read_file$`, ArgPattern: pattern}}})
		pc.localPaths = newLocalPathIdentity(f.home, f.ws)
		raw, _ := json.Marshal(map[string]string{"path": "~/.ssh/id_ed25519.pub"})
		if v := pc.CheckToolCallWithArgs(testReadTool, []string{"path", "~/.ssh/id_ed25519.pub"}, raw); !v.Matched {
			t.Errorf("pattern %q lost pair matching: %+v", pattern, v)
		}
	}
}

func TestSSHPublicKeyPresetSingleValue(t *testing.T) {
	presets, err := filepath.Glob(filepath.Join("..", "..", "..", "configs", "*.yaml"))
	if err != nil || len(presets) == 0 {
		t.Fatalf("presets: %v", err)
	}
	f := newLocalPathFixture(t)
	f.write(t, filepath.Join(f.home, ".ssh", "id_ed25519.pub"))
	for _, preset := range presets {
		t.Run(filepath.Base(preset), func(t *testing.T) {
			cfg, err := config.Load(preset)
			if err != nil {
				t.Fatal(err)
			}
			pc := New(cfg.MCPToolPolicy)
			pc.localPaths = newLocalPathIdentity(f.home, f.ws)
			raw := json.RawMessage(`{"path":"~/.ssh/id_ed25519.pub"}`)
			v := pc.CheckToolCallWithArgs(testReadTool, []string{"path", "~/.ssh/id_ed25519.pub"}, raw)
			if slices.Contains(v.Rules, testKeyReadRule) {
				t.Fatalf("preset public key: %+v", v)
			}
		})
	}
}

func TestSSHPublicKeyPatternBoundaries(t *testing.T) {
	f := newLocalPathFixture(t)
	public := filepath.Join(f.home, ".ssh", "id_ed25519.pub")
	f.write(t, public)
	pc := f.policy(true)
	if v := pc.CheckToolCall(testReadTool, []string{"~/.ssh/id_ed25519.pub"}); slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("values-only caller: %+v", v)
	}
	raw, _ := json.Marshal(map[string]string{"path": "~/.ssh/id_ed25519.pub"})
	// A custom pattern using the shipped name keeps all its pairwise semantics.
	custom := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: []config.ToolPolicyRule{{Name: testKeyReadRule, ToolPattern: `^read_file$`, ArgPattern: `(?i)\.pub\s+path`}}})
	if v := custom.CheckToolCallWithArgs(testReadTool, []string{"path", "~/.ssh/id_ed25519.pub"}, raw); !v.Matched {
		t.Fatalf("custom named rule: %+v", v)
	}
	// The existing scoped matcher and its alias combinations also remain intact.
	rules := DefaultToolPolicyRules()
	for i := range rules {
		if rules[i].Name == testKeyReadRule {
			rules[i].ArgKey = `^path$`
		}
	}
	scoped := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionBlock, Rules: rules})
	scoped.localPaths = newLocalPathIdentity(f.home, f.ws)
	if v := scoped.CheckToolCallWithArgs(testReadTool, []string{"~/.ssh/id_ed25519.pub"}, raw); !slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("custom scoped rule: %+v", v)
	}
}

// A JSON key is text a tool may act on. The single-value exception must not
// let a key that names a protected path, directly, nested, or through a local
// link, escape the rule because only one string value is present.
func TestCredentialArgument_KeyNamingPrivatePathStaysBlocked(t *testing.T) {
	pc := defaultConfig(t)
	for _, raw := range []string{
		`{"/home/user/.ssh/id_rsa":"x"}`,
		`{"~/.ssh/id_ed25519":"read"}`,
		`{"outer":{"/home/user/.ssh/id_rsa":"x"}}`,
		`{"list":[{"/home/user/.ssh/id_rsa":"x"}]}`,
	} {
		extracted := jsonrpc.ExtractStringsFromJSONResult(json.RawMessage(raw))
		v := pc.CheckToolCallWithArgs(testReadTool, extracted.Strings, json.RawMessage(raw))
		if !slices.Contains(v.Rules, testKeyReadRule) {
			t.Errorf("%s was not matched as credential access", raw)
		}
	}
	// Positive control: the same shape with a public-key value and an ordinary
	// key keeps the exception, so the cases above fail for the key alone.
	raw := `{"path":"/home/user/.ssh/id_ed25519.pub"}`
	extracted := jsonrpc.ExtractStringsFromJSONResult(json.RawMessage(raw))
	if v := pc.CheckToolCallWithArgs(testReadTool, extracted.Strings, json.RawMessage(raw)); slices.Contains(v.Rules, testKeyReadRule) {
		t.Errorf("%s matched credential access", raw)
	}
}
