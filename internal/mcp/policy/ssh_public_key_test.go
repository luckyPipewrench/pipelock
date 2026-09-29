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

func credentialRuleMatches(t *testing.T, pc *Config, toolName string, args map[string]any) bool {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	extracted := jsonrpc.ExtractStringsFromJSONResult(raw)
	v := pc.CheckToolCallWithArgs(toolName, extracted.Strings, raw)
	return slices.Contains(v.Rules, testKeyReadRule)
}

// A public key is published by design, so reading one is not credential
// access. Every spelling that can still reach the private half stays blocked.
func TestDefaultToolPolicyRules_SSHPublicKeyReads(t *testing.T) {
	pc := defaultConfig(t)
	tests := []struct {
		name      string
		path      string
		wantMatch bool
	}{
		{name: "rsa public key", path: "/home/user/.ssh/id_rsa.pub"},
		{name: "ed25519 public key", path: "/home/user/.ssh/id_ed25519.pub"},
		{name: "certificate", path: "/home/user/.ssh/id_ed25519-cert.pub"},
		{name: "upper case public key", path: "/HOME/USER/.SSH/ID_RSA.PUB"},
		{name: "tilde public key", path: "~/.ssh/id_ecdsa.pub"},
		{name: "windows public key", path: `C:\Users\v\.ssh\id_ed25519.pub`},
		{name: "public key backup", path: "/home/user/.ssh/id_rsa.pub.bak"},

		{name: "rsa private key", path: "/home/user/.ssh/id_rsa", wantMatch: true},
		{name: "ed25519 private key", path: "/home/user/.ssh/id_ed25519", wantMatch: true},
		{name: "upper case private key", path: "/HOME/USER/.SSH/ID_RSA", wantMatch: true},
		{name: "windows private key", path: `C:\Users\v\.ssh\id_rsa`, wantMatch: true},
		{name: "private key backup", path: "/home/user/.ssh/id_rsa.bak", wantMatch: true},
		{name: "editor backup", path: "/home/user/.ssh/id_rsa~", wantMatch: true},
		{name: "pkcs12 bundle", path: "/home/user/.ssh/id_rsa.p12", wantMatch: true},
		{name: "trailing dot", path: "/home/user/.ssh/id_rsa.", wantMatch: true},
		{name: "truncated extension", path: "/home/user/.ssh/id_rsa.pu", wantMatch: true},
		{name: "glob over every key", path: "/home/user/.ssh/id_*", wantMatch: true},
		{name: "glob after the name", path: "/home/user/.ssh/id_rsa*", wantMatch: true},
		{name: "glob in the extension", path: "/home/user/.ssh/id_rsa.pu?", wantMatch: true},
		{name: "bracket in the extension", path: "/home/user/.ssh/id_rsa.pu[b]", wantMatch: true},
		{name: "brace expansion", path: "/home/user/.ssh/id_rsa{,.pub}", wantMatch: true},
		{name: "dot dot after public key", path: "/home/user/.ssh/id_rsa.pub/../id_rsa", wantMatch: true},
		{name: "windows dot dot after public key", path: `C:\Users\v\.ssh\id_rsa.pub\..\id_rsa`, wantMatch: true},
		{name: "escaped separator after public key", path: "/home/user/.ssh/id_rsa.pub%2f..%2fid_rsa", wantMatch: true},
		{name: "dot dot after public key backup", path: "/home/user/.ssh/id_rsa.pub.bak/../id_rsa", wantMatch: true},
		{name: "dot dot after longer extension", path: "/home/user/.ssh/id_rsa.pubx/../id_rsa", wantMatch: true},
		{name: "dot dot after public key and a space", path: "/home/user/.ssh/id_rsa.pub /../id_rsa", wantMatch: true},
		{name: "windows dot dot after trailing dot", path: `C:\Users\v\.ssh\id_rsa.pub.\..\id_rsa`, wantMatch: true},
		{name: "windows dot dot two levels", path: `C:\Users\v\.ssh\id_rsa.pub\a\..\..\id_rsa`, wantMatch: true},
		{name: "authorized keys", path: "/home/user/.ssh/authorized_keys", wantMatch: true},
	}
	for _, tc := range tests {
		t.Run("read_file/"+tc.name, func(t *testing.T) {
			if got := credentialRuleMatches(t, pc, testReadTool, map[string]any{"path": tc.path}); got != tc.wantMatch {
				t.Fatalf("read_file(%q) credential match = %v, want %v", tc.path, got, tc.wantMatch)
			}
		})
		t.Run("bash/"+tc.name, func(t *testing.T) {
			command := "cat " + tc.path
			if got := credentialRuleMatches(t, pc, "bash", map[string]any{"command": command}); got != tc.wantMatch {
				t.Fatalf("bash(%q) credential match = %v, want %v", command, got, tc.wantMatch)
			}
		})
	}
}

// A command naming both halves is judged by the private one.
func TestDefaultToolPolicyRules_SSHPublicKeyDoesNotMaskPrivateKey(t *testing.T) {
	pc := defaultConfig(t)
	for _, command := range []string{
		"cat ~/.ssh/id_rsa.pub ~/.ssh/id_rsa",
		"cat ~/.ssh/id_rsa.pub; cat ~/.ssh/id_rsa",
		"cp ~/.ssh/id_ed25519.pub ~/.ssh/id_ed25519 /tmp/",
		`f=~/.ssh/id_rsa.pub; cat "${f%.pub}"`,
		"cat $(echo ~/.ssh/id_rsa.pub | sed s/.pub//)",
	} {
		if !credentialRuleMatches(t, pc, "bash", map[string]any{"command": command}) {
			t.Errorf("bash(%q) was not matched as credential access", command)
		}
	}
}

// The exception covers a call that names only public keys. Any separator after
// a `.pub` name in the same call, even in another argument, keeps the call
// matched, because the rule cannot tell a second path from a traversal.
func TestDefaultToolPolicyRules_SSHPublicKeyExceptionIsNarrow(t *testing.T) {
	pc := defaultConfig(t)
	allowed := []map[string]any{
		{"command": "cat ~/.ssh/id_ed25519.pub"},
		{"command": "ssh-keygen -lf ~/.ssh/id_ed25519.pub"},
		{"command": "gh ssh-key add ~/.ssh/id_ed25519.pub --title laptop"},
	}
	for _, args := range allowed {
		if credentialRuleMatches(t, pc, "bash", args) {
			t.Errorf("bash(%v) matched credential access", args)
		}
	}
	matched := []struct {
		tool string
		args map[string]any
	}{
		{tool: "bash", args: map[string]any{"command": "cat ~/.ssh/id_ed25519.pub | tee /tmp/key"}},
		{tool: "copy_file", args: map[string]any{"source": "/home/user/.ssh/id_ed25519.pub", "destination": "/tmp/key"}},
		{tool: testReadTool, args: map[string]any{"path": "/home/user/.ssh/id_ed25519.pub", "note": "a/b"}},
	}
	for _, tc := range matched {
		if !credentialRuleMatches(t, pc, tc.tool, tc.args) {
			t.Errorf("%s(%v) was not matched as credential access", tc.tool, tc.args)
		}
	}
}

// A link named like a public key is judged by the file it reaches.
func TestLocalPathIdentity_PublicKeyNameLinkedToPrivateKey(t *testing.T) {
	f := newLocalPathFixture(t)
	private := filepath.Join(f.home, ".ssh", "id_rsa")
	public := filepath.Join(f.home, ".ssh", "id_rsa.pub")
	f.write(t, private)
	f.write(t, public)
	disguised := filepath.Join(f.ws, "deploy.pub")
	f.link(t, private, disguised)

	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()})
	pc.localPaths = newLocalPathIdentity(f.home, f.ws)
	if v := checkPath(pc, testReadTool, "path", disguised); !slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("link named like a public key reaching the private key was not matched: %+v", v)
	}
	if v := checkPath(pc, testReadTool, "path", public); slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("real public key read was matched as credential access: %+v", v)
	}
	if v := checkPath(pc, testReadTool, "path", public+"/../id_rsa"); !slices.Contains(v.Rules, testKeyReadRule) {
		t.Fatalf("dot dot through the public key to the private key was not matched: %+v", v)
	}
}

// TestPresetCredentialRulesCarryDefault keeps each preset's credential rule in
// step with the built-in default. A preset may add locations, but it must keep
// every spelling the default blocks and the same public key exception.
func TestPresetCredentialRulesCarryDefault(t *testing.T) {
	presets, err := filepath.Glob(filepath.Join("..", "..", "..", "configs", "*.yaml"))
	if err != nil || len(presets) == 0 {
		t.Fatalf("no presets found: %v", err)
	}
	for _, preset := range presets {
		cfg, err := config.Load(preset)
		if err != nil {
			t.Fatalf("load %s: %v", preset, err)
		}
		found := false
		for _, rule := range cfg.MCPToolPolicy.Rules {
			if rule.Name != testKeyReadRule {
				continue
			}
			found = true
			if !strings.Contains(rule.ArgPattern, sensitiveFilePathPattern) {
				t.Errorf("%s: %q arg_pattern does not carry the built-in credential pattern", filepath.Base(preset), rule.Name)
			}
		}
		if !found {
			t.Errorf("%s: no %q rule", filepath.Base(preset), testKeyReadRule)
		}
	}
	// The examples keep their slash-only spelling of the other locations but
	// must carry the same key-name exception.
	for _, example := range []string{
		filepath.Join("..", "..", "..", "examples", "cursor-integration", "pipelock.yaml"),
		filepath.Join("..", "..", "..", "examples", "quickstart", "pipelock.yaml"),
	} {
		cfg, err := config.Load(example)
		if err != nil {
			t.Fatalf("load %s: %v", example, err)
		}
		found := false
		for _, rule := range cfg.MCPToolPolicy.Rules {
			if rule.Name == testKeyReadRule {
				found = true
				if !strings.Contains(rule.ArgPattern, sshKeyNamePattern) {
					t.Errorf("%s: %q arg_pattern does not carry the built-in key-name pattern", example, rule.Name)
				}
			}
		}
		if !found {
			t.Errorf("%s: no %q rule", example, testKeyReadRule)
		}
	}
}
