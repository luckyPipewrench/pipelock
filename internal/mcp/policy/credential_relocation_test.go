// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// credentialRelocationConfig builds the built-in rule set with a warn default so
// a rule's own action is what the assertions observe.
func credentialRelocationConfig(t *testing.T) *Config {
	t.Helper()
	pc := New(config.MCPToolPolicy{Enabled: true, Action: config.ActionWarn, Rules: DefaultToolPolicyRules()})
	if pc == nil {
		t.Fatal("policy config is nil")
	}
	return pc
}

func toolCallVerdict(t *testing.T, pc *Config, tool string, args map[string]any) Verdict {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatalf("marshal args: %v", err)
	}
	line, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": tool, "arguments": json.RawMessage(raw)},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return pc.CheckRequest(line)
}

func toolCallRules(t *testing.T, pc *Config, tool string, args map[string]any) []string {
	t.Helper()
	return toolCallVerdict(t, pc, tool, args).Rules
}

// TestCredentialRelocationIsCovered: a credential denied to a direct read must not
// be reachable by relocating it somewhere unguarded and reading it there. The
// credential rule matches unscoped, so the secret matches on the SOURCE side, and
// the verdict carries the rule's own block action rather than the warn default.
func TestCredentialRelocationIsCovered(t *testing.T) {
	pc := credentialRelocationConfig(t)
	for _, tool := range []string{"copy_file", "file_copy", "move_file", "file_move", "rename_file"} {
		v := toolCallVerdict(t, pc, tool, map[string]any{
			"source": "/home/victim/.ssh/id_rsa", "destination": "/tmp/staged",
		})
		if !slices.Contains(v.Rules, "Credential File Access") {
			t.Errorf("%s relocating an ssh key did not match Credential File Access, rules=%v", tool, v.Rules)
		}
		if v.Action != config.ActionBlock {
			t.Errorf("%s relocating an ssh key resolved action %q, want %q", tool, v.Action, config.ActionBlock)
		}
	}
}

// TestCredentialWindowsSpellingIsCovered: a Windows credential path is the same
// secret as its POSIX form. Policy normalization strips a backslash before a word
// character, so the separator may be absent by match time.
func TestCredentialWindowsSpellingIsCovered(t *testing.T) {
	pc := credentialRelocationConfig(t)
	for _, path := range []string{
		`C:\Users\victim\.ssh\id_rsa`,
		`C:\Users\victim\.aws\credentials`,
		"/home/victim/.ssh/id_rsa",
		"/home/victim/.aws/credentials",
	} {
		rules := toolCallRules(t, pc, "read_file", map[string]any{"path": path})
		if !slices.Contains(rules, "Credential File Access") {
			t.Errorf("read of %q did not match Credential File Access, rules=%v", path, rules)
		}
	}
}

// TestAuditTamperingCoversPipelockNamespace: the shell rule never covered
// /var/lib/pipelock, where the receipt chain and containment egress log live.
func TestAuditTamperingCoversPipelockNamespace(t *testing.T) {
	pc := credentialRelocationConfig(t)

	// The shell rule keeps EXTENSION coverage on purpose, and a review finding
	// proposing to scope it away was rejected. Assessment artifacts and the license
	// audit ledger default to relative paths in the working directory, and
	// `echo '' > events.jsonl` is the canonical evidence-truncation command, so
	// scoping it away would cost a real detection to avoid a hypothetical false
	// positive in two opt-in paranoid presets. What this change adds is the
	// /var/lib/pipelock namespace, which the shell rule never covered.
	for _, cmd := range []string{
		"rm /var/lib/pipelock/evidence/evidence-proxy-1.jsonl",
		"shred /var/lib/pipelock/contain/egress-events.jsonl",
		"echo '' > /var/lib/pipelock/evidence/evidence-proxy-1.jsonl",
		"rm /var/log/auth.log",
		"echo '' > events.jsonl",
		"shred agent.audit",
		"history -c",
	} {
		v := pc.CheckToolCall("bash", []string{cmd})
		if !slices.Contains(v.Rules, "Audit Log Tampering") {
			t.Errorf("%q did not match Audit Log Tampering, rules=%v", cmd, v.Rules)
		}
	}
}

// TestCredentialCoverageKeepsDeliberateAllowances: widening the credential rule
// must not start denying the operations the suite deliberately permits.
func TestCredentialCoverageKeepsDeliberateAllowances(t *testing.T) {
	pc := credentialRelocationConfig(t)

	if rules := toolCallRules(t, pc, "copy_file", map[string]any{
		"source": "/home/victim/.bashrc", "destination": "/tmp/backup",
	}); len(rules) != 0 {
		t.Errorf("copying a profile to an ordinary backup should stay allowed, rules=%v", rules)
	}
	if v := pc.CheckToolCall("bash", []string{"mv ~/.zshrc ~/.zshrc.old"}); v.Matched {
		t.Errorf("moving a profile aside should stay allowed, rules=%v", v.Rules)
	}
	if rules := toolCallRules(t, pc, "write_file", map[string]any{
		"path": "/home/victim/app.log", "content": "entry",
	}); len(rules) != 0 {
		t.Errorf("writing an ordinary log should stay allowed, rules=%v", rules)
	}
}
