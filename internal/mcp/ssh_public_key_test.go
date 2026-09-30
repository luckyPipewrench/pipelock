// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func TestSSHPublicKeyStdioLocalPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	ssh := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(ssh, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"id_ed25519.pub", "id_ed25519"} {
		if err := os.WriteFile(filepath.Join(ssh, name), []byte("fixture\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pc := buildPolicyConfig(config.ActionBlock, policy.DefaultToolPolicyRules())
	pc.EnableLocalPathIdentity()
	sc := testInputScanner(t)
	for _, tc := range []struct {
		path  string
		allow bool
	}{
		{filepath.Join(ssh, "id_ed25519.pub"), true},
		{"~/.ssh/id_ed25519.pub", true},
		{"~/.ssh/id_ed25519", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			args, _ := json.Marshal(map[string]string{"path": tc.path})
			req := `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"read_file","arguments":` + string(args) + `}}` + "\n"
			var serverIn, logW bytes.Buffer
			blocked := make(chan BlockedRequest, 10)
			ForwardScannedInput(transport.NewStdioReader(strings.NewReader(req)), transport.NewStdioWriter(&serverIn), &logW, config.ActionBlock, config.ActionBlock, blocked, nil, nil, MCPProxyOpts{Scanner: sc, PolicyCfg: pc})
			if got := strings.Contains(serverIn.String(), "tools/call"); got != tc.allow {
				t.Fatalf("forwarded=%v want=%v log=%s", got, tc.allow, logW.String())
			}
		})
	}
}
