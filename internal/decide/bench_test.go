package decide

import (
	"encoding/json"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// BenchmarkColdStart measures the full pipeline: config defaults, scanner
// construction, policy compilation, decision, and JSON marshaling. This
// simulates what happens on every Cursor hook invocation since the hook
// binary is spawned fresh each time.
func BenchmarkColdStart(b *testing.B) {
	for b.Loop() {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.DLP.ScanEnv = false
		cfg.MCPInputScanning.Enabled = true
		cfg.MCPInputScanning.Action = config.ActionBlock
		cfg.MCPToolPolicy = config.MCPToolPolicy{
			Enabled: true,
			Action:  config.ActionBlock,
			Rules:   policy.DefaultToolPolicyRules(),
		}
		cfg.ResponseScanning.Enabled = true
		cfg.ResponseScanning.Action = config.ActionBlock
		cfg.ApplyDefaults()

		sc := scanner.New(cfg)
		pc := policy.New(cfg.MCPToolPolicy)

		action := Action{
			Source: "cursor",
			Kind:   EventShellExecution,
			Shell:  &ShellPayload{Command: "git status", CWD: "/tmp/project"},
		}

		decision := Decide(cfg, sc, pc, action)

		out, err := json.Marshal(decision)
		if err != nil {
			b.Fatal(err)
		}
		if len(out) == 0 {
			b.Fatal("empty output")
		}
	}
}
