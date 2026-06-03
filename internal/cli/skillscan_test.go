// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func TestSkillScanHelp(t *testing.T) {
	cmd := rootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"skill-scan", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("skill-scan help: %v", err)
	}
	help := out.String()
	flatHelp := strings.ReplaceAll(help, "\n", " ")
	for _, want := range []string{"--lock-file", "--baseline", "--update", "--allowlist", "exact combo fingerprints", "--inventory-only", "Runtime network and tool enforcement remains Pipelock proper"} {
		if !strings.Contains(flatHelp, want) {
			t.Fatalf("help = %q, want %q", help, want)
		}
	}
	if strings.Contains(flatHelp, "YAML mapping skill_id") {
		t.Fatalf("help still describes obsolete allowlist format: %q", help)
	}
	if strings.Contains(strings.ToLower(help), "malicious") {
		t.Fatalf("help uses forbidden vocabulary: %q", help)
	}
}

func TestSkillScanExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
	}{
		{
			name: "clean",
			args: []string{"skill-scan", "--min-severity", "medium", filepath.Join("..", "skillscan", "testdata", "clean-skill")},
			code: 0,
		},
		{
			name: "finding",
			args: []string{"skill-scan", "--min-severity", "medium", filepath.Join("..", "skillscan", "testdata", "combo-skill")},
			code: skillScanExitFindings,
		},
		{
			name: "default high ignores cooccurrence",
			args: []string{"skill-scan", filepath.Join("..", "skillscan", "testdata", "combo-skill")},
			code: 0,
		},
		{
			name: "default high gates direct transfer",
			args: []string{"skill-scan", filepath.Join("..", "skillscan", "testdata", "direct-skill")},
			code: skillScanExitFindings,
		},
		{
			name: "fatal",
			args: []string{"skill-scan", "--min-severity", "urgent", filepath.Join("..", "skillscan", "testdata", "clean-skill")},
			code: skillScanExitError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := rootCmd()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetErr(&bytes.Buffer{})
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if tt.code == 0 {
				if err != nil {
					t.Fatalf("Execute err = %v, want nil", err)
				}
				return
			}
			var exitErr *cliutil.ExitError
			if !errors.As(err, &exitErr) {
				t.Fatalf("Execute err = %T %v, want ExitError", err, err)
			}
			if exitErr.Code != tt.code {
				t.Fatalf("exit code = %d, want %d", exitErr.Code, tt.code)
			}
		})
	}
}

func TestSkillScanJSONOutput(t *testing.T) {
	cmd := rootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"skill-scan", "--json", "--inventory-only", filepath.Join("..", "skillscan", "testdata", "clean-skill")})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	var decoded struct {
		Skills []struct {
			ID string `json:"skill_id"`
		} `json:"skills"`
		Findings []struct{} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("json output: %v\n%s", err, out.String())
	}
	if len(decoded.Skills) != 1 || decoded.Skills[0].ID != "clean-skill" {
		t.Fatalf("decoded = %+v", decoded)
	}
	if len(decoded.Findings) != 0 {
		t.Fatalf("decoded findings = %+v, want none", decoded.Findings)
	}
}
