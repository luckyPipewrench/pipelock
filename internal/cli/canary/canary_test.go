// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package canary

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func testRoot() *cobra.Command {
	root := &cobra.Command{Use: "pipelock"}
	root.AddCommand(Cmd())
	return root
}

func TestCanaryCmd_YAML_Default(t *testing.T) {
	cmd := testRoot()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"canary"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "canary_tokens:") {
		t.Fatalf("expected yaml output, got %q", out)
	}
	if !strings.Contains(out, "${AWS_CANARY_KEY}") {
		t.Fatalf("default should emit env var placeholder, got %q", out)
	}
	if strings.Contains(out, "AKIA"+"IOSFODNN7"+"CANARY1") {
		t.Fatal("default must not print literal canary value")
	}
}

func TestCanaryCmd_YAML_Literal(t *testing.T) {
	cmd := testRoot()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"canary", "--literal"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "AKIA") {
		t.Fatalf("--literal should emit actual value, got %q", out)
	}
}

func TestCanaryCmd_JSON(t *testing.T) {
	cmd := testRoot()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"canary", "--format", "json"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(buf.String()), &payload); err != nil {
		t.Fatalf("invalid json output: %v", err)
	}
	if _, ok := payload["canary_tokens"]; !ok {
		t.Fatalf("missing canary_tokens key in output: %v", payload)
	}
}

func TestCanaryCmd_InvalidFormat(t *testing.T) {
	cmd := testRoot()
	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"canary", "--format", "xml"})

	if err := cmd.Execute(); err == nil {
		t.Fatal("expected error for invalid format")
	}
}
