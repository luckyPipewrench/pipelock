// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package canary

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/internal/config"
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

func TestCanaryCmd_JSONConfigRoundTrip(t *testing.T) {
	const synthetic = "synthetic-canary-value"
	for _, tc := range []struct {
		name  string
		args  []string
		token config.CanaryToken
	}{
		{"placeholder", nil, config.CanaryToken{Name: "aws_canary", Value: "${AWS_CANARY_KEY}", EnvVar: "AWS_CANARY_KEY"}},
		{"literal", []string{"--literal"}, config.CanaryToken{Name: "aws_canary", Value: defaultCanaryValue(), EnvVar: "AWS_CANARY_KEY"}},
		{"no binding", []string{"--literal", "--env-var", "", "--value", synthetic}, config.CanaryToken{Name: "aws_canary", Value: synthetic}},
		{"escaping", []string{"--literal", "--env-var", "", "--name", "quoted\"name", "--value", "canary\"\\value\nline"}, config.CanaryToken{Name: "quoted\"name", Value: "canary\"\\value\nline"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := testRoot()
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetArgs(append([]string{"canary", "--format", "json"}, tc.args...))
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadBytes(buf.Bytes())
			if err != nil {
				t.Fatalf("generated JSON rejected by config loader: %v\n%s", err, buf.String())
			}
			if !cfg.CanaryTokens.Enabled || len(cfg.CanaryTokens.Tokens) != 1 || cfg.CanaryTokens.Tokens[0] != tc.token {
				t.Fatalf("loaded canary = %+v, want %+v", cfg.CanaryTokens, tc.token)
			}
			var raw struct {
				CanaryTokens struct {
					Tokens []map[string]any `json:"tokens"`
				} `json:"canary_tokens"`
			}
			if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
				t.Fatal(err)
			}
			if tc.token.EnvVar == "" {
				if _, exists := raw.CanaryTokens.Tokens[0]["env_var"]; exists {
					t.Fatal("empty optional env_var must be omitted")
				}
			}
			if tc.name == "placeholder" && !strings.Contains(buf.String(), "${AWS_CANARY_KEY}") {
				t.Fatal("placeholder replaced by literal")
			}
		})
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestCanaryCmd_JSONWriteError(t *testing.T) {
	want := errors.New("output unavailable")
	cmd := Cmd()
	cmd.SetOut(failingWriter{err: want})
	cmd.SetArgs([]string{"--format", "json"})
	if err := cmd.Execute(); !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
}

func TestCanaryCmd_YAMLWriteError(t *testing.T) {
	want := errors.New("output unavailable")
	for _, successfulWrites := range []int{0, 1} {
		t.Run(fmt.Sprintf("after_%d_writes", successfulWrites), func(t *testing.T) {
			cmd := Cmd()
			cmd.SetOut(&delayedFailingWriter{remaining: successfulWrites, err: want})
			if err := cmd.Execute(); !errors.Is(err, want) {
				t.Fatalf("error = %v, want %v", err, want)
			}
		})
	}
}

type delayedFailingWriter struct {
	remaining int
	err       error
}

func (w *delayedFailingWriter) Write(p []byte) (int, error) {
	if w.remaining == 0 {
		return 0, w.err
	}
	w.remaining--
	return len(p), nil
}

func TestCanaryCmd_YAMLConfigRoundTrip(t *testing.T) {
	cmd := testRoot()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"canary", "--literal", "--env-var", "", "--value", "synthetic-canary-value"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadBytes(buf.Bytes())
	if err != nil {
		t.Fatalf("generated YAML rejected by config loader: %v\n%s", err, buf.String())
	}
	got := cfg.CanaryTokens.Tokens
	if !cfg.CanaryTokens.Enabled || len(got) != 1 || got[0].Name != "aws_canary" || got[0].Value != "synthetic-canary-value" || got[0].EnvVar != "" {
		t.Fatalf("loaded canary = %+v", cfg.CanaryTokens)
	}
}
