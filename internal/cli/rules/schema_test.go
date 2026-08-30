// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	domrules "github.com/luckyPipewrench/pipelock/internal/rules"
)

func TestRulesSchemaCommand(t *testing.T) {
	originalVersion, originalCommit := cliutil.Version, cliutil.GitCommit
	cliutil.Version = "3.5.0"
	cliutil.GitCommit = "abcdef0123456789"
	t.Cleanup(func() {
		cliutil.Version = originalVersion
		cliutil.GitCommit = originalCommit
	})

	root := testRootCmd()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetArgs([]string{"rules", "schema"})
	if err := root.Execute(); err != nil {
		t.Fatalf("rules schema: %v", err)
	}

	var contract domrules.RuleSchemaContract
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&contract); err != nil {
		t.Fatalf("decode schema output: %v", err)
	}
	if contract.Producer.Version != "3.5.0" || contract.Producer.SourceRevision != "abcdef0123456789" {
		t.Fatalf("producer = %+v", contract.Producer)
	}
	if len(contract.Rule.Types) != 3 {
		t.Fatalf("rule types = %d, want 3", len(contract.Rule.Types))
	}
}

func TestRulesSchemaCommandRefusesUnknownRevision(t *testing.T) {
	originalVersion, originalCommit := cliutil.Version, cliutil.GitCommit
	cliutil.Version = "3.5.0"
	cliutil.GitCommit = "unknown"
	t.Cleanup(func() {
		cliutil.Version = originalVersion
		cliutil.GitCommit = originalCommit
	})

	root := testRootCmd()
	root.SetArgs([]string{"rules", "schema"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "source revision are unavailable") {
		t.Fatalf("rules schema error = %v", err)
	}
}

func TestRulesSchemaCommandRefusesPartialBuildStamps(t *testing.T) {
	originalVersion, originalCommit := cliutil.Version, cliutil.GitCommit
	cliutil.Version = "0.0.0-dev.unknown"
	cliutil.GitCommit = "abcdef0123456789"
	t.Cleanup(func() {
		cliutil.Version = originalVersion
		cliutil.GitCommit = originalCommit
	})

	root := testRootCmd()
	root.SetArgs([]string{"rules", "schema"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "exact build version") {
		t.Fatalf("rules schema partial-stamp error = %v", err)
	}
}

func TestRulesSchemaCommandReportsOutputFailure(t *testing.T) {
	originalVersion, originalCommit := cliutil.Version, cliutil.GitCommit
	cliutil.Version = "3.5.0"
	cliutil.GitCommit = "abcdef0123456789"
	t.Cleanup(func() {
		cliutil.Version = originalVersion
		cliutil.GitCommit = originalCommit
	})

	root := testRootCmd()
	root.SetOut(schemaErrorWriter{})
	root.SetArgs([]string{"rules", "schema"})
	err := root.Execute()
	if err == nil || !strings.Contains(err.Error(), "encode rule schema") {
		t.Fatalf("rules schema output error = %v", err)
	}
}

type schemaErrorWriter struct{}

func (schemaErrorWriter) Write([]byte) (int, error) {
	return 0, errors.New("forced schema output failure")
}
