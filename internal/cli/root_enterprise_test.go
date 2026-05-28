//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

// Lives in package cli_test (not cli) so the blank import of
// enterprise/cli — which itself imports internal/cli to register commands
// — does not create a build-time import cycle. External test packages
// can pull in both sides without forming one.
package cli_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cli"
	// Blank import to fire the enterprise/cli init() that registers the
	// conductor and fleet-sink commands. Without this, rootCmd() returns
	// a tree without them and these tests would fail under -tags enterprise.
	_ "github.com/luckyPipewrench/pipelock/enterprise/cli"
)

// Cmd is a cli.Execute()-compatible accessor for the root command. The
// production package keeps rootCmd unexported; for tests in the external
// package we re-derive the tree by invoking Execute against a no-op
// args set. Instead, we expose a thin helper via cli.ExportRootCmd in the
// internal-test file — see root_test_export_test.go.
func TestFleetSinkHelpRegistered(t *testing.T) {
	cmd := cli.ExportRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"fleet-sink", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("fleet-sink help: %v", err)
	}
	if got := out.String(); !strings.Contains(got, "--trusted-audit-key") {
		t.Fatalf("help output = %q, want trusted audit key flag", got)
	}
}

func TestConductorServeHelpRegistered(t *testing.T) {
	cmd := cli.ExportRootCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"conductor", "serve", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("conductor serve help: %v", err)
	}
	got := out.String()
	if !strings.Contains(got, "--publisher-token-file") || !strings.Contains(got, "--client-ca") {
		t.Fatalf("help output = %q, want conductor serve auth flags", got)
	}
}
