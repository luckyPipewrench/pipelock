// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package selfupdate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestCmd_Construction(t *testing.T) {
	cmd := Cmd()
	if cmd.Use != "update" {
		t.Fatalf("Use = %q", cmd.Use)
	}
	if len(cmd.Aliases) != 1 || cmd.Aliases[0] != "upgrade" {
		t.Fatalf("aliases = %v", cmd.Aliases)
	}
	for _, f := range []string{"check", "version", "yes", "rollback", "json", "insecure-skip-signature"} {
		if cmd.Flags().Lookup(f) == nil {
			t.Fatalf("missing flag --%s", f)
		}
	}
}

func TestRunCommand_CheckJSON(t *testing.T) {
	assets, _ := standardAssets(t, testLatest, testGOOS)
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "OLD")
	opts := baseOptions(rs, target)
	opts.CheckOnly = true
	opts.JSON = true
	out := &bytes.Buffer{}

	cmd := Cmd()
	cmd.SetOut(out)
	cmd.SetErr(out)

	if err := runCommand(context.Background(), cmd, opts, false); err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	var st Status
	if err := json.Unmarshal(out.Bytes(), &st); err != nil {
		t.Fatalf("json: %v (out=%q)", err, out.String())
	}
	if st.LatestVersion != testLatest || !st.UpdateAvailable {
		t.Fatalf("json status wrong: %+v", st)
	}
	// --check makes no changes.
	if got, _ := readFile(target); got != "OLD" {
		t.Fatalf("check mutated target: %q", got)
	}
}

func TestRunCommand_CheckHuman(t *testing.T) {
	assets, _ := standardAssets(t, testLatest, testGOOS)
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "OLD")
	opts := baseOptions(rs, target)
	opts.CheckOnly = true
	out := &bytes.Buffer{}

	cmd := Cmd()
	cmd.SetOut(out)
	cmd.SetErr(out)

	if err := runCommand(context.Background(), cmd, opts, false); err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if !strings.Contains(out.String(), "update is available") {
		t.Fatalf("expected availability message, got %q", out.String())
	}
}

func TestRunCommand_YesUpdateJSON(t *testing.T) {
	assets, _ := standardAssets(t, testLatest, testGOOS)
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "OLD")
	opts := baseOptions(rs, target)
	opts.AssumeYes = true
	opts.JSON = true
	out := &bytes.Buffer{}

	cmd := Cmd()
	cmd.SetOut(out)
	cmd.SetErr(out)

	if err := runCommand(context.Background(), cmd, opts, false); err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	var st Status
	if err := json.Unmarshal(out.Bytes(), &st); err != nil {
		t.Fatalf("json: %v (out=%q)", err, out.String())
	}
	if !st.Applied {
		t.Fatalf("expected applied, got %+v", st)
	}
}

func TestRunCommand_ConfirmDeclined(t *testing.T) {
	assets, _ := standardAssets(t, testLatest, testGOOS)
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "OLD")
	opts := baseOptions(rs, target)
	out := &bytes.Buffer{}

	cmd := Cmd()
	cmd.SetOut(out)
	cmd.SetErr(out)
	cmd.SetIn(strings.NewReader("n\n")) // decline

	if err := runCommand(context.Background(), cmd, opts, false); err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if !strings.Contains(out.String(), "cancelled") {
		t.Fatalf("expected cancellation, got %q", out.String())
	}
	if got, _ := readFile(target); got != "OLD" {
		t.Fatalf("declined update still mutated target: %q", got)
	}
}

func TestRunCommand_RollbackFlag(t *testing.T) {
	target := writeTargetBinary(t, "NEW")
	if err := os.WriteFile(target+backupSuffix, []byte("PREVIOUS"), 0o755); err != nil { // #nosec G306 -- test fixture binary needs exec bit
		t.Fatalf("write backup: %v", err)
	}
	opts := &Options{
		TargetPath:     target,
		CurrentVersion: testCurrent,
		Stdout:         &bytes.Buffer{},
		Stderr:         &bytes.Buffer{},
	}
	out := &bytes.Buffer{}
	cmd := Cmd()
	cmd.SetOut(out)
	cmd.SetErr(out)

	if err := runCommand(context.Background(), cmd, opts, true); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if got, _ := readFile(target); got != "PREVIOUS" {
		t.Fatalf("rollback failed: %q", got)
	}
}

func TestRunCommand_ErrorJSONEmitsStatus(t *testing.T) {
	assets, archiveName := standardAssets(t, testLatest, testGOOS)
	assets[checksumsFile] = []byte("deadbeef  " + archiveName + "\n")
	rs := newReleaseServer(t, testLatest, assets)
	target := writeTargetBinary(t, "ORIGINAL")
	opts := baseOptions(rs, target)
	opts.AssumeYes = true
	opts.JSON = true
	out := &bytes.Buffer{}
	cmd := Cmd()
	cmd.SetOut(out)
	cmd.SetErr(out)

	err := runCommand(context.Background(), cmd, opts, false)
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("expected ErrChecksumMismatch, got %v", err)
	}
	// JSON status with error field should have been emitted.
	if !strings.Contains(out.String(), `"error"`) {
		t.Fatalf("expected error field in JSON, got %q", out.String())
	}
}

// readFile is a tiny test helper.
func readFile(path string) (string, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- test reads its own temp file
	return string(b), err
}
