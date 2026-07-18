//go:build enterprise

// Copyright 2026 Pipelock contributors
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package entcli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/luckyPipewrench/pipelock/enterprise/dashboard"
)

func TestRunLegalHoldLifecycle(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "holds.json")
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	created := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)
	if err := runLegalHoldAdd(cmd, legalHoldAddOptions{
		storePath: path,
		id:        "hold-a",
		scope:     "agent-a",
		reason:    "active review",
		created:   created.Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("runLegalHoldAdd: %v", err)
	}
	if !strings.Contains(out.String(), "created legal hold hold-a") {
		t.Fatalf("add output = %q", out.String())
	}

	out.Reset()
	if err := runLegalHoldList(cmd, legalHoldListOptions{storePath: path}); err != nil {
		t.Fatalf("runLegalHoldList: %v", err)
	}
	if !strings.Contains(out.String(), "agent-a") || !strings.Contains(out.String(), "active review") {
		t.Fatalf("list output = %q", out.String())
	}

	released := created.Add(time.Hour)
	out.Reset()
	if err := runLegalHoldRelease(cmd, legalHoldReleaseOptions{
		storePath: path,
		id:        "hold-a",
		released:  released.Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("runLegalHoldRelease: %v", err)
	}
	store, err := dashboard.OpenLegalHoldStore(path)
	if err != nil {
		t.Fatalf("OpenLegalHoldStore: %v", err)
	}
	if got := store.List(); len(got) != 1 || got[0].Released == nil {
		t.Fatalf("holds = %+v, want released entry", got)
	}
}

func TestLegalHoldCommandsRejectMalformedTime(t *testing.T) {
	t.Parallel()

	cmd := &cobra.Command{}
	if err := runLegalHoldAdd(cmd, legalHoldAddOptions{created: "not-time"}); err == nil {
		t.Fatal("add accepted malformed --created")
	}
	if err := runLegalHoldRelease(cmd, legalHoldReleaseOptions{released: "not-time"}); err == nil {
		t.Fatal("release accepted malformed --released")
	}
}

func TestLegalHoldCmdStructure(t *testing.T) {
	t.Parallel()

	cmd := legalHoldCmd()
	got := map[string]bool{}
	for _, sub := range cmd.Commands() {
		got[sub.Name()] = true
	}
	for _, want := range []string{"list", "add", "release"} {
		if !got[want] {
			t.Fatalf("missing legal-hold subcommand %q", want)
		}
	}
}
