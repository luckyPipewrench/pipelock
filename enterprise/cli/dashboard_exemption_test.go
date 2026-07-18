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

func newExemptionTestCmd() (*cobra.Command, *bytes.Buffer) {
	cmd := &cobra.Command{}
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	return cmd, &buf
}

func TestRunExemptionLifecycleCommands(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "exemptions.json")
	cmd, out := newExemptionTestCmd()

	if err := runExemptionList(cmd, exemptionListOptions{storePath: storePath}); err != nil {
		t.Fatalf("runExemptionList(empty): %v", err)
	}
	if !strings.Contains(out.String(), "no exemption records") {
		t.Fatalf("empty list output = %q, want no-records message", out.String())
	}

	expiry := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	out.Reset()
	if err := runExemptionAdd(cmd, exemptionAddOptions{
		storePath: storePath,
		scope:     "api.vendor.example",
		owner:     "sec-team",
		reason:    "reviewed provider exception",
		expiryStr: expiry,
		createdBy: "operator-a",
	}); err != nil {
		t.Fatalf("runExemptionAdd: %v", err)
	}
	if !strings.Contains(out.String(), "created exemption record") {
		t.Fatalf("add output = %q, want created message", out.String())
	}

	store, err := dashboard.OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore: %v", err)
	}
	records := store.List()
	if len(records) != 1 {
		t.Fatalf("List() = %d records, want 1", len(records))
	}
	id := records[0].ID

	out.Reset()
	if err := runExemptionList(cmd, exemptionListOptions{storePath: storePath}); err != nil {
		t.Fatalf("runExemptionList(populated): %v", err)
	}
	if !strings.Contains(out.String(), "sec-team") || !strings.Contains(out.String(), "reviewed provider exception") {
		t.Fatalf("populated list output missing record fields: %q", out.String())
	}

	touchedAt := time.Now().Add(time.Minute).UTC().Format(time.RFC3339)
	out.Reset()
	if err := runExemptionTouch(cmd, exemptionTouchOptions{storePath: storePath, id: id, whenStr: touchedAt}); err != nil {
		t.Fatalf("runExemptionTouch: %v", err)
	}
	if !strings.Contains(out.String(), "touched exemption record "+id) {
		t.Fatalf("touch output = %q, want touched message", out.String())
	}

	renewedExpiry := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	out.Reset()
	if err := runExemptionRenew(cmd, exemptionRenewOptions{storePath: storePath, id: id, expiryStr: renewedExpiry}); err != nil {
		t.Fatalf("runExemptionRenew: %v", err)
	}
	if !strings.Contains(out.String(), "renewed exemption record "+id) {
		t.Fatalf("renew output = %q, want renewed message", out.String())
	}

	out.Reset()
	if err := runExemptionExpire(cmd, exemptionIDOptions{storePath: storePath, id: id}); err != nil {
		t.Fatalf("runExemptionExpire: %v", err)
	}
	if !strings.Contains(out.String(), "expired exemption record "+id) {
		t.Fatalf("expire output = %q, want expired message", out.String())
	}

	out.Reset()
	if err := runExemptionRemove(cmd, exemptionIDOptions{storePath: storePath, id: id}); err != nil {
		t.Fatalf("runExemptionRemove: %v", err)
	}
	if !strings.Contains(out.String(), "removed exemption record "+id) {
		t.Fatalf("remove output = %q, want removed message", out.String())
	}

	store, err = dashboard.OpenExemptionStore(storePath)
	if err != nil {
		t.Fatalf("OpenExemptionStore after remove: %v", err)
	}
	if records := store.List(); len(records) != 0 {
		t.Fatalf("records after remove = %d, want 0", len(records))
	}
}

func TestRunExemptionCommandErrors(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "exemptions.json")
	cmd, _ := newExemptionTestCmd()

	if err := runExemptionAdd(cmd, exemptionAddOptions{storePath: storePath, expiryStr: "not-time"}); err == nil || !strings.Contains(err.Error(), "--expiry") {
		t.Fatalf("runExemptionAdd bad expiry error = %v, want --expiry", err)
	}
	if err := runExemptionRenew(cmd, exemptionRenewOptions{storePath: storePath, id: "missing", expiryStr: "not-time"}); err == nil || !strings.Contains(err.Error(), "--expiry") {
		t.Fatalf("runExemptionRenew bad expiry error = %v, want --expiry", err)
	}
	if err := runExemptionTouch(cmd, exemptionTouchOptions{storePath: storePath, id: "missing", whenStr: "not-time"}); err == nil || !strings.Contains(err.Error(), "--when") {
		t.Fatalf("runExemptionTouch bad when error = %v, want --when", err)
	}
	if err := runExemptionExpire(cmd, exemptionIDOptions{storePath: storePath, id: "missing"}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("runExemptionExpire missing error = %v, want not found", err)
	}
	if err := runExemptionRemove(cmd, exemptionIDOptions{storePath: storePath, id: "missing"}); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("runExemptionRemove missing error = %v, want not found", err)
	}
}

func TestExemptionCmdStructure(t *testing.T) {
	root := exemptionCmd()
	subs := map[string]bool{}
	for _, c := range root.Commands() {
		subs[c.Name()] = true
	}
	for _, want := range []string{"list", "add", "expire", "renew", "touch", "remove"} {
		if !subs[want] {
			t.Fatalf("missing exemption subcommand %q", want)
		}
	}
	if id, err := generateExemptionID(); err != nil {
		t.Fatalf("generateExemptionID: %v", err)
	} else if !strings.HasPrefix(id, "exm_") || len(id) != len("exm_")+exemptionIDBytes*2 {
		t.Fatalf("generateExemptionID() = %q, want exm_ plus %d hex chars", id, exemptionIDBytes*2)
	}
}
