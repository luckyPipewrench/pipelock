// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
)

func TestMCPListenerSignedDriftResetCachesAuthorityAndAdvancesEpoch(t *testing.T) {
	var nilStates *mcpListenerClientStates
	if nilStates.upstreamDriftEpoch() != 0 {
		t.Fatal("nil listener state has a drift epoch")
	}

	states := newMCPListenerClientStates(nil)
	if decision := states.resetUpstreamToolDriftStateIfRequested(nil, nil); decision.Result != ResetAuthorityAbsent {
		t.Fatalf("nil tool config reset decision = %+v", decision)
	}
	if decision := states.resetUpstreamToolDriftStateIfRequested(&tools.ToolScanConfig{DetectDrift: false}, nil); decision.Result != ResetAuthorityAbsent {
		t.Fatalf("disabled drift reset decision = %+v", decision)
	}

	var unavailableLog bytes.Buffer
	missing := &tools.ToolScanConfig{DetectDrift: true, ListenerDriftResetFile: filepath.Join(t.TempDir(), "reset")}
	if decision := states.resetUpstreamToolDriftStateIfRequested(missing, &unavailableLog); decision.Result != ResetAuthorityUnreadable {
		t.Fatalf("missing authority reset decision = %+v", decision)
	}
	if !strings.Contains(unavailableLog.String(), "authority unavailable") {
		t.Fatalf("missing authority log = %q", unavailableLog.String())
	}

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "reset")
	cfg := &tools.ToolScanConfig{
		DetectDrift:                          true,
		ListenerDriftResetFile:               path,
		ListenerDriftResetAuthorityPublicKey: publicKey,
		ListenerDriftResetTarget:             "mcp://listener-reset-test",
	}
	authority, err := states.authorityForToolDriftReset(cfg)
	if err != nil {
		t.Fatalf("create listener reset authority: %v", err)
	}
	authority.now = func() time.Time { return resetAuthorityTestNow }
	cached, err := states.authorityForToolDriftReset(cfg)
	if err != nil || cached != authority {
		t.Fatalf("listener reset authority cache = %p, %v; want %p", cached, err, authority)
	}
	delegation, err := MintResetDelegation(
		privateKey,
		"listener-operator",
		ResetKindDrift,
		authority.Target(),
		authority.InstanceID(),
		states.upstreamDriftEpoch(),
		resetAuthorityTestNow,
		resetAuthorityTestNow.Add(time.Minute),
		strings.Repeat("c", 32),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalResetDelegation(delegation)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	var log bytes.Buffer
	decision := states.resetUpstreamToolDriftStateIfRequested(cfg, &log)
	if decision.Result != ResetAuthorityAccepted {
		t.Fatalf("signed listener reset decision = %+v; log=%q", decision, log.String())
	}
	if states.upstreamDriftEpoch() != 1 {
		t.Fatalf("listener reset epoch = %d, want 1", states.upstreamDriftEpoch())
	}
	if !strings.Contains(log.String(), "result=accepted") {
		t.Fatalf("accepted listener reset was not logged: %q", log.String())
	}

	summary := resetAuthorityDecisionSummary(ResetAuthorityDecision{Result: ResetAuthorityWrongEpoch, ExpectedEpoch: 4})
	if !strings.Contains(summary, "expected_epoch=4") {
		t.Fatalf("wrong epoch summary = %q", summary)
	}
}
