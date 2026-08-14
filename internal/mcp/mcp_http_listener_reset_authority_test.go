// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
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
	if _, err := states.authorityForToolDriftReset(&tools.ToolScanConfig{
		ListenerDriftResetAuthorityPublicKey: []byte("wrong-length"),
		ListenerDriftResetTarget:             cfg.ListenerDriftResetTarget,
	}); err == nil {
		t.Fatal("listener reset authority accepted malformed public key")
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

func TestMCPListenerLogsUnavailableSignedDriftResetAuthority(t *testing.T) {
	upstream, _ := principalStateUpstream(t)
	opts := MCPProxyOpts{
		Scanner:  testScannerForHTTP(t),
		InputCfg: newHTTPInputCfg(config.ActionBlock),
		ToolCfg: &tools.ToolScanConfig{
			DetectDrift:                          true,
			ListenerDriftResetFile:               filepath.Join(t.TempDir(), "reset"),
			ListenerDriftResetAuthorityPublicKey: []byte("wrong-length"),
			ListenerDriftResetTarget:             "mcp://listener-reset-test",
		},
	}
	_, log := startListenerProxyWithOpts(t, upstream.URL, opts)
	if !strings.Contains(log.String(), "tool drift reset authority unavailable") {
		t.Fatalf("listener startup log = %q, want unavailable authority", log.String())
	}
}

func TestMCPListenerRotatedResetAuthorityReportsCurrentMintBinding(t *testing.T) {
	for _, tt := range []struct {
		name         string
		rotateKey    bool
		rotateTarget bool
		want         ResetAuthorityResult
	}{
		{name: "key", rotateKey: true, want: ResetAuthorityWrongKey},
		{name: "target", rotateTarget: true, want: ResetAuthorityWrongTarget},
	} {
		t.Run(tt.name, func(t *testing.T) {
			oldPublicKey, oldPrivateKey, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			states := newMCPListenerClientStates(nil)
			path := filepath.Join(t.TempDir(), "reset")
			oldCfg := &tools.ToolScanConfig{
				DetectDrift:                          true,
				ListenerDriftResetFile:               path,
				ListenerDriftResetAuthorityPublicKey: oldPublicKey,
				ListenerDriftResetTarget:             "mcp://listener-before-rotation",
			}
			oldAuthority, err := states.authorityForToolDriftReset(oldCfg)
			if err != nil {
				t.Fatal(err)
			}
			oldAuthority.now = func() time.Time { return resetAuthorityTestNow }

			currentCfgValue := *oldCfg
			currentCfg := &currentCfgValue
			currentPrivateKey := oldPrivateKey
			if tt.rotateKey {
				currentCfg.ListenerDriftResetAuthorityPublicKey, currentPrivateKey, err = ed25519.GenerateKey(nil)
				if err != nil {
					t.Fatal(err)
				}
			}
			if tt.rotateTarget {
				currentCfg.ListenerDriftResetTarget = "mcp://listener-after-rotation"
			}
			currentAuthority, err := states.authorityForToolDriftReset(currentCfg)
			if err != nil {
				t.Fatal(err)
			}
			if currentAuthority == oldAuthority {
				t.Fatal("rotation reused the prior reset authority instance")
			}
			currentAuthority.now = func() time.Time { return resetAuthorityTestNow }

			stale, err := MintResetDelegation(
				oldPrivateKey, "listener-operator", ResetKindDrift, oldAuthority.Target(), oldAuthority.InstanceID(), 0,
				resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), strings.Repeat("a", 32),
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, resetDelegationBytes(t, stale), 0o600); err != nil {
				t.Fatal(err)
			}
			var rejectionLog bytes.Buffer
			if decision := states.resetUpstreamToolDriftStateIfRequested(currentCfg, &rejectionLog); decision.Result != tt.want {
				t.Fatalf("stale delegation decision = %+v, want %q", decision, tt.want)
			}
			for _, want := range []string{
				`expected_target="` + currentAuthority.Target() + `"`,
				`expected_instance="` + currentAuthority.InstanceID() + `"`,
				"expected_epoch=0",
			} {
				if !strings.Contains(rejectionLog.String(), want) {
					t.Fatalf("rotation rejection = %q, missing %q", rejectionLog.String(), want)
				}
			}

			fresh, err := MintResetDelegation(
				currentPrivateKey, "listener-operator", ResetKindDrift, currentAuthority.Target(), currentAuthority.InstanceID(), states.upstreamDriftEpoch(),
				resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), strings.Repeat("b", 32),
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, resetDelegationBytes(t, fresh), 0o600); err != nil {
				t.Fatal(err)
			}
			if decision := states.resetUpstreamToolDriftStateIfRequested(currentCfg, io.Discard); decision.Result != ResetAuthorityAccepted {
				t.Fatalf("delegation minted from rotation diagnostics = %+v", decision)
			}
			if states.upstreamDriftEpoch() != 1 {
				t.Fatalf("rotation reset epoch = %d, want 1", states.upstreamDriftEpoch())
			}
		})
	}
}

func TestMCPListenerRotationRejectsInFlightOldAuthorityDelegation(t *testing.T) {
	oldPublicKey, oldPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	states := newMCPListenerClientStates(nil)
	path := filepath.Join(t.TempDir(), "reset")
	oldCfg := &tools.ToolScanConfig{
		DetectDrift:                          true,
		ListenerDriftResetFile:               path,
		ListenerDriftResetAuthorityPublicKey: oldPublicKey,
		ListenerDriftResetTarget:             "mcp://listener-rotation-race",
	}
	oldAuthority, err := states.authorityForToolDriftReset(oldCfg)
	if err != nil {
		t.Fatalf("create old reset authority: %v", err)
	}
	oldAuthority.now = func() time.Time { return resetAuthorityTestNow }

	stale, err := MintResetDelegation(
		oldPrivateKey, "listener-operator", ResetKindDrift, oldAuthority.Target(), oldAuthority.InstanceID(), 0,
		resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), strings.Repeat("a", 32),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, resetDelegationBytes(t, stale), 0o600); err != nil {
		t.Fatal(err)
	}

	newPublicKey, newPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rotatedCfgValue := *oldCfg
	rotatedCfgValue.ListenerDriftResetAuthorityPublicKey = newPublicKey
	rotatedCfg := &rotatedCfgValue
	states.resetAuthorityToolCfgFn = func() *tools.ToolScanConfig { return rotatedCfg }

	var log bytes.Buffer
	decision := consumeToolDriftResetFile(path, oldAuthority, listenerDriftResetEpoch{
		states: states, authority: oldAuthority, resetFile: path,
	}, &log)
	if decision.Result != ResetAuthorityWrongEpoch {
		t.Fatalf("old-authority delegation result = %q, want wrong_epoch", decision.Result)
	}
	if got := states.upstreamDriftEpoch(); got != 0 {
		t.Fatalf("old-authority delegation advanced epoch after rotation to %d, want 0", got)
	}
	currentAuthority, err := states.authorityForToolDriftReset(rotatedCfg)
	if err != nil {
		t.Fatalf("read rotated reset authority: %v", err)
	}
	currentAuthority.now = func() time.Time { return resetAuthorityTestNow }
	for _, want := range []string{
		`expected_target="` + currentAuthority.Target() + `"`,
		`expected_instance="` + currentAuthority.InstanceID() + `"`,
		"expected_epoch=0",
	} {
		if !strings.Contains(log.String(), want) {
			t.Fatalf("rotation-race rejection = %q, missing %q", log.String(), want)
		}
	}

	fresh, err := MintResetDelegation(
		newPrivateKey, "listener-operator", ResetKindDrift, currentAuthority.Target(), currentAuthority.InstanceID(), 0,
		resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), strings.Repeat("b", 32),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, resetDelegationBytes(t, fresh), 0o600); err != nil {
		t.Fatal(err)
	}
	if decision := states.resetUpstreamToolDriftStateIfRequested(rotatedCfg, io.Discard); decision.Result != ResetAuthorityAccepted {
		t.Fatalf("delegation minted from current rotation binding = %+v", decision)
	}
	if got := states.upstreamDriftEpoch(); got != 1 {
		t.Fatalf("fresh rotated-authority delegation advanced epoch to %d, want 1", got)
	}
}

func TestMCPListenerReloadDisablingResetAuthorityRejectsInFlightDelegation(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	states := newMCPListenerClientStates(nil)
	path := filepath.Join(t.TempDir(), "reset")
	cfg := &tools.ToolScanConfig{
		DetectDrift:                          true,
		ListenerDriftResetFile:               path,
		ListenerDriftResetAuthorityPublicKey: publicKey,
		ListenerDriftResetTarget:             "mcp://listener-disable-race",
	}
	authority, err := states.authorityForToolDriftReset(cfg)
	if err != nil {
		t.Fatalf("create reset authority: %v", err)
	}
	authority.now = func() time.Time { return resetAuthorityTestNow }
	delegation, err := MintResetDelegation(
		privateKey, "listener-operator", ResetKindDrift, authority.Target(), authority.InstanceID(), 0,
		resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), strings.Repeat("c", 32),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, resetDelegationBytes(t, delegation), 0o600); err != nil {
		t.Fatal(err)
	}

	states.resetAuthorityToolCfgFn = func() *tools.ToolScanConfig { return nil }
	decision := consumeToolDriftResetFile(path, authority, listenerDriftResetEpoch{
		states: states, authority: authority, resetFile: path,
	}, io.Discard)
	if decision.Result != ResetAuthorityWrongEpoch {
		t.Fatalf("delegation after reset authority disable = %q, want wrong_epoch", decision.Result)
	}
	if got := states.upstreamDriftEpoch(); got != 0 {
		t.Fatalf("disabled authority delegation advanced epoch to %d, want 0", got)
	}
}

func TestListenerDriftResetEpochReportsReplacementAuthorityBinding(t *testing.T) {
	oldPublicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	states := newMCPListenerClientStates(nil)
	oldCfg := &tools.ToolScanConfig{
		DetectDrift:                          true,
		ListenerDriftResetFile:               filepath.Join(t.TempDir(), "old-reset"),
		ListenerDriftResetAuthorityPublicKey: oldPublicKey,
		ListenerDriftResetTarget:             "mcp://listener-before-replacement",
	}
	oldAuthority, err := states.authorityForToolDriftReset(oldCfg)
	if err != nil {
		t.Fatal(err)
	}
	currentPublicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	currentCfg := &tools.ToolScanConfig{
		DetectDrift:                          true,
		ListenerDriftResetFile:               filepath.Join(t.TempDir(), "current-reset"),
		ListenerDriftResetAuthorityPublicKey: currentPublicKey,
		ListenerDriftResetTarget:             "mcp://listener-after-replacement",
	}
	currentAuthority, err := states.authorityForToolDriftReset(currentCfg)
	if err != nil {
		t.Fatal(err)
	}

	epoch := listenerDriftResetEpoch{states: states, authority: oldAuthority, resetFile: oldCfg.ListenerDriftResetFile}
	if epoch.AdvanceEpoch(0) {
		t.Fatal("replaced authority advanced the listener epoch")
	}
	target, instanceID, gotEpoch := epoch.CurrentBinding()
	if target != currentAuthority.Target() || instanceID != currentAuthority.InstanceID() || gotEpoch != 0 {
		t.Fatalf("current replacement binding = %q/%q/%d, want %q/%q/0", target, instanceID, gotEpoch, currentAuthority.Target(), currentAuthority.InstanceID())
	}
}

func TestListenerDriftResetEpochFailsClosedWhenReloadConfigIsInvalid(t *testing.T) {
	states := newMCPListenerClientStates(nil)
	states.resetAuthorityToolCfgFn = func() *tools.ToolScanConfig {
		return &tools.ToolScanConfig{
			DetectDrift:                          true,
			ListenerDriftResetFile:               filepath.Join(t.TempDir(), "reset"),
			ListenerDriftResetAuthorityPublicKey: []byte("wrong-length"),
			ListenerDriftResetTarget:             "mcp://listener-invalid-reload",
		}
	}
	target, instanceID, epoch := (listenerDriftResetEpoch{states: states}).CurrentBinding()
	if target != "" || instanceID != "" || epoch != 0 {
		t.Fatalf("invalid reload binding = %q/%q/%d, want empty/empty/0", target, instanceID, epoch)
	}
}
