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
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

const adaptiveResetTestTarget = "mcp://adaptive-test"

func newAdaptiveResetAuthority(t *testing.T) (*ResetAuthority, ed25519.PrivateKey) {
	t.Helper()
	pub, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newResetAuthority(pub, adaptiveResetTestTarget, strings.Repeat("a", 32), func() time.Time {
		return resetAuthorityTestNow
	})
	if err != nil {
		t.Fatal(err)
	}
	return authority, privateKey
}

func writeAdaptiveResetDelegation(t *testing.T, path string, privateKey ed25519.PrivateKey, authority *ResetAuthority, kind ResetKind, epoch uint64, nonce string) {
	t.Helper()
	d, err := MintResetDelegation(privateKey, "adaptive-operator", kind, authority.Target(), authority.InstanceID(), epoch, resetAuthorityTestNow, resetAuthorityTestNow.Add(time.Minute), nonce)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := MarshalResetDelegation(d)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestConsumeAdaptiveResetFileAcceptsSignedDelegationOnce(t *testing.T) {
	authority, privateKey := newAdaptiveResetAuthority(t)
	path := filepath.Join(t.TempDir(), "reset")
	writeAdaptiveResetDelegation(t, path, privateKey, authority, ResetKindAdaptive, 4, strings.Repeat("b", 32))
	var logW bytes.Buffer
	if got := consumeAdaptiveResetFile(path, authority, 4, &logW).Result; got != ResetAuthorityAccepted {
		t.Fatalf("consume result = %q, want accepted; log=%q", got, logW.String())
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("accepted delegation remained at control path: %v", err)
	}
	if !strings.Contains(logW.String(), `issuer="adaptive-operator"`) || !strings.Contains(logW.String(), "result=accepted") {
		t.Fatalf("accepted reset was not fully audited: %q", logW.String())
	}
	writeAdaptiveResetDelegation(t, path, privateKey, authority, ResetKindAdaptive, 4, strings.Repeat("b", 32))
	if got := consumeAdaptiveResetFile(path, authority, 4, &logW).Result; got != ResetAuthorityReplayed {
		t.Fatalf("second use result = %q, want replayed", got)
	}
}

func TestConsumeAdaptiveResetFileIgnoresOwnershipAndMode(t *testing.T) {
	authority, privateKey := newAdaptiveResetAuthority(t)
	for index, mode := range []os.FileMode{0o600, 0o666} {
		t.Run(mode.String(), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "reset")
			nonce := strings.Repeat("c", 31) + string(rune('0'+index))
			writeAdaptiveResetDelegation(t, path, privateKey, authority, ResetKindAdaptive, uint64(mode), nonce)
			if err := os.Chmod(path, mode); err != nil {
				t.Fatal(err)
			}
			if got := consumeAdaptiveResetFile(path, authority, uint64(mode), nil).Result; got != ResetAuthorityAccepted {
				t.Fatalf("mode %o result = %q, want accepted", mode, got)
			}
		})
	}
}

// resettableRecorder is a mockRecorder that also satisfies adaptiveResetter, so
// ForwardScanned can clear its escalation when the operator reset file appears.
type resettableRecorder struct {
	mockRecorder
	resetCalls int
}

func (r *resettableRecorder) Reset() (prevScore float64, prevLevel int) {
	r.resetCalls++
	prevScore, prevLevel = r.score, r.level
	r.score = 0
	r.level = 0
	return prevScore, prevLevel
}

func blockAllCriticalCfg() *config.AdaptiveEnforcement {
	return &config.AdaptiveEnforcement{
		Enabled:             true,
		EscalationThreshold: 5.0,
		Levels: config.EscalationLevels{
			Critical: config.EscalationActions{BlockAll: ptrBool(true)},
		},
	}
}

func TestForwardScanned_AdaptiveResetFileConsumesSignedAuthority(t *testing.T) {
	sc := newAdaptiveTestScanner()
	defer sc.Close()
	authority, privateKey := newAdaptiveResetAuthority(t)
	resetPath := filepath.Join(t.TempDir(), "reset")
	writeAdaptiveResetDelegation(t, resetPath, privateKey, authority, ResetKindAdaptive, 0, strings.Repeat("d", 32))

	rec := &resettableRecorder{mockRecorder: mockRecorder{level: 3}}
	var epoch atomic.Uint64
	opts := buildTestOpts(sc, withRec(rec), withAdaptive(blockAllCriticalCfg()), withResetFile(resetPath))
	opts.AdaptiveResetAuthority = authority
	opts.AdaptiveResetEpoch = &epoch
	cleanResp := makeResponse(1, "clean safe content") + "\n"
	var outBuf, logBuf bytes.Buffer
	if _, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(cleanResp)), transport.NewStdioWriter(&outBuf), &logBuf, nil, opts); err != nil {
		t.Fatalf("ForwardScanned: %v", err)
	}
	if rec.resetCalls != 1 || rec.EscalationLevel() != 0 || epoch.Load() != 1 {
		t.Fatalf("authorized reset calls=%d level=%d epoch=%d, want 1/0/1", rec.resetCalls, rec.EscalationLevel(), epoch.Load())
	}
	if strings.Contains(outBuf.String(), "-32001") || !strings.Contains(logBuf.String(), "result=accepted") {
		t.Fatalf("authorized reset did not clear airlock: response=%s log=%s", outBuf.String(), logBuf.String())
	}
}

func TestForwardScanned_AdaptiveResetAuthorityFailuresKeepAirlock(t *testing.T) {
	sc := newAdaptiveTestScanner()
	defer sc.Close()
	authority, privateKey := newAdaptiveResetAuthority(t)
	cleanResp := makeResponse(1, "clean safe content") + "\n"

	t.Run("wrong kind", func(t *testing.T) {
		resetPath := filepath.Join(t.TempDir(), "reset")
		writeAdaptiveResetDelegation(t, resetPath, privateKey, authority, ResetKindDrift, 0, strings.Repeat("e", 32))
		rec := &resettableRecorder{mockRecorder: mockRecorder{level: 3}}
		var epoch atomic.Uint64
		opts := buildTestOpts(sc, withRec(rec), withAdaptive(blockAllCriticalCfg()), withResetFile(resetPath))
		opts.AdaptiveResetAuthority, opts.AdaptiveResetEpoch = authority, &epoch
		var outBuf, logBuf bytes.Buffer
		if _, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(cleanResp)), transport.NewStdioWriter(&outBuf), &logBuf, nil, opts); err != nil {
			t.Fatalf("ForwardScanned: %v", err)
		}
		if rec.resetCalls != 0 || !strings.Contains(outBuf.String(), "-32001") || !strings.Contains(logBuf.String(), "result=wrong_kind") {
			t.Fatalf("wrong kind cleared airlock: calls=%d response=%s log=%s", rec.resetCalls, outBuf.String(), logBuf.String())
		}
	})

	t.Run("absent authority", func(t *testing.T) {
		resetPath := filepath.Join(t.TempDir(), "reset")
		writeAdaptiveResetDelegation(t, resetPath, privateKey, authority, ResetKindAdaptive, 0, strings.Repeat("f", 32))
		rec := &resettableRecorder{mockRecorder: mockRecorder{level: 3}}
		opts := buildTestOpts(sc, withRec(rec), withAdaptive(blockAllCriticalCfg()), withResetFile(resetPath))
		var outBuf bytes.Buffer
		if _, err := ForwardScanned(transport.NewStdioReader(strings.NewReader(cleanResp)), transport.NewStdioWriter(&outBuf), io.Discard, nil, opts); err != nil {
			t.Fatalf("ForwardScanned: %v", err)
		}
		if rec.resetCalls != 0 || !strings.Contains(outBuf.String(), "-32001") {
			t.Fatalf("absent authority cleared airlock: calls=%d response=%s", rec.resetCalls, outBuf.String())
		}
		if _, err := os.Stat(resetPath); err != nil {
			t.Fatalf("absent authority removed operator control file: %v", err)
		}
	})
}
