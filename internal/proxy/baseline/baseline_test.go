// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package baseline

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	testAgent        = "agent-1"
	testManifestHMAC = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("chmod 0o000 does not make files unreadable for EUID 0")
	}
}

// makeReadOnly removes all permissions from a directory for testing.
// 0o000 satisfies gosec G302 (<=0o600) and prevents any file writes.
func makeReadOnly(dir string) error { return os.Chmod(dir, 0o000) }

// restoreWritable restores permissions so t.TempDir cleanup succeeds.
func restoreWritable(dir string) error { return os.Chmod(dir, 0o750) } //nolint:gosec // G302: directory needs execute bit for traversal

// keyDirReadExecMode is r-x: traverse+read but deny writes, to force a
// persistence WRITE failure while keeping the dir traversable. Declared as a
// var so os.Chmod call sites take an identifier, not an octal literal that
// gosec G302 flags.
var keyDirReadExecMode os.FileMode = 0o500

func normalMetrics() SessionMetrics {
	return SessionMetrics{
		ToolCalls:   4,
		UniqueTools: 2,
		Domains:     5,
		BytesTotal:  1000,
		DurationSec: 60,
		Requests:    10,
	}
}

func TestNewManager_Defaults(t *testing.T) {
	cfg := Config{Enabled: true, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if mgr.cfg.LearningWindow != 10 {
		t.Errorf("expected default LearningWindow=10, got %d", mgr.cfg.LearningWindow)
	}
	if mgr.cfg.SensitivitySigma != 2.0 {
		t.Errorf("expected default SensitivitySigma=2.0, got %f", mgr.cfg.SensitivitySigma)
	}
	if mgr.cfg.DeviationAction != "warn" {
		t.Errorf("expected default DeviationAction=warn, got %s", mgr.cfg.DeviationAction)
	}
	if mgr.cfg.SeasonalityMode != seasonalityNone {
		t.Errorf("expected default SeasonalityMode=none, got %s", mgr.cfg.SeasonalityMode)
	}
}

func TestReadRegularFileNoSymlinkReadsRegularFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("secure no-follow baseline reads fail closed on Windows; see the Windows-specific fail-closed test")
	}
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, []byte("profile"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	got, err := readRegularFileNoSymlink(path, "baseline profile", 1024)
	if err != nil {
		t.Fatalf("readRegularFileNoSymlink: %v", err)
	}
	if string(got) != "profile" {
		t.Fatalf("data = %q, want profile", got)
	}
}

func TestReadRegularFileNoSymlinkRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation requires privileges on some CI hosts")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	link := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(target, []byte("profile"), 0o600); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if _, err := readRegularFileNoSymlink(link, "baseline profile", 1024); err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("readRegularFileNoSymlink symlink error = %v, want symlink rejection", err)
	}
}

func TestReadRegularFileNoSymlinkRejectsSymlinkParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation requires privileges on some CI hosts")
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatalf("Mkdir root: %v", err)
	}
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o750); err != nil {
		t.Fatalf("Mkdir realDir: %v", err)
	}
	path := filepath.Join(realDir, "profile.json")
	if err := os.WriteFile(path, []byte("profile"), 0o600); err != nil {
		t.Fatalf("WriteFile profile: %v", err)
	}
	linkDir := filepath.Join(root, "linked")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatalf("Symlink parent: %v", err)
	}
	_, err := readRegularFileNoSymlinkInRoot(filepath.Join(linkDir, "profile.json"), root, "baseline profile", 1024)
	if err == nil || !strings.Contains(err.Error(), "parent directory") || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("readRegularFileNoSymlink parent symlink error = %v, want parent symlink rejection", err)
	}
}

func TestReadRegularFileNoSymlinkAllowsSymlinkedPrefixAboveTrustedRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation requires privileges on some CI hosts")
	}
	dir := t.TempDir()
	realPrefix := filepath.Join(dir, "real-prefix")
	if err := os.Mkdir(realPrefix, 0o750); err != nil {
		t.Fatalf("Mkdir realPrefix: %v", err)
	}
	trustedRoot := filepath.Join(realPrefix, "baseline")
	if err := os.Mkdir(trustedRoot, 0o750); err != nil {
		t.Fatalf("Mkdir trustedRoot: %v", err)
	}
	path := filepath.Join(trustedRoot, "profile.json")
	if err := os.WriteFile(path, []byte("profile"), 0o600); err != nil {
		t.Fatalf("WriteFile profile: %v", err)
	}
	prefixLink := filepath.Join(dir, "linked-prefix")
	if err := os.Symlink(realPrefix, prefixLink); err != nil {
		t.Fatalf("Symlink prefix: %v", err)
	}

	rootThroughPrefix := filepath.Join(prefixLink, "baseline")
	got, err := readRegularFileNoSymlinkInRoot(filepath.Join(rootThroughPrefix, "profile.json"), rootThroughPrefix, "baseline profile", 1024)
	if err != nil {
		t.Fatalf("readRegularFileNoSymlinkInRoot through symlinked prefix: %v", err)
	}
	if string(got) != "profile" {
		t.Fatalf("data = %q, want profile", got)
	}
}

func TestReadRegularFileNoSymlinkRejectsSymlinkSwap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows lacks O_NOFOLLOW for a deterministic post-Lstat symlink swap rejection")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(path, []byte("profile"), 0o600); err != nil {
		t.Fatalf("WriteFile profile: %v", err)
	}
	if err := os.WriteFile(target, []byte("replacement"), 0o600); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}
	_, err := readRegularFileNoSymlinkWithOpenHook(path, "baseline profile", 1024, func() error {
		if err := os.Remove(path); err != nil {
			return err
		}
		return os.Symlink(target, path)
	})
	if err == nil {
		t.Fatal("readRegularFileNoSymlinkWithOpenHook succeeded after symlink swap")
	}
	if !strings.Contains(err.Error(), "symlink raced into place") && !strings.Contains(err.Error(), "changed during read") {
		t.Fatalf("swap error = %v, want symlink race or changed-file rejection", err)
	}
}

func TestReadRegularFileNoSymlinkRejectsParentSymlinkSwapWithinTrustedRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows lacks O_NOFOLLOW for a deterministic parent symlink swap rejection")
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatalf("Mkdir root: %v", err)
	}
	profiles := filepath.Join(root, "profiles")
	if err := os.Mkdir(profiles, 0o750); err != nil {
		t.Fatalf("Mkdir profiles: %v", err)
	}
	path := filepath.Join(profiles, "profile.json")
	if err := os.WriteFile(path, []byte("profile"), 0o600); err != nil {
		t.Fatalf("WriteFile profile: %v", err)
	}
	outside := filepath.Join(dir, "outside")
	if err := os.Mkdir(outside, 0o750); err != nil {
		t.Fatalf("Mkdir outside: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "profile.json"), []byte("replacement"), 0o600); err != nil {
		t.Fatalf("WriteFile outside profile: %v", err)
	}

	_, err := readRegularFileNoSymlinkInRootWithOpenHook(path, root, "baseline profile", 1024, func() error {
		if err := os.Remove(path); err != nil {
			return err
		}
		if err := os.Remove(profiles); err != nil {
			return err
		}
		return os.Symlink(outside, profiles)
	})
	if err == nil {
		t.Fatal("readRegularFileNoSymlinkInRootWithOpenHook succeeded after parent symlink swap")
	}
	if !strings.Contains(err.Error(), "symlink raced into place") && !strings.Contains(err.Error(), "parent directory") {
		t.Fatalf("swap error = %v, want parent symlink race rejection", err)
	}
}

func TestBaseline_InvalidDeviationActionRejected(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T) error
	}{
		{
			name: "new_manager",
			run: func(t *testing.T) error {
				t.Helper()
				_, err := NewManager(Config{
					Enabled:         true,
					DeviationAction: "observe",
					ProfileDir:      t.TempDir(),
				})
				return err
			},
		},
		{
			name: "reconfigure",
			run: func(t *testing.T) error {
				t.Helper()
				mgr, err := NewManager(Config{Enabled: true, ProfileDir: t.TempDir()})
				if err != nil {
					t.Fatalf("NewManager: %v", err)
				}
				return mgr.Reconfigure(Config{
					Enabled:         true,
					DeviationAction: "observe",
					ProfileDir:      t.TempDir(),
				})
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(t); err == nil {
				t.Fatal("expected invalid deviation_action to be rejected")
			}
		})
	}
}

func TestBaseline_Learning(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Record 3 sessions with slightly varying tool calls.
	for i := range 3 {
		mgr.RecordSession(testAgent, SessionMetrics{
			ToolCalls: 3 + i, UniqueTools: 2, Domains: 5,
			BytesTotal: 1000, DurationSec: 60, Requests: 10,
		})
	}

	// Profile should be available but not ratified.
	profile := mgr.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("expected profile after learning window")
	}
	if profile.Ratified {
		t.Error("profile should not be ratified yet")
	}
	if profile.SessionCount != 3 {
		t.Errorf("expected session count 3, got %d", profile.SessionCount)
	}
	if profile.ObservedSessionCount != 3 {
		t.Errorf("expected observed session count 3, got %d", profile.ObservedSessionCount)
	}
	if profile.TrimmedSessionCount != 0 {
		t.Errorf("expected trimmed session count 0, got %d", profile.TrimmedSessionCount)
	}

	// Mean of [3,4,5] = 4.0.
	if math.Abs(profile.Metrics.ToolCallsPerSession.Mean-4.0) > 0.1 {
		t.Errorf("expected mean ~4.0, got %f", profile.Metrics.ToolCallsPerSession.Mean)
	}
}

func TestBaseline_StateTransitions(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Initial state should be observe (no agent yet).
	if state := mgr.GetState(testAgent); state != StateObserve {
		t.Errorf("expected %q, got %q", StateObserve, state)
	}

	// Record 2 sessions: still in observe.
	for range 2 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if state := mgr.GetState(testAgent); state != StateObserve {
		t.Errorf("expected %q after 2 sessions, got %q", StateObserve, state)
	}

	// Record 3rd session: transitions to ratify (observe->learn->ratify).
	mgr.RecordSession(testAgent, normalMetrics())
	if state := mgr.GetState(testAgent); state != StateRatify {
		t.Errorf("expected %q after learning window, got %q", StateRatify, state)
	}

	// Ratify: transitions to locked.
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}
	if state := mgr.GetState(testAgent); state != StateLocked {
		t.Errorf("expected %q after ratification, got %q", StateLocked, state)
	}

	// Profile should now be ratified.
	profile := mgr.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("profile should not be nil after ratification")
	}
	if !profile.Ratified {
		t.Error("profile should be ratified")
	}
	if profile.RatifiedAt == nil {
		t.Error("ratified_at should be set")
	}
}

func TestBaseline_ProfileSnapshotsDeepCopyRatifiedAt(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	profile, ok := mgr.GetAgentProfile(testAgent)
	if !ok {
		t.Fatal("GetAgentProfile should find learned profile")
	}
	if profile.RatifiedAt == nil {
		t.Fatal("ratified snapshot should include RatifiedAt")
	}
	original := *profile.RatifiedAt
	*profile.RatifiedAt = time.Unix(0, 0).UTC()

	again, ok := mgr.GetAgentProfile(testAgent)
	if !ok {
		t.Fatal("GetAgentProfile should still find learned profile")
	}
	if again.RatifiedAt == nil || !again.RatifiedAt.Equal(original) {
		t.Fatalf("GetAgentProfile leaked mutable RatifiedAt pointer: got %v want %v", again.RatifiedAt, original)
	}

	list := mgr.ListProfiles()
	if len(list) != 1 || list[0].RatifiedAt == nil {
		t.Fatalf("ListProfiles should include ratified profile snapshot: %+v", list)
	}
	*list[0].RatifiedAt = time.Unix(1, 0).UTC()
	again, ok = mgr.GetAgentProfile(testAgent)
	if !ok {
		t.Fatal("GetAgentProfile should still find learned profile after list mutation")
	}
	if again.RatifiedAt == nil || !again.RatifiedAt.Equal(original) {
		t.Fatalf("ListProfiles leaked mutable RatifiedAt pointer: got %v want %v", again.RatifiedAt, original)
	}
}

func TestBaseline_ProfileSnapshotsIncludeLearningAgents(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	mgr.RecordSession(testAgent, normalMetrics())

	if _, ok := mgr.GetAgentProfile("missing-agent"); ok {
		t.Fatal("GetAgentProfile should not find unknown agents")
	}

	profile, ok := mgr.GetAgentProfile(testAgent)
	if !ok {
		t.Fatal("GetAgentProfile should include learning agent")
	}
	if profile.AgentKey != testAgent || profile.State != StateObserve || profile.SessionCount != 0 {
		t.Fatalf("unexpected learning snapshot: %+v", profile)
	}

	profiles := mgr.ListProfiles()
	if len(profiles) != 1 {
		t.Fatalf("ListProfiles count = %d, want 1: %+v", len(profiles), profiles)
	}
	if profiles[0].AgentKey != testAgent || profiles[0].State != StateObserve || profiles[0].SessionCount != 0 {
		t.Fatalf("unexpected learning list snapshot: %+v", profiles[0])
	}
}

func TestBaseline_DeviationDetection(t *testing.T) {
	cfg := Config{
		Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir(),
		SensitivitySigma: 2.0,
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Learn normal behavior (identical sessions = zero stddev).
	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	// Normal session = no deviations.
	devs := mgr.Check(testAgent, normalMetrics())
	if len(devs) != 0 {
		t.Errorf("expected no deviations for normal session, got %d", len(devs))
	}

	// Anomalous session = deviations.
	anomalous := SessionMetrics{
		ToolCalls: 47, UniqueTools: 15, Domains: 50,
		BytesTotal: 100000, DurationSec: 60, Requests: 10,
	}
	devs = mgr.Check(testAgent, anomalous)
	if len(devs) == 0 {
		t.Error("expected deviations for anomalous session")
	}

	// Check explainability.
	for _, d := range devs {
		if d.Metric == "" {
			t.Error("deviation metric should not be empty")
		}
		if d.Severity == "" {
			t.Error("deviation severity should not be empty")
		}
		if d.Delta <= 0 {
			t.Errorf("deviation delta should be positive, got %f", d.Delta)
		}
	}
}

func TestBaseline_A2AIdentityDeviation(t *testing.T) {
	cfg := Config{
		Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir(),
		SensitivitySigma: 2.0,
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}
	// A locked profile that never learned this A2A method: seeing it now is a
	// deviation. This exercises the A2A tool-identity branch in Check.
	current := normalMetrics()
	current.ToolIdentities = []string{"a2a:message/send"}
	devs := mgr.Check(testAgent, current)
	found := false
	for _, d := range devs {
		if d.Metric == "tool_identity:a2a:message/send" {
			found = true
			if d.Severity != severityHigh {
				t.Errorf("A2A identity deviation severity = %q, want %q", d.Severity, severityHigh)
			}
		}
	}
	if !found {
		t.Fatalf("expected a tool_identity deviation for an unlearned A2A method, got %+v", devs)
	}
}

func TestCollectToolIdentities(t *testing.T) {
	got := collectToolIdentities([]SessionMetrics{
		{ToolIdentities: []string{"a2a:message/send", "  ", "tool:read"}},
		{ToolIdentities: []string{"a2a:message/send", "tool:write"}},
	})
	want := []string{"a2a:message/send", "tool:read", "tool:write"}
	if len(got) != len(want) {
		t.Fatalf("collectToolIdentities = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("collectToolIdentities[%d] = %q, want %q (full %v)", i, got[i], want[i], got)
		}
	}
	if collectToolIdentities(nil) != nil {
		t.Error("collectToolIdentities(nil) should be nil")
	}
}

func TestBaseline_UnratifiedNoEnforcement(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}

	// State is ratify but NOT locked. Check should return nil.
	devs := mgr.Check(testAgent, SessionMetrics{ToolCalls: 999})
	if len(devs) != 0 {
		t.Errorf("expected no deviations before ratification, got %d", len(devs))
	}
}

func TestBaseline_UnknownAgentCheck(t *testing.T) {
	cfg := Config{Enabled: true, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	devs := mgr.Check("nonexistent", normalMetrics())
	if devs != nil {
		t.Error("expected nil for unknown agent")
	}
}

func TestBaseline_Ratify_WrongState(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Try to ratify before learning.
	mgr.RecordSession(testAgent, normalMetrics())
	err = mgr.Ratify(testAgent)
	if err == nil {
		t.Error("expected error ratifying in observe state")
	}
}

func TestBaseline_Ratify_NotFound(t *testing.T) {
	cfg := Config{Enabled: true, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	err = mgr.Ratify("nonexistent")
	if err == nil {
		t.Error("expected error ratifying nonexistent agent")
	}
}

func TestBaseline_Reset(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}
	if state := mgr.GetState(testAgent); state != StateLocked {
		t.Fatalf("expected locked, got %q", state)
	}

	// Reset back to observe.
	if err := mgr.Reset(testAgent); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if state := mgr.GetState(testAgent); state != StateObserve {
		t.Errorf("expected observe after reset, got %q", state)
	}
	if profile := mgr.GetProfile(testAgent); profile != nil {
		t.Error("profile should be nil after reset")
	}
	devs := mgr.Check(testAgent, SessionMetrics{ToolCalls: 999})
	if len(devs) != 0 {
		t.Errorf("expected reset profile to stop enforcement, got %d deviations", len(devs))
	}
}

func TestBaseline_Reset_FailsClosedWhenRemovalFails(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: dir}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}
	if state := mgr.GetState(testAgent); state != StateLocked {
		t.Fatalf("expected locked after ratify, got %q", state)
	}

	// Force os.Remove to fail by replacing the persisted profile file with a
	// NON-EMPTY directory at the same path. ENOTEMPTY fails regardless of
	// test privilege, unlike a read-only parent dir (bypassed under root).
	path := filepath.Join(dir, testAgent+profileFileExt)
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove seeded profile: %v", err)
	}
	if err := os.Mkdir(path, 0o750); err != nil {
		t.Fatalf("mkdir blocker dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, "blocker"), []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}

	// Forget must fail closed: surface the removal error and leave the
	// profile enforcing, NOT report success while the locked profile would
	// resurrect on the next loadProfiles().
	if err := mgr.Reset(testAgent); err == nil {
		t.Fatal("expected Reset to error when persisted profile cannot be removed")
	}
	if state := mgr.GetState(testAgent); state != StateLocked {
		t.Fatalf("profile must stay locked after failed forget, got %q", state)
	}
	if profile := mgr.GetProfile(testAgent); profile == nil {
		t.Fatal("profile must remain in memory after failed forget")
	}
	if devs := mgr.Check(testAgent, SessionMetrics{ToolCalls: 9999}); len(devs) == 0 {
		t.Fatal("enforcement must remain active after a failed forget")
	}
}

// seedLockedProfile creates a ratified, locked, persisted profile for testAgent
// in dir and returns its on-disk path.
func seedLockedProfile(t *testing.T, dir string) string {
	t.Helper()
	return seedLockedProfileFor(t, dir, testAgent)
}

func seedLockedProfileFor(t *testing.T, dir, agentKey string) string {
	t.Helper()
	return seedLockedProfileForMetrics(t, dir, agentKey, normalMetrics())
}

func seedLockedProfileForMetrics(t *testing.T, dir, agentKey string, metrics SessionMetrics) string {
	t.Helper()
	seed, err := NewManager(Config{Enabled: true, LearningWindow: 3, ProfileDir: dir})
	if err != nil {
		t.Fatalf("seed NewManager: %v", err)
	}
	for range 3 {
		seed.RecordSession(agentKey, metrics)
	}
	if err := seed.Ratify(agentKey); err != nil {
		t.Fatalf("seed Ratify: %v", err)
	}
	path := filepath.Join(dir, agentKey+profileFileExt)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("seed profile not persisted: %v", err)
	}
	return path
}

func seedPendingProfile(t *testing.T, dir, action string) (*Manager, string) {
	t.Helper()
	mgr, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: action,
		ProfileDir:      dir,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if state := mgr.GetState(testAgent); state != StateRatify {
		t.Fatalf("seeded state = %q, want %q", state, StateRatify)
	}
	path := filepath.Join(dir, testAgent+profileFileExt)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("seed pending profile not persisted: %v", err)
	}
	if _, err := os.Stat(baselineIntegrityManifestPath(dir)); err != nil {
		t.Fatalf("seed pending manifest not persisted: %v", err)
	}
	return mgr, path
}

func rewriteProfileToolCallsMean(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	var profile Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatalf("unmarshal profile: %v", err)
	}
	profile.Metrics.ToolCallsPerSession = Range{
		Min:    100,
		Max:    100,
		Mean:   100,
		StdDev: 0,
	}
	data, err = json.MarshalIndent(profile, "", "  ")
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}
}

func waitForPath(path string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(filepath.Clean(path)); err == nil {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		<-ticker.C
	}
}

func rewriteProfileState(t *testing.T, path string, state ProfileState) {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read profile: %v", err)
	}
	var profile Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		t.Fatalf("unmarshal profile: %v", err)
	}
	profile.State = state
	data, err = json.MarshalIndent(profile, "", "  ")
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}
}

func baselineIntegrityManifestPath(dir string) string {
	return filepath.Join(dir, integrityManifestDirName, integrityManifestFileName)
}

func baselineIntegrityKeyPath(dir string) string {
	return filepath.Clean(dir) + ".integrity.key"
}

func persistIntegrityManifestForExistingProfile(t *testing.T, dir, agentKey string) {
	t.Helper()
	cfg := Config{Enabled: true, ProfileDir: dir}
	if err := normalizeIntegrityConfig(&cfg); err != nil {
		t.Fatalf("normalize integrity config: %v", err)
	}
	mgr := &Manager{
		cfg: cfg,
		agents: map[string]*agentState{
			agentKey: {
				profile: &Profile{State: StateLocked},
				state:   StateLocked,
			},
		},
	}
	if err := mgr.persistIntegrityManifest(nil); err != nil {
		t.Fatalf("persist integrity manifest: %v", err)
	}
}

func copyFileBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}

func writeFileBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Clean(path), data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func loadVerifiedIntegrityManifestForTest(t *testing.T, dir string) ([]byte, integrityManifest) {
	t.Helper()
	cfg := Config{Enabled: true, ProfileDir: dir}
	if err := normalizeIntegrityConfig(&cfg); err != nil {
		t.Fatalf("normalize integrity config: %v", err)
	}
	mgr := &Manager{cfg: cfg}
	key, err := mgr.loadIntegrityKey(false)
	if err != nil {
		t.Fatalf("load integrity key: %v", err)
	}
	data, err := os.ReadFile(filepath.Clean(baselineIntegrityManifestPath(dir)))
	if err != nil {
		t.Fatalf("read integrity manifest: %v", err)
	}
	manifest, err := verifyIntegrityManifest(data, key)
	if err != nil {
		t.Fatalf("verify integrity manifest: %v", err)
	}
	return key, manifest
}

func readVerifiedIntegrityManifest(t *testing.T, dir string) integrityManifest {
	t.Helper()
	_, manifest := loadVerifiedIntegrityManifestForTest(t, dir)
	return manifest
}

func rewriteIntegrityManifest(t *testing.T, dir string, edit func(*integrityManifest)) {
	t.Helper()
	key, manifest := loadVerifiedIntegrityManifestForTest(t, dir)
	edit(&manifest)
	writeSignedIntegrityManifest(t, dir, key, manifest)
}

func rewriteAcceptedIntegrityManifest(t *testing.T, dir string, edit func(*integrityManifest)) {
	t.Helper()
	key, manifest := loadVerifiedIntegrityManifestForTest(t, dir)
	edit(&manifest)
	mac := writeSignedIntegrityManifest(t, dir, key, manifest)
	cfg := Config{Enabled: true, ProfileDir: dir}
	if err := normalizeIntegrityConfig(&cfg); err != nil {
		t.Fatalf("normalize integrity config: %v", err)
	}
	mgr := &Manager{cfg: cfg}
	if err := mgr.writeIntegrityHighWater(manifest.Generation, key, mac); err != nil {
		t.Fatalf("accept rewritten integrity manifest: %v", err)
	}
}

func writeSignedIntegrityManifest(t *testing.T, dir string, key []byte, manifest integrityManifest) string {
	t.Helper()
	mac, err := signIntegrityManifest(manifest, key)
	if err != nil {
		t.Fatalf("sign rewritten integrity manifest: %v", err)
	}
	out, err := json.MarshalIndent(integrityManifestFile{Manifest: manifest, HMAC: mac}, "", "  ")
	if err != nil {
		t.Fatalf("marshal rewritten integrity manifest: %v", err)
	}
	writeFileBytes(t, baselineIntegrityManifestPath(dir), out)
	return mac
}

// TestBaseline_LoadProfiles_FailsClosedOnCorruptProfileUnderEnforcement proves
// that a persisted profile which exists but cannot be read or parsed fails the
// manager's startup when the deviation action is enforcing (ask/block).
// Silently skipping it (the pre-fix behavior) erased a locked agent's
// enforcement on the next restart - a fail-open on a security control.
func TestBaseline_LoadProfiles_FailsClosedOnCorruptProfileUnderEnforcement(t *testing.T) {
	corruptJSON := func(t *testing.T, path string) {
		t.Helper()
		if err := os.WriteFile(path, []byte("{ not valid json"), 0o600); err != nil {
			t.Fatalf("corrupt profile: %v", err)
		}
	}
	// replaceWithBrokenSymlink makes os.ReadFile fail (ENOENT via a dangling
	// link) while keeping the dir entry a non-directory with the profile
	// extension, so it reaches the read path. This is privilege-independent -
	// a chmod-000 regular file is bypassed under root.
	replaceWithBrokenSymlink := func(t *testing.T, path string) {
		t.Helper()
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove seeded profile: %v", err)
		}
		if err := os.Symlink(filepath.Join(t.TempDir(), "does-not-exist"), path); err != nil {
			t.Fatalf("symlink at profile path: %v", err)
		}
	}

	tests := []struct {
		name    string
		action  string
		corrupt func(*testing.T, string)
		wantErr bool
	}{
		{"malformed_json_block_fails_closed", deviationActionBlock, corruptJSON, true},
		{"read_error_block_fails_closed", deviationActionBlock, replaceWithBrokenSymlink, true},
		{"malformed_json_ask_fails_closed", deviationActionAsk, corruptJSON, true},
		{"read_error_ask_fails_closed", deviationActionAsk, replaceWithBrokenSymlink, true},
		{"malformed_json_warn_starts_skipping", deviationActionWarn, corruptJSON, false},
		{"read_error_warn_starts_skipping", deviationActionWarn, replaceWithBrokenSymlink, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := seedLockedProfile(t, dir)
			tc.corrupt(t, path)

			_, err := NewManager(Config{
				Enabled:         true,
				LearningWindow:  3,
				DeviationAction: tc.action,
				ProfileDir:      dir,
			})
			if tc.wantErr && err == nil {
				t.Fatalf("NewManager: want fail-closed error for corrupt profile under deviation_action %q, got nil (fail-open)", tc.action)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("NewManager: want success under deviation_action %q, got %v", tc.action, err)
			}
		})
	}
}

func TestBaseline_LoadProfiles_VerifiesLockedProfileIntegrityManifest(t *testing.T) {
	dir := t.TempDir()
	_ = seedLockedProfile(t, dir)

	restarted, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err != nil {
		t.Fatalf("NewManager with intact locked profile: %v", err)
	}
	if state := restarted.GetState(testAgent); state != StateLocked {
		t.Fatalf("state = %q, want %q", state, StateLocked)
	}
	if devs := restarted.Check(testAgent, SessionMetrics{ToolCalls: 9999}); len(devs) == 0 {
		t.Fatal("locked profile loaded through integrity manifest must enforce")
	}
}

func TestBaseline_LoadProfiles_AllowsAgentNamedManifestUnderEnforcement(t *testing.T) {
	dir := t.TempDir()
	const agentKey = "manifest"
	_ = seedLockedProfileFor(t, dir, agentKey)

	restarted, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err != nil {
		t.Fatalf("NewManager with agent named manifest: %v", err)
	}
	if state := restarted.GetState(agentKey); state != StateLocked {
		t.Fatalf("state = %q, want %q", state, StateLocked)
	}
	if devs := restarted.Check(agentKey, SessionMetrics{ToolCalls: 9999}); len(devs) == 0 {
		t.Fatal("agent named manifest must still enforce")
	}
}

func TestBaseline_LoadProfiles_FailsClosedOnLockedProfileTamperUnderEnforcement(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(t *testing.T, dir, path string)
	}{
		{
			name: "deleted_profile",
			tamper: func(t *testing.T, _, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatalf("delete profile: %v", err)
				}
			},
		},
		{
			name: "dir_swapped_profile",
			tamper: func(t *testing.T, _, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove profile: %v", err)
				}
				if err := os.Mkdir(path, 0o750); err != nil {
					t.Fatalf("mkdir profile path: %v", err)
				}
			},
		},
		{
			name: "profile_symlink",
			tamper: func(t *testing.T, _, path string) {
				t.Helper()
				data := copyFileBytes(t, path)
				target := filepath.Join(t.TempDir(), "copied-profile")
				writeFileBytes(t, target, data)
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove profile: %v", err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatalf("symlink profile path: %v", err)
				}
			},
		},
		{
			name: "profile_oversized",
			tamper: func(t *testing.T, _, path string) {
				t.Helper()
				oversized := make([]byte, baselineProfileMaxSize+1)
				for i := range oversized {
					oversized[i] = 'a'
				}
				if err := os.WriteFile(path, oversized, 0o600); err != nil {
					t.Fatalf("write oversized profile: %v", err)
				}
			},
		},
		{
			name: "state_downgrade",
			tamper: func(t *testing.T, _, path string) {
				t.Helper()
				rewriteProfileState(t, path, StateObserve)
			},
		},
		{
			name: "learned_range_edit",
			tamper: func(t *testing.T, _, path string) {
				t.Helper()
				rewriteProfileToolCallsMean(t, path)
			},
		},
		{
			name: "manifest_hmac_forged",
			tamper: func(t *testing.T, dir, _ string) {
				t.Helper()
				manifestPath := baselineIntegrityManifestPath(dir)
				data, err := os.ReadFile(filepath.Clean(manifestPath))
				if err != nil {
					t.Fatalf("read manifest: %v", err)
				}
				var manifest integrityManifestFile
				if err := json.Unmarshal(data, &manifest); err != nil {
					t.Fatalf("unmarshal manifest: %v", err)
				}
				prefix := "0"
				if manifest.HMAC[0] == '0' {
					prefix = "1"
				}
				manifest.HMAC = prefix + manifest.HMAC[1:]
				data, err = json.MarshalIndent(manifest, "", "  ")
				if err != nil {
					t.Fatalf("marshal forged manifest: %v", err)
				}
				if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
					t.Fatalf("write forged manifest: %v", err)
				}
			},
		},
		{
			name: "wrong_hmac_key",
			tamper: func(t *testing.T, dir, _ string) {
				t.Helper()
				wrongKey := "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"
				if err := os.WriteFile(baselineIntegrityKeyPath(dir), []byte(wrongKey), 0o600); err != nil {
					t.Fatalf("write wrong key: %v", err)
				}
			},
		},
		{
			name: "hmac_key_deleted",
			tamper: func(t *testing.T, dir, _ string) {
				t.Helper()
				if err := os.Remove(baselineIntegrityKeyPath(dir)); err != nil {
					t.Fatalf("delete hmac key: %v", err)
				}
			},
		},
		{
			name: "hmac_key_directory",
			tamper: func(t *testing.T, dir, _ string) {
				t.Helper()
				keyPath := baselineIntegrityKeyPath(dir)
				if err := os.Remove(keyPath); err != nil {
					t.Fatalf("remove hmac key: %v", err)
				}
				if err := os.Mkdir(keyPath, 0o750); err != nil {
					t.Fatalf("mkdir hmac key path: %v", err)
				}
			},
		},
		{
			name: "hmac_key_symlink",
			tamper: func(t *testing.T, dir, _ string) {
				t.Helper()
				keyPath := baselineIntegrityKeyPath(dir)
				data := copyFileBytes(t, keyPath)
				target := filepath.Join(t.TempDir(), "copied-key")
				writeFileBytes(t, target, data)
				if err := os.Remove(keyPath); err != nil {
					t.Fatalf("remove hmac key: %v", err)
				}
				if err := os.Symlink(target, keyPath); err != nil {
					t.Fatalf("symlink hmac key path: %v", err)
				}
			},
		},
		{
			name: "manifest_deleted",
			tamper: func(t *testing.T, dir, _ string) {
				t.Helper()
				if err := os.Remove(baselineIntegrityManifestPath(dir)); err != nil {
					t.Fatalf("delete manifest: %v", err)
				}
			},
		},
		{
			name: "manifest_symlink",
			tamper: func(t *testing.T, dir, _ string) {
				t.Helper()
				manifestPath := baselineIntegrityManifestPath(dir)
				data := copyFileBytes(t, manifestPath)
				target := filepath.Join(t.TempDir(), "copied-manifest")
				writeFileBytes(t, target, data)
				if err := os.Remove(manifestPath); err != nil {
					t.Fatalf("remove manifest: %v", err)
				}
				if err := os.Symlink(target, manifestPath); err != nil {
					t.Fatalf("symlink manifest path: %v", err)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := seedLockedProfile(t, dir)
			tc.tamper(t, dir, path)

			_, err := NewManager(Config{
				Enabled:         true,
				LearningWindow:  3,
				DeviationAction: deviationActionBlock,
				ProfileDir:      dir,
			})
			if err == nil {
				t.Fatal("NewManager: want fail-closed error for locked profile integrity tamper under block")
			}
		})
	}
}

func TestBaseline_LoadProfiles_WarnModeDoesNotFailClosedOnIntegrityTamper(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(t *testing.T, dir, path string)
	}{
		{
			name: "deleted_profile",
			tamper: func(t *testing.T, _, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatalf("delete profile: %v", err)
				}
			},
		},
		{
			name: "dir_swapped_profile",
			tamper: func(t *testing.T, _, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatalf("remove profile: %v", err)
				}
				if err := os.Mkdir(path, 0o750); err != nil {
					t.Fatalf("mkdir profile path: %v", err)
				}
			},
		},
		{
			name: "manifest_deleted",
			tamper: func(t *testing.T, dir, _ string) {
				t.Helper()
				if err := os.Remove(baselineIntegrityManifestPath(dir)); err != nil {
					t.Fatalf("delete manifest: %v", err)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := seedLockedProfile(t, dir)
			tc.tamper(t, dir, path)

			if _, err := NewManager(Config{
				Enabled:         true,
				LearningWindow:  3,
				DeviationAction: deviationActionWarn,
				ProfileDir:      dir,
			}); err != nil {
				t.Fatalf("NewManager under warn should stay lenient: %v", err)
			}
		})
	}
}

func TestBaseline_PendingProfileIntegrityTamper(t *testing.T) {
	tests := []struct {
		name            string
		action          string
		wantRatifyError bool
		wantLoadError   bool
	}{
		{
			name:            "block_fails_closed",
			action:          deviationActionBlock,
			wantRatifyError: true,
			wantLoadError:   true,
		},
		{
			name:            "ask_fails_closed",
			action:          deviationActionAsk,
			wantRatifyError: true,
			wantLoadError:   true,
		},
		{
			name:   "warn_is_lenient",
			action: deviationActionWarn,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name+"_ratify", func(t *testing.T) {
			dir := t.TempDir()
			mgr, path := seedPendingProfile(t, dir, tc.action)
			rewriteProfileToolCallsMean(t, path)

			err := mgr.Ratify(testAgent)
			if tc.wantRatifyError {
				if err == nil {
					t.Fatal("Ratify: want pending-profile integrity error")
				}
				if state := mgr.GetState(testAgent); state != StateRatify {
					t.Fatalf("state after failed ratify = %q, want %q", state, StateRatify)
				}
				return
			}
			if err != nil {
				t.Fatalf("Ratify under %q should be lenient: %v", tc.action, err)
			}
			if state := mgr.GetState(testAgent); state != StateLocked {
				t.Fatalf("state after lenient ratify = %q, want %q", state, StateLocked)
			}
		})

		t.Run(tc.name+"_load", func(t *testing.T) {
			dir := t.TempDir()
			_, path := seedPendingProfile(t, dir, tc.action)
			rewriteProfileToolCallsMean(t, path)

			mgr, err := NewManager(Config{
				Enabled:         true,
				LearningWindow:  3,
				DeviationAction: tc.action,
				ProfileDir:      dir,
			})
			if tc.wantLoadError {
				if err == nil {
					t.Fatal("NewManager: want pending-profile integrity error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewManager under %q should be lenient: %v", tc.action, err)
			}
			if state := mgr.GetState(testAgent); state != StateRatify {
				t.Fatalf("loaded state = %q, want %q", state, StateRatify)
			}
		})
	}
}

func TestBaseline_VerifyPendingProfileIntegrityEdges(t *testing.T) {
	t.Run("in_memory_profile_dir_skips_integrity_check", func(t *testing.T) {
		mgr := &Manager{cfg: Config{DeviationAction: deviationActionBlock}}
		if err := mgr.verifyPendingProfileIntegrityForRatify(testAgent); err != nil {
			t.Fatalf("verifyPendingProfileIntegrityForRatify without ProfileDir: %v", err)
		}
	})

	t.Run("missing_integrity_key", func(t *testing.T) {
		dir := t.TempDir()
		mgr, _ := seedPendingProfile(t, dir, deviationActionBlock)
		if err := os.Remove(baselineIntegrityKeyPath(dir)); err != nil {
			t.Fatalf("remove integrity key: %v", err)
		}

		if err := mgr.verifyPersistedProfileIntegrity(testAgent); err == nil {
			t.Fatal("verifyPersistedProfileIntegrity: want missing key error")
		}
	})

	t.Run("invalid_manifest_hmac", func(t *testing.T) {
		dir := t.TempDir()
		mgr, _ := seedPendingProfile(t, dir, deviationActionBlock)
		var file integrityManifestFile
		data := copyFileBytes(t, baselineIntegrityManifestPath(dir))
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatalf("parse manifest file: %v", err)
		}
		file.HMAC = strings.Repeat("0", sha256.Size*2)
		out, err := json.Marshal(file)
		if err != nil {
			t.Fatalf("marshal manifest file: %v", err)
		}
		writeFileBytes(t, baselineIntegrityManifestPath(dir), out)

		if err := mgr.verifyPersistedProfileIntegrity(testAgent); err == nil {
			t.Fatal("verifyPersistedProfileIntegrity: want invalid manifest error")
		}
	})

	t.Run("rollback_generation_rejected", func(t *testing.T) {
		dir := t.TempDir()
		mgr, _ := seedPendingProfile(t, dir, deviationActionBlock)
		key, err := mgr.loadIntegrityKey(false)
		if err != nil {
			t.Fatalf("load integrity key: %v", err)
		}
		if err := mgr.writeIntegrityHighWater(2, key, testManifestHMAC); err != nil {
			t.Fatalf("write advanced high-water: %v", err)
		}

		if err := mgr.verifyPersistedProfileIntegrity(testAgent); err == nil {
			t.Fatal("verifyPersistedProfileIntegrity: want rollback rejection")
		}
	})

	t.Run("missing_target_entry_after_other_manifest_entry", func(t *testing.T) {
		dir := t.TempDir()
		mgr, _ := seedPendingProfile(t, dir, deviationActionBlock)
		rewriteIntegrityManifest(t, dir, func(manifest *integrityManifest) {
			manifest.Profiles = []integrityManifestEntry{{
				AgentKey: "other-agent",
				SHA256:   strings.Repeat("0", sha256.Size*2),
				State:    StateRatify,
			}}
		})

		if err := mgr.verifyPersistedProfileIntegrity(testAgent); err == nil {
			t.Fatal("verifyPersistedProfileIntegrity: want missing target entry error")
		}
	})

	t.Run("manifest_state_mismatch", func(t *testing.T) {
		dir := t.TempDir()
		mgr, _ := seedPendingProfile(t, dir, deviationActionBlock)
		rewriteIntegrityManifest(t, dir, func(manifest *integrityManifest) {
			manifest.Profiles[0].State = StateLocked
		})

		if err := mgr.verifyPersistedProfileIntegrity(testAgent); err == nil {
			t.Fatal("verifyPersistedProfileIntegrity: want manifest state mismatch error")
		}
	})

	t.Run("profile_missing", func(t *testing.T) {
		dir := t.TempDir()
		mgr, path := seedPendingProfile(t, dir, deviationActionBlock)
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove pending profile: %v", err)
		}

		if err := mgr.verifyPersistedProfileIntegrity(testAgent); err == nil {
			t.Fatal("verifyPersistedProfileIntegrity: want missing profile error")
		}
	})

	t.Run("profile_parse_failure_after_matching_hash", func(t *testing.T) {
		dir := t.TempDir()
		mgr, path := seedPendingProfile(t, dir, deviationActionBlock)
		data := []byte("{ not json")
		writeFileBytes(t, path, data)
		rewriteIntegrityManifest(t, dir, func(manifest *integrityManifest) {
			manifest.Profiles[0].SHA256 = profileBytesHash(data)
		})

		if err := mgr.verifyPersistedProfileIntegrity(testAgent); err == nil {
			t.Fatal("verifyPersistedProfileIntegrity: want profile parse error")
		}
	})

	t.Run("empty_profile_agent_key_uses_filename", func(t *testing.T) {
		dir := t.TempDir()
		mgr, path := seedPendingProfile(t, dir, deviationActionBlock)
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("read pending profile: %v", err)
		}
		var profile Profile
		if err := json.Unmarshal(data, &profile); err != nil {
			t.Fatalf("parse pending profile: %v", err)
		}
		profile.AgentKey = ""
		data, err = json.Marshal(profile)
		if err != nil {
			t.Fatalf("marshal pending profile: %v", err)
		}
		writeFileBytes(t, path, data)
		rewriteAcceptedIntegrityManifest(t, dir, func(manifest *integrityManifest) {
			manifest.Profiles[0].SHA256 = profileBytesHash(data)
		})

		if err := mgr.verifyPersistedProfileIntegrity(testAgent); err != nil {
			t.Fatalf("verifyPersistedProfileIntegrity with filename-derived agent key: %v", err)
		}
	})

	t.Run("profile_agent_key_mismatch", func(t *testing.T) {
		dir := t.TempDir()
		mgr, path := seedPendingProfile(t, dir, deviationActionBlock)
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("read pending profile: %v", err)
		}
		var profile Profile
		if err := json.Unmarshal(data, &profile); err != nil {
			t.Fatalf("parse pending profile: %v", err)
		}
		profile.AgentKey = "other-agent"
		data, err = json.Marshal(profile)
		if err != nil {
			t.Fatalf("marshal pending profile: %v", err)
		}
		writeFileBytes(t, path, data)
		rewriteIntegrityManifest(t, dir, func(manifest *integrityManifest) {
			manifest.Profiles[0].SHA256 = profileBytesHash(data)
		})

		if err := mgr.verifyPersistedProfileIntegrity(testAgent); err == nil {
			t.Fatal("verifyPersistedProfileIntegrity: want declared agent mismatch error")
		}
	})

	t.Run("profile_state_mismatch_after_matching_hash", func(t *testing.T) {
		dir := t.TempDir()
		mgr, path := seedPendingProfile(t, dir, deviationActionBlock)
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			t.Fatalf("read pending profile: %v", err)
		}
		var profile Profile
		if err := json.Unmarshal(data, &profile); err != nil {
			t.Fatalf("parse pending profile: %v", err)
		}
		profile.State = StateObserve
		data, err = json.Marshal(profile)
		if err != nil {
			t.Fatalf("marshal pending profile: %v", err)
		}
		writeFileBytes(t, path, data)
		rewriteIntegrityManifest(t, dir, func(manifest *integrityManifest) {
			manifest.Profiles[0].SHA256 = profileBytesHash(data)
		})

		if err := mgr.verifyPersistedProfileIntegrity(testAgent); err == nil {
			t.Fatal("verifyPersistedProfileIntegrity: want profile state mismatch error")
		}
	})
}

func TestBaseline_VerifyPersistedIntegrityManifestEntryFaults(t *testing.T) {
	tests := []struct {
		name   string
		tamper func(t *testing.T, dir, path string)
	}{
		{
			name: "unsupported_manifest_state",
			tamper: func(t *testing.T, dir, _ string) {
				rewriteIntegrityManifest(t, dir, func(manifest *integrityManifest) {
					manifest.Profiles[0].State = StateObserve
				})
			},
		},
		{
			name: "profile_parse_failure_after_matching_hash",
			tamper: func(t *testing.T, dir, path string) {
				data := []byte("{ not json")
				writeFileBytes(t, path, data)
				rewriteIntegrityManifest(t, dir, func(manifest *integrityManifest) {
					manifest.Profiles[0].SHA256 = profileBytesHash(data)
				})
			},
		},
		{
			name: "profile_agent_key_mismatch",
			tamper: func(t *testing.T, dir, path string) {
				data := copyFileBytes(t, path)
				var profile Profile
				if err := json.Unmarshal(data, &profile); err != nil {
					t.Fatalf("parse profile: %v", err)
				}
				profile.AgentKey = "other-agent"
				data, err := json.Marshal(profile)
				if err != nil {
					t.Fatalf("marshal profile: %v", err)
				}
				writeFileBytes(t, path, data)
				rewriteIntegrityManifest(t, dir, func(manifest *integrityManifest) {
					manifest.Profiles[0].SHA256 = profileBytesHash(data)
				})
			},
		},
		{
			name: "profile_state_mismatch",
			tamper: func(t *testing.T, dir, path string) {
				data := copyFileBytes(t, path)
				var profile Profile
				if err := json.Unmarshal(data, &profile); err != nil {
					t.Fatalf("parse profile: %v", err)
				}
				profile.State = StateRatify
				data, err := json.Marshal(profile)
				if err != nil {
					t.Fatalf("marshal profile: %v", err)
				}
				writeFileBytes(t, path, data)
				rewriteIntegrityManifest(t, dir, func(manifest *integrityManifest) {
					manifest.Profiles[0].SHA256 = profileBytesHash(data)
				})
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := seedLockedProfile(t, dir)
			tc.tamper(t, dir, path)

			if _, err := NewManager(Config{
				Enabled:         true,
				LearningWindow:  3,
				DeviationAction: deviationActionBlock,
				ProfileDir:      dir,
			}); err == nil {
				t.Fatal("NewManager: want fail-closed integrity error")
			}
		})
	}
}

func TestBaseline_LoadProfiles_NoManifestStartupBoundaries(t *testing.T) {
	tests := []struct {
		name    string
		action  string
		seed    func(t *testing.T, dir string)
		wantErr bool
	}{
		{
			name:   "first_run_empty_enforcing",
			action: deviationActionBlock,
		},
		{
			name:   "first_run_empty_warn",
			action: deviationActionWarn,
		},
		{
			name:   "profile_dir_wipe_after_integrity_state_fails_closed",
			action: deviationActionBlock,
			seed: func(t *testing.T, dir string) {
				t.Helper()
				_ = seedLockedProfile(t, dir)
				if err := os.RemoveAll(dir); err != nil {
					t.Fatalf("wipe profile dir: %v", err)
				}
			},
			wantErr: true,
		},
		{
			name:   "profiles_without_manifest_enforcing_fails_closed",
			action: deviationActionBlock,
			seed: func(t *testing.T, dir string) {
				t.Helper()
				_ = seedLockedProfile(t, dir)
				if err := os.Remove(baselineIntegrityManifestPath(dir)); err != nil {
					t.Fatalf("delete manifest: %v", err)
				}
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.seed != nil {
				tc.seed(t, dir)
			}

			_, err := NewManager(Config{
				Enabled:         true,
				LearningWindow:  3,
				DeviationAction: tc.action,
				ProfileDir:      dir,
			})
			if tc.wantErr {
				if err == nil {
					t.Fatal("NewManager: want fail-closed error under block")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewManager: %v", err)
			}
		})
	}
}

func TestBaseline_PendingProfileIntegrityCleanResetAndWipe(t *testing.T) {
	t.Run("pending_reset_leaves_clean_integrity_state", func(t *testing.T) {
		dir := t.TempDir()
		mgr, _ := seedPendingProfile(t, dir, deviationActionBlock)
		if err := mgr.Reset(testAgent); err != nil {
			t.Fatalf("Reset pending profile: %v", err)
		}
		restarted, err := NewManager(Config{
			Enabled:         true,
			LearningWindow:  3,
			DeviationAction: deviationActionBlock,
			ProfileDir:      dir,
		})
		if err != nil {
			t.Fatalf("NewManager after pending reset: %v", err)
		}
		if agents := restarted.ListAgents(); len(agents) != 0 {
			t.Fatalf("agents after pending reset restart = %v, want none", agents)
		}
	})

	t.Run("full_wipe_clears_trusted_integrity_state", func(t *testing.T) {
		dir := t.TempDir()
		seedPendingProfile(t, dir, deviationActionBlock)
		for _, path := range []string{
			dir,
			baselineIntegrityKeyPath(dir),
			baselineIntegrityKeyPath(dir) + ".generation",
			baselineIntegrityKeyPath(dir) + ".generation.lock",
		} {
			if err := os.RemoveAll(filepath.Clean(path)); err != nil {
				t.Fatalf("remove %s: %v", path, err)
			}
		}
		restarted, err := NewManager(Config{
			Enabled:         true,
			LearningWindow:  3,
			DeviationAction: deviationActionBlock,
			ProfileDir:      dir,
		})
		if err != nil {
			t.Fatalf("NewManager after full trusted-state wipe: %v", err)
		}
		if agents := restarted.ListAgents(); len(agents) != 0 {
			t.Fatalf("agents after full trusted-state wipe = %v, want none", agents)
		}
	})
}

func TestBaseline_IntegrityManifestCoversLockedAndRatifyProfiles(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	for range 3 {
		mgr.RecordSession("agent-a", normalMetrics())
	}
	for range 3 {
		mgr.RecordSession("agent-b", normalMetrics())
	}
	if err := mgr.Ratify("agent-a"); err != nil {
		t.Fatalf("Ratify agent-a: %v", err)
	}

	manifest := readVerifiedIntegrityManifest(t, dir)
	if len(manifest.Profiles) != 2 {
		t.Fatalf("manifest profile count = %d, want 2", len(manifest.Profiles))
	}
	if manifest.Profiles[0].AgentKey != "agent-a" || manifest.Profiles[0].State != StateLocked {
		t.Fatalf("first manifest entry = %+v, want locked agent-a", manifest.Profiles[0])
	}
	if manifest.Profiles[1].AgentKey != "agent-b" || manifest.Profiles[1].State != StateRatify {
		t.Fatalf("second manifest entry = %+v, want ratify agent-b", manifest.Profiles[1])
	}

	restarted, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err != nil {
		t.Fatalf("NewManager restart: %v", err)
	}
	if state := restarted.GetState("agent-a"); state != StateLocked {
		t.Fatalf("agent-a state = %q, want %q", state, StateLocked)
	}
	if state := restarted.GetState("agent-b"); state != StateRatify {
		t.Fatalf("agent-b state = %q, want %q", state, StateRatify)
	}
}

func TestBaseline_RatifyReplacesPendingManifestEntry(t *testing.T) {
	dir := t.TempDir()
	mgr, _ := seedPendingProfile(t, dir, deviationActionBlock)

	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	manifest := readVerifiedIntegrityManifest(t, dir)
	if len(manifest.Profiles) != 1 {
		t.Fatalf("manifest profile count = %d, want 1", len(manifest.Profiles))
	}
	if manifest.Profiles[0].AgentKey != testAgent || manifest.Profiles[0].State != StateLocked {
		t.Fatalf("manifest entry = %+v, want locked test agent", manifest.Profiles[0])
	}
}

func TestBaseline_LoadProfiles_RejectsManifestRollbackUnderEnforcement(t *testing.T) {
	dir := t.TempDir()
	profilePath := seedLockedProfile(t, dir)
	manifestPath := baselineIntegrityManifestPath(dir)
	rolledBackProfile := copyFileBytes(t, profilePath)
	rolledBackManifest := copyFileBytes(t, manifestPath)

	rewriteProfileToolCallsMean(t, profilePath)
	persistIntegrityManifestForExistingProfile(t, dir, testAgent)

	writeFileBytes(t, profilePath, rolledBackProfile)
	writeFileBytes(t, manifestPath, rolledBackManifest)

	_, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err == nil {
		t.Fatal("NewManager: want fail-closed error for replayed older manifest/profile generation")
	}
}

func TestBaseline_LoadProfiles_RejectsRollbackWithForgedPublicHighWaterDigest(t *testing.T) {
	dir := t.TempDir()
	profilePath := seedLockedProfile(t, dir)
	manifestPath := baselineIntegrityManifestPath(dir)
	rolledBackProfile := copyFileBytes(t, profilePath)
	rolledBackManifest := copyFileBytes(t, manifestPath)
	rolledBackGeneration := readVerifiedIntegrityManifest(t, dir).Generation

	rewriteProfileToolCallsMean(t, profilePath)
	persistIntegrityManifestForExistingProfile(t, dir, testAgent)

	writeFileBytes(t, profilePath, rolledBackProfile)
	writeFileBytes(t, manifestPath, rolledBackManifest)
	cfg := Config{Enabled: true, ProfileDir: dir}
	if err := normalizeIntegrityConfig(&cfg); err != nil {
		t.Fatalf("normalize integrity config: %v", err)
	}
	mgr := &Manager{cfg: cfg}
	forged, err := json.Marshal(integrityHighWaterState{
		Generation:   rolledBackGeneration,
		Context:      mgr.integrityStateContextID(),
		ManifestHMAC: testManifestHMAC,
		Digest:       legacyPublicIntegrityGenerationDigest(mgr.integrityStateContextID(), rolledBackGeneration),
	})
	if err != nil {
		t.Fatalf("marshal forged high-water: %v", err)
	}
	writeFileBytes(t, baselineIntegrityKeyPath(dir)+".generation", forged)

	_, err = NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err == nil {
		t.Fatal("NewManager: want fail-closed error for replayed profile with forged public high-water digest")
	}
}

func legacyPublicIntegrityGenerationDigest(contextID string, generation uint64) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("baseline-integrity-generation-v1\n%s\n%d", contextID, generation)))
	return hex.EncodeToString(sum[:])
}

func TestBaseline_LoadProfiles_RejectsSameGenerationManifestSwap(t *testing.T) {
	dir := t.TempDir()
	profilePath := seedLockedProfile(t, dir)
	originalProfile := copyFileBytes(t, profilePath)

	rewriteProfileToolCallsMean(t, profilePath)
	persistIntegrityManifestForExistingProfile(t, dir, testAgent)
	key, acceptedManifest := loadVerifiedIntegrityManifestForTest(t, dir)
	if acceptedManifest.Generation < 2 {
		t.Fatalf("accepted manifest generation = %d, want at least 2", acceptedManifest.Generation)
	}
	if len(acceptedManifest.Profiles) != 1 {
		t.Fatalf("accepted manifest profiles = %d, want 1", len(acceptedManifest.Profiles))
	}

	swapped := acceptedManifest
	swapped.Profiles[0].SHA256 = profileBytesHash(originalProfile)
	writeFileBytes(t, profilePath, originalProfile)
	writeSignedIntegrityManifest(t, dir, key, swapped)

	_, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err == nil {
		t.Fatal("NewManager: want fail-closed error for same-generation manifest swap")
	}
}

func TestBaseline_LoadProfiles_InvalidNewerManifestDoesNotAdvanceHighWater(t *testing.T) {
	dir := t.TempDir()
	profilePath := seedLockedProfile(t, dir)
	originalProfile := copyFileBytes(t, profilePath)
	originalManifest := copyFileBytes(t, baselineIntegrityManifestPath(dir))
	key, manifest := loadVerifiedIntegrityManifestForTest(t, dir)
	manifest.Generation++
	writeSignedIntegrityManifest(t, dir, key, manifest)
	rewriteProfileToolCallsMean(t, profilePath)

	_, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err == nil {
		t.Fatal("NewManager: want fail-closed error for invalid newer manifest/profile pair")
	}

	writeFileBytes(t, profilePath, originalProfile)
	writeFileBytes(t, baselineIntegrityManifestPath(dir), originalManifest)
	if _, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	}); err != nil {
		t.Fatalf("restored last known-good manifest/profile should still pass because high-water was not advanced: %v", err)
	}
}

func TestBaseline_LoadProfiles_RejectsMissingHighWaterWithSignedManifest(t *testing.T) {
	dir := t.TempDir()
	seedLockedProfile(t, dir)
	if err := os.Remove(baselineIntegrityKeyPath(dir) + ".generation"); err != nil {
		t.Fatalf("delete high-water: %v", err)
	}

	_, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err == nil {
		t.Fatal("NewManager: want fail-closed error when manifest exists but generation high-water is missing")
	}
}

func TestBaseline_LoadProfiles_RejectsDuplicateAgentMaskingLockedProfileUnderEnforcement(t *testing.T) {
	dir := t.TempDir()
	_ = seedLockedProfile(t, dir)

	mask := Profile{
		AgentKey: testAgent,
		State:    StateObserve,
		Metrics: ProfileMetrics{
			ToolCallsPerSession: Range{Min: 100, Max: 100, Mean: 100, StdDev: 0},
		},
	}
	data, err := json.Marshal(mask)
	if err != nil {
		t.Fatalf("marshal masking profile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "zz-mask.json"), data, 0o600); err != nil {
		t.Fatalf("write masking profile: %v", err)
	}

	_, err = NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err == nil {
		t.Fatal("NewManager: want fail-closed error for duplicate profile that could mask a locked agent")
	}
}

func TestBaseline_ResetLastLockedProfilePersistsEmptyIntegrityManifest(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	if err := mgr.Reset(testAgent); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	if _, err := os.Stat(baselineIntegrityManifestPath(dir)); err != nil {
		t.Fatalf("empty integrity manifest should remain after reset: %v", err)
	}

	restarted, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err != nil {
		t.Fatalf("NewManager after reset: %v", err)
	}
	if agents := restarted.ListAgents(); len(agents) != 0 {
		t.Fatalf("agents after reset restart = %v, want none", agents)
	}
}

func TestBaseline_ResetManifestFailureRestoresPersistedProfile(t *testing.T) {
	dir := t.TempDir()
	profilePath := seedLockedProfile(t, dir)
	mgr, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := os.WriteFile(baselineIntegrityKeyPath(dir), []byte("not-a-valid-key\n"), 0o600); err != nil {
		t.Fatalf("corrupt integrity key: %v", err)
	}

	if err := mgr.Reset(testAgent); err == nil {
		t.Fatal("Reset: want manifest update error")
	}
	if _, err := os.Stat(profilePath); err != nil {
		t.Fatalf("profile should be restored after manifest update failure: %v", err)
	}
	if devs := mgr.Check(testAgent, SessionMetrics{ToolCalls: 9999}); len(devs) == 0 {
		t.Fatal("in-memory enforcement must remain active after failed reset")
	}
}

func TestBaseline_ResetHighWaterFailureDoesNotEraseEnforcementOnRestart(t *testing.T) {
	skipIfRoot(t)
	parent := t.TempDir()
	dir := filepath.Join(parent, "profiles")
	keyDir := filepath.Join(parent, "keys")
	keyPath := filepath.Join(keyDir, "baseline.key")
	mgr, err := NewManager(Config{
		Enabled: true, LearningWindow: 3, DeviationAction: deviationActionBlock,
		ProfileDir: dir, IntegrityKeyPath: keyPath,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}
	if err := os.Chmod(keyDir, keyDirReadExecMode); err != nil {
		t.Fatalf("make key dir read-only: %v", err)
	}
	err = mgr.Reset(testAgent)
	if err == nil {
		t.Fatal("Reset: want high-water persistence error")
	}
	if devs := mgr.Check(testAgent, SessionMetrics{ToolCalls: 9999}); len(devs) == 0 {
		t.Fatal("in-memory enforcement must remain active after failed reset")
	}
	if err := restoreWritable(keyDir); err != nil {
		t.Fatalf("restore key dir writable: %v", err)
	}

	restarted, err := NewManager(Config{
		Enabled: true, LearningWindow: 3, DeviationAction: deviationActionBlock,
		ProfileDir: dir, IntegrityKeyPath: keyPath,
	})
	if err != nil {
		msg := err.Error()
		if !strings.Contains(msg, "high-water") &&
			!strings.Contains(msg, "missing from integrity manifest") &&
			!strings.Contains(msg, "rollback") {
			t.Fatalf("restart failed for unrelated reason: %v", err)
		}
		return
	}
	if state := restarted.GetState(testAgent); state != StateLocked {
		t.Fatalf("failed Reset must not erase persisted enforcement on restart; state = %q", state)
	}
	if devs := restarted.Check(testAgent, SessionMetrics{ToolCalls: 9999}); len(devs) == 0 {
		t.Fatal("failed Reset must leave restarted manager enforcing or fail closed")
	}
}

func TestBaseline_ResetMissingIntegrityKeyRestoresPersistedProfile(t *testing.T) {
	dir := t.TempDir()
	profilePath := seedLockedProfile(t, dir)
	mgr, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := os.Remove(baselineIntegrityKeyPath(dir)); err != nil {
		t.Fatalf("delete integrity key: %v", err)
	}

	if err := mgr.Reset(testAgent); err == nil {
		t.Fatal("Reset: want manifest update error after integrity key deletion")
	}
	if _, err := os.Stat(profilePath); err != nil {
		t.Fatalf("profile should be restored after missing-key manifest failure: %v", err)
	}
	if devs := mgr.Check(testAgent, SessionMetrics{ToolCalls: 9999}); len(devs) == 0 {
		t.Fatal("in-memory enforcement must remain active after failed reset")
	}
}

func TestBaseline_ReconfigureLoadsProfilesBeforeCommittingEnforcingConfig(t *testing.T) {
	startDir := t.TempDir()
	_ = seedLockedProfile(t, startDir)
	mgr, err := NewManager(Config{
		Enabled:         true,
		DeviationAction: deviationActionBlock,
		ProfileDir:      startDir,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	reloadDir := t.TempDir()
	path := seedLockedProfile(t, reloadDir)
	if err := os.WriteFile(path, []byte("{ not valid json"), 0o600); err != nil {
		t.Fatalf("corrupt profile: %v", err)
	}

	err = mgr.Reconfigure(Config{
		Enabled:         true,
		DeviationAction: deviationActionBlock,
		ProfileDir:      reloadDir,
	})
	if err == nil {
		t.Fatal("Reconfigure: want fail-closed error for corrupt profile under block")
	}
	if mgr.cfg.DeviationAction != deviationActionBlock {
		t.Fatalf("failed Reconfigure committed deviation_action = %q, want %q", mgr.cfg.DeviationAction, deviationActionBlock)
	}
	if mgr.cfg.ProfileDir != startDir {
		t.Fatalf("failed Reconfigure committed profile_dir = %q, want %q", mgr.cfg.ProfileDir, startDir)
	}
	if state := mgr.GetState(testAgent); state != StateLocked {
		t.Fatalf("failed Reconfigure changed profile state = %q, want %q", state, StateLocked)
	}
	if devs := mgr.Check(testAgent, SessionMetrics{ToolCalls: 9999}); len(devs) == 0 {
		t.Fatal("failed Reconfigure must preserve existing locked-profile enforcement")
	}
}

func TestBaseline_ReconfigureLoadsValidProfilesUnderEnforcement(t *testing.T) {
	mgr, err := NewManager(Config{
		Enabled:         true,
		DeviationAction: deviationActionWarn,
		ProfileDir:      t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	reloadDir := t.TempDir()
	_ = seedLockedProfile(t, reloadDir)

	if err := mgr.Reconfigure(Config{
		Enabled:         true,
		DeviationAction: deviationActionBlock,
		ProfileDir:      reloadDir,
	}); err != nil {
		t.Fatalf("Reconfigure with intact profile under block: %v", err)
	}
	if state := mgr.GetState(testAgent); state != StateLocked {
		t.Fatalf("reconfigured profile state = %q, want %q", state, StateLocked)
	}
	if devs := mgr.Check(testAgent, SessionMetrics{ToolCalls: 9999}); len(devs) == 0 {
		t.Fatal("reconfigured locked profile must detect deviations")
	}
}

func TestBaseline_ReconfigureReplacesProfilesWhenProfileDirChanges(t *testing.T) {
	startDir := t.TempDir()
	_ = seedLockedProfile(t, startDir)
	mgr, err := NewManager(Config{
		Enabled:         true,
		DeviationAction: deviationActionBlock,
		ProfileDir:      startDir,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	reloadDir := t.TempDir()
	replacementMetrics := normalMetrics()
	replacementMetrics.ToolCalls = 100
	_ = seedLockedProfileForMetrics(t, reloadDir, testAgent, replacementMetrics)

	if err := mgr.Reconfigure(Config{
		Enabled:         true,
		DeviationAction: deviationActionBlock,
		ProfileDir:      reloadDir,
	}); err != nil {
		t.Fatalf("Reconfigure with replacement profile dir: %v", err)
	}

	if devs := mgr.Check(testAgent, replacementMetrics); len(devs) != 0 {
		t.Fatalf("reconfigured manager kept stale profile, got deviations: %+v", devs)
	}
	if devs := mgr.Check(testAgent, normalMetrics()); len(devs) == 0 {
		t.Fatal("reconfigured manager must enforce replacement profile from new profile dir")
	}
}

func TestBaseline_LoadProfiles_MixedValidAndCorruptFailsClosedUnderBlock(t *testing.T) {
	dir := t.TempDir()
	_ = seedLockedProfileFor(t, dir, "agent-2")
	corruptPath := filepath.Join(dir, testAgent+profileFileExt)
	if err := os.WriteFile(corruptPath, []byte("{ not valid json"), 0o600); err != nil {
		t.Fatalf("write corrupt profile: %v", err)
	}

	_, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err == nil {
		t.Fatal("NewManager: want fail-closed error when any persisted profile is corrupt under block")
	}
}

// TestBaseline_LoadProfiles_ValidProfileLoadsAndEnforcesUnderBlock ensures the
// fail-closed load does not regress the normal path: an intact locked profile
// still loads and enforces under block mode.
func TestBaseline_LoadProfiles_ValidProfileLoadsAndEnforcesUnderBlock(t *testing.T) {
	dir := t.TempDir()
	_ = seedLockedProfile(t, dir)

	mgr, err := NewManager(Config{
		Enabled:         true,
		LearningWindow:  3,
		DeviationAction: deviationActionBlock,
		ProfileDir:      dir,
	})
	if err != nil {
		t.Fatalf("NewManager with intact profile under block: %v", err)
	}
	if state := mgr.GetState(testAgent); state != StateLocked {
		t.Fatalf("reloaded profile state = %q, want %q", state, StateLocked)
	}
	if devs := mgr.Check(testAgent, SessionMetrics{ToolCalls: 9999}); len(devs) == 0 {
		t.Fatal("reloaded locked profile must still detect deviations")
	}
}

func TestBaseline_LoadProfiles_EmptyOrAbsentProfileDirAllowedUnderBlock(t *testing.T) {
	tests := []struct {
		name string
		dir  string
	}{
		{"empty", t.TempDir()},
		{"absent", filepath.Join(t.TempDir(), "profiles")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewManager(Config{
				Enabled:         true,
				DeviationAction: deviationActionBlock,
				ProfileDir:      tc.dir,
			})
			if err != nil {
				t.Fatalf("NewManager with %s profile dir under block: %v", tc.name, err)
			}
		})
	}
}

func TestBaseline_Reset_NotFound(t *testing.T) {
	cfg := Config{Enabled: true, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	err = mgr.Reset("nonexistent")
	if err == nil {
		t.Error("expected error resetting nonexistent agent")
	}
}

func TestBaseline_PoisonResistance(t *testing.T) {
	// Use 10 normal sessions + 1 outlier. With enough normal data,
	// the outlier's z-score exceeds 3 sigma and gets trimmed.
	cfg := Config{
		Enabled: true, LearningWindow: 11, ProfileDir: t.TempDir(),
		PoisonResistance: true,
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// 10 normal sessions with slight variation.
	for i := range 10 {
		mgr.RecordSession(testAgent, SessionMetrics{
			ToolCalls: 3 + (i % 3), UniqueTools: 2, Domains: 5,
			BytesTotal: 1000, DurationSec: 60, Requests: 10,
		})
	}
	// Poison session: extremely high tool calls.
	mgr.RecordSession(testAgent, SessionMetrics{
		ToolCalls: 100000, UniqueTools: 2, Domains: 5,
		BytesTotal: 1000, DurationSec: 60, Requests: 10,
	})

	profile := mgr.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("expected profile after learning")
	}

	// The poison session should be trimmed. Mean should be close to 4 (normal).
	if profile.Metrics.ToolCallsPerSession.Mean > 10 {
		t.Errorf("poison session should be trimmed; mean=%f (expected ~4)", profile.Metrics.ToolCallsPerSession.Mean)
	}
	if profile.ObservedSessionCount != 11 {
		t.Errorf("observed session count = %d, want 11", profile.ObservedSessionCount)
	}
	if profile.TrimmedSessionCount != 1 {
		t.Errorf("trimmed session count = %d, want 1", profile.TrimmedSessionCount)
	}
}

func TestBaseline_PoisonResistance_AllOutliers(t *testing.T) {
	// If all sessions are outliers, use original data to avoid empty profile.
	cfg := Config{
		Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir(),
		PoisonResistance: true,
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// 3 identical sessions: zero stddev means nothing is an outlier.
	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}

	profile := mgr.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("expected profile")
	}
	if profile.SessionCount != 3 {
		t.Errorf("expected 3 sessions, got %d", profile.SessionCount)
	}
}

func TestBaseline_NoPoisonResistance(t *testing.T) {
	cfg := Config{
		Enabled: true, LearningWindow: 5, ProfileDir: t.TempDir(),
		PoisonResistance: false,
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 4 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	mgr.RecordSession(testAgent, SessionMetrics{
		ToolCalls: 10000, UniqueTools: 2, Domains: 5,
		BytesTotal: 1000, DurationSec: 60, Requests: 10,
	})

	profile := mgr.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("expected profile")
	}

	// Without poison resistance, the outlier inflates the mean.
	if profile.Metrics.ToolCallsPerSession.Mean < 100 {
		t.Errorf("without poison resistance, mean should be high; got %f", profile.Metrics.ToolCallsPerSession.Mean)
	}
}

func TestBaseline_LockDimensions(t *testing.T) {
	cfg := Config{
		Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir(),
		SensitivitySigma: 2.0,
		LockDimensions:   []string{"tool_calls"},
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	// Anomalous domains but only tool_calls is enforced.
	devs := mgr.Check(testAgent, SessionMetrics{
		ToolCalls: 4, UniqueTools: 2, Domains: 999,
		BytesTotal: 1000, DurationSec: 60, Requests: 10,
	})
	if len(devs) != 0 {
		t.Errorf("expected no deviations (domains not enforced), got %d: %v", len(devs), devs)
	}

	// Anomalous tool_calls IS enforced.
	devs = mgr.Check(testAgent, SessionMetrics{
		ToolCalls: 999, UniqueTools: 2, Domains: 5,
		BytesTotal: 1000, DurationSec: 60, Requests: 10,
	})
	if len(devs) == 0 {
		t.Error("expected deviation for anomalous tool_calls")
	}
}

func TestBaseline_AutoRatify(t *testing.T) {
	cfg := Config{
		Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir(),
		AutoRatify: true,
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}

	// Auto-ratify should skip StateRatify and go straight to locked.
	if state := mgr.GetState(testAgent); state != StateLocked {
		t.Errorf("expected %q with auto-ratify, got %q", StateLocked, state)
	}

	profile := mgr.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("expected profile with auto-ratify")
	}
	if !profile.Ratified {
		t.Error("profile should be auto-ratified")
	}
}

func TestBaseline_Persistence(t *testing.T) {
	dir := t.TempDir()

	// Create and learn a profile.
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: dir}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	// Verify file exists.
	profilePath := filepath.Join(dir, testAgent+profileFileExt)
	if _, err := os.Stat(profilePath); err != nil {
		t.Fatalf("profile file should exist: %v", err)
	}

	// Load a new manager and verify profile is restored.
	mgr2, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager (reload): %v", err)
	}

	profile := mgr2.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("profile should be loaded from disk")
	}
	if !profile.Ratified {
		t.Error("loaded profile should be ratified")
	}
	if profile.State != StateLocked {
		t.Errorf("loaded profile state should be %q, got %q", StateLocked, profile.State)
	}
}

func TestBaseline_Persistence_NoDir(t *testing.T) {
	// ProfileDir empty = no persistence (in-memory only).
	cfg := Config{Enabled: true, LearningWindow: 3}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}

	// Should work fine without persistence.
	profile := mgr.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("expected profile (in-memory)")
	}
}

func TestBaseline_Persistence_NonexistentDir(t *testing.T) {
	// ProfileDir set but doesn't exist = load returns no error (empty).
	cfg := Config{Enabled: true, ProfileDir: filepath.Join(t.TempDir(), "nonexistent")}
	_, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager should succeed with nonexistent dir: %v", err)
	}
}

func TestBaseline_ListAgents(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	mgr.RecordSession("agent-b", normalMetrics())
	mgr.RecordSession("agent-a", normalMetrics())

	agents := mgr.ListAgents()
	if len(agents) != 2 {
		t.Fatalf("expected 2 agents, got %d", len(agents))
	}
	// Should be sorted.
	if agents[0] != "agent-a" || agents[1] != "agent-b" {
		t.Errorf("expected sorted list [agent-a, agent-b], got %v", agents)
	}
}

func TestBaseline_RecordSession_InLockedState(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	// Recording in locked state should be a no-op.
	mgr.RecordSession(testAgent, SessionMetrics{ToolCalls: 999})

	profile := mgr.GetProfile(testAgent)
	if profile.SessionCount != 3 {
		t.Errorf("session count should still be 3, got %d", profile.SessionCount)
	}
}

func TestBaseline_RecordSession_InRatifyState(t *testing.T) {
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: t.TempDir()}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}

	// State is ratify. Recording should be a no-op.
	if state := mgr.GetState(testAgent); state != StateRatify {
		t.Fatalf("expected ratify, got %q", state)
	}

	mgr.RecordSession(testAgent, SessionMetrics{ToolCalls: 999})

	profile := mgr.GetProfile(testAgent)
	if profile.SessionCount != 3 {
		t.Errorf("session count should still be 3, got %d", profile.SessionCount)
	}
}

func TestBaseline_DeviationSeverity(t *testing.T) {
	// Test severity levels based on sigma distance.
	tests := []struct {
		name     string
		baseline Range
		observed float64
		sigma    float64
		wantSev  string
	}{
		{
			name:     "low severity (just outside threshold, under 2 sigma from mean)",
			baseline: Range{Min: 0, Max: 10, Mean: 5, StdDev: 2},
			observed: 8.5, // 1.75 sigma from mean, but sensitivity=1.0, so distance>1.0 triggers.
			sigma:    1.0, // Trigger threshold: 1 sigma. Distance: 1.75. Under 2 sigma = low.
			wantSev:  severityLow,
		},
		{
			name:     "medium severity (between 2 and 3 sigma from mean)",
			baseline: Range{Min: 0, Max: 10, Mean: 5, StdDev: 1},
			observed: 7.5, // 2.5 sigma from mean.
			sigma:    1.0, // Trigger threshold: 1 sigma.
			wantSev:  severityMedium,
		},
		{
			name:     "high severity (beyond 3 sigma from mean)",
			baseline: Range{Min: 0, Max: 10, Mean: 5, StdDev: 1},
			observed: 9, // 4.0 sigma from mean.
			sigma:    1.0,
			wantSev:  severityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dev := checkDeviation("test_metric", tt.baseline, tt.observed, tt.sigma)
			if dev == nil {
				t.Fatal("expected deviation")
			}
			if dev.Severity != tt.wantSev {
				distance := math.Abs(tt.observed-tt.baseline.Mean) / tt.baseline.StdDev
				t.Errorf("severity=%q (want %q), distance=%.2f sigma", dev.Severity, tt.wantSev, distance)
			}
		})
	}
}

func TestBaseline_DeviationZeroStdDev(t *testing.T) {
	// Zero stddev: any difference is a deviation.
	baseline := Range{Min: 5, Max: 5, Mean: 5, StdDev: 0}

	// Same value: no deviation.
	dev := checkDeviation("test", baseline, 5, 2.0)
	if dev != nil {
		t.Error("expected no deviation for same value with zero stddev")
	}

	// Different value: deviation with high severity.
	dev = checkDeviation("test", baseline, 6, 2.0)
	if dev == nil {
		t.Fatal("expected deviation for different value with zero stddev")
	}
	if dev.Severity != severityHigh {
		t.Errorf("expected high severity, got %q", dev.Severity)
	}
}

func TestBaseline_WithinBounds(t *testing.T) {
	// Value within sigma threshold: no deviation.
	baseline := Range{Min: 3, Max: 7, Mean: 5, StdDev: 1}
	dev := checkDeviation("test", baseline, 6.5, 2.0)
	if dev != nil {
		t.Error("expected no deviation for value within 2 sigma")
	}
}

func TestBaseline_LoadCorruptProfile(t *testing.T) {
	dir := t.TempDir()

	// Write a corrupt profile file.
	corrupt := filepath.Join(dir, "corrupt-agent.json")
	if err := os.WriteFile(corrupt, []byte("not-json"), 0o600); err != nil {
		t.Fatalf("writing corrupt file: %v", err)
	}

	cfg := Config{Enabled: true, ProfileDir: dir}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager should succeed even with corrupt profiles: %v", err)
	}

	// Corrupt profile should be silently skipped.
	agents := mgr.ListAgents()
	if len(agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(agents))
	}
}

func TestBaseline_LoadDirectoryEntry(t *testing.T) {
	dir := t.TempDir()

	// Create a subdirectory (should be skipped).
	if err := os.Mkdir(filepath.Join(dir, "subdir"), 0o750); err != nil {
		t.Fatalf("creating subdir: %v", err)
	}

	cfg := Config{Enabled: true, ProfileDir: dir}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	agents := mgr.ListAgents()
	if len(agents) != 0 {
		t.Errorf("expected 0 agents, got %d", len(agents))
	}
}

func TestBaseline_ProfileSerialization(t *testing.T) {
	profile := Profile{
		AgentKey:     testAgent,
		State:        StateLocked,
		SessionCount: 5,
		Ratified:     true,
		Metrics: ProfileMetrics{
			ToolCallsPerSession: Range{Min: 2, Max: 8, Mean: 5, StdDev: 1.5},
		},
	}

	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshaling: %v", err)
	}

	var loaded Profile
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("unmarshaling: %v", err)
	}

	if loaded.AgentKey != testAgent {
		t.Errorf("expected agent key %q, got %q", testAgent, loaded.AgentKey)
	}
	if loaded.State != StateLocked {
		t.Errorf("expected state %q, got %q", StateLocked, loaded.State)
	}
}

func TestBaseline_TrimOutliers_TooFewSessions(t *testing.T) {
	// With fewer than 3 sessions, outlier trimming returns all sessions.
	sessions := []SessionMetrics{
		{ToolCalls: 1},
		{ToolCalls: 1000},
	}

	result := trimOutliers(sessions)
	if len(result) != 2 {
		t.Errorf("expected 2 sessions (too few to trim), got %d", len(result))
	}
}

func TestComputeRange_Empty(t *testing.T) {
	r := computeRange(nil)
	if r.Min != 0 || r.Max != 0 || r.Mean != 0 || r.StdDev != 0 {
		t.Errorf("expected zero range for empty input, got %+v", r)
	}
}

func TestComputeRange_SingleValue(t *testing.T) {
	r := computeRange([]float64{42})
	if r.Min != 42 || r.Max != 42 || r.Mean != 42 {
		t.Errorf("unexpected range for single value: %+v", r)
	}
	if r.StdDev != 0 {
		t.Errorf("stddev should be 0 for single value, got %f", r.StdDev)
	}
}

func TestBaseline_LoadProfileWithEmptyAgentKey(t *testing.T) {
	dir := t.TempDir()

	// Write profile with empty agent_key. Should derive from filename.
	profile := Profile{
		AgentKey:     "",
		State:        StateLocked,
		SessionCount: 3,
		Ratified:     true,
		Metrics: ProfileMetrics{
			ToolCallsPerSession: Range{Min: 4, Max: 4, Mean: 4, StdDev: 0},
		},
	}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("marshal filename-derived profile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "derived-agent.json"), data, 0o600); err != nil {
		t.Fatalf("writing profile: %v", err)
	}
	persistIntegrityManifestForExistingProfile(t, dir, "derived-agent")

	cfg := Config{Enabled: true, DeviationAction: deviationActionBlock, ProfileDir: dir}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Should be loaded with key derived from filename.
	p := mgr.GetProfile("derived-agent")
	if p == nil {
		t.Fatal("expected profile loaded from filename-derived key")
	}
	if state := mgr.GetState("derived-agent"); state != StateLocked {
		t.Fatalf("derived profile state = %q, want %q", state, StateLocked)
	}
	if devs := mgr.Check("derived-agent", SessionMetrics{ToolCalls: 9999}); len(devs) == 0 {
		t.Fatal("filename-derived locked profile must still detect deviations")
	}
}

func TestBaseline_NonJSONFileSkipped(t *testing.T) {
	dir := t.TempDir()

	// Write a non-JSON file (wrong extension).
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	cfg := Config{Enabled: true, ProfileDir: dir}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if len(mgr.ListAgents()) != 0 {
		t.Error("non-JSON files should be skipped")
	}
}

func TestBaseline_ResetDeletesFile(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: dir}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}
	if err := mgr.Ratify(testAgent); err != nil {
		t.Fatalf("Ratify: %v", err)
	}

	profilePath := filepath.Join(dir, testAgent+profileFileExt)
	if _, err := os.Stat(profilePath); err != nil {
		t.Fatalf("profile file should exist: %v", err)
	}

	if err := mgr.Reset(testAgent); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	if _, err := os.Stat(profilePath); !os.IsNotExist(err) {
		t.Error("profile file should be deleted after reset")
	}
}

func TestBaseline_AutoRatify_PersistFailure_StaysRatify(t *testing.T) {
	// Create a profile directory that exists but is not writable.
	// persistProfile will fail, so auto-ratify must roll back to StateRatify.
	dir := t.TempDir()
	cfg := Config{
		Enabled:        true,
		LearningWindow: 3,
		ProfileDir:     dir,
		AutoRatify:     true,
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Make the directory read-only so writes fail.
	// Remove write permission so profile writes fail.
	// G302 requires <=0o600 for files, but directories need execute bit
	// to be traversable; 0o500 = r-x (read+traverse, no write).
	if err := makeReadOnly(dir); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() {
		// Restore write permission so t.TempDir cleanup succeeds.
		_ = restoreWritable(dir)
	})

	// Record enough sessions to trigger auto-ratify.
	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}

	// Profile must stay in StateRatify because persistence failed.
	if state := mgr.GetState(testAgent); state != StateRatify {
		t.Errorf("expected %q when persistence fails, got %q", StateRatify, state)
	}

	profile := mgr.GetProfile(testAgent)
	if profile == nil {
		t.Fatal("expected profile to exist")
	}
	if profile.Ratified {
		t.Error("profile must not be ratified when persistence failed")
	}
	if profile.RatifiedAt != nil {
		t.Error("ratified_at must be nil when persistence failed")
	}
	if profile.State != StateRatify {
		t.Errorf("profile.State should be %q, got %q", StateRatify, profile.State)
	}
}

func TestBaseline_Ratify_PersistFailure_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Enabled:        true,
		LearningWindow: 3,
		ProfileDir:     dir,
	}
	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// Learn a profile (writable dir during learning).
	for range 3 {
		mgr.RecordSession(testAgent, normalMetrics())
	}

	if state := mgr.GetState(testAgent); state != StateRatify {
		t.Fatalf("expected %q, got %q", StateRatify, state)
	}

	// Remove the profile file written during RecordSession (best-effort
	// persistence of the unratified profile), then make the directory
	// read-only so Ratify's persistProfile call cannot create it.
	profilePath := filepath.Join(dir, testAgent+profileFileExt)
	_ = os.Remove(filepath.Clean(profilePath))

	if err := makeReadOnly(dir); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() {
		_ = restoreWritable(dir)
	})

	// Ratify must return an error when persistence fails.
	err = mgr.Ratify(testAgent)
	if err == nil {
		t.Fatal("expected error from Ratify when persistence fails")
	}
}

func TestNewManager_CreatesProfileDir(t *testing.T) {
	// Profile dir does not exist yet. NewManager must create it.
	parent := t.TempDir()
	dir := filepath.Join(parent, "subdir", "profiles")
	cfg := Config{Enabled: true, ProfileDir: dir}
	_, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	info, statErr := os.Stat(dir)
	if statErr != nil {
		t.Fatalf("profile dir not created: %v", statErr)
	}
	if !info.IsDir() {
		t.Fatal("profile path is not a directory")
	}
}

// TestBaseline_IntegrityKeyPathInsideProfileDirRejected covers the
// normalizeIntegrityConfig containment check: the integrity key must live
// outside the profile directory, or an attacker who can write the profile
// directory could also forge the key. Exercised on both the NewManager and
// Reconfigure paths.
func TestBaseline_IntegrityKeyPathInsideProfileDirRejected(t *testing.T) {
	dir := t.TempDir()
	inside := filepath.Join(dir, "integrity.key")

	if _, err := NewManager(Config{
		Enabled:          true,
		LearningWindow:   3,
		DeviationAction:  deviationActionBlock,
		ProfileDir:       dir,
		IntegrityKeyPath: inside,
	}); err == nil {
		t.Fatal("NewManager: want error for integrity key path inside profile_dir")
	}

	mgr, err := NewManager(Config{Enabled: true, LearningWindow: 3, ProfileDir: dir})
	if err != nil {
		t.Fatalf("baseline NewManager: %v", err)
	}
	if err := mgr.Reconfigure(Config{
		Enabled:          true,
		LearningWindow:   3,
		DeviationAction:  deviationActionBlock,
		ProfileDir:       dir,
		IntegrityKeyPath: inside,
	}); err == nil {
		t.Fatal("Reconfigure: want error for integrity key path inside profile_dir")
	}
}

// TestBaseline_CorruptIntegrityKeyRejectedUnderEnforcement covers the
// integrity-key decode and length branches: a key file that is not valid hex
// or is the wrong length must fail closed under enforcement rather than be
// treated as a usable key.
func TestBaseline_CorruptIntegrityKeyRejectedUnderEnforcement(t *testing.T) {
	oversizedKey := make([]byte, integrityStateMaxSize+1)
	for i := range oversizedKey {
		oversizedKey[i] = 'a'
	}
	for _, tc := range []struct {
		name string
		key  []byte
	}{
		{name: "non_hex", key: []byte("zzzz-not-hex-key\n")},
		{name: "short_hex", key: []byte("abcd\n")},
		{name: "oversized", key: oversizedKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			seedLockedProfile(t, dir)
			if err := os.WriteFile(baselineIntegrityKeyPath(dir), tc.key, 0o600); err != nil {
				t.Fatalf("overwrite integrity key: %v", err)
			}
			if _, err := NewManager(Config{
				Enabled:         true,
				LearningWindow:  3,
				DeviationAction: deviationActionBlock,
				ProfileDir:      dir,
			}); err == nil {
				t.Fatal("NewManager: want fail-closed error for corrupt integrity key")
			}
		})
	}
}

func TestBaseline_HighWaterLockHelperProcess(t *testing.T) {
	mode := os.Getenv("PIPELOCK_BASELINE_LOCK_HELPER")
	if mode == "" {
		return
	}
	keyPath := os.Getenv("PIPELOCK_BASELINE_LOCK_KEY")
	profileDir := os.Getenv("PIPELOCK_BASELINE_LOCK_PROFILE_DIR")
	readyPath := os.Getenv("PIPELOCK_BASELINE_LOCK_READY")
	releasePath := os.Getenv("PIPELOCK_BASELINE_LOCK_RELEASE")
	startedPath := os.Getenv("PIPELOCK_BASELINE_LOCK_STARTED")
	acquiredPath := os.Getenv("PIPELOCK_BASELINE_LOCK_ACQUIRED")

	switch mode {
	case "hold":
		unlock, err := acquireIntegrityHighWaterLock(keyPath)
		if err != nil {
			t.Fatalf("acquire lock: %v", err)
		}
		if err := os.WriteFile(filepath.Clean(readyPath), []byte("ready"), 0o600); err != nil {
			unlock()
			t.Fatalf("write ready marker: %v", err)
		}
		if !waitForPath(releasePath, 5*time.Second) {
			unlock()
			t.Fatal("timed out waiting for release marker")
		}
		unlock()
	case "advance":
		if err := os.WriteFile(filepath.Clean(startedPath), []byte("started"), 0o600); err != nil {
			t.Fatalf("write started marker: %v", err)
		}
		mgr := &Manager{cfg: Config{
			ProfileDir:       profileDir,
			IntegrityKeyPath: keyPath,
			DeviationAction:  deviationActionBlock,
		}}
		key, err := mgr.loadIntegrityKey(false)
		if err != nil {
			t.Fatalf("load key: %v", err)
		}
		if err := mgr.acceptIntegrityManifestGeneration(2, testManifestHMAC, key); err != nil {
			t.Fatalf("accept generation: %v", err)
		}
		if err := os.WriteFile(filepath.Clean(acquiredPath), []byte("acquired"), 0o600); err != nil {
			t.Fatalf("write acquired marker: %v", err)
		}
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
	os.Exit(0)
}

func TestBaseline_HighWaterLockSerializesAcrossProcesses(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("uses /proc/self/exe to re-exec the test binary without a variable subprocess path")
	}

	dir := t.TempDir()
	keyPath := baselineIntegrityKeyPath(dir)
	mgr := &Manager{cfg: Config{
		ProfileDir:       dir,
		IntegrityKeyPath: keyPath,
		DeviationAction:  deviationActionBlock,
	}}
	key, err := mgr.loadIntegrityKey(true)
	if err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if err := mgr.writeIntegrityHighWater(1, key, testManifestHMAC); err != nil {
		t.Fatalf("seed high-water: %v", err)
	}

	markers := t.TempDir()
	readyPath := filepath.Join(markers, "ready")
	releasePath := filepath.Join(markers, "release")
	startedPath := filepath.Join(markers, "started")
	acquiredPath := filepath.Join(markers, "acquired")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	holdOutput := &bytes.Buffer{}
	hold := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestBaseline_HighWaterLockHelperProcess$")
	hold.Env = append(os.Environ(),
		"PIPELOCK_BASELINE_LOCK_HELPER=hold",
		"PIPELOCK_BASELINE_LOCK_KEY="+keyPath,
		"PIPELOCK_BASELINE_LOCK_PROFILE_DIR="+dir,
		"PIPELOCK_BASELINE_LOCK_READY="+readyPath,
		"PIPELOCK_BASELINE_LOCK_RELEASE="+releasePath,
	)
	hold.Stdout = holdOutput
	hold.Stderr = holdOutput
	if err := hold.Start(); err != nil {
		t.Fatalf("start lock holder: %v", err)
	}
	t.Cleanup(func() {
		_ = os.WriteFile(filepath.Clean(releasePath), []byte("release"), 0o600)
		if hold.ProcessState == nil {
			_ = hold.Process.Kill()
		}
	})
	if !waitForPath(readyPath, 2*time.Second) {
		t.Fatalf("lock holder did not become ready:\n%s", holdOutput.String())
	}

	advanceOutput := &bytes.Buffer{}
	advance := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestBaseline_HighWaterLockHelperProcess$")
	advance.Env = append(os.Environ(),
		"PIPELOCK_BASELINE_LOCK_HELPER=advance",
		"PIPELOCK_BASELINE_LOCK_KEY="+keyPath,
		"PIPELOCK_BASELINE_LOCK_PROFILE_DIR="+dir,
		"PIPELOCK_BASELINE_LOCK_STARTED="+startedPath,
		"PIPELOCK_BASELINE_LOCK_ACQUIRED="+acquiredPath,
	)
	advance.Stdout = advanceOutput
	advance.Stderr = advanceOutput
	if err := advance.Start(); err != nil {
		t.Fatalf("start second manager: %v", err)
	}
	advanceDone := false
	t.Cleanup(func() {
		if advanceDone {
			return
		}
		if advance.ProcessState == nil {
			_ = advance.Process.Kill()
		}
		_ = advance.Wait()
	})
	if !waitForPath(startedPath, 2*time.Second) {
		t.Fatalf("second manager did not start high-water advance:\n%s", advanceOutput.String())
	}
	if waitForPath(acquiredPath, 150*time.Millisecond) {
		t.Fatal("second manager advanced high-water while another process held the lock")
	}
	if err := os.WriteFile(filepath.Clean(releasePath), []byte("release"), 0o600); err != nil {
		t.Fatalf("release lock holder: %v", err)
	}
	if err := hold.Wait(); err != nil {
		t.Fatalf("lock holder exited with error: %v\n%s", err, holdOutput.String())
	}
	if err := advance.Wait(); err != nil {
		advanceDone = true
		t.Fatalf("second manager exited with error: %v\n%s", err, advanceOutput.String())
	}
	advanceDone = true
	if !waitForPath(acquiredPath, time.Second) {
		t.Fatal("second manager did not advance after lock release")
	}
}

// TestBaseline_HighWaterTamperFailsClosedUnderEnforcement covers the
// readIntegrityHighWater validation branches: the monotonic generation
// high-water is a trusted anchor, so a symlinked, non-regular, oversized,
// corrupt, zero, or context/digest-mismatched high-water file must fail
// closed under enforcement rather than be trusted.
func TestBaseline_HighWaterTamperFailsClosedUnderEnforcement(t *testing.T) {
	highWaterPath := func(dir string) string { return baselineIntegrityKeyPath(dir) + ".generation" }

	tests := []struct {
		name   string
		tamper func(t *testing.T, dir string)
	}{
		{
			name: "corrupt_json",
			tamper: func(t *testing.T, dir string) {
				if err := os.WriteFile(highWaterPath(dir), []byte("not-json"), 0o600); err != nil {
					t.Fatalf("write high-water: %v", err)
				}
			},
		},
		{
			name: "oversized",
			tamper: func(t *testing.T, dir string) {
				big := make([]byte, 8*1024)
				for i := range big {
					big[i] = 'a'
				}
				if err := os.WriteFile(highWaterPath(dir), big, 0o600); err != nil {
					t.Fatalf("write high-water: %v", err)
				}
			},
		},
		{
			name: "zero_generation",
			tamper: func(t *testing.T, dir string) {
				data, _ := json.Marshal(integrityHighWaterState{Generation: 0})
				if err := os.WriteFile(highWaterPath(dir), data, 0o600); err != nil {
					t.Fatalf("write high-water: %v", err)
				}
			},
		},
		{
			name: "context_mismatch",
			tamper: func(t *testing.T, dir string) {
				data, _ := json.Marshal(integrityHighWaterState{Generation: 1, Context: "bogus-context", Digest: "bogus-digest"})
				if err := os.WriteFile(highWaterPath(dir), data, 0o600); err != nil {
					t.Fatalf("write high-water: %v", err)
				}
			},
		},
		{
			name: "bad_digest_hex",
			tamper: func(t *testing.T, dir string) {
				cfg := Config{Enabled: true, ProfileDir: dir}
				if err := normalizeIntegrityConfig(&cfg); err != nil {
					t.Fatalf("normalize integrity config: %v", err)
				}
				mgr := &Manager{cfg: cfg}
				data, _ := json.Marshal(integrityHighWaterState{
					Generation:   1,
					Context:      mgr.integrityStateContextID(),
					ManifestHMAC: testManifestHMAC,
					Digest:       "not-hex",
				})
				if err := os.WriteFile(highWaterPath(dir), data, 0o600); err != nil {
					t.Fatalf("write high-water: %v", err)
				}
			},
		},
		{
			name: "short_digest",
			tamper: func(t *testing.T, dir string) {
				cfg := Config{Enabled: true, ProfileDir: dir}
				if err := normalizeIntegrityConfig(&cfg); err != nil {
					t.Fatalf("normalize integrity config: %v", err)
				}
				mgr := &Manager{cfg: cfg}
				data, _ := json.Marshal(integrityHighWaterState{
					Generation:   1,
					Context:      mgr.integrityStateContextID(),
					ManifestHMAC: testManifestHMAC,
					Digest:       "abcd",
				})
				if err := os.WriteFile(highWaterPath(dir), data, 0o600); err != nil {
					t.Fatalf("write high-water: %v", err)
				}
			},
		},
		{
			name: "symlink",
			tamper: func(t *testing.T, dir string) {
				p := highWaterPath(dir)
				data := copyFileBytes(t, p)
				target := filepath.Join(t.TempDir(), "copied-hw")
				writeFileBytes(t, target, data)
				if err := os.Remove(p); err != nil {
					t.Fatalf("remove high-water: %v", err)
				}
				if err := os.Symlink(target, p); err != nil {
					t.Fatalf("symlink high-water: %v", err)
				}
			},
		},
		{
			name: "directory",
			tamper: func(t *testing.T, dir string) {
				p := highWaterPath(dir)
				if err := os.Remove(p); err != nil {
					t.Fatalf("remove high-water: %v", err)
				}
				if err := os.Mkdir(p, 0o750); err != nil {
					t.Fatalf("mkdir high-water: %v", err)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			seedLockedProfile(t, dir)
			if _, err := os.Stat(highWaterPath(dir)); err != nil {
				t.Fatalf("high-water not seeded: %v", err)
			}
			tc.tamper(t, dir)
			if _, err := NewManager(Config{
				Enabled:         true,
				LearningWindow:  3,
				DeviationAction: deviationActionBlock,
				ProfileDir:      dir,
			}); err == nil {
				t.Fatal("NewManager: want fail-closed error for high-water tamper under block")
			}
		})
	}
}

// TestBaseline_NoProfileDirSkipsIntegrity covers the ProfileDir-unset early
// return in normalizeIntegrityConfig: an in-memory-only baseline has no
// persisted state to protect.
func TestBaseline_NoProfileDirSkipsIntegrity(t *testing.T) {
	mgr, err := NewManager(Config{Enabled: true, LearningWindow: 3, DeviationAction: deviationActionBlock})
	if err != nil {
		t.Fatalf("NewManager without ProfileDir: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected a manager")
	}
}

// TestBaseline_IntegrityIOErrorsFailClosed covers the integrity IO error
// branches: an unreadable key or high-water file, and write failures when the
// containing directory is not writable, must fail closed rather than proceed
// with erased or unverifiable enforcement state.
func TestBaseline_IntegrityIOErrorsFailClosed(t *testing.T) {
	highWaterPath := func(dir string) string { return baselineIntegrityKeyPath(dir) + ".generation" }

	t.Run("unreadable_key", func(t *testing.T) {
		skipIfRoot(t)
		dir := t.TempDir()
		seedLockedProfile(t, dir)
		keyPath := baselineIntegrityKeyPath(dir)
		if err := os.Chmod(keyPath, 0o000); err != nil {
			t.Fatalf("chmod key: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(keyPath, 0o600) })
		if _, err := NewManager(Config{
			Enabled: true, LearningWindow: 3, DeviationAction: deviationActionBlock, ProfileDir: dir,
		}); err == nil {
			t.Fatal("want fail-closed on unreadable integrity key")
		}
	})

	t.Run("unreadable_high_water", func(t *testing.T) {
		skipIfRoot(t)
		dir := t.TempDir()
		seedLockedProfile(t, dir)
		hw := highWaterPath(dir)
		if err := os.Chmod(hw, 0o000); err != nil {
			t.Fatalf("chmod high-water: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(hw, 0o600) })
		if _, err := NewManager(Config{
			Enabled: true, LearningWindow: 3, DeviationAction: deviationActionBlock, ProfileDir: dir,
		}); err == nil {
			t.Fatal("want fail-closed on unreadable integrity high-water")
		}
	})

	t.Run("key_generation_dir_conflict", func(t *testing.T) {
		parent := t.TempDir()
		dir := filepath.Join(parent, "profiles")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("mkdir profile dir: %v", err)
		}
		// Point the integrity key at a path whose parent directory cannot be
		// created because a regular file already occupies that name, so
		// persist-time key generation fails and the lock returns an error.
		blocker := filepath.Join(parent, "blocker")
		if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
			t.Fatalf("write blocker file: %v", err)
		}
		mgr, err := NewManager(Config{
			Enabled: true, LearningWindow: 3, ProfileDir: dir,
			IntegrityKeyPath: filepath.Join(blocker, "integrity.key"),
		})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		for range 3 {
			mgr.RecordSession(testAgent, normalMetrics())
		}
		if err := mgr.Ratify(testAgent); err == nil {
			t.Fatal("want persist error when integrity key directory cannot be created")
		}
		if _, err := os.Stat(filepath.Join(dir, testAgent+profileFileExt)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("profile should be removed after manifest persistence failure, stat error = %v", err)
		}
	})

	t.Run("manifest_dir_conflict_does_not_advance_high_water", func(t *testing.T) {
		parent := t.TempDir()
		dir := filepath.Join(parent, "profiles")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("mkdir profile dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, integrityManifestDirName), []byte("not-a-directory"), 0o600); err != nil {
			t.Fatalf("write manifest dir blocker: %v", err)
		}

		mgr, err := NewManager(Config{Enabled: true, LearningWindow: 3, ProfileDir: dir})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		for range 3 {
			mgr.RecordSession(testAgent, normalMetrics())
		}
		if err := mgr.Ratify(testAgent); err == nil {
			t.Fatal("want persist error when integrity manifest directory cannot be created")
		}
		if _, err := os.Stat(highWaterPath(dir)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("high-water should not advance before manifest write succeeds, stat error = %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, testAgent+profileFileExt)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("profile should be removed after manifest persistence failure, stat error = %v", err)
		}
		if err := os.Remove(filepath.Join(dir, integrityManifestDirName)); err != nil {
			t.Fatalf("remove manifest dir blocker: %v", err)
		}
		if _, err := NewManager(Config{
			Enabled: true, LearningWindow: 3, DeviationAction: deviationActionBlock, ProfileDir: dir,
		}); err != nil {
			t.Fatalf("NewManager after clearing failed first persist manifest conflict: %v", err)
		}
	})

	t.Run("lock_conflict_does_not_seed_trusted_state", func(t *testing.T) {
		parent := t.TempDir()
		dir := filepath.Join(parent, "profiles")
		lockPath := baselineIntegrityKeyPath(dir) + ".generation.lock"
		if err := os.MkdirAll(lockPath, 0o750); err != nil {
			t.Fatalf("create lock path directory: %v", err)
		}
		mgr, err := NewManager(Config{
			Enabled: true, LearningWindow: 3, DeviationAction: deviationActionBlock, ProfileDir: dir,
		})
		if err != nil {
			t.Fatalf("NewManager: %v", err)
		}
		for range 3 {
			mgr.RecordSession(testAgent, normalMetrics())
		}
		if _, err := os.Stat(filepath.Join(dir, testAgent+profileFileExt)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("profile should be removed after lock failure, stat error = %v", err)
		}
		if _, err := os.Stat(baselineIntegrityKeyPath(dir)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("integrity key should not be created before acquiring high-water lock, stat error = %v", err)
		}
		if err := os.Remove(lockPath); err != nil {
			t.Fatalf("remove lock path directory: %v", err)
		}
		if _, err := NewManager(Config{
			Enabled: true, LearningWindow: 3, DeviationAction: deviationActionBlock, ProfileDir: dir,
		}); err != nil {
			t.Fatalf("NewManager after clearing failed first persist lock conflict: %v", err)
		}
	})
}

// TestBaseline_IntegrityGenerationInvariants directly exercises the
// generation high-water invariants: a zero generation is rejected, and the
// next generation refuses to advance past its maximum (overflow).
func TestBaseline_IntegrityGenerationInvariants(t *testing.T) {
	dir := t.TempDir()
	mgr, err := NewManager(Config{Enabled: true, LearningWindow: 3, ProfileDir: dir})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	key, err := mgr.loadIntegrityKey(true)
	if err != nil {
		t.Fatalf("load key: %v", err)
	}
	if err := mgr.writeIntegrityHighWater(0, key, testManifestHMAC); err == nil {
		t.Fatal("want error writing a zero generation high-water")
	}
	if err := mgr.acceptIntegrityManifestGeneration(0, testManifestHMAC, key); err == nil {
		t.Fatal("want error accepting a zero generation manifest")
	}
	if err := mgr.writeIntegrityHighWater(math.MaxUint64, key, testManifestHMAC); err != nil {
		t.Fatalf("write max high-water: %v", err)
	}
	if _, err := mgr.nextIntegrityManifestGeneration(); err == nil {
		t.Fatal("want overflow error advancing past the maximum generation")
	}
}

func TestBaseline_VerifyIntegrityManifestRejectsMalformedFiles(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	valid := integrityManifest{
		SchemaVersion: integrityManifestVersion,
		Algorithm:     integrityManifestAlg,
		Generation:    1,
	}
	mac, err := signIntegrityManifest(valid, key)
	if err != nil {
		t.Fatalf("sign manifest: %v", err)
	}
	mustJSON := func(t *testing.T, file integrityManifestFile) []byte {
		t.Helper()
		data, err := json.Marshal(file)
		if err != nil {
			t.Fatalf("marshal manifest file: %v", err)
		}
		return data
	}

	tests := []struct {
		name string
		data []byte
	}{
		{name: "invalid_json", data: []byte("{")},
		{name: "trailing_data", data: append(mustJSON(t, integrityManifestFile{Manifest: valid, HMAC: mac}), []byte("\n{}")...)},
		{name: "wrong_schema", data: mustJSON(t, integrityManifestFile{Manifest: integrityManifest{SchemaVersion: 99, Algorithm: integrityManifestAlg}, HMAC: mac})},
		{name: "wrong_algorithm", data: mustJSON(t, integrityManifestFile{Manifest: integrityManifest{SchemaVersion: integrityManifestVersion, Algorithm: "none"}, HMAC: mac})},
		{name: "bad_hmac_hex", data: mustJSON(t, integrityManifestFile{Manifest: valid, HMAC: "not-hex"})},
		{name: "short_hmac", data: mustJSON(t, integrityManifestFile{Manifest: valid, HMAC: "abcd"})},
		{name: "hmac_mismatch", data: mustJSON(t, integrityManifestFile{Manifest: valid, HMAC: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := verifyIntegrityManifest(tc.data, key); err == nil {
				t.Fatal("verifyIntegrityManifest: want error")
			}
		})
	}
}

func TestBaseline_PersistedProfileFilesExistEdges(t *testing.T) {
	dir := t.TempDir()
	mgr := &Manager{cfg: Config{ProfileDir: dir}}

	exists, err := mgr.persistedProfileFilesExist(nil)
	if err != nil {
		t.Fatalf("empty dir scan: %v", err)
	}
	if exists {
		t.Fatal("empty dir should not report profiles")
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write manifest-named profile: %v", err)
	}
	exists, err = mgr.persistedProfileFilesExist(map[string]bool{"manifest": true})
	if err != nil {
		t.Fatalf("excluded profile scan: %v", err)
	}
	if exists {
		t.Fatal("excluded manifest-named profile should not count")
	}
	exists, err = mgr.persistedProfileFilesExist(nil)
	if err != nil {
		t.Fatalf("profile scan: %v", err)
	}
	if !exists {
		t.Fatal("manifest-named profile should count")
	}

	badDir := t.TempDir()
	mgr.cfg.ProfileDir = badDir
	if err := os.Mkdir(filepath.Join(badDir, "bad.json"), 0o750); err != nil {
		t.Fatalf("mkdir profile path: %v", err)
	}
	if _, err := mgr.persistedProfileFilesExist(nil); err == nil {
		t.Fatal("directory profile path should error")
	}

	mgr.cfg.ProfileDir = filepath.Join(t.TempDir(), "missing")
	if _, err := mgr.persistedProfileFilesExist(nil); err == nil {
		t.Fatal("missing profile directory should error")
	}
}

func TestBaseline_PersistIntegrityManifestSkipsWithoutProfileDir(t *testing.T) {
	mgr := &Manager{}
	if err := mgr.persistIntegrityManifest(map[string]bool{testAgent: true}); err != nil {
		t.Fatalf("persistIntegrityManifest without ProfileDir: %v", err)
	}
}

// TestBaseline_HighWaterDigestMismatchFailsClosed covers the digest-mismatch
// branch: a high-water whose context matches but whose digest does not (a
// forged generation value) must fail closed under enforcement.
func TestBaseline_HighWaterDigestMismatchFailsClosed(t *testing.T) {
	dir := t.TempDir()
	seedLockedProfile(t, dir)
	hw := baselineIntegrityKeyPath(dir) + ".generation"
	data, err := os.ReadFile(filepath.Clean(hw))
	if err != nil {
		t.Fatalf("read high-water: %v", err)
	}
	var st integrityHighWaterState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("unmarshal high-water: %v", err)
	}
	st.Digest = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	out, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("marshal high-water: %v", err)
	}
	if err := os.WriteFile(hw, out, 0o600); err != nil {
		t.Fatalf("write high-water: %v", err)
	}
	if _, err := NewManager(Config{
		Enabled: true, LearningWindow: 3, DeviationAction: deviationActionBlock, ProfileDir: dir,
	}); err == nil {
		t.Fatal("want fail-closed on high-water digest mismatch")
	}
}

func TestBaseline_IntegrityGenerationErrorBranches(t *testing.T) {
	t.Run("next_generation_returns_initial_generation", func(t *testing.T) {
		dir := t.TempDir()
		cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: dir}
		if err := normalizeIntegrityConfig(&cfg); err != nil {
			t.Fatalf("normalize integrity config: %v", err)
		}
		mgr := &Manager{cfg: cfg}

		generation, err := mgr.nextIntegrityManifestGeneration()
		if err != nil {
			t.Fatalf("nextIntegrityManifestGeneration: %v", err)
		}
		if generation != 1 {
			t.Fatalf("generation = %d, want 1", generation)
		}
	})

	t.Run("missing_high_water_refuses_next_generation_when_trusted_state_exists", func(t *testing.T) {
		dir := t.TempDir()
		cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: dir}
		if err := normalizeIntegrityConfig(&cfg); err != nil {
			t.Fatalf("normalize integrity config: %v", err)
		}
		mgr := &Manager{cfg: cfg}
		key, err := mgr.loadIntegrityKey(true)
		if err != nil {
			t.Fatalf("load integrity key: %v", err)
		}

		if _, err := mgr.nextIntegrityManifestGenerationLocked(key, false); err == nil {
			t.Fatal("nextIntegrityManifestGenerationLocked: want missing high-water error")
		}
	})

	t.Run("next_generation_lock_open_failure", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := baselineIntegrityKeyPath(dir)
		lockPath := keyPath + ".generation.lock"
		if err := os.MkdirAll(lockPath, 0o750); err != nil {
			t.Fatalf("mkdir lock path: %v", err)
		}
		mgr := &Manager{cfg: Config{
			ProfileDir:       dir,
			IntegrityKeyPath: keyPath,
			DeviationAction:  deviationActionBlock,
		}}

		if _, err := mgr.nextIntegrityManifestGeneration(); err == nil {
			t.Fatal("nextIntegrityManifestGeneration: want lock open error")
		}
		if err := os.Remove(lockPath); err != nil {
			t.Fatalf("remove lock path: %v", err)
		}
	})

	t.Run("next_generation_load_key_failure", func(t *testing.T) {
		dir := t.TempDir()
		cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: dir}
		if err := normalizeIntegrityConfig(&cfg); err != nil {
			t.Fatalf("normalize integrity config: %v", err)
		}
		if err := os.WriteFile(cfg.IntegrityKeyPath, []byte("not-hex\n"), 0o600); err != nil {
			t.Fatalf("write corrupt integrity key: %v", err)
		}
		mgr := &Manager{cfg: cfg}

		if _, err := mgr.nextIntegrityManifestGeneration(); err == nil {
			t.Fatal("nextIntegrityManifestGeneration: want key load error")
		}
	})

	t.Run("accept_generation_lock_open_failure", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := baselineIntegrityKeyPath(dir)
		lockPath := keyPath + ".generation.lock"
		if err := os.MkdirAll(lockPath, 0o750); err != nil {
			t.Fatalf("mkdir lock path: %v", err)
		}
		mgr := &Manager{cfg: Config{
			ProfileDir:       dir,
			IntegrityKeyPath: keyPath,
			DeviationAction:  deviationActionBlock,
		}}

		if err := mgr.acceptIntegrityManifestGeneration(1, testManifestHMAC, []byte("0123456789abcdef0123456789abcdef")); err == nil {
			t.Fatal("acceptIntegrityManifestGeneration: want lock open error")
		}
		if err := os.Remove(lockPath); err != nil {
			t.Fatalf("remove lock path: %v", err)
		}
	})
}

func TestBaseline_CleanupNewIntegrityTrustedStateErrors(t *testing.T) {
	originalErr := errors.New("manifest commit failed")

	t.Run("disabled_returns_original_error", func(t *testing.T) {
		mgr := &Manager{}
		err := mgr.cleanupNewIntegrityTrustedState(false, originalErr)
		if !errors.Is(err, originalErr) {
			t.Fatalf("cleanupNewIntegrityTrustedState = %v, want original error", err)
		}
	})

	t.Run("remove_failure_is_joined", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "integrity-key")
		if err := os.Mkdir(keyPath, 0o750); err != nil {
			t.Fatalf("mkdir key path: %v", err)
		}
		childPath := filepath.Join(keyPath, "child")
		if err := os.WriteFile(childPath, []byte("x"), 0o600); err != nil {
			t.Fatalf("write key child: %v", err)
		}
		t.Cleanup(func() {
			_ = os.Remove(childPath)
			_ = os.Remove(keyPath)
		})
		mgr := &Manager{cfg: Config{IntegrityKeyPath: keyPath}}

		err := mgr.cleanupNewIntegrityTrustedState(true, originalErr)
		if err == nil {
			t.Fatal("cleanupNewIntegrityTrustedState: want cleanup error")
		}
		if !errors.Is(err, originalErr) {
			t.Fatalf("cleanup error = %v, want original error in chain", err)
		}
	})

	t.Run("successful_cleanup_returns_original_error", func(t *testing.T) {
		dir := t.TempDir()
		keyPath := filepath.Join(dir, "integrity-key")
		highWaterPath := keyPath + ".generation"
		if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
			t.Fatalf("write key: %v", err)
		}
		if err := os.WriteFile(highWaterPath, []byte("high-water"), 0o600); err != nil {
			t.Fatalf("write high-water: %v", err)
		}
		mgr := &Manager{cfg: Config{IntegrityKeyPath: keyPath}}

		err := mgr.cleanupNewIntegrityTrustedState(true, originalErr)
		if !errors.Is(err, originalErr) {
			t.Fatalf("cleanupNewIntegrityTrustedState = %v, want original error", err)
		}
		for _, path := range []string{keyPath, highWaterPath} {
			if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("%s should have been removed, stat error = %v", path, statErr)
			}
		}
	})
}

func TestBaseline_PersistIntegrityManifestProfileFaults(t *testing.T) {
	t.Run("invalid_agent_key_refused", func(t *testing.T) {
		dir := t.TempDir()
		cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: dir}
		if err := normalizeIntegrityConfig(&cfg); err != nil {
			t.Fatalf("normalize integrity config: %v", err)
		}
		mgr := &Manager{
			cfg: cfg,
			agents: map[string]*agentState{
				"../bad": {profile: &Profile{State: StateLocked}, state: StateLocked},
			},
		}

		if err := mgr.persistIntegrityManifest(nil); err == nil {
			t.Fatal("persistIntegrityManifest: want invalid agent key error")
		}
	})

	t.Run("manifest_profile_read_failure", func(t *testing.T) {
		dir := t.TempDir()
		cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: dir}
		if err := normalizeIntegrityConfig(&cfg); err != nil {
			t.Fatalf("normalize integrity config: %v", err)
		}
		mgr := &Manager{
			cfg: cfg,
			agents: map[string]*agentState{
				testAgent: {profile: &Profile{State: StateLocked}, state: StateLocked},
			},
		}

		if err := mgr.persistIntegrityManifest(nil); err == nil {
			t.Fatal("persistIntegrityManifest: want missing profile read error")
		}
	})

	t.Run("trusted_state_without_high_water_fails_generation_advance", func(t *testing.T) {
		dir := t.TempDir()
		cfg := Config{Enabled: true, LearningWindow: 3, ProfileDir: dir}
		if err := normalizeIntegrityConfig(&cfg); err != nil {
			t.Fatalf("normalize integrity config: %v", err)
		}
		mgr := &Manager{
			cfg: cfg,
			agents: map[string]*agentState{
				testAgent: {profile: &Profile{State: StateLocked}, state: StateLocked},
			},
		}
		if _, err := mgr.loadIntegrityKey(true); err != nil {
			t.Fatalf("load integrity key: %v", err)
		}
		profilePath := filepath.Join(dir, testAgent+profileFileExt)
		if err := os.WriteFile(profilePath, []byte(`{"state":"locked"}`), 0o600); err != nil {
			t.Fatalf("write profile: %v", err)
		}

		if err := mgr.persistIntegrityManifest(nil); err == nil {
			t.Fatal("persistIntegrityManifest: want missing high-water generation error")
		}
	})
}

func TestReadRegularFileNoSymlinkRejectsPathEscapingTrustedRoot(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatalf("Mkdir root: %v", err)
	}
	outside := filepath.Join(dir, "outside.json")
	if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile outside: %v", err)
	}
	_, err := readRegularFileNoSymlinkInRoot(outside, root, "baseline profile", 1024)
	if err == nil || !strings.Contains(err.Error(), "escapes trusted root") {
		t.Fatalf("escape error = %v, want escapes trusted root", err)
	}
}

func TestReadRegularFileNoSymlinkRejectsEmptyTrustedRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := readRegularFileNoSymlinkInRoot(path, "", "baseline profile", 1024)
	if err == nil || !strings.Contains(err.Error(), "trusted root is empty") {
		t.Fatalf("empty root error = %v, want trusted root is empty", err)
	}
}

func TestReadRegularFileNoSymlinkBeforeOpenHookError(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatalf("Mkdir root: %v", err)
	}
	path := filepath.Join(root, "profile.json")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	sentinel := errors.New("prepare failed")
	_, err := readRegularFileNoSymlinkInRootWithOpenHook(path, root, "baseline profile", 1024, func() error { return sentinel })
	if err == nil || !strings.Contains(err.Error(), "prepare open") {
		t.Fatalf("beforeOpen error = %v, want prepare open", err)
	}
}

func TestReadRegularFileNoSymlinkRejectsOversizeFile(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatalf("Mkdir root: %v", err)
	}
	path := filepath.Join(root, "profile.json")
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := readRegularFileNoSymlinkInRoot(path, root, "baseline profile", 4)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("oversize error = %v, want exceeds maximum size", err)
	}
}

func TestReadRegularFileNoSymlinkRejectsPostOpenFileSwap(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("secure no-follow baseline reads fail closed on Windows")
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatalf("Mkdir root: %v", err)
	}
	path := filepath.Join(root, "profile.json")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Pre-create a distinct file so the swap has a guaranteed-different inode
	// (os.Remove + os.WriteFile can reuse the original inode on some
	// filesystems, which would defeat the os.SameFile check and flake).
	other := filepath.Join(root, "other-profile.json")
	if err := os.WriteFile(other, []byte("swapped"), 0o600); err != nil {
		t.Fatalf("WriteFile other: %v", err)
	}
	// The open hook fires after the pre-open Lstat but before the open, so
	// renaming a different inode over the path makes the opened file a
	// different inode and the post-open os.SameFile check must reject the read.
	swap := func() error {
		return os.Rename(other, path)
	}
	_, err := readRegularFileNoSymlinkInRootWithOpenHook(path, root, "baseline profile", 1024, swap)
	if err == nil || !strings.Contains(err.Error(), "changed during read") {
		t.Fatalf("post-open swap error = %v, want changed-during-read rejection", err)
	}
}

func TestReadRegularFileNoSymlinkRejectsPostOpenGrowthPastLimit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("secure no-follow baseline reads fail closed on Windows")
	}
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatalf("Mkdir root: %v", err)
	}
	path := filepath.Join(root, "profile.json")
	if err := os.WriteFile(path, []byte("ok"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Append past the limit in the open hook (same inode, so SameFile passes)
	// to exercise the post-open size check.
	grow := func() error {
		f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, err = f.Write([]byte("0123456789"))
		return err
	}
	_, err := readRegularFileNoSymlinkInRootWithOpenHook(path, root, "baseline profile", 4, grow)
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("post-open growth error = %v, want exceeds maximum size", err)
	}
}
