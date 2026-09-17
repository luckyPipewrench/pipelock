// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	posturepkg "github.com/luckyPipewrench/pipelock/internal/posture"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain/workspacediff"
	"github.com/luckyPipewrench/pipelock/internal/signing"
)

// writeContainConfigWithSigningKey writes a minimal valid pipelock.yaml
// pointing flight_recorder.signing_key_path at a freshly generated ed25519
// key, and returns the config path and the public key so a test can verify
// the emitted statement's signature.
func writeContainConfigWithSigningKey(t *testing.T, dir string) (configPath string, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyPath := filepath.Join(dir, "signing.key")
	if err := signing.SavePrivateKey(priv, keyPath); err != nil {
		t.Fatalf("save private key: %v", err)
	}
	configPath = filepath.Join(dir, "pipelock.yaml")
	body := fmt.Sprintf("metrics_listen: 127.0.0.1:9091\nflight_recorder:\n  signing_key_path: %s\n", keyPath)
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return configPath, pub
}

func testPostureEmission(path string, err error) (postureEmission, error) {
	if err != nil {
		return postureEmission{}, err
	}
	capsuleSHA256, err := workspacediff.HashFileSHA256(path)
	if err != nil {
		return postureEmission{}, err
	}
	return postureEmission{path: path, capsuleSHA256: capsuleSHA256}, nil
}

func testCapsuleSHA256(t *testing.T, path string) string {
	t.Helper()
	capsuleSHA256, err := workspacediff.HashFileSHA256(path)
	if err != nil {
		t.Fatalf("hash capsule: %v", err)
	}
	return capsuleSHA256
}

// workspaceInvBody renders a workspace-inventory JSON body granting path to
// testAgentUser, matching the on-disk shape recordWorkspaceGrant produces.
func workspaceInvBody(t *testing.T, path string) []byte {
	t.Helper()
	inv := workspaceInventory{Workspaces: []workspaceGrant{
		{Path: path, Mode: workspaceModeReadWrite, Owner: "josh", Created: "2026-01-01T00:00:00Z", AgentUser: testAgentUser},
	}}
	data, err := json.Marshal(inv)
	if err != nil {
		t.Fatalf("marshal inventory: %v", err)
	}
	return data
}

func TestRunContainRun_EmitsSignedWorkspaceStatement_SessionBound(t *testing.T) {
	env := allPassEnv(t)
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "existing.txt"), []byte("before"), 0o600); err != nil {
		t.Fatal(err)
	}
	invBody := workspaceInvBody(t, workspace)
	baseReadFile := env.readFile
	env.readFile = func(path string) ([]byte, error) {
		if path == env.workspaceInvPath {
			return invBody, nil
		}
		return baseReadFile(path)
	}

	postureDir := t.TempDir()
	configDir := t.TempDir()
	configPath, pub := writeContainConfigWithSigningKey(t, configDir)

	const fakeCapsuleBytes = "signed-posture-capsule-bytes"
	runEnv := containRunEnv{
		probe:      env,
		loadConfig: func(f string) (*config.Config, error) { return config.Load(f) },
		launch: func(_ context.Context, _ *probeEnv, _ []string, _ io.Reader, _ io.Writer, _ io.Writer) error {
			// Session activity: add a file, modify one, and leave one untouched.
			if err := os.WriteFile(filepath.Join(workspace, "new.txt"), []byte("added"), 0o600); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(workspace, "existing.txt"), []byte("after"), 0o600)
		},
		emitPosture: func(_ *config.Config, _ ed25519.PrivateKey, outputDir string, _ *probeEnv, _ []string) (postureEmission, error) {
			path := filepath.Join(outputDir, "proof.json")
			if err := os.MkdirAll(outputDir, 0o750); err != nil {
				return postureEmission{}, err
			}
			if err := os.WriteFile(path, []byte(fakeCapsuleBytes), 0o600); err != nil {
				return postureEmission{}, err
			}
			return testPostureEmission(path, nil)
		},
	}
	opts := containRunOptions{
		configFile:            configPath,
		postureOutput:         postureDir,
		workspaceDiffCapBytes: 1 << 20,
	}
	var stdout, stderr bytes.Buffer
	if err := runContainRun(context.Background(), strings.NewReader(""), &stdout, &stderr, runEnv, opts, []string{"claude"}); err != nil {
		t.Fatalf("runContainRun: %v\nstderr:\n%s", err, stderr.String())
	}
	if strings.Contains(stderr.String(), "workspace change statement failed") {
		t.Fatalf("unexpected statement failure warning: %s", stderr.String())
	}

	stmtPath := filepath.Join(postureDir, "workspace-change-statement.json")
	data, err := os.ReadFile(filepath.Clean(stmtPath))
	if err != nil {
		t.Fatalf("read statement: %v", err)
	}
	var signed workspacediff.SignedStatement
	if err := json.Unmarshal(data, &signed); err != nil {
		t.Fatalf("unmarshal statement: %v", err)
	}
	if len(signed.Statements) != 1 {
		t.Fatalf("statements = %d, want 1", len(signed.Statements))
	}
	if got := "boundary_check=" + string(signed.Statements[0].BoundaryCheck); !strings.Contains(stdout.String(), got) {
		t.Fatalf("stdout missing statement boundary-check outcome %q:\n%s", got, stdout.String())
	}

	st := signed.Statements[0]
	switch st.BoundaryCheck {
	case workspacediff.BoundaryCheckMountID:
		if !strings.Contains(stdout.String(), "signed workspace change statement") {
			t.Fatalf("stdout missing statement line:\n%s", stdout.String())
		}
		if !strings.Contains(stdout.String(), workspaceStatementWrittenLine) {
			t.Fatalf("stdout missing machine-readable outcome line:\n%s", stdout.String())
		}
		if st.Incomplete {
			t.Fatalf("statement unexpectedly incomplete: %+v", st)
		}
	case workspacediff.BoundaryCheckDeviceOnly:
		if !strings.Contains(stdout.String(), workspaceStatementIncompleteLine) {
			t.Fatalf("stdout missing machine-readable incomplete outcome line:\n%s", stdout.String())
		}
		if strings.Contains(stdout.String(), workspaceStatementWrittenLine) {
			t.Fatalf("stdout must not also claim the written outcome for an incomplete statement:\n%s", stdout.String())
		}
		if !st.Incomplete {
			t.Fatalf("device-only boundary check must mark the statement incomplete: %+v", st)
		}
	default:
		// A boundary check this test does not know about would otherwise make
		// both branches above unreachable and the assertions silently vacuous.
		t.Fatalf("unknown boundary check %q; this test asserts nothing for it", st.BoundaryCheck)
	}

	// Session binding: the statement carries the sha256 of THIS run's exact
	// posture capsule bytes.
	wantCapsuleHash, err := workspacediff.HashFileSHA256(filepath.Join(postureDir, "proof.json"))
	if err != nil {
		t.Fatalf("hash capsule: %v", err)
	}
	if signed.PostureCapsuleSHA256 != wantCapsuleHash {
		t.Fatalf("posture_capsule_sha256 = %q, want %q", signed.PostureCapsuleSHA256, wantCapsuleHash)
	}
	if err := workspacediff.Verify(signed, pub); err != nil {
		t.Fatalf("verify signature: %v", err)
	}
	if st.Root != filepath.Clean(workspace) {
		t.Fatalf("root = %q, want %q", st.Root, workspace)
	}
	assertContainsPath(t, "added", st.Added, filepath.Join(workspace, "new.txt"))
	assertContainsPath(t, "modified", st.Modified, filepath.Join(workspace, "existing.txt"))
}

func TestRunContainRun_WorkspaceRootDisappearsMidSession_StatementSaysSo(t *testing.T) {
	env := allPassEnv(t)
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "f.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	invBody := workspaceInvBody(t, workspace)
	baseReadFile := env.readFile
	env.readFile = func(path string) ([]byte, error) {
		if path == env.workspaceInvPath {
			return invBody, nil
		}
		return baseReadFile(path)
	}

	postureDir := t.TempDir()
	configDir := t.TempDir()
	configPath, _ := writeContainConfigWithSigningKey(t, configDir)

	runEnv := containRunEnv{
		probe:      env,
		loadConfig: func(f string) (*config.Config, error) { return config.Load(f) },
		launch: func(_ context.Context, _ *probeEnv, _ []string, _ io.Reader, _ io.Writer, _ io.Writer) error {
			return os.RemoveAll(workspace)
		},
		emitPosture: func(_ *config.Config, _ ed25519.PrivateKey, outputDir string, _ *probeEnv, _ []string) (postureEmission, error) {
			path := filepath.Join(outputDir, "proof.json")
			if err := os.MkdirAll(outputDir, 0o750); err != nil {
				return postureEmission{}, err
			}
			if err := os.WriteFile(path, []byte("capsule"), 0o600); err != nil {
				return postureEmission{}, err
			}
			return testPostureEmission(path, nil)
		},
	}
	opts := containRunOptions{
		configFile:            configPath,
		postureOutput:         postureDir,
		workspaceDiffCapBytes: 1 << 20,
	}
	var stdout, stderr bytes.Buffer
	if err := runContainRun(context.Background(), strings.NewReader(""), &stdout, &stderr, runEnv, opts, []string{"claude"}); err != nil {
		t.Fatalf("runContainRun: %v\nstderr:\n%s", err, stderr.String())
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(postureDir, "workspace-change-statement.json")))
	if err != nil {
		t.Fatalf("read statement: %v", err)
	}
	var signed workspacediff.SignedStatement
	if err := json.Unmarshal(data, &signed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(signed.Statements) != 1 || !signed.Statements[0].Incomplete {
		t.Fatalf("expected an Incomplete statement for the vanished root, got %+v", signed.Statements)
	}
	if signed.Statements[0].IncompleteReason == "" {
		t.Fatalf("expected a non-empty reason")
	}

	// M5: an incomplete statement is still SIGNED and WRITTEN, but that must
	// never read as [PASS] -- an operator scanning for [PASS]/[FAIL] lines
	// must see the incomplete outcome, not a clean result.
	if strings.Contains(stdout.String(), "[PASS] signed workspace change statement") {
		t.Fatalf("an incomplete statement must not be reported as [PASS]:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), workspaceStatementIncompleteLine) {
		t.Fatalf("stdout missing the machine-readable incomplete outcome line:\n%s", stdout.String())
	}
	if strings.Contains(stdout.String(), workspaceStatementWrittenLine) {
		t.Fatalf("stdout must not ALSO claim the written outcome for an incomplete statement:\n%s", stdout.String())
	}
}

func TestRunContainRun_NoGrants_NoStatementEmitted(t *testing.T) {
	env := allPassEnv(t) // default readFile already returns an empty workspace inventory
	postureDir := t.TempDir()
	configDir := t.TempDir()
	configPath, _ := writeContainConfigWithSigningKey(t, configDir)

	runEnv := containRunEnv{
		probe:      env,
		loadConfig: func(f string) (*config.Config, error) { return config.Load(f) },
		launch: func(_ context.Context, _ *probeEnv, _ []string, _ io.Reader, _ io.Writer, _ io.Writer) error {
			return nil
		},
		emitPosture: func(_ *config.Config, _ ed25519.PrivateKey, outputDir string, _ *probeEnv, _ []string) (postureEmission, error) {
			path := filepath.Join(outputDir, "proof.json")
			if err := os.MkdirAll(outputDir, 0o750); err != nil {
				return postureEmission{}, err
			}
			return testPostureEmission(path, os.WriteFile(path, []byte("capsule"), 0o600))
		},
	}
	opts := containRunOptions{configFile: configPath, postureOutput: postureDir, workspaceDiffCapBytes: 1 << 20}
	var stdout bytes.Buffer
	if err := runContainRun(context.Background(), strings.NewReader(""), &stdout, io.Discard, runEnv, opts, []string{"claude"}); err != nil {
		t.Fatalf("runContainRun: %v", err)
	}
	if strings.Contains(stdout.String(), "workspace change statement") {
		t.Fatalf("did not expect a statement line with no granted workspaces:\n%s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(postureDir, "workspace-change-statement.json")); !os.IsNotExist(err) {
		t.Fatalf("expected no statement file, stat err = %v", err)
	}
}

func TestRunContainRun_MissingSigningKey_WarnsButLaunchStillSucceeds(t *testing.T) {
	env := allPassEnv(t)
	workspace := t.TempDir()
	invBody := workspaceInvBody(t, workspace)
	baseReadFile := env.readFile
	env.readFile = func(path string) ([]byte, error) {
		if path == env.workspaceInvPath {
			return invBody, nil
		}
		return baseReadFile(path)
	}

	postureDir := t.TempDir()
	// Config with NO flight_recorder.signing_key_path configured.
	configPath := filepath.Join(t.TempDir(), "pipelock.yaml")
	if err := os.WriteFile(configPath, []byte("metrics_listen: 127.0.0.1:9091\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	launched := false
	runEnv := containRunEnv{
		probe:       env,
		loadConfig:  func(f string) (*config.Config, error) { return config.Load(f) },
		emitPosture: emitContainRunPosture,
		launch: func(_ context.Context, _ *probeEnv, _ []string, _ io.Reader, _ io.Writer, _ io.Writer) error {
			launched = true
			return nil
		},
	}
	opts := containRunOptions{configFile: configPath, postureOutput: postureDir, workspaceDiffCapBytes: 1 << 20}
	var stdout bytes.Buffer
	if err := runContainRun(context.Background(), strings.NewReader(""), &stdout, io.Discard, runEnv, opts, []string{"claude"}); err == nil || !strings.Contains(err.Error(), "posture capsule") {
		t.Fatalf("runContainRun error = %v, want posture emission failure", err)
	}
	if launched {
		t.Fatalf("launch ran after posture emission rejected the missing signing key")
	}
	// M5: the signing key is resolved BEFORE launch, so an unavailable key is
	// reported up front, not discovered only after the agent already ran.
	if !strings.Contains(stdout.String(), "workspace change statement will be unavailable") {
		t.Fatalf("expected the key warning before posture emission, got:\n%s", stdout.String())
	}
}

// TestRunContainRun_KeyRotationBetweenLoadAndEmitUsesPreLaunchKey proves the
// signing key is read before posture emission and reused by REAL posture
// emission and statement signing. Replacing the key file in that interval
// must not let the capsule and statement acquire different signers.
func TestRunContainRun_KeyRotationBetweenLoadAndEmitUsesPreLaunchKey(t *testing.T) {
	env := allPassEnv(t)
	workspace := t.TempDir()
	invBody := workspaceInvBody(t, workspace)
	baseReadFile := env.readFile
	env.readFile = func(path string) ([]byte, error) {
		if path == env.workspaceInvPath {
			return invBody, nil
		}
		return baseReadFile(path)
	}

	postureDir := t.TempDir()
	configDir := t.TempDir()
	configPath, preLaunchPub := writeContainConfigWithSigningKey(t, configDir)

	// A second key replaces the configured key file between preload and emit.
	_, rotatedPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(configDir, "signing.key")

	runEnv := containRunEnv{
		probe:      env,
		loadConfig: func(f string) (*config.Config, error) { return config.Load(f) },
		launch:     func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error { return nil },
		emitPosture: func(cfg *config.Config, privKey ed25519.PrivateKey, outputDir string, probe *probeEnv, args []string) (postureEmission, error) {
			if err := signing.SavePrivateKey(rotatedPriv, keyPath); err != nil {
				return postureEmission{}, err
			}
			return emitContainRunPosture(cfg, privKey, outputDir, probe, args)
		},
	}
	opts := containRunOptions{configFile: configPath, postureOutput: postureDir, workspaceDiffCapBytes: 1 << 20}
	if err := runContainRun(context.Background(), strings.NewReader(""), io.Discard, io.Discard, runEnv, opts, []string{"claude"}); err != nil {
		t.Fatalf("runContainRun: %v", err)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(postureDir, "workspace-change-statement.json")))
	if err != nil {
		t.Fatalf("read statement: %v", err)
	}
	var signed workspacediff.SignedStatement
	if err := json.Unmarshal(data, &signed); err != nil {
		t.Fatal(err)
	}
	if err := workspacediff.Verify(signed, preLaunchPub); err != nil {
		t.Fatalf("expected the statement to verify against the PRE-launch key, got %v", err)
	}
	proofPath := filepath.Join(postureDir, posturepkg.ProofFilename)
	proofData, err := os.ReadFile(proofPath)
	if err != nil {
		t.Fatalf("read posture capsule: %v", err)
	}
	var capsule posturepkg.Capsule
	if err := json.Unmarshal(proofData, &capsule); err != nil {
		t.Fatalf("parse posture capsule: %v", err)
	}
	if _, err := posturepkg.VerifyCapsule(&capsule, preLaunchPub, posturepkg.VerifyOpts{
		Policy:               posturepkg.PolicyNone,
		SkipMinScoreGate:     true,
		SkipReceiptFreshness: true,
	}); err != nil {
		t.Fatalf("expected the posture capsule to verify against the pre-launch key, got %v", err)
	}
}

func assertContainsPath(t *testing.T, label string, got []string, want string) {
	t.Helper()
	for _, p := range got {
		if p == want {
			return
		}
	}
	t.Fatalf("%s = %v, want to contain %q", label, got, want)
}

// TestRunContainRun_ConfigLoadedOnceReusedForCapsuleAndStatementKey is the H2
// regression: the posture capsule and the workspace-statement signing key
// must come from the SAME config snapshot. Before this fix, Run() loaded the
// config file twice pre-launch (once to resolve the statement signing key,
// once again inside the posture emitter) with no snapshot in between, so an
// operator (or an attacker who can write the config) rotating
// flight_recorder.signing_key_path between those two reads could make the
// capsule and the statement sign under DIFFERENT keys for the same session.
// This test rewrites the config file's signing key on the FIRST config load
// and proves the posture emitter still observes the pre-rotation key,
// because loadConfig is now called exactly once and its result is reused.
func TestRunContainRun_ConfigLoadedOnceReusedForCapsuleAndStatementKey(t *testing.T) {
	env := allPassEnv(t)
	workspace := t.TempDir()
	invBody := workspaceInvBody(t, workspace)
	baseReadFile := env.readFile
	env.readFile = func(path string) ([]byte, error) {
		if path == env.workspaceInvPath {
			return invBody, nil
		}
		return baseReadFile(path)
	}

	postureDir := t.TempDir()
	configDir := t.TempDir()
	configPath, preLoadPub := writeContainConfigWithSigningKey(t, configDir)

	_, rotatedPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rotatedKeyPath := filepath.Join(configDir, "rotated-during-load.key")
	if err := signing.SavePrivateKey(rotatedPriv, rotatedKeyPath); err != nil {
		t.Fatal(err)
	}

	loadCalls := 0
	var observedKeyPaths []string
	runEnv := containRunEnv{
		probe: env,
		loadConfig: func(f string) (*config.Config, error) {
			loadCalls++
			cfg, loadErr := config.Load(f)
			if loadErr != nil {
				return nil, loadErr
			}
			observedKeyPaths = append(observedKeyPaths, cfg.FlightRecorder.SigningKeyPath)
			// Rewrite the config on disk to point at a DIFFERENT signing key
			// immediately after this read, simulating a rotation that lands
			// exactly in the gap a second, redundant load would expose.
			body := fmt.Sprintf("metrics_listen: 127.0.0.1:9091\nflight_recorder:\n  signing_key_path: %s\n", rotatedKeyPath)
			if writeErr := os.WriteFile(f, []byte(body), 0o600); writeErr != nil {
				return nil, writeErr
			}
			return cfg, nil
		},
		launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error { return nil },
		emitPosture: func(cfg *config.Config, _ ed25519.PrivateKey, outputDir string, _ *probeEnv, _ []string) (postureEmission, error) {
			if cfg.FlightRecorder.SigningKeyPath != observedKeyPaths[0] {
				t.Fatalf("posture emitter cfg signing key = %q, want the pre-rotation key %q (config was reloaded)",
					cfg.FlightRecorder.SigningKeyPath, observedKeyPaths[0])
			}
			path := filepath.Join(outputDir, "proof.json")
			if err := os.MkdirAll(outputDir, 0o750); err != nil {
				return postureEmission{}, err
			}
			return testPostureEmission(path, os.WriteFile(path, []byte("capsule bytes"), 0o600))
		},
	}
	opts := containRunOptions{configFile: configPath, postureOutput: postureDir, workspaceDiffCapBytes: 1 << 20}
	if err := runContainRun(context.Background(), strings.NewReader(""), io.Discard, io.Discard, runEnv, opts, []string{"claude"}); err != nil {
		t.Fatalf("runContainRun: %v", err)
	}
	if loadCalls != 1 {
		t.Fatalf("config loaded %d times, want exactly 1 (capsule and statement key must share one snapshot)", loadCalls)
	}

	data, err := os.ReadFile(filepath.Clean(filepath.Join(postureDir, "workspace-change-statement.json")))
	if err != nil {
		t.Fatalf("read statement: %v", err)
	}
	var signed workspacediff.SignedStatement
	if err := json.Unmarshal(data, &signed); err != nil {
		t.Fatal(err)
	}
	if err := workspacediff.Verify(signed, preLoadPub); err != nil {
		t.Fatalf("expected the statement to verify against the PRE-rotation key, got %v", err)
	}
}

// TestRunContainRun_SnapshotFailurePreLaunch_WarnsButLaunchStillSucceeds is
// the adjacent fix: docs/contain-cli.md promises the workspace change
// statement never blocks launch on its own, matching the existing
// missing-signing-key behavior. Before this fix, a pre-launch snapshot
// error aborted the ENTIRE session instead of warning and proceeding with
// the statement unavailable.
func TestRunContainRun_SnapshotFailurePreLaunch_WarnsButLaunchStillSucceeds(t *testing.T) {
	env := allPassEnv(t)
	workspace := t.TempDir()
	invBody := workspaceInvBody(t, workspace)
	baseReadFile := env.readFile
	env.readFile = func(path string) ([]byte, error) {
		if path == env.workspaceInvPath {
			return invBody, nil
		}
		return baseReadFile(path)
	}

	postureDir := t.TempDir()
	configDir := t.TempDir()
	configPath, _ := writeContainConfigWithSigningKey(t, configDir)

	var launched bool
	runEnv := containRunEnv{
		probe:      env,
		loadConfig: func(f string) (*config.Config, error) { return config.Load(f) },
		launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error {
			launched = true
			return nil
		},
		emitPosture: func(_ *config.Config, _ ed25519.PrivateKey, outputDir string, _ *probeEnv, _ []string) (postureEmission, error) {
			path := filepath.Join(outputDir, "proof.json")
			if err := os.MkdirAll(outputDir, 0o750); err != nil {
				return postureEmission{}, err
			}
			return testPostureEmission(path, os.WriteFile(path, []byte("capsule"), 0o600))
		},
	}
	// workspaceDiffCapBytes=0 makes workspacediff.Snapshot fail deterministically
	// ("capBytes must be positive") without needing filesystem permission tricks.
	opts := containRunOptions{configFile: configPath, postureOutput: postureDir, workspaceDiffCapBytes: 0}
	var stdout bytes.Buffer
	if err := runContainRun(context.Background(), strings.NewReader(""), &stdout, io.Discard, runEnv, opts, []string{"claude"}); err != nil {
		t.Fatalf("runContainRun should not abort on a pre-launch snapshot failure: %v\nstdout:\n%s", err, stdout.String())
	}
	if !launched {
		t.Fatal("expected launch to proceed despite the pre-launch snapshot failure")
	}
	if !strings.Contains(stdout.String(), workspaceStatementUnavailableLine) {
		t.Fatalf("stdout missing the unavailable outcome line:\n%s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(postureDir, "workspace-change-statement.json")); !os.IsNotExist(err) {
		t.Fatalf("expected no statement file to be written, stat err = %v", err)
	}
}

func TestRunContainRun_StatementErrorsRemainVisibleAndPreserveLaunchResult(t *testing.T) {
	workspace := t.TempDir()
	postureDir := t.TempDir()
	configPath, _ := writeContainConfigWithSigningKey(t, t.TempDir())

	for _, tt := range []struct {
		name      string
		launchErr error
	}{
		{name: "statement hashing failure is reported", launchErr: nil},
		{name: "launch failure survives statement failure", launchErr: errors.New("agent exited 7")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := allPassEnv(t)
			invBody := workspaceInvBody(t, workspace)
			readFile := env.readFile
			env.readFile = func(path string) ([]byte, error) {
				if path == env.workspaceInvPath {
					return invBody, nil
				}
				return readFile(path)
			}
			var stdout, stderr bytes.Buffer
			runEnv := containRunEnv{
				probe:      env,
				loadConfig: func(string) (*config.Config, error) { return config.Load(configPath) },
				launch: func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error {
					return tt.launchErr
				},
				emitPosture: func(*config.Config, ed25519.PrivateKey, string, *probeEnv, []string) (postureEmission, error) {
					return postureEmission{path: filepath.Join(postureDir, "missing-proof.json")}, nil
				},
			}
			err := runContainRun(context.Background(), strings.NewReader(""), &stdout, &stderr, runEnv, containRunOptions{
				configFile:            configPath,
				postureOutput:         postureDir,
				workspaceDiffCapBytes: 1 << 20,
			}, []string{"claude"})
			if !strings.Contains(stdout.String(), workspaceStatementUnavailableLine) || !strings.Contains(stderr.String(), "workspace change statement failed") {
				t.Fatalf("statement failure was not visible: stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			if !errors.Is(err, tt.launchErr) {
				t.Fatalf("runContainRun error = %v, want launch error %v", err, tt.launchErr)
			}
		})
	}
}

func TestRunContainRun_RefusesMissingConfigLoaderOrLoadFailure(t *testing.T) {
	for _, tt := range []struct {
		name       string
		loadConfig func(string) (*config.Config, error)
		want       string
	}{
		{name: "missing loader", want: "loadConfig is not set"},
		{name: "loader failure", loadConfig: func(string) (*config.Config, error) { return nil, errors.New("config unreadable") }, want: "loading config"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			env := allPassEnv(t)
			runEnv := containRunEnv{
				probe:      env,
				loadConfig: tt.loadConfig,
				launch:     func(context.Context, *probeEnv, []string, io.Reader, io.Writer, io.Writer) error { return nil },
				emitPosture: func(*config.Config, ed25519.PrivateKey, string, *probeEnv, []string) (postureEmission, error) {
					return postureEmission{}, nil
				},
			}
			err := runContainRun(context.Background(), strings.NewReader(""), io.Discard, io.Discard, runEnv, containRunOptions{workspaceDiffCapBytes: 1 << 20}, []string{"claude"})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("runContainRun error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestEmitContainRunWorkspaceStatementRejectsIncompleteInputs(t *testing.T) {
	workspace := t.TempDir()
	posturePath := filepath.Join(t.TempDir(), "posture.json")
	if err := os.WriteFile(posturePath, []byte("capsule"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env := allPassEnv(t)
	env.now = func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) }
	before, err := workspacediff.Snapshot(workspace, 1<<20, workspacediff.DefaultBudget())
	if err != nil {
		t.Fatal(err)
	}
	grant := workspaceGrant{Path: workspace}
	tests := []struct {
		name    string
		opts    containRunOptions
		before  map[string]workspacediff.Manifest
		grants  []workspaceGrant
		key     ed25519.PrivateKey
		wantErr string
	}{
		{name: "missing start snapshot", opts: containRunOptions{workspaceDiffCapBytes: 1 << 20}, before: map[string]workspacediff.Manifest{}, grants: []workspaceGrant{grant}, key: priv, wantErr: "missing session-start snapshot"},
		{name: "end snapshot rejects invalid cap", opts: containRunOptions{}, before: map[string]workspacediff.Manifest{workspace: before}, grants: []workspaceGrant{grant}, key: priv, wantErr: "snapshot"},
		{name: "root mismatch is not signed", opts: containRunOptions{workspaceDiffCapBytes: 1 << 20}, before: map[string]workspacediff.Manifest{workspace: {Root: "other", CapBytes: 1, Entries: map[string]workspacediff.Entry{}}}, grants: []workspaceGrant{grant}, key: priv, wantErr: "diff"},
		{name: "invalid signing key is refused", opts: containRunOptions{workspaceDiffCapBytes: 1 << 20}, before: map[string]workspacediff.Manifest{workspace: before}, grants: []workspaceGrant{grant}, key: nil, wantErr: "invalid signing key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, _, emitErr := emitContainRunWorkspaceStatement(tt.opts, env, tt.before, tt.grants, posturePath, testCapsuleSHA256(t, posturePath), tt.key)
			if emitErr == nil || !strings.Contains(emitErr.Error(), tt.wantErr) {
				t.Fatalf("emit error = %v, want %q", emitErr, tt.wantErr)
			}
		})
	}
}

func TestWorkspaceStatementHelpersKeepOneObservationPerWorkspace(t *testing.T) {
	workspace := t.TempDir()
	posturePath := filepath.Join(t.TempDir(), "posture.json")
	if err := os.WriteFile(posturePath, []byte("capsule"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := resolveWorkspaceStatementSigningKey(&config.Config{FlightRecorder: config.FlightRecorder{SigningKeyPath: filepath.Join(t.TempDir(), "missing.key")}}); err == nil || !strings.Contains(err.Error(), "load signing key") {
		t.Fatalf("missing signing key error = %v, want contextual load failure", err)
	}

	grant := workspaceGrant{Path: workspace}
	snapshots, err := snapshotWorkspaces([]workspaceGrant{grant, grant}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("snapshots = %d, want one per unique workspace", len(snapshots))
	}
	snapshot := snapshots[workspace]
	snapshot.BoundaryCheck = workspacediff.BoundaryCheckDeviceOnly
	path, incomplete, reason, boundary, err := emitContainRunWorkspaceStatement(
		containRunOptions{workspaceDiffCapBytes: 1 << 20}, allPassEnv(t), map[string]workspacediff.Manifest{workspace: snapshot}, []workspaceGrant{grant, grant}, posturePath, testCapsuleSHA256(t, posturePath), priv)
	if err != nil {
		t.Fatalf("emit statement: %v", err)
	}
	if !incomplete || boundary != workspacediff.BoundaryCheckDeviceOnly || !strings.Contains(reason, "mount boundary check unavailable") {
		t.Fatalf("statement outcome = incomplete:%t boundary:%q reason:%q, want explicit device-only incompleteness", incomplete, boundary, reason)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var signed workspacediff.SignedStatement
	if err := json.Unmarshal(data, &signed); err != nil {
		t.Fatal(err)
	}
	if len(signed.Statements) != 1 {
		t.Fatalf("signed statements = %d, want one for duplicate grants", len(signed.Statements))
	}
}

func TestEmitContainRunWorkspaceStatementRefusesUnwritableOutput(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc is the Linux read-only output surface used by this error-path test")
	}
	workspace := t.TempDir()
	posturePath := "/proc/version"
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	before, err := workspacediff.Snapshot(workspace, 1<<20, workspacediff.DefaultBudget())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := emitContainRunWorkspaceStatement(
		containRunOptions{workspaceDiffCapBytes: 1 << 20}, allPassEnv(t), map[string]workspacediff.Manifest{workspace: before}, []workspaceGrant{{Path: workspace}}, posturePath, testCapsuleSHA256(t, posturePath), priv); err == nil {
		t.Fatal("expected statement emission to fail when its output directory cannot create the atomic file")
	}
}
