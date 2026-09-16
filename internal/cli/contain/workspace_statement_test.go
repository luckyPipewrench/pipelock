// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"

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
		emitPosture: func(_ *config.Config, outputDir string, _ *probeEnv, _ []string) (string, error) {
			path := filepath.Join(outputDir, "proof.json")
			if err := os.MkdirAll(outputDir, 0o750); err != nil {
				return "", err
			}
			if err := os.WriteFile(path, []byte(fakeCapsuleBytes), 0o600); err != nil {
				return "", err
			}
			return path, nil
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
	if !strings.Contains(stdout.String(), "signed workspace change statement") {
		t.Fatalf("stdout missing statement line:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), workspaceStatementWrittenLine) {
		t.Fatalf("stdout missing machine-readable outcome line:\n%s", stdout.String())
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
	if len(signed.Statements) != 1 {
		t.Fatalf("statements = %d, want 1", len(signed.Statements))
	}
	st := signed.Statements[0]
	if st.Root != filepath.Clean(workspace) {
		t.Fatalf("root = %q, want %q", st.Root, workspace)
	}
	assertContainsPath(t, "added", st.Added, filepath.Join(workspace, "new.txt"))
	assertContainsPath(t, "modified", st.Modified, filepath.Join(workspace, "existing.txt"))
	if st.Incomplete {
		t.Fatalf("statement unexpectedly incomplete: %+v", st)
	}
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
		emitPosture: func(_ *config.Config, outputDir string, _ *probeEnv, _ []string) (string, error) {
			path := filepath.Join(outputDir, "proof.json")
			if err := os.MkdirAll(outputDir, 0o750); err != nil {
				return "", err
			}
			if err := os.WriteFile(path, []byte("capsule"), 0o600); err != nil {
				return "", err
			}
			return path, nil
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
		emitPosture: func(_ *config.Config, outputDir string, _ *probeEnv, _ []string) (string, error) {
			path := filepath.Join(outputDir, "proof.json")
			if err := os.MkdirAll(outputDir, 0o750); err != nil {
				return "", err
			}
			return path, os.WriteFile(path, []byte("capsule"), 0o600)
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
		probe:      env,
		loadConfig: func(f string) (*config.Config, error) { return config.Load(f) },
		launch: func(_ context.Context, _ *probeEnv, _ []string, _ io.Reader, _ io.Writer, _ io.Writer) error {
			launched = true
			return nil
		},
		emitPosture: func(_ *config.Config, outputDir string, _ *probeEnv, _ []string) (string, error) {
			path := filepath.Join(outputDir, "proof.json")
			if err := os.MkdirAll(outputDir, 0o750); err != nil {
				return "", err
			}
			return path, os.WriteFile(path, []byte("capsule"), 0o600)
		},
	}
	opts := containRunOptions{configFile: configPath, postureOutput: postureDir, workspaceDiffCapBytes: 1 << 20}
	var stdout bytes.Buffer
	if err := runContainRun(context.Background(), strings.NewReader(""), &stdout, io.Discard, runEnv, opts, []string{"claude"}); err != nil {
		t.Fatalf("runContainRun should not fail the whole session on a statement error: %v", err)
	}
	if !launched {
		t.Fatalf("expected the tool to still launch")
	}
	// M5: the signing key is resolved BEFORE launch, so an unavailable key is
	// reported up front, not discovered only after the agent already ran.
	if !strings.Contains(stdout.String(), "workspace change statement will be unavailable") {
		t.Fatalf("expected an upfront WARN before launch, got:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), workspaceStatementUnavailableLine) {
		t.Fatalf("expected the machine-readable unavailable line, got:\n%s", stdout.String())
	}
	if _, err := os.Stat(filepath.Join(postureDir, "workspace-change-statement.json")); !os.IsNotExist(err) {
		t.Fatalf("expected no statement file to be written")
	}
}

// TestRunContainRun_KeyRotationMidSession_StatementUsesPreLaunchKey is M5:
// the signing key is loaded once, before launch, and reused for the
// post-launch statement even if the config's key path is rewritten to point
// at a DIFFERENT key while the launched tool is running. Without the fix
// (loading the key again after launch), the statement would end up signed by
// the rotated-in key, one the posture capsule launched under was never bound
// to.
func TestRunContainRun_KeyRotationMidSession_StatementUsesPreLaunchKey(t *testing.T) {
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

	// A SECOND, different key the operator "rotates in" while the tool runs.
	_, rotatedPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	rotatedKeyPath := filepath.Join(configDir, "rotated.key")
	if err := signing.SavePrivateKey(rotatedPriv, rotatedKeyPath); err != nil {
		t.Fatal(err)
	}

	runEnv := containRunEnv{
		probe:      env,
		loadConfig: func(f string) (*config.Config, error) { return config.Load(f) },
		launch: func(_ context.Context, _ *probeEnv, _ []string, _ io.Reader, _ io.Writer, _ io.Writer) error {
			// Simulate an operator rotating the signing key mid-session by
			// rewriting the config the launched process's session would
			// otherwise re-read.
			body := fmt.Sprintf("metrics_listen: 127.0.0.1:9091\nflight_recorder:\n  signing_key_path: %s\n", rotatedKeyPath)
			return os.WriteFile(configPath, []byte(body), 0o600)
		},
		emitPosture: func(_ *config.Config, outputDir string, _ *probeEnv, _ []string) (string, error) {
			path := filepath.Join(outputDir, "proof.json")
			if err := os.MkdirAll(outputDir, 0o750); err != nil {
				return "", err
			}
			return path, os.WriteFile(path, []byte("capsule bytes"), 0o600)
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
		emitPosture: func(cfg *config.Config, outputDir string, _ *probeEnv, _ []string) (string, error) {
			if cfg.FlightRecorder.SigningKeyPath != observedKeyPaths[0] {
				t.Fatalf("posture emitter cfg signing key = %q, want the pre-rotation key %q (config was reloaded)",
					cfg.FlightRecorder.SigningKeyPath, observedKeyPaths[0])
			}
			path := filepath.Join(outputDir, "proof.json")
			if err := os.MkdirAll(outputDir, 0o750); err != nil {
				return "", err
			}
			return path, os.WriteFile(path, []byte("capsule bytes"), 0o600)
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
		emitPosture: func(_ *config.Config, outputDir string, _ *probeEnv, _ []string) (string, error) {
			path := filepath.Join(outputDir, "proof.json")
			if err := os.MkdirAll(outputDir, 0o750); err != nil {
				return "", err
			}
			return path, os.WriteFile(path, []byte("capsule"), 0o600)
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
