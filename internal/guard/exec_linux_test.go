// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"golang.org/x/sys/unix"
)

func TestReadExecEnvironmentOwnsInheritedDescriptor(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	if _, err := writer.Write([]byte(`["PATH=/developer/bin"]`)); err != nil {
		t.Fatalf("write environment: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	inheritedFD, err := unix.Dup(int(reader.Fd()))
	if err != nil {
		t.Fatalf("dup inherited descriptor: %v", err)
	}
	if err := reader.Close(); err != nil {
		_ = unix.Close(inheritedFD)
		t.Fatalf("close original reader: %v", err)
	}
	got, err := readExecEnvironment(strconv.Itoa(inheritedFD))
	if err != nil {
		t.Fatalf("read inherited environment: %v", err)
	}
	if len(got) != 1 || got[0] != "PATH=/developer/bin" {
		t.Fatalf("environment = %v", got)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(inheritedFD, &stat); !errors.Is(err, unix.EBADF) {
		_ = unix.Close(inheritedFD)
		t.Fatalf("inherited descriptor remained open: %v", err)
	}
}

func TestOpenExecStatusWriterValidatesAndOwnsDescriptor(t *testing.T) {
	for _, raw := range []string{"", "2", "not-a-number"} {
		if _, err := openExecStatusWriter(raw); err == nil {
			t.Fatalf("status descriptor %q was accepted", raw)
		}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer func() { _ = reader.Close() }()
	inheritedFD, err := unix.Dup(int(writer.Fd()))
	if err != nil {
		t.Fatalf("dup status descriptor: %v", err)
	}
	_ = writer.Close()
	status, err := openExecStatusWriter(strconv.Itoa(inheritedFD))
	if err != nil {
		t.Fatalf("openExecStatusWriter: %v", err)
	}
	flags, err := unix.FcntlInt(uintptr(inheritedFD), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("read status descriptor flags: %v", err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("guard status descriptor is not close-on-exec")
	}
	if err := status.Close(); err != nil {
		t.Fatalf("close status writer: %v", err)
	}
}

func TestReadExecEnvironmentRoundTripAndClose(t *testing.T) {
	want := []string{"PATH=/developer/bin", "LD_PRELOAD=/developer/hook.so", "TOKEN=preserved-value"}
	payload, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	reader := &trackedReadCloser{Reader: bytes.NewReader(payload)}
	got, err := decodeExecEnvironment(reader)
	if err != nil {
		t.Fatalf("readExecEnvironment: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("environment = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("environment[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if !reader.closed {
		t.Fatal("environment reader remained open after decoding")
	}
}

func TestReadExecEnvironmentRejectsDuplicateKeys(t *testing.T) {
	reader := &trackedReadCloser{Reader: strings.NewReader(`["PATH=/usr/bin","PATH=/workspace/bin"]`)}
	if _, err := decodeExecEnvironment(reader); err == nil {
		t.Fatal("duplicate environment keys were accepted")
	}
	if !reader.closed {
		t.Fatal("environment reader remained open after refusal")
	}
}

func TestDecodeExecEnvironmentRejectsMalformedAndOversizedPayloads(t *testing.T) {
	readFailure := errors.New("read failed")
	for _, testCase := range []struct {
		name   string
		reader io.ReadCloser
		want   string
	}{
		{name: "read failure", reader: &trackedReadCloser{Reader: errorReader{err: readFailure}}, want: "reading guard environment"},
		{name: "oversized", reader: &trackedReadCloser{Reader: strings.NewReader(strings.Repeat("x", execEnvironmentMaxPayload+1))}, want: "exceeds 8 MiB"},
		{name: "invalid JSON", reader: &trackedReadCloser{Reader: strings.NewReader("not-json")}, want: "decoding guard environment"},
		{name: "missing equals", reader: &trackedReadCloser{Reader: strings.NewReader(`["PATH"]`)}, want: "malformed entry"},
		{name: "empty key", reader: &trackedReadCloser{Reader: strings.NewReader(`["=value"]`)}, want: "malformed entry"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := decodeExecEnvironment(testCase.reader)
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want %q", err, testCase.want)
			}
		})
	}
	for _, raw := range []string{"", "2", "not-a-number"} {
		if _, err := readExecEnvironment(raw); err == nil {
			t.Fatalf("descriptor %q was accepted", raw)
		}
	}
}

func TestExecEntryPointsRejectInvalidControls(t *testing.T) {
	t.Setenv(execModeEnv, "1")
	if !IsExecMode() {
		t.Fatal("exec mode marker was ignored")
	}
	workspace := t.TempDir()
	tempDir := t.TempDir()
	controls, err := ExecControlEnvironment(ExecControlOptions{
		Declaration: config.Guard{}, PolicyHash: "policy-hash", Workspace: workspace,
		TempDir: tempDir, Binary: "/usr/bin/true", EnvironmentFD: 3, StatusFD: 4,
	})
	if err != nil {
		t.Fatalf("ExecControlEnvironment: %v", err)
	}
	declarationJSON, err := json.Marshal(config.Guard{})
	if err != nil {
		t.Fatalf("marshal declaration: %v", err)
	}
	wantControls := []string{
		execModeEnv + "=1",
		execDeclarationEnv + "=" + string(declarationJSON),
		execProfileEnv + "=",
		execPolicyHashEnv + "=policy-hash",
		execWorkspaceEnv + "=" + workspace,
		execTempDirEnv + "=" + tempDir,
		execBinaryEnv + "=/usr/bin/true",
		execEnvironmentEnv + "=3",
		execStatusEnv + "=4",
	}
	if len(controls) != len(wantControls) {
		t.Fatalf("controls = %v", controls)
	}
	for _, want := range wantControls {
		if !slices.Contains(controls, want) {
			t.Fatalf("controls missing %q: %v", want, controls)
		}
	}
	largeDeclaration := config.Guard{Services: []config.GuardService{{Name: strings.Repeat("x", guardDeclarationEnvironmentMaxPayload+1)}}}
	if _, err := ExecControlEnvironment(ExecControlOptions{Declaration: largeDeclaration, PolicyHash: "hash", Workspace: t.TempDir(), TempDir: t.TempDir(), Binary: "/usr/bin/true", EnvironmentFD: 3, StatusFD: 4}); err == nil || !strings.Contains(err.Error(), "64 KiB") {
		t.Fatalf("oversized declaration error = %v", err)
	}
	if err := runExec(nil, nil); err == nil || !strings.Contains(err.Error(), "missing operator command") {
		t.Fatalf("runExec error = %v", err)
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }

type trackedReadCloser struct {
	io.Reader
	closed bool
}

func (r *trackedReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestRunExecWithAppliesPolicyAndReplacesProcess(t *testing.T) {
	workspace := t.TempDir()
	tempDir := t.TempDir()
	t.Setenv(execWorkspaceEnv, workspace)
	t.Setenv(execTempDirEnv, tempDir)
	t.Setenv(execPolicyHashEnv, "policy-hash")
	t.Setenv(execBinaryEnv, "/usr/bin/true")
	t.Setenv(execDeclarationEnv, `{}`)
	t.Setenv(execProfileEnv, "")

	var replaced bool
	err := runExecWith(
		[]string{"/usr/bin/true", "argument"},
		[]string{"PATH=/usr/bin", "__PIPELOCK_ATTACKER=value", "TOKEN=preserved"},
		func(prepared *PreparedManifest) (EnforcementRecord, error) {
			if prepared == nil || !prepared.Complete() {
				t.Fatal("prepared manifest is incomplete")
			}
			return EnforcementRecord{State: EnforcementEnforced, Mechanism: "landlock", Coverage: CoverageFull}, nil
		},
		func(binary string, command, environment []string) error {
			replaced = true
			if binary != "/usr/bin/true" || len(command) != 2 || command[1] != "argument" {
				t.Fatalf("replacement binary=%q command=%v", binary, command)
			}
			if slices.Contains(environment, "__PIPELOCK_ATTACKER=value") || !slices.Contains(environment, "TOKEN=preserved") {
				t.Fatalf("replacement environment=%v", environment)
			}
			return nil
		},
		func(proof ExecutionProof) error {
			if err := proof.Verify("policy-hash"); err != nil {
				t.Fatalf("execution proof: %v", err)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("runExecWith: %v", err)
	}
	if !replaced {
		t.Fatal("process replacement was not called")
	}
}

func TestRunExecWithRefusesIncompleteControlsAndEnforcement(t *testing.T) {
	validControls := func(t *testing.T) {
		t.Helper()
		t.Setenv(execWorkspaceEnv, t.TempDir())
		t.Setenv(execTempDirEnv, t.TempDir())
		t.Setenv(execPolicyHashEnv, "policy-hash")
		t.Setenv(execBinaryEnv, "/usr/bin/true")
		t.Setenv(execDeclarationEnv, `{}`)
		t.Setenv(execProfileEnv, "")
	}
	noReplace := func(string, []string, []string) error {
		t.Fatal("refused execution reached process replacement")
		return nil
	}
	for _, testCase := range []struct {
		name    string
		prepare func(*testing.T)
		command []string
		apply   func(*PreparedManifest) (EnforcementRecord, error)
		want    string
	}{
		{name: "missing command", prepare: validControls, want: "missing operator command"},
		{name: "missing controls", prepare: func(t *testing.T) {}, command: []string{"true"}, want: "incomplete guard execution controls"},
		{name: "invalid declaration", prepare: func(t *testing.T) { validControls(t); t.Setenv(execDeclarationEnv, "{") }, command: []string{"true"}, want: "decoding guard declaration"},
		{name: "invalid declaration structure", prepare: func(t *testing.T) {
			validControls(t)
			t.Setenv(execDeclarationEnv, `{"profiles":[{"name":"worker","manifests":["missing"]}]}`)
		}, command: []string{"true"}, want: "validating guard declaration"},
		{name: "prepare failure", prepare: func(t *testing.T) {
			validControls(t)
			t.Setenv(execWorkspaceEnv, "/usr/local/bin")
		}, command: []string{"true"}, want: "preparing manifest"},
		{name: "apply failure", prepare: validControls, command: []string{"true"}, apply: func(*PreparedManifest) (EnforcementRecord, error) {
			return EnforcementRecord{State: EnforcementRefused, Reason: "kernel refused"}, errors.New("apply failed")
		}, want: "apply failed"},
		{name: "unenforced record", prepare: validControls, command: []string{"true"}, apply: func(*PreparedManifest) (EnforcementRecord, error) {
			return EnforcementRecord{State: EnforcementRefused, Reason: "not enforced"}, nil
		}, want: "not enforced"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			testCase.prepare(t)
			apply := testCase.apply
			if apply == nil {
				apply = func(*PreparedManifest) (EnforcementRecord, error) {
					t.Fatal("invalid controls reached enforcement")
					return EnforcementRecord{}, nil
				}
			}
			err := runExecWith(testCase.command, nil, apply, noReplace, func(ExecutionProof) error { return nil })
			if err == nil || !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %v, want %q", err, testCase.want)
			}
		})
	}
}

func TestRunExecWithReportsExecFailureAfterEnforcement(t *testing.T) {
	t.Setenv(execWorkspaceEnv, t.TempDir())
	t.Setenv(execTempDirEnv, t.TempDir())
	t.Setenv(execPolicyHashEnv, "policy-hash")
	t.Setenv(execBinaryEnv, "/usr/bin/true")
	t.Setenv(execDeclarationEnv, `{}`)
	t.Setenv(execProfileEnv, "")
	wantErr := errors.New("exec refused")
	var proofs []ExecutionProof
	err := runExecWith(
		[]string{"/usr/bin/true"}, nil,
		func(*PreparedManifest) (EnforcementRecord, error) {
			return EnforcementRecord{State: EnforcementEnforced, Mechanism: "landlock", Coverage: CoverageFull}, nil
		},
		func(string, []string, []string) error { return wantErr },
		func(proof ExecutionProof) error {
			proofs = append(proofs, proof)
			return nil
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("runExecWith error = %v", err)
	}
	if len(proofs) != 2 || proofs[0].ExecError != "" || proofs[1].ExecError != wantErr.Error() {
		t.Fatalf("execution status sequence = %+v", proofs)
	}
}

func TestPrepareExecutionGrantsExactResolvedExecutable(t *testing.T) {
	workspace := t.TempDir()
	executableDir := t.TempDir()
	executable := filepath.Join(executableDir, "developer-tool")
	if err := os.WriteFile(executable, []byte("tool"), 0o600); err != nil {
		t.Fatalf("write executable: %v", err)
	}
	executableRoot, err := os.OpenRoot(executableDir)
	if err != nil {
		t.Fatalf("open executable root: %v", err)
	}
	defer func() { _ = executableRoot.Close() }()
	executableFile, err := executableRoot.Open("developer-tool")
	if err != nil {
		t.Fatalf("open executable: %v", err)
	}
	if err := executableFile.Chmod(0o700); err != nil {
		_ = executableFile.Close()
		t.Fatalf("make executable: %v", err)
	}
	if err := executableFile.Close(); err != nil {
		t.Fatalf("close executable: %v", err)
	}
	prepared, err := PrepareExecution(config.Defaults(), "", workspace, workspace, executable, os.Getuid())
	if err != nil {
		t.Fatalf("PrepareExecution: %v", err)
	}
	defer func() { _ = prepared.Close() }()
	granted := false
	for _, outcome := range prepared.Outcomes() {
		if outcome.DeclaredPath == executableDir && outcome.State.Granted() {
			t.Fatalf("executable directory %q was granted", executableDir)
		}
		if outcome.DeclaredPath == executable && outcome.State.Granted() {
			granted = true
		}
	}
	if !granted {
		t.Fatalf("exact executable %q was not granted: %+v", executable, prepared.Outcomes())
	}
}

func TestPrepareExecutionRefusesWorkspaceThatBypassesWriteFloor(t *testing.T) {
	_, err := PrepareExecution(config.Defaults(), "", "/usr/local/bin", t.TempDir(), "/usr/bin/true", os.Getuid())
	if err == nil || !strings.Contains(err.Error(), "compiled floor") {
		t.Fatalf("dangerous workspace error = %v, want compiled-floor refusal", err)
	}
}

func TestPrepareExecutionRefusesTempDirThatBypassesWriteFloor(t *testing.T) {
	_, err := PrepareExecution(config.Defaults(), "", t.TempDir(), "/usr/local/bin", "/usr/bin/true", os.Getuid())
	if err == nil || !strings.Contains(err.Error(), "compiled floor") || !strings.Contains(err.Error(), "temporary directory") {
		t.Fatalf("dangerous temporary directory error = %v, want compiled-floor refusal", err)
	}
}

func TestPrepareExecutionDoesNotGrantPrivateCertificateTrees(t *testing.T) {
	workspace := t.TempDir()
	prepared, err := PrepareExecution(config.Defaults(), "", workspace, workspace, "/usr/bin/true", os.Getuid())
	if err != nil {
		t.Fatalf("PrepareExecution: %v", err)
	}
	defer func() { _ = prepared.Close() }()
	for _, outcome := range prepared.Outcomes() {
		if outcome.DeclaredPath == "/etc/ssl" || outcome.DeclaredPath == "/etc/pki" || strings.HasPrefix(outcome.DeclaredPath, "/etc/ssl/private") {
			t.Fatalf("private certificate tree was granted: %+v", outcome)
		}
	}
}

func TestPrepareExecutionRefusesWorkspaceSymlinkThatBypassesWriteFloor(t *testing.T) {
	alias := filepath.Join(t.TempDir(), "workspace")
	if err := os.Symlink("/usr/local/bin", alias); err != nil {
		t.Fatalf("create workspace symlink: %v", err)
	}
	prepared, err := PrepareExecution(config.Defaults(), "", alias, t.TempDir(), "/usr/bin/true", os.Getuid())
	if prepared != nil {
		_ = prepared.Close()
	}
	if err == nil || !strings.Contains(err.Error(), "compiled floor") {
		t.Fatalf("workspace symlink bypass error = %v", err)
	}
}

func TestPrepareExecutionRejectsMissingConfigAndProfile(t *testing.T) {
	if _, err := PrepareExecution(nil, "", t.TempDir(), "", "", os.Getuid()); err == nil {
		t.Fatal("nil execution config was accepted")
	}
	cfg := config.Defaults()
	cfg.Guard.Profiles = []config.GuardProfile{{Name: "worker"}}
	if _, err := PrepareExecution(cfg, "", t.TempDir(), "", "", os.Getuid()); err == nil || !strings.Contains(err.Error(), "profile is required") {
		t.Fatalf("missing profile error = %v", err)
	}
	if _, err := PrepareExecution(cfg, "missing", t.TempDir(), "", "", os.Getuid()); err == nil {
		t.Fatal("unknown execution profile was accepted")
	}
}
