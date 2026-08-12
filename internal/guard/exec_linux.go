// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package guard

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/processexec"
)

const (
	execModeEnv        = "__PIPELOCK_GUARD_EXEC"
	execDeclarationEnv = "__PIPELOCK_GUARD_DECLARATION"
	execProfileEnv     = "__PIPELOCK_GUARD_PROFILE"
	execPolicyHashEnv  = "__PIPELOCK_GUARD_POLICY_HASH"
	execWorkspaceEnv   = "__PIPELOCK_GUARD_WORKSPACE"
	execTempDirEnv     = "__PIPELOCK_GUARD_TEMP_DIR"
	execBinaryEnv      = "__PIPELOCK_GUARD_BINARY"
	execEnvironmentEnv = "__PIPELOCK_GUARD_ENVIRONMENT_FD"
	execStatusEnv      = "__PIPELOCK_GUARD_STATUS_FD"
)

const execEnvironmentMaxPayload = 8 << 20

const guardDeclarationEnvironmentMaxPayload = 64 << 10

// IsExecMode reports whether this process is the final Guard pre-exec helper.
func IsExecMode() bool { return os.Getenv(execModeEnv) == "1" }

// ExecControlEnvironment returns the fixed control entries the standalone
// init adds only to the Guard helper. The declaration contains paths and exact
// destinations, never the developer's secret-bearing environment.
func ExecControlEnvironment(opts ExecControlOptions) ([]string, error) {
	encoded, err := json.Marshal(opts.Declaration)
	if err != nil {
		return nil, fmt.Errorf("encoding guard declaration: %w", err)
	}
	if len(encoded) > guardDeclarationEnvironmentMaxPayload {
		return nil, errors.New("guard declaration exceeds the 64 KiB environment transport limit")
	}
	return []string{
		execModeEnv + "=1",
		execDeclarationEnv + "=" + string(encoded),
		execProfileEnv + "=" + opts.Profile,
		execPolicyHashEnv + "=" + opts.PolicyHash,
		execWorkspaceEnv + "=" + opts.Workspace,
		execTempDirEnv + "=" + opts.TempDir,
		execBinaryEnv + "=" + opts.Binary,
		execEnvironmentEnv + "=" + strconv.Itoa(opts.EnvironmentFD),
		execStatusEnv + "=" + strconv.Itoa(opts.StatusFD),
	}, nil
}

// RunExec applies Guard and replaces this helper with the operator command.
// It exits on failure and does not return on success.
func RunExec() {
	environment, err := readExecEnvironment(os.Getenv(execEnvironmentEnv))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[guard] REFUSED: %v\n", err)
		os.Exit(1)
	}
	status, err := openExecStatusWriter(os.Getenv(execStatusEnv))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[guard] REFUSED: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = status.Close() }()
	err = runExecWith(os.Args[1:], environment,
		func(prepared *PreparedManifest) (EnforcementRecord, error) { return prepared.ApplyForExec() },
		processexec.Replace,
		func(proof ExecutionProof) error { return json.NewEncoder(status).Encode(proof) },
	)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "[guard] REFUSED: %v\n", err)
		os.Exit(1)
	}
}

func openExecStatusWriter(rawFD string) (*os.File, error) {
	fd, err := strconv.Atoi(rawFD)
	if err != nil || fd < 3 {
		return nil, errors.New("invalid guard status descriptor")
	}
	file := os.NewFile(uintptr(fd), "guard-status")
	if file == nil {
		return nil, errors.New("opening guard status descriptor")
	}
	syscall.CloseOnExec(fd)
	return file, nil
}

func readExecEnvironment(rawFD string) ([]string, error) {
	fd, err := strconv.Atoi(rawFD)
	if err != nil || fd < 3 {
		return nil, errors.New("invalid guard environment descriptor")
	}
	file := os.NewFile(uintptr(fd), "guard-environment")
	if file == nil {
		return nil, errors.New("opening guard environment descriptor")
	}
	return decodeExecEnvironment(file)
}

func decodeExecEnvironment(reader io.ReadCloser) ([]string, error) {
	defer func() { _ = reader.Close() }()
	payload, err := io.ReadAll(io.LimitReader(reader, execEnvironmentMaxPayload+1))
	if err != nil {
		return nil, fmt.Errorf("reading guard environment: %w", err)
	}
	if len(payload) > execEnvironmentMaxPayload {
		return nil, errors.New("guard environment exceeds 8 MiB")
	}
	var environment []string
	if err := json.Unmarshal(payload, &environment); err != nil {
		return nil, fmt.Errorf("decoding guard environment: %w", err)
	}
	seen := make(map[string]struct{}, len(environment))
	for _, entry := range environment {
		key, _, ok := strings.Cut(entry, "=")
		if !ok || key == "" || strings.IndexByte(entry, 0) >= 0 {
			return nil, errors.New("guard environment contains a malformed entry")
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("guard environment contains duplicate key %q", key)
		}
		seen[key] = struct{}{}
	}
	return environment, nil
}

func runExec(command, environment []string) error {
	return runExecWith(command, environment,
		func(prepared *PreparedManifest) (EnforcementRecord, error) { return prepared.ApplyForExec() },
		processexec.Replace,
		func(ExecutionProof) error { return nil },
	)
}

func runExecWith(
	command, environment []string,
	apply func(*PreparedManifest) (EnforcementRecord, error),
	replace func(string, []string, []string) error,
	report func(ExecutionProof) error,
) error {
	if len(command) == 0 {
		return errors.New("missing operator command")
	}
	workspace := os.Getenv(execWorkspaceEnv)
	tempDir := os.Getenv(execTempDirEnv)
	policyHash := os.Getenv(execPolicyHashEnv)
	binary := filepath.Clean(os.Getenv(execBinaryEnv))
	if workspace == "" || tempDir == "" || policyHash == "" || !filepath.IsAbs(binary) {
		return errors.New("incomplete guard execution controls")
	}

	var declaration config.Guard
	if err := json.Unmarshal([]byte(os.Getenv(execDeclarationEnv)), &declaration); err != nil {
		return fmt.Errorf("decoding guard declaration: %w", err)
	}
	cfg := config.Defaults()
	cfg.Guard = declaration
	if err := cfg.ValidateGuardDeclaration(); err != nil {
		return fmt.Errorf("validating guard declaration: %w", err)
	}

	prepared, err := PrepareExecution(cfg, os.Getenv(execProfileEnv), workspace, tempDir, binary, os.Getuid())
	if err != nil {
		return fmt.Errorf("preparing manifest: %w", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = prepared.Close()
		}
	}()
	// Keep this goroutine on the exact thread that enters the Landlock domain
	// until exec replaces the process image. ApplyForExec pins internally while
	// issuing the syscalls, but unpins when it returns; without this outer pin,
	// the Go scheduler could migrate us to an unrestricted runtime thread in the
	// small gap before syscall.Exec and the workload would inherit no policy.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	record, err := apply(prepared)
	if err != nil {
		return fmt.Errorf("%s: %w", record.Describe(), err)
	}
	if !record.Enforced() {
		return fmt.Errorf("%s", record.Describe())
	}
	closed = true
	if err := prepared.Close(); err != nil {
		return fmt.Errorf("closing prepared manifest: %w", err)
	}
	proof := NewExecutionProof(record, ExecControlOptions{
		Profile: os.Getenv(execProfileEnv), PolicyHash: policyHash,
		Workspace: workspace, TempDir: tempDir, Binary: binary,
	}, command)
	if err := report(proof); err != nil {
		return fmt.Errorf("reporting guard enforcement: %w", err)
	}
	_, _ = fmt.Fprintf(os.Stderr, "[guard] %s; policy_hash=%s\n", record.Describe(), policyHash)

	clean := make([]string, 0, len(environment))
	for _, entry := range environment {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(strings.ToUpper(key), "__PIPELOCK_") {
			continue
		}
		clean = append(clean, entry)
	}
	if err := replace(binary, command, clean); err != nil {
		proof.ExecError = err.Error()
		if reportErr := report(proof); reportErr != nil {
			return errors.Join(err, fmt.Errorf("reporting guard exec failure: %w", reportErr))
		}
		return err
	}
	return nil
}
