// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestIntegration_StandaloneInitRejectsMalformedDeveloperEnvironmentPipe(t *testing.T) {
	testBinary := buildTestBinary(t)
	payload, err := encodeDeveloperEnvironment([]string{"FIRST=one", "SECOND=two"})
	if err != nil {
		t.Fatalf("encodeDeveloperEnvironment: %v", err)
	}

	duplicate := make([]byte, 0, len(payload)+13)
	duplicate = append(duplicate, payload[:8]...)
	binary.BigEndian.PutUint32(duplicate[8:12], 2)
	duplicate = append(duplicate, payload[12:25]...)
	duplicate = append(duplicate, 0, 0, 0, 9)
	duplicate = append(duplicate, "FIRST=two"...)

	for _, testCase := range []struct {
		name    string
		payload []byte
	}{
		{name: "duplicate", payload: duplicate},
		{name: "truncated", payload: payload[:len(payload)-1]},
		{name: "oversize", payload: make([]byte, developerEnvironmentMaxPayload+1)},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			stderr, exitCode := runStandaloneInitWithDeveloperPipe(t, testBinary, testCase.payload)
			if exitCode != 1 {
				t.Fatalf("exit code = %d, want 1\nstderr: %s", exitCode, stderr)
			}
			if !strings.Contains(stderr, "developer env transport") {
				t.Fatalf("stderr missing developer environment transport failure:\n%s", stderr)
			}
		})
	}
}

func runStandaloneInitWithDeveloperPipe(t *testing.T, binary string, payload []byte) (string, int) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create developer environment pipe: %v", err)
	}
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, binary)
	cmd.Env = initChildEnvironment([]string{
		standaloneInitEnv + "=1",
		"__PIPELOCK_SANDBOX_WORKSPACE=" + t.TempDir(),
		"__PIPELOCK_SANDBOX_COMMAND=true",
		sandboxSocketEnv + "=" + filepath.Join(t.TempDir(), "proxy.sock"),
		developerEnvironmentControlEnv + "=" + strconv.Itoa(developerEnvironmentFD),
		noNetNSEnvKey + "=1",
	})
	cmd.ExtraFiles = []*os.File{reader}
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start standalone init: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close parent pipe reader: %v", err)
	}
	_, _ = writer.Write(payload)
	if err := writer.Close(); err != nil {
		t.Fatalf("close pipe writer: %v", err)
	}

	err = cmd.Wait()
	if ctx.Err() != nil {
		t.Fatalf("standalone init timed out: %v\nstderr: %s", ctx.Err(), stderr.String())
	}
	if err == nil {
		return stderr.String(), 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("standalone init failed to execute: %v", err)
	}
	return stderr.String(), exitErr.ExitCode()
}
