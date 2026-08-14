// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPreparedSandboxCmd_HardeningFailureReapsChild(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create readiness pipe: %v", err)
	}
	launch := &PreparedSandboxCmd{
		Cmd:                       exec.CommandContext(t.Context(), "sh", "-c", "sleep 30"), // #nosec G204 G702 -- fixed literal test command
		ParentHardeningAfterStart: true,
		readinessReader:           reader,
		readinessWriter:           writer,
	}
	boom := errors.New("harden denied")
	err = launch.StartWithParentHardening(func() error { return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("hardening failure = %v, want %v", err, boom)
	}
	if launch.Cmd.ProcessState == nil {
		t.Fatal("hardening failure left sandbox child unreaped")
	}
}

func TestPreparedSandboxCmd_ReadinessWriteFailureReapsChild(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create readiness pipe: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close readiness writer: %v", err)
	}
	launch := &PreparedSandboxCmd{
		Cmd:                       exec.CommandContext(t.Context(), "sh", "-c", "sleep 30"), // #nosec G204 G702 -- fixed literal test command
		ParentHardeningAfterStart: true,
		readinessReader:           reader,
		readinessWriter:           writer,
	}
	err = launch.StartWithParentHardening(func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "releasing sandbox target") {
		t.Fatalf("readiness write failure = %v", err)
	}
	if launch.Cmd.ProcessState == nil {
		t.Fatal("readiness write failure left sandbox child unreaped")
	}
}
