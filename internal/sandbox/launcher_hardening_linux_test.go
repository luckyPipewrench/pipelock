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

func TestPreparedSandboxCmd_EagerHardeningOrderingAndFailures(t *testing.T) {
	var nilLaunch *PreparedSandboxCmd
	nilLaunch.Close()
	if err := nilLaunch.StartWithParentHardening(func() error { return nil }); err == nil {
		t.Fatal("nil launch started")
	}
	if err := (&PreparedSandboxCmd{Cmd: exec.CommandContext(t.Context(), "true")}).StartWithParentHardening(nil); err == nil {
		t.Fatal("nil hardening callback started a child")
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	launch := &PreparedSandboxCmd{
		Cmd:             exec.CommandContext(t.Context(), "true"), // #nosec G204 G702 -- fixed literal test command
		readinessReader: reader,
		readinessWriter: writer,
	}
	hardened := false
	if err := launch.StartWithParentHardening(func() error {
		hardened = true
		return nil
	}); err != nil {
		t.Fatalf("eager StartWithParentHardening: %v", err)
	}
	if !hardened {
		t.Fatal("eager launch started before parent hardening callback")
	}
	if launch.readinessReader != nil {
		t.Fatal("eager launch retained readiness reader")
	}
	if err := launch.Cmd.Wait(); err != nil {
		t.Fatalf("wait eager child: %v", err)
	}
	launch.Close()

	blocked := &PreparedSandboxCmd{Cmd: exec.CommandContext(t.Context(), "true")} // #nosec G204 G702 -- fixed literal test command
	boom := errors.New("eager hardening denied")
	if err := blocked.StartWithParentHardening(func() error { return boom }); !errors.Is(err, boom) {
		t.Fatalf("eager hardening error = %v, want %v", err, boom)
	}
	if blocked.Cmd.Process != nil {
		t.Fatal("failed eager hardening started a child")
	}

	startFailureReader, startFailureWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	startFailure := &PreparedSandboxCmd{
		Cmd:             exec.Command("/definitely/not/a/pipelock-test-command"), // #nosec G204 G702 -- fixed literal test command
		readinessReader: startFailureReader,
		readinessWriter: startFailureWriter,
	}
	if err := startFailure.StartWithParentHardening(func() error { return nil }); err == nil || !strings.Contains(err.Error(), "starting sandbox child") {
		t.Fatalf("eager start failure = %v", err)
	}
	if startFailure.readinessReader != nil || startFailure.readinessWriter != nil {
		t.Fatal("failed eager start retained readiness descriptors")
	}
}

func TestPreparedSandboxCmd_GatedSuccessReleasesOnlyAfterHardening(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "sh", "-c", "read -r -n 1 <&3") // #nosec G204 G702 -- fixed literal test command
	cmd.ExtraFiles = []*os.File{reader}
	launch := &PreparedSandboxCmd{
		Cmd:                       cmd,
		ParentHardeningAfterStart: true,
		readinessReader:           reader,
		readinessWriter:           writer,
	}
	hardened := false
	if err := launch.StartWithParentHardening(func() error {
		hardened = true
		return nil
	}); err != nil {
		t.Fatalf("gated StartWithParentHardening: %v", err)
	}
	if !hardened || launch.readinessReader != nil || launch.readinessWriter != nil {
		t.Fatalf("gated success state hardened=%v reader=%v writer=%v", hardened, launch.readinessReader, launch.readinessWriter)
	}
	if err := launch.Cmd.Wait(); err != nil {
		t.Fatalf("wait gated child: %v", err)
	}
	if err := launch.releaseTargetStart(); err == nil {
		t.Fatal("released launch allowed a second target-start signal")
	}
}

func TestPrepareSandboxCmdRejectsGateWithoutOrderingWrapper(t *testing.T) {
	if cmd, err := PrepareSandboxCmd(LaunchConfig{GateTargetStart: true}); err == nil || cmd != nil {
		t.Fatalf("PrepareSandboxCmd gate result = %v, %v; want explicit wrapper error", cmd, err)
	}
}
