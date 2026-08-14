// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"context"
	"os/exec"
	"syscall"
	"testing"
)

func TestCmdNeedsHardeningGate(t *testing.T) {
	tests := []struct {
		name string
		cmd  *exec.Cmd
		want bool
	}{
		{name: "nil command", want: false},
		{name: "ordinary command", cmd: exec.CommandContext(context.Background(), "true"), want: false}, // #nosec G204 G702 -- fixed literal test command
		{
			name: "uid mapping",
			cmd: &exec.Cmd{SysProcAttr: &syscall.SysProcAttr{
				UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000, Size: 1}},
			}},
			want: true,
		},
		{
			name: "gid mapping",
			cmd: &exec.Cmd{SysProcAttr: &syscall.SysProcAttr{
				GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000, Size: 1}},
			}},
			want: true,
		},
		{
			name: "user namespace clone",
			cmd:  &exec.Cmd{SysProcAttr: &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER}},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CmdNeedsHardeningGate(tt.cmd); got != tt.want {
				t.Fatalf("CmdNeedsHardeningGate() = %v, want %v", got, tt.want)
			}
		})
	}
}
