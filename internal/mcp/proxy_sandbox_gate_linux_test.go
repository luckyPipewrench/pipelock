// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package mcp

import (
	"context"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/sandbox"
)

// TestRunProxyWithSandbox_RefusesMappedCommand pins the refusal on the legacy
// plain-command entry point.
//
// That entry point calls Start directly, so a mapped command routed through it
// receives neither the UID/GID map ordering nor the parent hardening, and
// receives them missing with no error. The runtime uses the prepared gated
// launch today; this refusal is what stops a future mapped caller from
// reintroducing the ungated path by picking the older-looking function.
func TestRunProxyWithSandbox_RefusesMappedCommand(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		attr *syscall.SysProcAttr
	}{
		{
			name: "uid mappings",
			attr: &syscall.SysProcAttr{
				UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000, Size: 1}},
			},
		},
		{
			name: "gid mappings",
			attr: &syscall.SysProcAttr{
				GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: 1000, Size: 1}},
			},
		},
		{
			name: "user namespace clone flag",
			attr: &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cmd := exec.CommandContext(t.Context(), "/bin/true")
			cmd.SysProcAttr = tc.attr

			// The refusal must happen before any launch, so it returns
			// immediately. A bounded context keeps a regressed guard reported as
			// a failure rather than as a hang: without the refusal this call
			// proceeds into the full proxy flow and blocks on stdin, which would
			// stall CI instead of naming the defect.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			errCh := make(chan error, 1)
			go func() {
				errCh <- RunProxyWithSandbox(ctx, cmd, strings.NewReader(""), &strings.Builder{}, &strings.Builder{}, MCPProxyOpts{})
			}()

			var err error
			select {
			case err = <-errCh:
			case <-ctx.Done():
				t.Fatal("mapped command was not refused; the ungated entry point proceeded to launch")
			}
			if err == nil {
				t.Fatal("mapped command was accepted by the ungated entry point")
			}
			if !strings.Contains(err.Error(), "RunProxyWithSandboxLaunch") {
				t.Fatalf("refusal must name the gated entry point, got: %v", err)
			}
			if cmd.Process != nil {
				t.Fatal("mapped command was started before the refusal")
			}
		})
	}
}

// TestRunProxyWithSandbox_AllowsUnmappedCommand keeps the refusal narrow: an
// ordinary command still goes through, so the guard cannot quietly disable the
// legacy entry point for the callers it exists to serve.
func TestRunProxyWithSandbox_AllowsUnmappedCommand(t *testing.T) {
	t.Parallel()

	cmd := exec.CommandContext(t.Context(), "/bin/true")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- RunProxyWithSandbox(ctx, cmd, strings.NewReader(""), &strings.Builder{}, &strings.Builder{}, MCPProxyOpts{})
	}()
	var err error
	select {
	case err = <-errCh:
	case <-ctx.Done():
		t.Fatal("unmapped command did not complete; proxy flow blocked")
	}
	if err != nil && strings.Contains(err.Error(), "RunProxyWithSandboxLaunch") {
		t.Fatalf("unmapped command must not hit the mapped-launch refusal: %v", err)
	}
}

func TestRunProxyWithSandboxLaunchRejectsNilAndFailedMappedLaunch(t *testing.T) {
	t.Parallel()
	if err := RunProxyWithSandboxLaunch(context.Background(), nil, strings.NewReader(""), &strings.Builder{}, &strings.Builder{}, MCPProxyOpts{}); err == nil || !strings.Contains(err.Error(), "sandbox launch is nil") {
		t.Fatalf("nil prepared launch error = %v", err)
	}

	launch := &sandbox.PreparedSandboxCmd{
		Cmd:                       exec.CommandContext(context.Background(), "/definitely/not/a/pipelock-test-command"), // #nosec G204 G702 -- fixed literal test command
		ParentHardeningAfterStart: true,
	}
	err := RunProxyWithSandboxLaunch(context.Background(), launch, strings.NewReader(""), &strings.Builder{}, &strings.Builder{}, MCPProxyOpts{})
	if err == nil || !strings.Contains(err.Error(), "starting sandboxed MCP server") {
		t.Fatalf("failed mapped launch error = %v", err)
	}
}
