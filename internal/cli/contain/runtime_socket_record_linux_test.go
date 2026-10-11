// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestRuntimeSocketMountRecordMatchesSystemd(t *testing.T) {
	runner, err := exec.LookPath("systemd-run")
	if err != nil {
		t.Skip("systemd-run unavailable for mount record proof")
	}
	manager, err := exec.LookPath("systemctl")
	if err != nil {
		t.Skip("systemctl unavailable for mount record proof")
	}
	ctx, _, env := runtimeMountSystemdFixture(t)
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- fixed systemd executables and test-owned arguments
		cmd.Env = env
		return cmd.CombinedOutput()
	}
	unit := "pipelock-runtime-record-" + strconv.FormatInt(time.Now().UnixNano(), 10) + ".service"
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), testwait.Deadline(10*time.Second))
		defer stop()
		_, _ = run(cleanup, manager, "--user", "stop", unit)
	})
	args := []string{"--user", "--collect", "--service-type=exec", "--unit=" + unit, "--property=PrivateUsers=true", "--property=PrivateNetwork=true"}
	for _, property := range runtimeSocketMountProperties() {
		args = append(args, "--property="+property)
	}
	args = append(args, "--", "/usr/bin/sleep", "60")
	if out, err := run(ctx, runner, args...); err != nil {
		t.Fatalf("starting disposable user unit: %v: %s", err, out)
	}
	out, err := run(ctx, manager, "--user", "show", unit, "--property=TemporaryFileSystem", "--value")
	if err != nil {
		t.Fatalf("observing disposable user unit: %v: %s", err, out)
	}
	if err := sameLifecyclePathList(strings.TrimSpace(string(out)), runtimeSocketTemporaryFileSystems()); err != nil {
		t.Fatalf("systemd mount options differ from launch record: %v: %s", err, out)
	}
	t.Logf("systemd mount record: %s", strings.TrimSpace(string(out)))
}
