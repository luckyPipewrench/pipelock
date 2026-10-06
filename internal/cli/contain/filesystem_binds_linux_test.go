// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestLifecycleAdmissionUsesCapturedTypedBinds(t *testing.T) {
	fixture := loadSystemd261Binds(t)
	plain := fixture.Cases[0]
	for _, tc := range fixture.Cases {
		if tc.Name == "plain" {
			plain = tc
		}
	}
	show := showProperty(t, plain.Show, "BindPaths")
	entries, err := parseTypedSystemdBinds(plain.Typed)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("typed tuple admits when show omits norbind", func(t *testing.T) {
		l, fields := enforceShowLifecycle(t, show)
		b := lifecycleTestBackend(fields)
		b.binds = func(context.Context, string) ([]systemdBindEntry, []systemdBindEntry, error) {
			return entries, nil, nil
		}
		actions := 0
		b.action = func(context.Context, string, ...string) error {
			actions++
			fields["ActiveState"], fields["MainPID"] = "inactive", "0"
			return nil
		}
		b.cgroupEmpty = func(string) (bool, error) { return true, nil }
		b.wait = func(context.Context, time.Duration) error { return nil }
		done := make(chan error, 1)
		done <- nil
		if err := superviseLifecycleService(context.Background(), done, func() {}, l, 966, b); err != nil {
			t.Fatal(err)
		}
		if !l.record.AdmissionObserved || actions == 0 || !l.record.CleanupComplete {
			t.Fatalf("admitted=%v actions=%d cleanup=%v phase=%s", l.record.AdmissionObserved, actions, l.record.CleanupComplete, l.record.Phase)
		}
	})

	t.Run("display form without an option does not admit", func(t *testing.T) {
		l, fields := enforceShowLifecycle(t, show)
		b := lifecycleTestBackend(fields)
		b.binds = func(context.Context, string) ([]systemdBindEntry, []systemdBindEntry, error) {
			return nil, nil, errTypedBindsUnavailable
		}
		b.action = func(context.Context, string, ...string) error {
			fields["ActiveState"], fields["MainPID"] = "inactive", "0"
			return nil
		}
		b.wait = func(context.Context, time.Duration) error { return nil }
		b.cgroupEmpty = func(string) (bool, error) { return fields["ActiveState"] == "inactive", nil }
		done := make(chan error, 1)
		done <- nil
		err := superviseLifecycleService(context.Background(), done, func() {}, l, 966, b)
		if err == nil || l.record.AdmissionObserved || !l.record.OwnershipObserved || !l.record.CleanupComplete || l.record.Phase != "incomplete" {
			t.Fatalf("err=%v owned=%v admitted=%v cleanup=%v phase=%s", err, l.record.OwnershipObserved, l.record.AdmissionObserved, l.record.CleanupComplete, l.record.Phase)
		}
	})
}

func TestMissingAbsoluteBusctlSelectsFailClosedDisplayFallback(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "busctl")
	err := exec.CommandContext(t.Context(), missing).Run()
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absolute executable error = %T %v", err, err)
	}
	if !lifecycleBusctlMissing(err) {
		t.Fatal("absolute ENOENT was not treated as a missing busctl")
	}
	if !lifecycleBusctlMissing(&exec.Error{Name: "busctl", Err: exec.ErrNotFound}) {
		t.Fatal("PATH lookup control was not treated as a missing busctl")
	}
	denied := &fs.PathError{Op: "fork/exec", Path: "/usr/bin/busctl", Err: fs.ErrPermission}
	if lifecycleBusctlMissing(denied) || lifecycleBusctlMissing(errors.New("busctl exit 1")) || lifecycleBusctlMissing(nil) {
		t.Fatal("a present busctl that failed was treated as missing")
	}

	unavailable := func(context.Context, string) ([]systemdBindEntry, []systemdBindEntry, error) {
		return nil, nil, errTypedBindsUnavailable
	}
	fields := map[string]string{"BindPaths": "/tmp/a:/tmp/a", "BindReadOnlyPaths": ""}
	if _, err := observeLifecycleBinds(t.Context(), lifecycleBackend{binds: unavailable}, "unit.service", fields); err == nil {
		t.Fatal("display form without norbind or rbind was accepted")
	}
	fields["BindPaths"] = "/tmp/a:/tmp/a:norbind"
	observed, err := observeLifecycleBinds(t.Context(), lifecycleBackend{binds: unavailable}, "unit.service", fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := matchTypedBindEntries(observed.BindPaths, []string{canonicalBind("/tmp/a", "/tmp/a", "norbind")}); err != nil {
		t.Fatal(err)
	}
}

func enforceShowLifecycle(t *testing.T, bindShow string) (*containRunLifecycle, map[string]string) {
	t.Helper()
	l, fields := lifecycleFixture()
	record := enforceLifecycleRecord(fields)
	record.Schema = 1
	record.FilesystemMode = config.ContainmentFilesystemModeEnforce
	record.FilesystemBindPaths = []string{canonicalBind("/tmp/cfs-r2-capture/plain", "/tmp/cfs-r2-capture/plain", "norbind")}
	l.record = record
	fields["BindPaths"] = bindShow
	return l, fields
}
