// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
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
			t.Fatal("stopped a service whose binds were not typed")
			return nil
		}
		done := make(chan error, 1)
		done <- nil
		err := superviseLifecycleService(context.Background(), done, func() {}, l, 966, b)
		if err == nil || l.record.AdmissionObserved || l.record.CleanupComplete {
			t.Fatalf("err=%v admitted=%v cleanup=%v", err, l.record.AdmissionObserved, l.record.CleanupComplete)
		}
	})
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
