// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestLifecycleTypedBindReaderReportsManagerFailure(t *testing.T) {
	if !lifecycleBusctlMissing(&exec.Error{Name: "/usr/bin/busctl", Err: exec.ErrNotFound}) {
		t.Fatal("a missing busctl was treated as a manager error")
	}
	if !lifecycleBusctlMissing(os.ErrNotExist) {
		t.Fatal("ENOENT was treated as a manager error")
	}
	if lifecycleBusctlMissing(errors.New("busctl exit 1")) || lifecycleBusctlMissing(nil) {
		t.Fatal("an ordinary manager error was treated as a missing reader")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := lifecycleSystemdBinds(ctx, "pipelock-no-such-unit.service")
	if err == nil {
		t.Fatal("cancelled bind read returned binds")
	}

	live, liveCancel := context.WithTimeout(context.Background(), testwait.Deadline(3*time.Second))
	defer liveCancel()
	binds, readOnly, err := lifecycleSystemdBinds(live, "pipelock-no-such-unit.service")
	if err != nil {
		if !strings.Contains(err.Error(), "busctl") && !strings.Contains(err.Error(), "bind") {
			t.Fatalf("manager err = %v", err)
		}
		return
	}
	if len(binds) != 0 || len(readOnly) != 0 {
		t.Fatalf("missing unit returned binds %v %v", binds, readOnly)
	}
}

func TestObserveLifecycleBindsRejectsDisplayFallback(t *testing.T) {
	ctx := context.Background()
	backend := lifecycleBackend{}
	_, err := observeLifecycleBinds(ctx, backend, "unit.service", map[string]string{
		"BindPaths":         "/srv/agent:/srv/agent:norbind",
		"BindReadOnlyPaths": `"unterminated`,
	})
	if err == nil || !strings.Contains(err.Error(), "read-only bind paths") {
		t.Fatalf("read-only = %v", err)
	}
	_, err = observeLifecycleBinds(ctx, backend, "unit.service", map[string]string{
		"BindPaths":         "/srv/agent",
		"BindReadOnlyPaths": "/tmp/.X11-unix/X0:/tmp/.X11-unix/X0:rbind",
	})
	if err == nil || !strings.Contains(err.Error(), "lifecycle bind paths") {
		t.Fatalf("bind = %v", err)
	}
	_, err = observeLifecycleBinds(ctx, backend, "unit.service", map[string]string{
		"BindPaths":         "/srv/agent:/srv/agent:norbind",
		"BindReadOnlyPaths": "/tmp/.X11-unix/X0",
	})
	if err == nil || !strings.Contains(err.Error(), "read-only bind paths") {
		t.Fatalf("read-only canonical = %v", err)
	}
}

func TestEntriesFromCanonicalBindsAcceptsRbindAndRejectsTheRest(t *testing.T) {
	got, err := entriesFromCanonicalBinds([]string{"/tmp/.X11-unix/X0:/tmp/.X11-unix/X0:rbind"})
	if err != nil || len(got) != 1 || got[0].Flags != systemdBindRecursiveFlag {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if _, err := entriesFromCanonicalBinds([]string{"nosep"}); err == nil {
		t.Fatal("accepted a bind without separators")
	}
	if _, err := entriesFromCanonicalBinds([]string{"/src:/src:maybe"}); err == nil || !strings.Contains(err.Error(), "maybe") {
		t.Fatalf("option = %v", err)
	}
}

func TestLifecycleFilesystemMatchRejectsAMissingObservation(t *testing.T) {
	l, _ := lifecycleFixture()
	l.record.FilesystemMode = config.ContainmentFilesystemModeEnforce
	l.record.FilesystemBindReadOnlyPaths = []string{"/tmp/.X11-unix/X0:/tmp/.X11-unix/X0:rbind"}
	if err := lifecycleFilesystemBindsMatch(nil, l.record); err == nil || !strings.Contains(err.Error(), "not observed") {
		t.Fatalf("nil = %v", err)
	}
	observed := &lifecycleBindObservation{ReadOnly: []systemdBindEntry{{Source: "/other", Destination: "/other"}}}
	if err := lifecycleFilesystemBindsMatch(observed, l.record); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("mismatch = %v", err)
	}
	if err := confirmLifecycleFilesystem(context.Background(), lifecycleBackend{}, map[string]string{}, containLifecycleRecord{}); err != nil {
		t.Fatal(err)
	}
}

func TestLifecycleFilesystemOwnedUsesDisplayTextWhenBindsAreAbsent(t *testing.T) {
	l, fields := lifecycleFixture()
	if err := lifecycleFilesystemOwned(fields, l.record, nil); err != nil {
		t.Fatal(err)
	}
	l.record.FilesystemMode = config.ContainmentFilesystemModeEnforce
	l.record.FilesystemBindPaths = []string{"/srv/agent:/srv/agent:norbind"}
	l.record.FilesystemBindReadOnlyPaths = []string{"/tmp/.X11-unix/X0:/tmp/.X11-unix/X0:rbind"}
	l.record.FilesystemTemporaryFileSystem = "/dev/shm"
	l.record.FilesystemProtectKernelTunables = "yes"
	l.record.FilesystemProtectKernelModules = "yes"
	l.record.FilesystemProtectControlGroups = "yes"
	fields["ProtectSystem"] = "strict"
	fields["ProtectHome"] = "tmpfs"
	fields["NoNewPrivileges"] = "yes"
	fields["BindPaths"] = `"unterminated`
	if err := lifecycleFilesystemOwned(fields, l.record, nil); err == nil || !strings.Contains(err.Error(), "bind paths") {
		t.Fatalf("bind = %v", err)
	}
	fields["BindPaths"] = "/srv/agent:/srv/agent:norbind"
	fields["BindReadOnlyPaths"] = `"unterminated`
	if err := lifecycleFilesystemOwned(fields, l.record, nil); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("read-only parse = %v", err)
	}
	fields["BindReadOnlyPaths"] = "/tmp/.X11-unix/X1:/tmp/.X11-unix/X1:rbind"
	fields["InaccessiblePaths"] = "/etc/pipelock/tls"
	fields["TemporaryFileSystem"] = "/dev/shm"
	fields["ProtectKernelTunables"] = "yes"
	fields["ProtectKernelModules"] = "yes"
	fields["ProtectControlGroups"] = "yes"
	if err := lifecycleFilesystemOwned(fields, l.record, nil); err == nil || !strings.Contains(err.Error(), "read-only bind paths differ") {
		t.Fatalf("differ = %v", err)
	}
}

func TestLifecyclePathListsAndShowYes(t *testing.T) {
	if lifecyclePathSingleton(" ") != nil {
		t.Fatal("blank path became a list")
	}
	if err := sameLifecyclePathList(`"unterminated`, []string{"/etc/pipelock/tls"}); err == nil {
		t.Fatal("accepted an unbalanced path list")
	}
	if parsed, err := parseSystemdPathList("  "); err != nil || parsed != nil {
		t.Fatalf("blank = %v %v", parsed, err)
	}
	if _, err := parseSystemdPathList(`"unterminated`); err == nil {
		t.Fatal("accepted an unbalanced path list")
	}
	parsed, err := parseSystemdPathList(`"/etc/pipe lock" /var/lib/pipelock`)
	if err != nil || len(parsed) != 2 || parsed[0] != "/etc/pipe lock" {
		t.Fatalf("parsed = %v %v", parsed, err)
	}
	if samePathSet([]string{"/a"}, []string{"/a", "/b"}) {
		t.Fatal("different lengths compared equal")
	}
	if systemdShowYes("yes", " ") || !systemdShowYes("true", "yes") {
		t.Fatal("systemd yes comparison drifted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if lifecycleObservationRetryable(ctx, 0) {
		t.Fatal("cancelled context was retryable")
	}
	if lifecycleObservationRetryable(context.Background(), 0) {
		t.Fatal("context without a deadline was retryable")
	}
}

func TestRetryLifecycleTypedObservationStopsWhenNothingWaits(t *testing.T) {
	err := retryLifecycleTypedObservation(context.Background(), lifecycleBackend{}, 0, func() error {
		return errLifecycleTypedObservation
	})
	if !errors.Is(err, errLifecycleTypedObservation) {
		t.Fatalf("err = %v", err)
	}
}

func TestRetryLifecycleTypedObservationStopsOnWaitAndInstantPolls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), testwait.Deadline(2*time.Second))
	defer cancel()
	reads := 0
	err := retryLifecycleTypedObservation(ctx, lifecycleBackend{wait: func(context.Context, time.Duration) error {
		return errors.New("wait failed")
	}}, 0, func() error {
		reads++
		return errLifecycleTypedObservation
	})
	if !errors.Is(err, errLifecycleTypedObservation) || reads != 1 {
		t.Fatalf("wait err=%v reads=%d", err, reads)
	}

	reads = 0
	err = retryLifecycleTypedObservation(ctx, lifecycleBackend{wait: func(context.Context, time.Duration) error {
		return nil
	}}, 0, func() error {
		reads++
		return errLifecycleTypedObservation
	})
	if !errors.Is(err, errLifecycleTypedObservation) || reads != lifecycleTypedRetryInstantCap {
		t.Fatalf("instant err=%v reads=%d", err, reads)
	}
}

func TestLifecycleFilesystemAdmissionStopsOnIdentityChanges(t *testing.T) {
	l, fields := lifecycleFixture()
	bindLifecycleFixture(l, fields)
	l.record.FilesystemMode = config.ContainmentFilesystemModeEnforce
	ctx := context.Background()

	err := lifecycleFilesystemAdmission(ctx, lifecycleBackend{show: func(context.Context, string) (map[string]string, error) {
		return nil, errors.New("show failed")
	}}, l, 966)
	if err == nil || !strings.Contains(err.Error(), "show failed") {
		t.Fatalf("show = %v", err)
	}

	changed := map[string]string{"InvocationID": strings.Repeat("c", 32)}
	err = lifecycleFilesystemAdmission(ctx, lifecycleBackend{show: func(context.Context, string) (map[string]string, error) {
		return changed, nil
	}}, l, 966)
	if !errors.Is(err, errLifecycleInvocationChanged) {
		t.Fatalf("changed = %v", err)
	}

	err = lifecycleFilesystemAdmission(ctx, lifecycleBackend{show: func(context.Context, string) (map[string]string, error) {
		bad := map[string]string{}
		for k, v := range fields {
			bad[k] = v
		}
		bad["User"] = "0"
		return bad, nil
	}}, l, 966)
	if err == nil || !strings.Contains(err.Error(), "user") {
		t.Fatalf("identity = %v", err)
	}

	l.record.FilesystemProtectKernelTunables = "yes"
	l.record.FilesystemProtectKernelModules = "yes"
	l.record.FilesystemProtectControlGroups = "yes"
	ready := map[string]string{}
	for k, v := range fields {
		ready[k] = v
	}
	ready["ProtectSystem"] = "strict"
	ready["ProtectHome"] = "tmpfs"
	ready["NoNewPrivileges"] = "yes"
	ready["ProtectKernelTunables"] = "yes"
	ready["ProtectKernelModules"] = "yes"
	ready["ProtectControlGroups"] = "yes"
	calls := 0
	err = lifecycleFilesystemAdmission(ctx, lifecycleBackend{show: func(context.Context, string) (map[string]string, error) {
		calls++
		if calls == 1 {
			return ready, nil
		}
		return nil, errors.New("second show failed")
	}, binds: func(context.Context, string) ([]systemdBindEntry, []systemdBindEntry, error) {
		return nil, nil, nil
	}}, l, 966)
	if err == nil || !strings.Contains(err.Error(), "second show failed") {
		t.Fatalf("second = %v calls=%d", err, calls)
	}
}

func TestLaunchRecordsFilesystemProfileBeforeTheClientStarts(t *testing.T) {
	l, fields := lifecycleFixture()
	fields["LoadState"] = "not-found"
	backend := lifecycleTestBackend(fields)
	opts := containedAgentCommandOptions{
		ctx:  context.Background(),
		args: []string{"claude"},
		uid:  966,
		filesystem: filesystemProfile{
			Mode:              config.ContainmentFilesystemModeEnforce,
			BindPaths:         []string{"/srv/agent-home:/srv/agent-home:norbind"},
			BindReadOnlyPaths: []string{"/tmp/.X11-unix/X0:/tmp/.X11-unix/X0:rbind"},
			Properties:        []string{"InaccessiblePaths=/etc/pipelock/tls"},
		},
	}
	err := launchContainedAgentLifecycleWithBackend(opts, l, backend, func(containedAgentCommandOptions) (*exec.Cmd, string) {
		return exec.Command("/no/such/pipelock-launch-helper"), ""
	})
	if err == nil {
		t.Fatal("missing helper started")
	}
	if l.record.FilesystemMode != config.ContainmentFilesystemModeEnforce ||
		len(l.record.FilesystemBindPaths) != 1 ||
		l.record.FilesystemTemporaryFileSystem != "/dev/shm" ||
		l.record.FilesystemProtectKernelTunables != "yes" ||
		!strings.Contains(strings.Join(l.record.FilesystemInaccessiblePaths, ","), "/etc/pipelock/tls") {
		t.Fatalf("record = %+v", l.record)
	}
}
