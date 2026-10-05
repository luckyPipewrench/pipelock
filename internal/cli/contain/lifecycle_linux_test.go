// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func lifecycleFixture() (*containRunLifecycle, map[string]string) {
	runID := strings.Repeat("a", 32)
	unit := "pipelock-contain-" + runID + ".service"
	l := &containRunLifecycle{record: containLifecycleRecord{Schema: 1, RunID: runID, Unit: unit}, save: func(containLifecycleRecord) error { return nil }, close: func() error { return nil }, argv: []string{defaultLaunchScript, "node", "driver.mjs"}}
	fields := map[string]string{
		"Id": unit, "LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "123",
		"Transient": "yes", "Description": lifecycleDescriptionPrefix + runID, "InvocationID": strings.Repeat("b", 32),
		"ControlGroup": "/system.slice/" + unit, "User": "966",
		"PrivateNetwork": "yes", "PrivateTmp": "yes", "JoinsNamespaceOf": containedNetworkNamespaceUnit,
		"KillMode": "control-group", "SendSIGKILL": "yes", "Restart": "no",
	}
	return l, fields
}

func bindLifecycleFixture(l *containRunLifecycle, fields map[string]string) {
	l.record.AdmissionObserved = true
	l.record.InvocationID, l.record.ControlGroup = fields["InvocationID"], fields["ControlGroup"]
}

func lifecycleTestBackend(fields map[string]string) lifecycleBackend {
	return lifecycleBackend{
		show:        func(context.Context, string) (map[string]string, error) { return fields, nil },
		action:      func(context.Context, string, ...string) error { return nil },
		cgroupEmpty: func(string) (bool, error) { return true, nil },
		wait:        func(context.Context, time.Duration) error { return errors.New("unexpected poll") }, now: time.Now,
		execStart: func(context.Context, string) ([]string, error) {
			return []string{defaultLaunchScript, "node", "driver.mjs"}, nil
		},
	}
}

func TestLifecycleOwnedRejectsAmbiguousIdentity(t *testing.T) {
	changes := map[string]string{
		"Id": "unrelated.service", "Transient": "no", "Description": "unrelated", "InvocationID": "", "ControlGroup": "/system.slice/unrelated.service", "User": "0",
		"PrivateNetwork": "no", "PrivateTmp": "no", "JoinsNamespaceOf": "unrelated.service",
		"KillMode": "process", "SendSIGKILL": "no", "Restart": "always",
	}
	for key, value := range changes {
		t.Run(key, func(t *testing.T) {
			l, fields := lifecycleFixture()
			if err := lifecycleOwned(fields, l.record, 966); err != nil {
				t.Fatalf("valid fixture: %v", err)
			}
			fields[key] = value
			if err := lifecycleOwned(fields, l.record, 966); err == nil {
				t.Fatal("accepted changed identity")
			}
		})
	}
	for _, value := range []string{"bad", strings.Repeat("0", 32), strings.Repeat("c", 32)} {
		l, fields := lifecycleFixture()
		bindLifecycleFixture(l, fields)
		fields["InvocationID"] = value
		if err := lifecycleOwned(fields, l.record, 966); err == nil {
			t.Fatalf("accepted invocation %q", value)
		}
	}
}

func TestLifecycleCleanupNeedsAdmission(t *testing.T) {
	l, fields := lifecycleFixture()
	b := lifecycleTestBackend(fields)
	b.action = func(context.Context, string, ...string) error { t.Fatal("acted without admission"); return nil }
	if err := stopLifecycleService(context.Background(), l, 966, b); err == nil {
		t.Fatal("accepted missing admission")
	}
}

func TestLifecycleCleanupStopsOnlyBoundService(t *testing.T) {
	l, fields := lifecycleFixture()
	bindLifecycleFixture(l, fields)
	b := lifecycleTestBackend(fields)
	var actions [][]string
	b.action = func(_ context.Context, unit string, args ...string) error {
		if unit != l.record.Unit {
			t.Fatal("wrong target")
		}
		actions = append(actions, args)
		fields["ActiveState"], fields["SubState"], fields["MainPID"] = "inactive", "dead", "0"
		fields["InvocationID"], fields["ControlGroup"] = "", ""
		return nil
	}
	b.wait = func(context.Context, time.Duration) error { return nil }
	if err := stopLifecycleService(context.Background(), l, 966, b); err != nil {
		t.Fatal(err)
	}
	if len(actions) != 1 || strings.Join(actions[0], " ") != "--no-block stop" || !l.record.CleanupComplete || !l.record.CgroupEmpty {
		t.Fatalf("cleanup = %+v; actions=%v", l.record, actions)
	}
	if _, ok := l.record.Terminal["ExecStart"]; ok {
		t.Fatal("persisted raw child arguments")
	}
}

func TestLifecycleCleanupAcceptsGoneOnlyWithEmptyBoundCgroup(t *testing.T) {
	for _, empty := range []bool{false, true} {
		l, fields := lifecycleFixture()
		bindLifecycleFixture(l, fields)
		b := lifecycleTestBackend(map[string]string{"Id": l.record.Unit, "LoadState": "not-found"})
		b.cgroupEmpty = func(group string) (bool, error) {
			if group != l.record.ControlGroup {
				t.Fatal("wrong cgroup")
			}
			return empty, nil
		}
		b.action = func(context.Context, string, ...string) error { t.Fatal("acted on gone unit"); return nil }
		err := stopLifecycleService(context.Background(), l, 966, b)
		if (err == nil) != empty || l.record.CleanupComplete != empty {
			t.Fatalf("empty=%v err=%v record=%+v", empty, err, l.record)
		}
	}
}

func TestLifecycleCleanupRejectsChangedInvocationWithoutAction(t *testing.T) {
	l, fields := lifecycleFixture()
	bindLifecycleFixture(l, fields)
	fields["InvocationID"] = strings.Repeat("c", 32)
	b := lifecycleTestBackend(fields)
	b.action = func(context.Context, string, ...string) error { t.Fatal("acted on unrelated invocation"); return nil }
	if err := stopLifecycleService(context.Background(), l, 966, b); err == nil {
		t.Fatal("accepted different invocation")
	}
}

func TestLifecycleCleanupEscalatesAndRechecksOwnership(t *testing.T) {
	l, fields := lifecycleFixture()
	bindLifecycleFixture(l, fields)
	b := lifecycleTestBackend(fields)
	clock := time.Unix(1, 0)
	b.now = func() time.Time { return clock }
	b.wait = func(context.Context, time.Duration) error { clock = clock.Add(4 * time.Second); return nil }
	var actions int
	b.action = func(_ context.Context, unit string, args ...string) error {
		if unit != l.record.Unit {
			t.Fatal("wrong unit")
		}
		actions++
		if actions == 2 {
			if strings.Join(args, " ") != "kill --kill-whom=all --signal=KILL" {
				t.Fatal(args)
			}
			fields["ActiveState"], fields["MainPID"] = "inactive", "0"
		}
		return nil
	}
	if err := stopLifecycleService(context.Background(), l, 966, b); err != nil {
		t.Fatal(err)
	}
	if !l.record.StopRequested || !l.record.KillRequested || !l.record.CleanupComplete {
		t.Fatalf("record=%+v", l.record)
	}
}

func TestLifecycleCleanupErrorsNeverPass(t *testing.T) {
	for _, name := range []string{"show", "cgroup", "stop", "wait", "cancelled", "terminal-owner"} {
		t.Run(name, func(t *testing.T) {
			l, fields := lifecycleFixture()
			bindLifecycleFixture(l, fields)
			b := lifecycleTestBackend(fields)
			ctx := context.Background()
			switch name {
			case "show":
				b.show = func(context.Context, string) (map[string]string, error) { return nil, errors.New("show failed") }
			case "cgroup":
				b.cgroupEmpty = func(string) (bool, error) { return false, errors.New("unreadable") }
			case "stop":
				b.action = func(context.Context, string, ...string) error { return errors.New("stop failed") }
			case "wait": // default wait refuses
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "terminal-owner":
				fields["ActiveState"], fields["MainPID"], fields["Description"] = "inactive", "0", "other"
			}
			if err := stopLifecycleService(ctx, l, 966, b); err == nil || l.record.CleanupComplete {
				t.Fatalf("err=%v record=%+v", err, l.record)
			}
		})
	}
}

func TestLifecycleSupervisionPersistsSuccessfulTerminalWitness(t *testing.T) {
	l, fields := lifecycleFixture()
	b := lifecycleTestBackend(fields)
	var records []containLifecycleRecord
	l.save = func(r containLifecycleRecord) error { records = append(records, r); return nil }
	showCount := 0
	b.show = func(context.Context, string) (map[string]string, error) {
		showCount++
		if showCount > 2 {
			fields["ActiveState"], fields["MainPID"] = "inactive", "0"
		}
		return fields, nil
	}
	done := make(chan error, 1)
	done <- nil
	cancelled := false
	if err := superviseLifecycleService(context.Background(), done, func() { cancelled = true }, l, 966, b); err != nil {
		t.Fatal(err)
	}
	if !cancelled || len(records) != 2 || records[0].Phase != "admitted" || records[1].Phase != "complete" || !records[1].Final || !records[1].CleanupComplete {
		t.Fatalf("records=%+v cancelled=%v", records, cancelled)
	}
}

func TestLifecycleSupervisionCancellationStillCleansBoundService(t *testing.T) {
	l, fields := lifecycleFixture()
	b := lifecycleTestBackend(fields)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	b.show = func(ctx context.Context, _ string) (map[string]string, error) {
		if ctx.Err() != nil {
			t.Fatal("cleanup/admission inherited cancellation")
		}
		return fields, nil
	}
	b.action = func(context.Context, string, ...string) error {
		fields["ActiveState"], fields["MainPID"] = "inactive", "0"
		return nil
	}
	b.wait = func(context.Context, time.Duration) error { return nil }
	done := make(chan error, 1)
	err := superviseLifecycleService(ctx, done, func() { done <- nil }, l, 966, b)
	if err == nil || !l.record.Cancelled || !l.record.CleanupComplete || l.record.Phase != "incomplete" {
		t.Fatalf("err=%v record=%+v", err, l.record)
	}
}

func TestLifecycleSupervisionMissingAdmissionRefusesCleanup(t *testing.T) {
	l, _ := lifecycleFixture()
	b := lifecycleTestBackend(map[string]string{"Id": l.record.Unit, "LoadState": "not-found"})
	b.action = func(context.Context, string, ...string) error { t.Fatal("acted without ownership"); return nil }
	done := make(chan error, 1)
	done <- nil
	if err := superviseLifecycleService(context.Background(), done, func() {}, l, 966, b); err == nil || l.record.CleanupComplete || !l.record.Final {
		t.Fatalf("err=%v record=%+v", err, l.record)
	}
}

func TestLifecycleSupervisionReportFailureStillCleans(t *testing.T) {
	l, fields := lifecycleFixture()
	b := lifecycleTestBackend(fields)
	l.save = func(containLifecycleRecord) error { return errors.New("closed report") }
	b.action = func(context.Context, string, ...string) error {
		fields["ActiveState"], fields["MainPID"] = "inactive", "0"
		return nil
	}
	b.wait = func(context.Context, time.Duration) error { return nil }
	done := make(chan error, 1)
	done <- nil
	if err := superviseLifecycleService(context.Background(), done, func() {}, l, 966, b); err == nil || !l.record.CleanupComplete {
		t.Fatalf("err=%v record=%+v", err, l.record)
	}
}

func TestLifecycleOutputDirectoryAndAtomicRecords(t *testing.T) {
	parent := lifecycleTestParent(t)
	path := filepath.Join(parent, "receipt")
	dir, err := openLifecycleDirectory(path, lifecycleTestOwner(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	l, _ := lifecycleFixture()
	if err := writeLifecycleRecord(dir, l.record); err != nil {
		t.Fatal(err)
	}
	l.record.Phase = "complete"
	if err := writeLifecycleRecord(dir, l.record); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Clean(filepath.Join(path, lifecycleFilename)))
	if err != nil {
		t.Fatal(err)
	}
	var got containLifecycleRecord
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got.Phase != "complete" {
		t.Fatal(got)
	}
	info, err := os.Stat(filepath.Join(path, lifecycleFilename))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("info=%v err=%v", info, err)
	}
	if _, err := openLifecycleDirectory(path, lifecycleTestOwner(t)); err == nil {
		t.Fatal("reused existing output")
	}
}

func TestLifecycleOutputRejectsSymlinksAndUnsafeAncestors(t *testing.T) {
	parent := lifecycleTestParent(t)
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	control, err := openLifecycleDirectory(filepath.Join(target, "control"), lifecycleTestOwner(t))
	if err != nil {
		t.Fatalf("valid ancestor control: %v", err)
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"relative", "/", filepath.Join(parent, "missing", "child"), filepath.Join(link, "child"), parent + "/../child"} {
		if dir, err := openLifecycleDirectory(path, lifecycleTestOwner(t)); err == nil {
			_ = dir.Close()
			t.Fatalf("accepted %s", path)
		}
	}
	if err := os.Chmod(target, 0o777); err != nil { //nolint:gosec // G302: deliberate unsafe mode in an owned synthetic rejection fixture.
		t.Fatal(err)
	}
	if dir, err := openLifecycleDirectory(filepath.Join(target, "child"), lifecycleTestOwner(t)); err == nil {
		_ = dir.Close()
		t.Fatal("accepted writable ancestor")
	}
}

func TestLifecycleRecordCannotFollowTemporarySymlink(t *testing.T) {
	parent := lifecycleTestParent(t)
	dir, err := openLifecycleDirectory(filepath.Join(parent, "receipt"), lifecycleTestOwner(t))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dir.Close() }()
	target := filepath.Join(parent, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir.Name(), ".lifecycle-next")); err != nil {
		t.Fatal(err)
	}
	l, _ := lifecycleFixture()
	if err := writeLifecycleRecord(dir, l.record); err == nil {
		t.Fatal("followed temporary symlink")
	}
	body, err := os.ReadFile(filepath.Clean(target))
	if err != nil || string(body) != "unchanged" {
		t.Fatalf("body=%q err=%v", body, err)
	}
}

func TestLifecycleCommandPropertiesAreOptIn(t *testing.T) {
	opts := containedAgentCommandOptions{ctx: context.Background(), uid: 966, gid: 966, homeDir: "/home/pipelock-agent", args: []string{"node", "driver.mjs"}}
	plain, _ := containedAgentCommand(opts)
	if strings.Contains(strings.Join(plain.Args, " "), lifecycleDescriptionPrefix) {
		t.Fatal("changed default command")
	}
	l, _ := lifecycleFixture()
	opts.lifecycleUnit, opts.lifecycleRunID = l.record.Unit, l.record.RunID
	cmd, unit := containedAgentCommand(opts)
	joined := strings.Join(cmd.Args, " ")
	for _, want := range []string{"--unit=" + l.record.Unit, "--description=" + lifecycleDescriptionPrefix + l.record.RunID, "--property=KillMode=control-group", "--property=SendSIGKILL=yes", "--property=TimeoutStopSec=5s", "--property=Restart=no"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if unit != l.record.Unit {
		t.Fatal(unit)
	}
}

func TestLifecycleCgroupEvidenceIsBoundedAndUnambiguous(t *testing.T) {
	for _, tt := range []struct {
		body  string
		empty bool
		valid bool
	}{
		{"populated 0\nfrozen 0\n", true, true}, {"populated 1\n", false, true}, {"", false, false}, {"populated 2\n", false, false}, {"populated 0\npopulated 1\n", false, false}, {strings.Repeat("x", 4097), false, false},
	} {
		empty, err := parseLifecycleCgroupEvents([]byte(tt.body))
		if (err == nil) != tt.valid || empty != tt.empty {
			t.Fatalf("body=%q empty=%v err=%v", tt.body, empty, err)
		}
	}
	for _, path := range []string{"/", "/system.slice/unrelated.service", "/system.slice/pipelock-contain-x/child", "/system.slice/../pipelock-contain-x"} {
		if _, err := lifecycleCgroupEmpty(path); err == nil {
			t.Fatalf("accepted %q", path)
		}
	}
}

func TestLifecycleOutputRejectsNonRootInProduction(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("non-root guard")
	}
	if _, err := newContainRunLifecycle(filepath.Join(lifecycleTestParent(t), "new")); err == nil {
		t.Fatal("non-root lifecycle output accepted")
	}
}

func TestLifecycleErrorIsBounded(t *testing.T) {
	if got := boundedLifecycleError(errors.New(strings.Repeat("x", 2000))); len(got) != 1024 {
		t.Fatal(len(got))
	}
	if boundedLifecycleError(nil) == "" {
		t.Fatal("empty incomplete explanation")
	}
}

func TestLifecycleTypedArgvPreservesArgumentBoundaries(t *testing.T) {
	argv := []string{defaultLaunchScript, "node", "path with spaces", "a\nb", "\\\"<>&", "\u2028"}
	row := []any{defaultLaunchScript, argv, false, 0, 0, 0, 0, 0, 0, 0}
	body, err := json.Marshal(map[string]any{"type": "a(sasbttttuii)", "data": [][]any{row}})
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseLifecycleExecStart(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(argv) {
		t.Fatal(got)
	}
	for i := range got {
		if got[i] != argv[i] {
			t.Fatalf("argument %d changed", i)
		}
	}
	l, _ := lifecycleFixture()
	l.argv = argv
	b := lifecycleTestBackend(nil)
	b.execStart = func(context.Context, string) ([]string, error) { return got, nil }
	if err := verifyLifecycleArgv(context.Background(), b, l); err != nil {
		t.Fatal(err)
	}
	l.argv = append(l.argv, "extra")
	if err := verifyLifecycleArgv(context.Background(), b, l); err == nil {
		t.Fatal("accepted different argv")
	}
}

func TestLifecycleTypedArgvRejectsMalformedPayload(t *testing.T) {
	for _, body := range []string{
		`not json`, `{"type":"as","data":[]}`, `{"type":"a(sasbttttuii)","data":[]}`, `{"type":"a(sasbttttuii)","data":[[]]}`,
		`{"type":"a(sasbttttuii)","data":[["/usr/bin/true",["/usr/local/bin/plk-launch"],false,0,0,0,0,0,0,0]]}`,
		`{"type":"a(sasbttttuii)","data":[["/usr/local/bin/plk-launch",["/usr/bin/true"],false,0,0,0,0,0,0,0]]}`,
		`{"type":"a(sasbttttuii)","data":[["/usr/local/bin/plk-launch",["/usr/local/bin/plk-launch"],true,0,0,0,0,0,0,0]]}`,
		`{"type":"a(sasbttttuii)","data":[[12,[],false,0,0,0,0,0,0,0]]}`,
		`{"type":"a(sasbttttuii)","type":"a(sasbttttuii)","data":[]}`,
		`{"type":"a(sasbttttuii)","data":[["/usr/local/bin/plk-launch",["/usr/local/bin/plk-launch"],null,0,0,0,0,0,0,0]]}`, strings.Repeat("x", maxCmdOutputBytes+1),
	} {
		if _, err := parseLifecycleExecStart([]byte(body)); err == nil {
			t.Fatalf("accepted %q", body)
		}
	}
	l, _ := lifecycleFixture()
	if err := verifyLifecycleArgv(context.Background(), lifecycleBackend{}, l); err == nil {
		t.Fatal("accepted missing typed reader")
	}
	b := lifecycleTestBackend(nil)
	b.execStart = func(context.Context, string) ([]string, error) { return nil, errors.New("unavailable") }
	if err := verifyLifecycleArgv(context.Background(), b, l); err == nil {
		t.Fatal("accepted failed typed read")
	}
}

func TestLifecycleCancellationDominatesSuccessfulClientAndCleanup(t *testing.T) {
	for _, duringCleanup := range []bool{false, true} {
		l, fields := lifecycleFixture()
		b := lifecycleTestBackend(fields)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if !duringCleanup {
			cancel()
		}
		b.action = func(context.Context, string, ...string) error {
			cancel()
			fields["ActiveState"], fields["MainPID"] = "inactive", "0"
			return nil
		}
		b.wait = func(context.Context, time.Duration) error { return nil }
		done := make(chan error, 1)
		done <- nil
		err := superviseLifecycleService(ctx, done, func() {}, l, 966, b)
		if !errors.Is(err, context.Canceled) || !l.record.Cancelled || l.record.Phase != "incomplete" || !l.record.CleanupComplete {
			t.Fatalf("duringCleanup=%v err=%v record=%+v", duringCleanup, err, l.record)
		}
	}
}

func TestTransientTypedBindReadStillStopsOwnedService(t *testing.T) {
	entries := func(t *testing.T, l *containRunLifecycle) []systemdBindEntry {
		t.Helper()
		got, err := entriesFromCanonicalBinds(l.record.FilesystemBindPaths)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	supervise := func(t *testing.T, stage string) (reads, actions int, active string, l *containRunLifecycle, err error) {
		t.Helper()
		l, fields := enforceShowLifecycle(t, "/tmp/cfs-r2-capture/plain:/tmp/cfs-r2-capture/plain:norbind")
		valid := entries(t, l)
		b := lifecycleTestBackend(fields)
		b.cgroupEmpty = func(string) (bool, error) { return fields["ActiveState"] == "inactive", nil }
		b.action = func(context.Context, string, ...string) error {
			actions++
			fields["ActiveState"], fields["MainPID"] = "inactive", "0"
			return nil
		}
		waits := 0
		b.wait = func(context.Context, time.Duration) error {
			waits++
			if stage == "admission-persistent" || (stage == "cleanup-persistent" && waits <= 2) || stage == "identity" {
				return errors.New("no further poll")
			}
			return nil
		}
		b.binds = func(context.Context, string) ([]systemdBindEntry, []systemdBindEntry, error) {
			reads++
			switch stage {
			case "admission":
				if reads == 1 {
					return nil, nil, errors.New("one transient typed-read transport failure")
				}
			case "cleanup":
				if reads == 3 {
					return nil, nil, errors.New("one transient typed-read transport failure")
				}
			case "admission-persistent":
				return nil, nil, errors.New("typed read still down")
			case "cleanup-persistent":
				if reads > 2 {
					return nil, nil, errors.New("typed read still down")
				}
			case "identity":
				if reads > 2 {
					fields["User"] = "0"
				}
			case "mismatch":
				if reads > 2 {
					return nil, nil, nil
				}
			}
			return valid, nil, nil
		}
		done := make(chan error, 1)
		done <- nil
		err = superviseLifecycleService(context.Background(), done, func() {}, l, 966, b)
		return reads, actions, fields["ActiveState"], l, err
	}

	t.Run("admission retries then stops", func(t *testing.T) {
		reads, actions, active, l, err := supervise(t, "admission")
		if err != nil || actions != 1 || active != "inactive" || !l.record.AdmissionObserved || !l.record.CleanupComplete || reads < 2 {
			t.Fatalf("reads=%d actions=%d active=%s admitted=%v cleanup=%v err=%v", reads, actions, active, l.record.AdmissionObserved, l.record.CleanupComplete, err)
		}
	})
	t.Run("cleanup retries then stops", func(t *testing.T) {
		reads, actions, active, l, err := supervise(t, "cleanup")
		if err != nil || actions != 1 || active != "inactive" || !l.record.AdmissionObserved || !l.record.CleanupComplete || reads < 4 {
			t.Fatalf("reads=%d actions=%d active=%s admitted=%v cleanup=%v err=%v", reads, actions, active, l.record.AdmissionObserved, l.record.CleanupComplete, err)
		}
	})
	t.Run("unobserved admission is not stopped", func(t *testing.T) {
		reads, actions, active, l, err := supervise(t, "admission-persistent")
		if err == nil || actions != 0 || active != "active" || l.record.AdmissionObserved || l.record.CleanupComplete || reads != 1 {
			t.Fatalf("reads=%d actions=%d active=%s admitted=%v cleanup=%v err=%v", reads, actions, active, l.record.AdmissionObserved, l.record.CleanupComplete, err)
		}
	})
	t.Run("owned service stops when the typed read keeps failing", func(t *testing.T) {
		reads, actions, active, l, err := supervise(t, "cleanup-persistent")
		if err != nil || actions != 1 || active != "inactive" || !l.record.AdmissionObserved || !l.record.CleanupComplete {
			t.Fatalf("reads=%d actions=%d active=%s admitted=%v cleanup=%v err=%v", reads, actions, active, l.record.AdmissionObserved, l.record.CleanupComplete, err)
		}
	})
	t.Run("changed identity is not stopped", func(t *testing.T) {
		_, actions, active, l, err := supervise(t, "identity")
		if err == nil || actions != 0 || active != "active" || !l.record.AdmissionObserved || l.record.CleanupComplete {
			t.Fatalf("actions=%d active=%s admitted=%v cleanup=%v err=%v", actions, active, l.record.AdmissionObserved, l.record.CleanupComplete, err)
		}
	})
	t.Run("bind mismatch is not stopped", func(t *testing.T) {
		_, actions, active, l, err := supervise(t, "mismatch")
		if err == nil || actions != 0 || active != "active" || !l.record.AdmissionObserved || l.record.CleanupComplete {
			t.Fatalf("actions=%d active=%s admitted=%v cleanup=%v err=%v", actions, active, l.record.AdmissionObserved, l.record.CleanupComplete, err)
		}
	})
}

func lifecycleTestParent(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// TempDir's numbered child uses 0777 before umask, which can leave it
	// group-writable. Secure only this test-owned lifecycle output parent.
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: owner-only directory requires the execute bit for traversal.
		t.Fatal(err)
	}
	return dir
}

func lifecycleTestOwner(t *testing.T) uint32 {
	t.Helper()
	uid, err := strconv.ParseUint(strconv.Itoa(os.Geteuid()), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	return uint32(uid)
}

func TestLifecyclePendingAdmissionDoesNotGrantOwnership(t *testing.T) {
	l, fields := lifecycleFixture()
	if lifecycleAdmissionPending(fields, l.record) {
		t.Fatal("fully observed identity should not be pending")
	}
	fields["ActiveState"], fields["InvocationID"], fields["ControlGroup"] = "activating", "", ""
	if !lifecycleAdmissionPending(fields, l.record) {
		t.Fatal("reserved service should await runtime identity")
	}
	if err := lifecycleOwned(fields, l.record, 966); err == nil {
		t.Fatal("pending service must not authorize cleanup")
	}
	fields["Description"] = "other"
	if lifecycleAdmissionPending(fields, l.record) {
		t.Fatal("unrelated service should not be pending")
	}
}

func TestLifecycleTypedArgvRejectsTrailingValuesAndCaseAliases(t *testing.T) {
	valid := `{"type":"a(sasbttttuii)","data":[["/usr/local/bin/plk-launch",["/usr/local/bin/plk-launch","node"],false,0,0,0,0,0,0,0]]}`
	if _, err := parseLifecycleExecStart([]byte(valid)); err != nil {
		t.Fatalf("valid control refused: %v", err)
	}
	for name, body := range map[string]string{
		"second object":    valid + `{}`,
		"second scalar":    valid + `true`,
		"Type replacement": strings.Replace(valid, `"type":`, `"Type":`, 1),
		"Data replacement": strings.Replace(valid, `"data":`, `"Data":`, 1),
		"type and Type":    strings.Replace(valid, `"type":`, `"Type":"a(sasbttttuii)","type":`, 1),
		"data and Data":    strings.Replace(valid, `"data":`, `"Data":[],"data":`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseLifecycleExecStart([]byte(body)); err == nil {
				t.Fatal("accepted noncanonical observation")
			}
		})
	}
}
