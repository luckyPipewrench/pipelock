// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestLifecycleInitializationPublishesFreshReservedIdentity(t *testing.T) {
	seen := make(map[string]bool)
	for range 2 {
		dir, err := openLifecycleDirectory(filepath.Join(lifecycleTestParent(t), "receipt"), lifecycleTestOwner(t))
		if err != nil {
			t.Fatal(err)
		}
		l, err := initializeContainRunLifecycle(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = l.close() })
		body, err := os.ReadFile(filepath.Join(dir.Name(), lifecycleFilename))
		if err != nil {
			t.Fatal(err)
		}
		var got containLifecycleRecord
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		nonce, err := hex.DecodeString(got.RunID)
		if err != nil || len(nonce) != 16 || seen[got.RunID] || got.RunID != l.record.RunID || got.Unit != "pipelock-contain-"+got.RunID+".service" {
			t.Fatalf("identity is not fresh or correctly bound: %+v, %v", got, err)
		}
		seen[got.RunID] = true
		if got.Schema != 1 || got.Phase != "reserved" || got.Final || got.AdmissionObserved || got.ArgvObserved || got.CleanupComplete || got.InvocationID != "" || got.ControlGroup != "" {
			t.Fatalf("reservation claimed execution or cleanup: %+v", got)
		}
		if got.AdmissionTimeoutSeconds != 3 || got.CleanupTimeoutSeconds != 12 || got.ClientWaitTimeoutSeconds != 2 {
			t.Fatalf("wrong advertised lifecycle deadlines: %+v", got)
		}
		l.record.Phase = "admitted"
		if err := l.write(); err != nil {
			t.Fatal(err)
		}
		body, err = os.ReadFile(filepath.Join(dir.Name(), lifecycleFilename))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(body, &got); err != nil || got.Phase != "admitted" || got.RunID != l.record.RunID {
			t.Fatalf("initialized writer lost identity: %+v, %v", got, err)
		}
		if err := l.close(); err != nil {
			t.Fatal(err)
		}
		if err := l.write(); err == nil {
			t.Fatal("closed lifecycle retained a usable publication descriptor")
		}
	}
}

func TestLifecycleInitializationClosesDirectoryAfterPublicationFailure(t *testing.T) {
	dir, err := openLifecycleDirectory(filepath.Join(lifecycleTestParent(t), "receipt"), lifecycleTestOwner(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	collision := filepath.Join(dir.Name(), ".lifecycle-next")
	if err := os.WriteFile(collision, []byte("reserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := initializeContainRunLifecycle(dir); err == nil || l != nil {
		t.Fatalf("unpublished lifecycle escaped: %+v, %v", l, err)
	}
	if _, err := dir.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("failed initialization retained descriptor: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir.Name(), lifecycleFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed initialization published a record: %v", err)
	}
	body, err := os.ReadFile(filepath.Clean(collision))
	if err != nil || string(body) != "reserved" {
		t.Fatalf("temporary collision changed: %q, %v", body, err)
	}
}

func TestLifecycleSystemdShowParsesBoundUnitOnly(t *testing.T) {
	const unit = "pipelock-contain-0123456789abcdef0123456789abcdef.service"
	for _, tt := range []struct {
		name string
		body string
		code int
		want map[string]string
		err  string
	}{
		{"loaded", "Id=" + unit + "\nLoadState=loaded\nDescription=marker=with-equals\nInvocationID=\n", 0, map[string]string{"Id": unit, "LoadState": "loaded", "Description": "marker=with-equals", "InvocationID": ""}, ""},
		{"not found", "Id=" + unit + "\nLoadState=not-found\n", 1, map[string]string{"Id": unit, "LoadState": "not-found"}, ""},
		{"loaded command failure", "Id=" + unit + "\nLoadState=loaded\n", 5, nil, "systemctl exit 5"},
		{"missing separator", "Id=" + unit + "\nLoadState loaded\n", 0, nil, "malformed"},
		{"empty key", "Id=" + unit + "\n=value\nLoadState=loaded\n", 0, nil, "malformed"},
		{"duplicate identity", "Id=" + unit + "\nId=" + unit + "\nLoadState=loaded\n", 0, nil, "duplicate"},
		{"missing identity", "LoadState=not-found\n", 1, nil, "missing or mismatched"},
		{"different identity", "Id=unrelated.service\nLoadState=not-found\n", 1, nil, "missing or mismatched"},
		{"missing load state", "Id=" + unit + "\n", 0, nil, "missing or mismatched"},
		{"empty load state", "Id=" + unit + "\nLoadState=\n", 0, nil, "missing or mismatched"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseLifecycleSystemdShow(unit, tt.body, tt.code)
			if tt.err != "" {
				if err == nil || !strings.Contains(err.Error(), tt.err) || got != nil {
					t.Fatalf("invalid observation = %v, %v; want %q", got, err, tt.err)
				}
				return
			}
			if err != nil || !maps.Equal(got, tt.want) {
				t.Fatalf("properties = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
}

func TestLifecycleSystemdShowExcludesTextualExecStart(t *testing.T) {
	if slices.Contains(strings.Split(lifecycleSystemdProperties, ","), "ExecStart") {
		t.Fatal("scalar observation requested human-readable argv")
	}
}

func TestLifecycleSupervisionPreservesMultilineArgv(t *testing.T) {
	l, fields := lifecycleFixture()
	l.argv = []string{defaultLaunchScript, "printf", "%s", "first line\nsecond line\n"}
	row := []any{defaultLaunchScript, l.argv, false, 0, 0, 0, 0, 0, 0, 0}
	body, err := json.Marshal(map[string]any{"type": "a(sasbttttuii)", "data": [][]any{row}})
	if err != nil {
		t.Fatal(err)
	}
	b := lifecycleTestBackend(fields)
	var observations, typedReads, actions int
	b.show = func(_ context.Context, unit string) (map[string]string, error) {
		if unit != l.record.Unit {
			t.Fatal("observed a different unit")
		}
		observations++
		var out strings.Builder
		for _, property := range strings.Split(lifecycleSystemdProperties, ",") {
			value := fields[property]
			if property == "ExecStart" {
				// systemctl joins argv with spaces without escaping newlines.
				value = "{ path=" + defaultLaunchScript + " ; argv[]=" + strings.Join(l.argv, " ") + " ; }"
			}
			out.WriteString(property + "=" + value + "\n")
		}
		return parseLifecycleSystemdShow(unit, out.String(), 0)
	}
	b.execStart = func(_ context.Context, unit string) ([]string, error) {
		if unit != l.record.Unit {
			t.Fatal("read typed argv from a different unit")
		}
		typedReads++
		return parseLifecycleExecStart(body)
	}
	b.cgroupEmpty = func(group string) (bool, error) {
		if group != "/system.slice/"+l.record.Unit {
			t.Fatal("checked a different cgroup")
		}
		return actions != 0, nil
	}
	b.action = func(_ context.Context, unit string, args ...string) error {
		if unit != l.record.Unit || !slices.Equal(args, []string{"--no-block", "stop"}) || observations != 4 || typedReads != 2 || !l.record.AdmissionObserved || !l.record.ArgvObserved {
			t.Fatalf("action lacked confirmed ownership: %s %v observations=%d typed=%d record=%+v", unit, args, observations, typedReads, l.record)
		}
		actions++
		fields["ActiveState"], fields["MainPID"] = "inactive", "0"
		return nil
	}
	b.wait = func(context.Context, time.Duration) error { return nil }
	done := make(chan error, 1)
	l.save = func(record containLifecycleRecord) error {
		if record.Phase == "admitted" {
			if observations != 2 || typedReads != 1 || !record.ArgvObserved || record.InvocationID != fields["InvocationID"] {
				t.Fatalf("admission lacked typed command confirmation: %+v", record)
			}
			done <- nil
		}
		return nil
	}
	if err := superviseLifecycleService(context.Background(), done, func() { done <- nil }, l, 966, b); err != nil {
		t.Fatal(err)
	}
	if observations != 5 || typedReads != 2 || actions != 1 || !l.record.Final || !l.record.CleanupComplete || !l.record.CgroupEmpty || l.record.Phase != "complete" {
		t.Fatalf("incomplete multiline supervision: observations=%d typed=%d actions=%d record=%+v", observations, typedReads, actions, l.record)
	}
}

func TestLifecycleRecordFailurePreservesPublishedWitness(t *testing.T) {
	for _, failure := range []string{"oversized", "temporary collision", "closed directory"} {
		t.Run(failure, func(t *testing.T) {
			dir, err := openLifecycleDirectory(filepath.Join(lifecycleTestParent(t), "receipt"), lifecycleTestOwner(t))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = dir.Close() })
			l, _ := lifecycleFixture()
			l.record.Phase = "admitted"
			if err := writeLifecycleRecord(dir, l.record); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir.Name(), lifecycleFilename)
			before, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			l.record.Phase, l.record.Final = "complete", true
			switch failure {
			case "oversized":
				l.record.Failure = strings.Repeat("x", maxCmdOutputBytes)
			case "temporary collision":
				if err := os.WriteFile(filepath.Join(dir.Name(), ".lifecycle-next"), []byte("reserved"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "closed directory":
				if err := dir.Close(); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeLifecycleRecord(dir, l.record); err == nil {
				t.Fatal("failed publication reported success")
			}
			after, err := os.ReadFile(filepath.Clean(path))
			if err != nil || string(after) != string(before) {
				t.Fatalf("last published witness changed: before=%s after=%s err=%v", before, after, err)
			}
			if failure == "temporary collision" {
				body, err := os.ReadFile(filepath.Join(dir.Name(), ".lifecycle-next"))
				if err != nil || string(body) != "reserved" {
					t.Fatalf("unowned temporary file changed: %q, %v", body, err)
				}
			}
		})
	}
}

func TestLifecycleRecordRenameFailureRemovesOnlyItsTemporaryFile(t *testing.T) {
	dir, err := openLifecycleDirectory(filepath.Join(lifecycleTestParent(t), "receipt"), lifecycleTestOwner(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	obstruction := filepath.Join(dir.Name(), lifecycleFilename)
	if err := os.Mkdir(obstruction, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(obstruction, "sentinel")
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, _ := lifecycleFixture()
	if err := writeLifecycleRecord(dir, l.record); err == nil {
		t.Fatal("published over a directory")
	}
	if _, err := os.Lstat(filepath.Join(dir.Name(), ".lifecycle-next")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary record survived failed rename: %v", err)
	}
	body, err := os.ReadFile(filepath.Clean(sentinel))
	if err != nil || string(body) != "unchanged" {
		t.Fatalf("obstruction changed: %q, %v", body, err)
	}
}

func TestLifecycleRecordUsesRetainedDirectoryHandle(t *testing.T) {
	parent := lifecycleTestParent(t)
	path := filepath.Join(parent, "receipt")
	dir, err := openLifecycleDirectory(path, lifecycleTestOwner(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	retained := filepath.Join(parent, "retained")
	if err := os.Rename(path, retained); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	l, _ := lifecycleFixture()
	if err := writeLifecycleRecord(dir, l.record); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Clean(filepath.Join(retained, lifecycleFilename)))
	if err != nil {
		t.Fatal(err)
	}
	var got containLifecycleRecord
	if err := json.Unmarshal(body, &got); err != nil || got.RunID != l.record.RunID {
		t.Fatalf("wrong retained witness: %+v, %v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(path, lifecycleFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("publication followed replaced directory pathname: %v", err)
	}
}

func TestLifecycleCleanupRejectsObservationFailuresBeforeAction(t *testing.T) {
	for _, failure := range []string{"unit", "owned properties", "argv", "confirmation read", "confirmation identity", "kill"} {
		t.Run(failure, func(t *testing.T) {
			l, fields := lifecycleFixture()
			bindLifecycleFixture(l, fields)
			b := lifecycleTestBackend(fields)
			probeErr := errors.New("synthetic observation failure")
			want := ""
			var calls, actions int
			b.show = func(context.Context, string) (map[string]string, error) {
				calls++
				if calls == 2 {
					if failure == "confirmation read" {
						return nil, probeErr
					}
					if failure == "confirmation identity" {
						changed := maps.Clone(fields)
						changed["InvocationID"] = strings.Repeat("c", 32)
						return changed, nil
					}
				}
				return fields, nil
			}
			b.action = func(_ context.Context, unit string, args ...string) error {
				actions++
				if failure != "kill" || unit != l.record.Unit || !slices.Equal(args, []string{"kill", "--kill-whom=all", "--signal=KILL"}) {
					t.Fatalf("unauthorized action: %s %v", unit, args)
				}
				return probeErr
			}
			switch failure {
			case "unit":
				fields["Id"] = "unrelated.service"
				want = "different unit"
			case "owned properties":
				fields["PrivateNetwork"] = "no"
				want = "properties differ"
			case "argv":
				b.execStart = func(context.Context, string) ([]string, error) { return nil, probeErr }
			case "confirmation identity":
				want = "identity changed"
			case "kill":
				l.record.StopRequested = true
				clock := time.Unix(1, 0)
				b.now = func() time.Time { clock = clock.Add(4 * time.Second); return clock }
			}
			err := stopLifecycleService(context.Background(), l, 966, b)
			if err == nil || l.record.CleanupComplete || l.record.CgroupEmpty || l.record.KillRequested {
				t.Fatalf("failure became a cleanup witness: err=%v record=%+v", err, l.record)
			}
			if want != "" && !strings.Contains(err.Error(), want) {
				t.Fatalf("error=%v, want %q", err, want)
			}
			if want == "" && !errors.Is(err, probeErr) {
				t.Fatalf("lost observation error: %v", err)
			}
			if (actions == 1) != (failure == "kill") {
				t.Fatalf("actions=%d for %s", actions, failure)
			}
		})
	}
}

func TestLifecycleAdmissionFailuresNeverAuthorizeCleanup(t *testing.T) {
	for _, failure := range []string{"initial read", "ownership", "argv", "confirmation read", "confirmation properties", "confirmation invocation", "pending wait"} {
		t.Run(failure, func(t *testing.T) {
			l, fields := lifecycleFixture()
			b := lifecycleTestBackend(fields)
			probeErr := errors.New("synthetic admission failure")
			var observations, saves int
			b.show = func(context.Context, string) (map[string]string, error) {
				observations++
				if failure == "initial read" || (failure == "confirmation read" && observations == 2) {
					return nil, probeErr
				}
				observed := maps.Clone(fields)
				if observations == 2 {
					switch failure {
					case "confirmation properties":
						observed["Transient"] = "no"
					case "confirmation invocation":
						observed["InvocationID"] = strings.Repeat("c", 32)
					}
				}
				return observed, nil
			}
			b.action = func(context.Context, string, ...string) error {
				t.Fatal("cleanup acted without admitted ownership")
				return nil
			}
			b.cgroupEmpty = func(string) (bool, error) {
				t.Fatal("cleanup guessed an unbound cgroup")
				return false, nil
			}
			l.save = func(record containLifecycleRecord) error {
				saves++
				if !record.Final || record.Phase != "incomplete" || record.AdmissionObserved || record.ArgvObserved || record.CleanupComplete || record.InvocationID != "" || record.ControlGroup != "" {
					t.Fatalf("unverified record: %+v", record)
				}
				return nil
			}
			want := ""
			switch failure {
			case "ownership":
				fields["Description"] = "unrelated"
				want = "ownership is missing"
			case "argv":
				b.execStart = func(context.Context, string) ([]string, error) { return nil, probeErr }
			case "confirmation properties":
				want = "ownership is missing"
			case "confirmation invocation":
				want = "invocation changed during typed command observation"
			case "pending wait":
				fields["ActiveState"], fields["InvocationID"], fields["ControlGroup"] = "activating", "", ""
				b.wait = func(context.Context, time.Duration) error { return probeErr }
			}
			done := make(chan error, 1)
			cancelled := false
			err := superviseLifecycleService(context.Background(), done, func() { cancelled = true; done <- nil }, l, 966, b)
			if err == nil || !cancelled || saves != 1 || !strings.Contains(err.Error(), "cannot clean up an unobserved") {
				t.Fatalf("err=%v cancelled=%v saves=%d", err, cancelled, saves)
			}
			if want != "" && !strings.Contains(err.Error(), want) {
				t.Fatalf("lost admission reason %q: %v", want, err)
			}
			if want == "" && !errors.Is(err, probeErr) {
				t.Fatalf("lost admission error: %v", err)
			}
		})
	}
}

func TestLifecyclePendingAdmissionBindsOnlyAfterTypedConfirmation(t *testing.T) {
	l, fields := lifecycleFixture()
	b := lifecycleTestBackend(fields)
	var observations, polls, typedReads int
	b.show = func(ctx context.Context, unit string) (map[string]string, error) {
		if ctx.Err() != nil || unit != l.record.Unit {
			t.Fatalf("invalid observation: %s, %v", unit, ctx.Err())
		}
		observations++
		observed := maps.Clone(fields)
		switch observations {
		case 1:
			return map[string]string{"Id": unit, "LoadState": "not-found"}, nil
		case 2:
			observed["ActiveState"], observed["InvocationID"], observed["ControlGroup"] = "activating", "", ""
		case 5:
			observed["ActiveState"], observed["MainPID"] = "inactive", "0"
		}
		return observed, nil
	}
	b.wait = func(context.Context, time.Duration) error {
		polls++
		if l.record.AdmissionObserved || l.record.InvocationID != "" || l.record.ControlGroup != "" {
			t.Fatal("pending observation established ownership")
		}
		return nil
	}
	b.execStart = func(context.Context, string) ([]string, error) {
		typedReads++
		if l.record.AdmissionObserved {
			t.Fatal("ownership established before typed argv confirmation")
		}
		return append([]string(nil), l.argv...), nil
	}
	b.action = func(context.Context, string, ...string) error {
		t.Fatal("already terminal service was stopped")
		return nil
	}
	done := make(chan error, 1)
	l.save = func(record containLifecycleRecord) error {
		if record.Phase == "admitted" {
			if observations != 4 || !record.ArgvObserved || record.InvocationID != fields["InvocationID"] || record.ControlGroup != fields["ControlGroup"] {
				t.Fatalf("unconfirmed admission: observations=%d record=%+v", observations, record)
			}
			done <- nil
		}
		return nil
	}
	if err := superviseLifecycleService(context.Background(), done, func() {}, l, 966, b); err != nil {
		t.Fatal(err)
	}
	if observations != 5 || polls != 2 || typedReads != 1 || !l.record.Final || !l.record.CleanupComplete || !l.record.CgroupEmpty || l.record.Phase != "complete" {
		t.Fatalf("observations=%d polls=%d typed=%d record=%+v", observations, polls, typedReads, l.record)
	}
}

func TestLifecycleSupervisionReturnsFinalPublicationAndClientErrors(t *testing.T) {
	l, fields := lifecycleFixture()
	fields["ActiveState"], fields["MainPID"] = "failed", "0"
	fields["ExecMainCode"], fields["ExecMainStatus"] = "exited", "17"
	b := lifecycleTestBackend(fields)
	clientErr := errors.New("synthetic client failure")
	reportErr := errors.New("synthetic final publication failure")
	var saves int
	l.save = func(record containLifecycleRecord) error {
		saves++
		if record.Final {
			return reportErr
		}
		return nil
	}
	done := make(chan error, 1)
	done <- clientErr
	err := superviseLifecycleService(context.Background(), done, func() {}, l, 966, b)
	if !errors.Is(err, clientErr) || !errors.Is(err, reportErr) || saves != 2 {
		t.Fatalf("lost failure: err=%v saves=%d", err, saves)
	}
	if !l.record.CleanupComplete || !l.record.Final || l.record.Phase != "incomplete" || !strings.Contains(l.record.Failure, clientErr.Error()) || l.record.Terminal["ExecMainStatus"] != "17" {
		t.Fatalf("failure or terminal evidence lost: %+v", l.record)
	}
}

func TestLifecycleCancellationBoundsUnresponsiveClient(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		l, fields := lifecycleFixture()
		fields["ActiveState"], fields["MainPID"] = "inactive", "0"
		b := lifecycleTestBackend(fields)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		var clientCancellations int
		start := time.Now()
		err := superviseLifecycleService(ctx, make(chan error), func() { clientCancellations++ }, l, 966, b)
		if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "client did not exit within deadline") {
			t.Fatalf("lost cancellation or unresponsive client: %v", err)
		}
		if time.Since(start) != lifecycleClientTimeout || clientCancellations != 1 {
			t.Fatalf("client wait=%v cancellations=%d", time.Since(start), clientCancellations)
		}
		if !l.record.Final || !l.record.Cancelled || !l.record.CleanupComplete || l.record.Phase != "incomplete" {
			t.Fatalf("unresponsive client became success: %+v", l.record)
		}
	})
}

func TestLifecycleTypedArgvRejectsUnknownAndIncorrectFieldTypes(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field": `{"type":"a(sasbttttuii)","data":[],"unexpected":true}`,
		"data type":     `{"type":"a(sasbttttuii)","data":"not an array"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseLifecycleExecStart([]byte(body)); err == nil || !strings.Contains(err.Error(), "decode typed lifecycle ExecStart") {
				t.Fatalf("incorrect decoder failure: %v", err)
			}
		})
	}
}

func TestLifecycleContextPropagatesCancellation(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	ctx, cancel := containRunLifecycleContext(parent)
	defer cancel()
	cancelParent()
	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.Canceled) {
			t.Fatal(ctx.Err())
		}
	case <-time.After(testwait.Deadline(time.Second)):
		t.Fatal("lifecycle context lost parent cancellation")
	}
}

func TestLifecycleSystemCommandKeepsManagerEnvironmentLocal(t *testing.T) {
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/synthetic/remote-bus")
	t.Setenv("SYSTEMD_HOST", "synthetic-host")
	t.Setenv("LIFECYCLE_PRIVATE_VALUE", "synthetic-secret")
	out, code, err := lifecycleSystemCommand(context.Background(), "/usr/bin/env")
	if err != nil || code != 0 {
		t.Fatalf("command = %q, %d, %v", out, code, err)
	}
	got := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	want := []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_PAGER="}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Fatalf("manager environment=%v, want only %v", got, want)
	}
}

func TestLifecycleSystemCommandDistinguishesExitFailureAndOverflow(t *testing.T) {
	for _, scenario := range []string{"exit", "overflow"} {
		t.Run(scenario, func(t *testing.T) {
			script := `printf 'stdout witness;'; printf 'stderr witness' >&2; exit 17`
			args := []string{"-c", script}
			if scenario == "overflow" {
				args = []string{"-c", `printf '%s' "$1"`, "fixture", strings.Repeat("x", maxCmdOutputBytes+1)}
			}
			out, code, err := lifecycleSystemCommand(context.Background(), "/bin/sh", args...)
			if scenario == "exit" {
				if err != nil || code != 17 || out != "stdout witness;stderr witness" {
					t.Fatalf("exit = %q, %d, %v", out, code, err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "output exceeds bound") || code != -1 || out != "" {
				t.Fatalf("overflow = %q, %d, %v", out, code, err)
			}
		})
	}
	out, code, err := lifecycleSystemCommand(context.Background(), filepath.Join(t.TempDir(), "missing"))
	if err == nil || !errors.Is(err, os.ErrNotExist) || code != 0 || out != "" {
		t.Fatalf("start failure = %q, %d, %v", out, code, err)
	}
}

func TestLifecycleManagerCallsDoNotStartAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l, _ := lifecycleFixture()
	if fields, err := lifecycleSystemdShow(ctx, l.record.Unit); !errors.Is(err, context.Canceled) || fields != nil {
		t.Fatalf("show = %v, %v", fields, err)
	}
	if err := lifecycleSystemdAction(ctx, l.record.Unit, "--no-block", "stop"); !errors.Is(err, context.Canceled) {
		t.Fatalf("action = %v", err)
	}
	if argv, err := lifecycleExecStart(ctx, l.record.Unit); !errors.Is(err, context.Canceled) || argv != nil {
		t.Fatalf("typed argv = %v, %v", argv, err)
	}
	if err := launchContainedAgentLifecycle(containedAgentCommandOptions{ctx: ctx}, l); !errors.Is(err, context.Canceled) {
		t.Fatalf("launch = %v", err)
	}
	if l.record.AdmissionObserved || l.record.CleanupComplete || l.record.ArgvSHA256 != "" || l.argv == nil {
		t.Fatalf("cancelled launch altered ownership: %+v", l.record)
	}
}

func TestLifecycleLaunchOrdersWitnessBeforeStartingClient(t *testing.T) {
	image, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	imageHash := sha256.Sum256(image)
	argsHash := sha256.Sum256([]byte(`["node","path with spaces","line\nbreak"]`))
	for _, scenario := range []string{"inspection failure", "preexisting", "publication failure", "start failure", "normal exit", "client failure"} {
		t.Run(scenario, func(t *testing.T) {
			l, fields := lifecycleFixture()
			l.record.Phase = "reserved"
			b := lifecycleTestBackend(fields)
			probeErr := errors.New("synthetic launch failure")
			var observations int
			var records []containLifecycleRecord
			var child *exec.Cmd
			b.show = func(context.Context, string) (map[string]string, error) {
				observations++
				if observations == 1 {
					if scenario == "inspection failure" {
						return nil, probeErr
					}
					if scenario == "preexisting" {
						return fields, nil
					}
					return map[string]string{"Id": l.record.Unit, "LoadState": "not-found"}, nil
				}
				if child == nil || child.Process == nil || len(records) == 0 {
					t.Fatal("admission observation preceded client start or reservation publication")
				}
				observed := maps.Clone(fields)
				if observations >= 4 {
					observed["ActiveState"], observed["MainPID"] = "inactive", "0"
				}
				return observed, nil
			}
			l.save = func(record containLifecycleRecord) error {
				if len(records) == 0 && child != nil {
					t.Fatal("client built before candidate witness publication")
				}
				if record.ArgvSHA256 != hex.EncodeToString(argsHash[:]) || record.BinarySHA256 != hex.EncodeToString(imageHash[:]) {
					t.Fatalf("incorrect argv/image binding: %+v", record)
				}
				records = append(records, record)
				if scenario == "publication failure" {
					return probeErr
				}
				return nil
			}
			b.execStart = func(context.Context, string) ([]string, error) {
				return []string{defaultLaunchScript, "node", "path with spaces", "line\nbreak"}, nil
			}
			b.action = func(context.Context, string, ...string) error {
				t.Fatal("terminal child required a destructive action")
				return nil
			}
			command := func(opts containedAgentCommandOptions) (*exec.Cmd, string) {
				if len(records) != 1 || records[0].AdmissionObserved || opts.lifecycleUnit != l.record.Unit || opts.lifecycleRunID != l.record.RunID {
					t.Fatalf("client lacks reserved identity: opts=%+v records=%+v", opts, records)
				}
				switch scenario {
				case "start failure":
					child = exec.CommandContext(opts.ctx, "/bin/sh", "-c", "exit 0")
					child.Dir = filepath.Join(t.TempDir(), "missing")
				case "normal exit":
					child = exec.CommandContext(opts.ctx, "/bin/sh", "-c", "exit 0")
				case "client failure":
					child = exec.CommandContext(opts.ctx, "/bin/sh", "-c", "exit 17")
				default:
					t.Fatalf("client constructed after %s", scenario)
				}
				return child, opts.lifecycleUnit
			}
			opts := containedAgentCommandOptions{ctx: context.Background(), uid: 966, args: []string{"node", "path with spaces", "line\nbreak"}}
			err := launchContainedAgentLifecycleWithBackend(opts, l, b, command)
			switch scenario {
			case "inspection failure", "publication failure":
				if !errors.Is(err, probeErr) || child != nil || l.record.Final || l.record.AdmissionObserved {
					t.Fatalf("failed prelaunch escaped: child=%v err=%v record=%+v", child, err, l.record)
				}
			case "preexisting":
				if err == nil || !strings.Contains(err.Error(), "refusing preexisting") || child != nil || len(records) != 0 || l.record.ArgvSHA256 != "" {
					t.Fatalf("preexisting service was adopted: child=%v records=%+v err=%v", child, records, err)
				}
			case "start failure":
				if !errors.Is(err, os.ErrNotExist) || observations != 1 || len(records) != 1 || l.record.Final || l.record.AdmissionObserved {
					t.Fatalf("failed start claimed admission: observations=%d records=%+v err=%v", observations, records, err)
				}
			case "normal exit", "client failure":
				if scenario == "normal exit" && (err != nil || l.record.Phase != "complete") {
					t.Fatalf("successful launch = %v, phase=%s", err, l.record.Phase)
				}
				if scenario == "client failure" {
					var exitErr *exec.ExitError
					if !errors.As(err, &exitErr) || exitErr.ExitCode() != 17 || l.record.Phase != "incomplete" {
						t.Fatalf("lost client exit: err=%v record=%+v", err, l.record)
					}
				}
				if len(records) != 3 || !l.record.AdmissionObserved || !l.record.ArgvObserved || !l.record.Final || !l.record.CleanupComplete || child.ProcessState == nil {
					t.Fatalf("launch lacks complete supervision: records=%+v child=%v", records, child)
				}
				if records[0].Phase != "reserved" || records[1].Phase != "admitted" || child.WaitDelay != lifecycleClientTimeout || !slices.Equal(child.Env, []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_PAGER="}) {
					t.Fatalf("launch contract changed: records=%+v child=%v", records, child)
				}
			}
		})
	}
}

func TestLifecycleLaunchCancellationStopsOwnedServiceBeforeClient(t *testing.T) {
	l, fields := lifecycleFixture()
	b := lifecycleTestBackend(fields)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	var observations, stops int
	var child *exec.Cmd
	var clientCtx context.Context
	clientCancelled := make(chan bool, 1)
	b.show = func(observeCtx context.Context, unit string) (map[string]string, error) {
		if observeCtx.Err() != nil || unit != l.record.Unit {
			t.Fatalf("observation lost independent lifetime or unit binding: %s, %v", unit, observeCtx.Err())
		}
		observations++
		if observations == 1 {
			return map[string]string{"Id": unit, "LoadState": "not-found"}, nil
		}
		if observations == 2 {
			if child.Process == nil {
				t.Fatal("cancelled before client actually started")
			}
			cancel()
		}
		return fields, nil
	}
	b.action = func(cleanupCtx context.Context, unit string, args ...string) error {
		if ctx.Err() == nil || cleanupCtx.Err() != nil || clientCtx.Err() != nil || unit != l.record.Unit || !l.record.AdmissionObserved || !slices.Equal(args, []string{"--no-block", "stop"}) {
			t.Fatalf("cancellation violated ownership/order: unit=%s args=%v record=%+v", unit, args, l.record)
		}
		stops++
		fields["ActiveState"], fields["MainPID"] = "inactive", "0"
		return nil
	}
	b.wait = func(context.Context, time.Duration) error { return nil }
	command := func(opts containedAgentCommandOptions) (*exec.Cmd, string) {
		clientCtx = opts.ctx
		child = exec.CommandContext(opts.ctx, "/bin/cat")
		child.Stdin = reader
		child.Cancel = func() error {
			clientCancelled <- l.record.CleanupComplete
			return child.Process.Kill()
		}
		return child, opts.lifecycleUnit
	}
	err = launchContainedAgentLifecycleWithBackend(containedAgentCommandOptions{ctx: ctx, uid: 966, args: []string{"node", "driver.mjs"}}, l, b, command)
	if !errors.Is(err, context.Canceled) || stops != 1 || !l.record.Final || !l.record.CleanupComplete || !l.record.Cancelled || l.record.Phase != "incomplete" {
		t.Fatalf("cancelled launch lost cleanup result: stops=%d err=%v record=%+v", stops, err, l.record)
	}
	select {
	case cleanupComplete := <-clientCancelled:
		if !cleanupComplete {
			t.Fatal("client was killed before owned service cleanup completed")
		}
	default:
		t.Fatal("client cancellation was not delivered")
	}
	if child.ProcessState == nil || child.ProcessState.Success() {
		t.Fatalf("client was not reaped: %v", child.ProcessState)
	}
}
