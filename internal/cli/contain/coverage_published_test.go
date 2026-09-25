// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// ---------------------------------------------------------------------------
// published_services.go
// ---------------------------------------------------------------------------

// TestCovPubUnitNamesAndSocketsTCPBranch drives the TCP opt-in branch of
// publishedRecordUnitNames and publishedServiceSockets, which a unix-only
// publication never reaches.
func TestCovPubUnitNamesAndSocketsTCPBranch(t *testing.T) {
	record := publishedServiceRecord{Unit: publishedServiceUnitBase("viewer"), Name: "viewer", HostListen: "127.0.0.1:15900"}
	names := publishedRecordUnitNames(record)
	want := []string{
		"pipelock-published-viewer.socket", "pipelock-published-viewer.service",
		"pipelock-published-viewer-tcp.socket", "pipelock-published-viewer-tcp.service",
	}
	if len(names) != len(want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	for i, w := range want {
		if names[i] != w {
			t.Fatalf("names[%d] = %q, want %q", i, names[i], w)
		}
	}

	svc := publishedTestService()
	svc.HostListen = "127.0.0.1:15900"
	sockets := publishedServiceSockets(svc)
	wantSockets := []string{"pipelock-published-viewer.socket", "pipelock-published-viewer-tcp.socket"}
	if len(sockets) != len(wantSockets) || sockets[0] != wantSockets[0] || sockets[1] != wantSockets[1] {
		t.Fatalf("sockets = %v, want %v", sockets, wantSockets)
	}

	// Positive control: a unix-only record/service never grows the TCP pair.
	unixOnly := publishedRecordUnitNames(publishedServiceRecord{Unit: publishedServiceUnitBase("viewer"), Name: "viewer"})
	if len(unixOnly) != 2 {
		t.Fatalf("unix-only unit names = %v, want 2", unixOnly)
	}
	if got := publishedServiceSockets(publishedTestService()); len(got) != 1 {
		t.Fatalf("unix-only sockets = %v, want 1", got)
	}
}

// TestCovPubDecodePublishedServiceRecordsErrors exercises the two ways a
// recorded publication file can fail to decode: invalid JSON, and a unit name
// that does not match the canonical rendering of its own service name.
func TestCovPubDecodePublishedServiceRecordsErrors(t *testing.T) {
	t.Run("malformed json", func(t *testing.T) {
		if _, err := decodePublishedServiceRecords([]byte("{not json")); err == nil || !strings.Contains(err.Error(), "parse published service records") {
			t.Fatalf("err = %v, want parse failure", err)
		}
	})
	t.Run("non-canonical unit", func(t *testing.T) {
		data := []byte(`{"services":[{"unit":"wrong-unit","name":"viewer"}]}`)
		if _, err := decodePublishedServiceRecords(data); err == nil || !strings.Contains(err.Error(), "non-canonical unit") {
			t.Fatalf("err = %v, want non-canonical unit failure", err)
		}
	})
	// Positive control: a canonical record set decodes cleanly.
	t.Run("canonical record decodes", func(t *testing.T) {
		encoded, err := encodePublishedServiceRecords(desiredPublishedServices([]config.ContainmentPublishedService{publishedTestService()}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodePublishedServiceRecords(encoded); err != nil {
			t.Fatalf("canonical record set should decode: %v", err)
		}
	})
}

// TestCovPubReadPublishedServiceRecordsGenericError covers the read failure
// path distinct from a simply-absent record file.
func TestCovPubReadPublishedServiceRecordsGenericError(t *testing.T) {
	env := &installEnv{
		loopbackForwarderInvPath: "/etc/pipelock/contain/loopback-forwarders.json",
		readFile:                 func(string) ([]byte, error) { return nil, errors.New("permission denied") },
	}
	if _, err := readPublishedServiceRecords(env); err == nil || !strings.Contains(err.Error(), "read published service records") {
		t.Fatalf("err = %v, want read failure", err)
	}
}

// TestCovPubParseContainmentPublishedServicesFromConfigBytesErrors drives
// every failure branch of the single parser install/reload/verify all share:
// a malformed document, a non-mapping document, a non-mapping containment
// value, a non-sequence published_services value, and an unknown field.
func TestCovPubParseContainmentPublishedServicesFromConfigBytesErrors(t *testing.T) {
	tests := []struct{ name, body, want string }{
		{"malformed yaml document", "containment: [1, 2\n", "parse managed config"},
		{"top level not a mapping", "- one\n- two\n", "managed config must be a YAML mapping"},
		{"containment not a mapping", "containment: not-a-mapping\n", "containment must be a mapping"},
		{"published_services not a list", "containment:\n  published_services: not-a-list\n", "containment.published_services must be a list"},
		{
			"unknown field",
			"containment:\n  published_services:\n  - name: viewer\n    agent_port: 5900\n    operator_user: operator\n" +
				"    owner: ops\n    reason: r\n    expires_at: \"" + futureExpiryForTest + "\"\n    bogus_field: nope\n",
			"parse containment.published_services",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseContainmentPublishedServicesFromConfigBytes([]byte(tc.body), 8888, time.Now()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	t.Run("empty document returns no services", func(t *testing.T) {
		got, err := parseContainmentPublishedServicesFromConfigBytes(nil, 8888, time.Now())
		if err != nil || got != nil {
			t.Fatalf("got=%v err=%v, want nil,nil for an empty document", got, err)
		}
	})
}

// TestCovPubDeclaredContainmentPublishedServicesReadError covers the
// non-absent read-failure branch, distinct from "no managed config yet".
func TestCovPubDeclaredContainmentPublishedServicesReadError(t *testing.T) {
	env := &installEnv{
		configDir: "/etc/pipelock",
		readFile:  func(string) ([]byte, error) { return nil, errors.New("permission denied") },
	}
	if _, err := declaredContainmentPublishedServices(env, 8888); err == nil || !strings.Contains(err.Error(), "read managed config") {
		t.Fatalf("err = %v, want read failure", err)
	}
}

// TestCovPubDeclaredContainmentPublishedServicesAbsentConfig covers the
// distinct absent-config branch (nil, nil), as opposed to the generic
// read-error branch above.
func TestCovPubDeclaredContainmentPublishedServicesAbsentConfig(t *testing.T) {
	env := &installEnv{
		configDir: "/etc/pipelock",
		readFile:  func(string) ([]byte, error) { return nil, os.ErrNotExist },
	}
	got, err := declaredContainmentPublishedServices(env, 8888)
	if err != nil || got != nil {
		t.Fatalf("got=%v err=%v, want nil,nil for an absent managed config", got, err)
	}
}

// TestCovPubCheckPublishedOperatorsNilLookupUser covers the probe-cannot-
// resolve branch, reachable only when the environment has no lookupUser hook
// at all (as opposed to lookupUser returning an unknown-user error).
func TestCovPubCheckPublishedOperatorsNilLookupUser(t *testing.T) {
	env := &installEnv{agentUserName: testAgentUser}
	services := []config.ContainmentPublishedService{{Name: "viewer", OperatorUser: "operator"}}
	if err := checkPublishedOperators(env, services); err == nil || !strings.Contains(err.Error(), "cannot resolve operator_user") {
		t.Fatalf("err = %v, want unresolved operator failure", err)
	}
}

// TestCovPubInstallPublishedServicesCorruptedRecordsError covers the apply
// path's own read-and-decode failure of an already-on-disk record file.
func TestCovPubInstallPublishedServicesCorruptedRecordsError(t *testing.T) {
	env, _ := publishedInstallEnv(t, publishedTestConfig)
	recordPath := publishedServiceRecordPath(env.loopbackForwarderInvPath)
	if err := os.MkdirAll(filepath.Dir(recordPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(recordPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "parse published service records") {
		t.Fatalf("err = %v, want corrupted records failure", err)
	}
}

// TestCovPubInstallPublishedServicesMkdirAllError covers the record
// directory creation failure.
func TestCovPubInstallPublishedServicesMkdirAllError(t *testing.T) {
	env, _ := publishedInstallEnv(t, publishedTestConfig)
	env.mkdirAll = func(string, os.FileMode) error { return errors.New("mkdir denied") }
	if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "create published service record directory") {
		t.Fatalf("err = %v, want mkdir failure", err)
	}
}

// TestCovPubInstallPublishedServicesChmodError covers the idempotent-rerun
// chmod branch: an unchanged file's mode is still reasserted, and a failure
// there must abort the step.
func TestCovPubInstallPublishedServicesChmodError(t *testing.T) {
	env, runner := publishedInstallEnv(t, publishedTestConfig)
	if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err != nil {
		t.Fatalf("initial install: %v", err)
	}
	runner.on(argvFor("systemctl", "is-enabled", "pipelock-published-viewer.socket"), "enabled\n", 0, nil)
	runner.on(argvFor("systemctl", "is-active", "pipelock-published-viewer.socket"), "active\n", 0, nil)
	env.chmod = func(string, os.FileMode) error { return errors.New("chmod denied") }
	if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "chmod") {
		t.Fatalf("err = %v, want chmod failure on rerun", err)
	}
}

// TestCovPubInstallPublishedServicesBackupAndWriteError covers a fresh
// write's failure, as opposed to the reassert-mode-only chmod branch above.
func TestCovPubInstallPublishedServicesBackupAndWriteError(t *testing.T) {
	env, _ := publishedInstallEnv(t, publishedTestConfig)
	env.writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
	if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("err = %v, want write failure", err)
	}
}

// TestCovPubInstallPublishedServicesDaemonReloadError covers the apply-time
// daemon-reload failure after unit files are written.
func TestCovPubInstallPublishedServicesDaemonReloadError(t *testing.T) {
	env, runner := publishedInstallEnv(t, publishedTestConfig)
	runner.on(argvFor("systemctl", "daemon-reload"), "", 1, errors.New("dbus down"))
	if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "reload systemd after publishing services") {
		t.Fatalf("err = %v, want daemon-reload failure", err)
	}
}

// TestCovPubInstallPublishedServicesChangedUnitErrors covers the three
// per-changed-unit systemctl calls that only fire when a unit's rendered
// content differs from what is already on disk: stopping an active relay
// before its replacement is picked up, restarting an active changed socket,
// and the unconditional enable that always runs afterward.
func TestCovPubInstallPublishedServicesChangedUnitErrors(t *testing.T) {
	t.Run("stop changed relay error", func(t *testing.T) {
		env, runner := publishedInstallEnv(t, publishedTestConfig)
		relay := "pipelock-published-viewer.service"
		runner.on(argvFor("systemctl", "is-active", relay), "active\n", 0, nil)
		runner.on(argvFor("systemctl", "stop", relay), "", 1, errors.New("stop denied"))
		if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "stop changed published relay") {
			t.Fatalf("err = %v, want stop-changed-relay failure", err)
		}
	})

	t.Run("restart changed socket error", func(t *testing.T) {
		env, runner := publishedInstallEnv(t, publishedTestConfig)
		socket := "pipelock-published-viewer.socket"
		runner.on(argvFor("systemctl", "is-active", socket), "active\n", 0, nil)
		runner.on(argvFor("systemctl", "restart", socket), "", 1, errors.New("restart denied"))
		if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "restart changed published endpoint") {
			t.Fatalf("err = %v, want restart-changed-socket failure", err)
		}
	})

	t.Run("enable error", func(t *testing.T) {
		env, runner := publishedInstallEnv(t, publishedTestConfig)
		socket := "pipelock-published-viewer.socket"
		runner.on(argvFor("systemctl", "enable", "--now", socket), "", 1, errors.New("enable denied"))
		if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "enable published endpoint") {
			t.Fatalf("err = %v, want enable failure", err)
		}
	})
}

// TestCovPubRevokeErrors drives every failure branch of stepInstallPublished
// Services' revoke path: the disable and stop calls that close a removed
// endpoint before its files are touched, the generic read failure and the
// restoreBackup failure while removing its unit files, and the "already
// absent" continue that must never be treated as a failure.
func TestCovPubRevokeErrors(t *testing.T) {
	t.Run("disable failure aborts revoke", func(t *testing.T) {
		env, runner := publishedInstallEnv(t, publishedTestConfig)
		if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err != nil {
			t.Fatalf("install: %v", err)
		}
		runner.on(argvFor("systemctl", "disable", "--now", "pipelock-published-viewer.socket"), "", 1, errors.New("dbus down"))
		empty := []config.ContainmentPublishedService{}
		if _, err := stepInstallPublishedServices(&empty).apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "close revoked published endpoint") {
			t.Fatalf("err = %v, want disable failure", err)
		}
	})

	t.Run("stop failure aborts revoke", func(t *testing.T) {
		env, runner := publishedInstallEnv(t, publishedTestConfig)
		if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err != nil {
			t.Fatalf("install: %v", err)
		}
		runner.on(argvFor("systemctl", "stop", "pipelock-published-viewer.service"), "", 1, errors.New("dbus down"))
		empty := []config.ContainmentPublishedService{}
		if _, err := stepInstallPublishedServices(&empty).apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "stop revoked published relay") {
			t.Fatalf("err = %v, want stop failure", err)
		}
	})

	t.Run("read revoked unit generic error aborts revoke", func(t *testing.T) {
		env, _ := publishedInstallEnv(t, publishedTestConfig)
		if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err != nil {
			t.Fatalf("install: %v", err)
		}
		unitDir := filepath.Dir(env.proxyForwarderSocketPath)
		badPath := filepath.Join(unitDir, "pipelock-published-viewer.socket")
		base := env.readFile
		env.readFile = func(p string) ([]byte, error) {
			if p == badPath {
				return nil, errors.New("permission denied")
			}
			return base(p)
		}
		empty := []config.ContainmentPublishedService{}
		if _, err := stepInstallPublishedServices(&empty).apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "read revoked published unit") {
			t.Fatalf("err = %v, want read failure", err)
		}
	})

	t.Run("restoreBackup failure aborts revoke", func(t *testing.T) {
		env, _ := publishedInstallEnv(t, publishedTestConfig)
		if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err != nil {
			t.Fatalf("install: %v", err)
		}
		unitDir := filepath.Dir(env.proxyForwarderSocketPath)
		badPath := filepath.Join(unitDir, "pipelock-published-viewer.socket")
		env.removeFile = func(p string) error {
			if p == badPath {
				return errors.New("remove denied")
			}
			return os.Remove(p)
		}
		empty := []config.ContainmentPublishedService{}
		if _, err := stepInstallPublishedServices(&empty).apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "remove revoked published unit") {
			t.Fatalf("err = %v, want restoreBackup failure", err)
		}
	})

	t.Run("continue when revoked unit file already absent", func(t *testing.T) {
		env, _ := publishedInstallEnv(t, publishedTestConfig)
		recordPath := publishedServiceRecordPath(env.loopbackForwarderInvPath)
		if err := os.MkdirAll(filepath.Dir(recordPath), 0o750); err != nil {
			t.Fatal(err)
		}
		svc := publishedTestService()
		svc.HostListen = "127.0.0.1:15900"
		recordBytes, err := encodePublishedServiceRecords(desiredPublishedServices([]config.ContainmentPublishedService{svc}))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(recordPath, recordBytes, 0o600); err != nil {
			t.Fatal(err)
		}
		// Only the record exists; none of its (TCP-included) unit files were
		// ever written to disk, so the restore loop must skip every one of
		// them rather than treat their absence as a failure.
		empty := []config.ContainmentPublishedService{}
		if _, err := stepInstallPublishedServices(&empty).apply(context.Background(), env); err != nil {
			t.Fatalf("revoke of already-absent unit files: %v", err)
		}
	})
}

// TestCovPubInstallPublishedServicesUndoAllBranches drives every branch of
// the step's undo: the defensive stop/disable of a unit that was not
// previously running/enabled, the restore of a touched (changed) file, the
// restore of a retired (revoked) file, the daemon-reload, and the re-enable/
// restart of a unit that was previously active. A two-service install
// followed by a one-service reconciliation gives each branch a distinct
// governing unit so every injected failure is independently attributable.
func TestCovPubInstallPublishedServicesUndoAllBranches(t *testing.T) {
	env, runner, _ := newFakeEnv(t)

	unitA := publishedServiceUnitBase("viewer")
	unitB := publishedServiceUnitBase("editor")
	svcA := publishedTestService()
	svcB := svcA
	svcB.Name = "editor"
	svcB.AgentPort = 5901

	// Previous-state snapshot: A was neither active nor enabled, B was both.
	runner.on(argvFor("systemctl", "is-active", unitA+".socket"), "inactive\n", 3, nil)
	runner.on(argvFor("systemctl", "is-enabled", unitA+".socket"), "disabled\n", 1, nil)
	runner.on(argvFor("systemctl", "is-active", unitB+".socket"), "active\n", 0, nil)
	runner.on(argvFor("systemctl", "is-enabled", unitB+".service"), "enabled\n", 0, nil)

	both := []config.ContainmentPublishedService{svcA, svcB}
	if _, err := stepInstallPublishedServices(&both).apply(context.Background(), env); err != nil {
		t.Fatalf("initial two-service install: %v", err)
	}

	onlyA := []config.ContainmentPublishedService{svcA}
	s := stepInstallPublishedServices(&onlyA)
	if _, err := s.apply(context.Background(), env); err != nil {
		t.Fatalf("revoke editor: %v", err)
	}

	// Now stage every undo-time failure. These are registered after both
	// applies succeeded, so they can only be reached from undo() itself.
	runner.on(argvFor("systemctl", "stop", unitA+".socket"), "", 1, errors.New("stop denied"))
	runner.on(argvFor("systemctl", "disable", unitA+".socket"), "", 1, errors.New("disable denied"))
	runner.on(argvFor("systemctl", "enable", unitB+".service"), "", 1, errors.New("enable denied"))
	runner.on(argvFor("systemctl", "start", unitB+".socket"), "", 1, errors.New("start denied"))
	runner.on(argvFor("systemctl", "daemon-reload"), "", 1, errors.New("reload denied"))

	recordPath := publishedServiceRecordPath(env.loopbackForwarderInvPath)
	baseLstat := env.lstat
	env.lstat = func(p string) (os.FileInfo, error) {
		if p == recordPath+".bak" {
			return nil, errors.New("lstat denied")
		}
		return baseLstat(p)
	}
	baseWrite := env.writeFile
	env.writeFile = func(p string, data []byte, mode os.FileMode) error {
		if strings.Contains(p, unitB) {
			return errors.New("restore write denied")
		}
		return baseWrite(p, data, mode)
	}

	err := s.undo(context.Background(), env)
	if err == nil {
		t.Fatal("expected undo to report every injected failure")
	}
	for _, want := range []string{
		"stop denied", "disable denied", "enable denied", "start denied",
		"lstat denied", "restore write denied", "reload denied",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("undo err = %v, missing %q", err, want)
		}
	}
}

// TestCovPubRemovePublishedServicesPaths covers removePublishedServices: the
// unconfigured-host no-op, the record-read failure, and the combined
// systemctl-cleanup and restoreBackup failures collected across both loops.
func TestCovPubRemovePublishedServicesPaths(t *testing.T) {
	t.Run("empty loopback path is a no-op", func(t *testing.T) {
		env := &installEnv{}
		if err := removePublishedServices(context.Background(), env); err != nil {
			t.Fatalf("err = %v, want nil for an unconfigured host", err)
		}
	})

	t.Run("read records error propagates", func(t *testing.T) {
		env := &installEnv{
			loopbackForwarderInvPath: "/etc/pipelock/contain/loopback-forwarders.json",
			readFile:                 func(string) ([]byte, error) { return nil, errors.New("permission denied") },
		}
		if err := removePublishedServices(context.Background(), env); err == nil || !strings.Contains(err.Error(), "read published service records") {
			t.Fatalf("err = %v, want read failure", err)
		}
	})

	t.Run("cleanup and restore errors are collected", func(t *testing.T) {
		env, _ := publishedInstallEnv(t, publishedTestConfig)
		if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err != nil {
			t.Fatalf("install: %v", err)
		}
		env.runCmd = func(context.Context, string, ...string) (string, int, error) {
			return "", 1, errors.New("systemctl denied")
		}
		unitDir := filepath.Dir(env.proxyForwarderSocketPath)
		recordPath := publishedServiceRecordPath(env.loopbackForwarderInvPath)
		baseLstat := env.lstat
		env.lstat = func(p string) (os.FileInfo, error) {
			if p == filepath.Join(unitDir, "pipelock-published-viewer.socket")+".bak" || p == recordPath+".bak" {
				return nil, errors.New("lstat denied")
			}
			return baseLstat(p)
		}
		err := removePublishedServices(context.Background(), env)
		if err == nil {
			t.Fatal("expected combined cleanup/restore errors")
		}
		for _, want := range []string{"systemctl denied", "restore", "lstat denied"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("err = %v, missing %q", err, want)
			}
		}
	})
}

// TestCovPubDeclaredContainmentPublishedServicesForVerifyReadError covers the
// generic-read-failure branch, distinct from "no managed config yet".
func TestCovPubDeclaredContainmentPublishedServicesForVerifyReadError(t *testing.T) {
	env := &probeEnv{
		configPath: "/etc/pipelock/pipelock.yaml",
		readFile:   func(string) ([]byte, error) { return nil, errors.New("permission denied") },
	}
	_, problem, unusable := declaredContainmentPublishedServicesForVerify(env, 8888)
	if !unusable || !strings.Contains(problem, "read managed config") {
		t.Fatalf("problem=%q unusable=%v, want a read failure", problem, unusable)
	}
}

// TestCovPubProbePublishedServicesProcRootDefault covers the default-to-/proc
// branch, reusing the shared fixture (which already models a real /proc
// layout under that same default).
func TestCovPubProbePublishedServicesProcRootDefault(t *testing.T) {
	fx := newPublishedProbeFixture(t)
	fx.env.procRoot = ""
	if status, detail := fx.probe(); status != statusPass {
		t.Fatalf("default procRoot probe = %s %s, want pass", status, detail)
	}
}

// TestCovPubProbePublishedServicesAdditionalOutcomes drives two probe
// failures not covered by the existing outcomes table: the relay's
// is-active command itself failing (as opposed to reporting a recognized bad
// state), and an unparsable MainPID value.
func TestCovPubProbePublishedServicesAdditionalOutcomes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*publishedProbeFixture)
		want   string
	}{
		{"relay is-active command errors", func(fx *publishedProbeFixture) {
			base := fx.env.runCmd
			fx.env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
				if len(args) >= 2 && args[0] == "is-active" && args[1] == "pipelock-published-viewer.service" {
					return "", 1, errors.New("dbus down")
				}
				return base(ctx, name, args...)
			}
		}, "relay pipelock-published-viewer.service state unknown"},
		{"relay MainPID unparsable", func(fx *publishedProbeFixture) {
			fx.states["is-active pipelock-published-viewer.service"] = "active"
			fx.states["show pipelock-published-viewer.service --property=MainPID --value"] = "not-a-pid"
		}, "namespace unknown (MainPID"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := newPublishedProbeFixture(t)
			tt.mutate(fx)
			status, detail := fx.probe()
			if status == statusPass || !strings.Contains(detail, tt.want) {
				t.Fatalf("status=%s detail=%q, want FAIL containing %q", status, detail, tt.want)
			}
		})
	}
}

// TestCovPubProbePublishedSocketAccess drives every failure branch of
// probePublishedSocketAccess directly: no probe functions wired, a stat
// failure distinct from "does not exist", an operator lookup failure, and an
// owner UID the platform cannot report (a non-syscall FileInfo).
func TestCovPubProbePublishedSocketAccess(t *testing.T) {
	svc := publishedTestService()

	t.Run("nil stat or lookupUser", func(t *testing.T) {
		env := &probeEnv{}
		status, detail := probePublishedSocketAccess(env, svc)
		if status != statusFail || !strings.Contains(detail, "endpoint access unknown") {
			t.Fatalf("nil probe fns: %s %s", status, detail)
		}
	})

	t.Run("stat generic error", func(t *testing.T) {
		env := &probeEnv{
			stat:       func(string) (os.FileInfo, error) { return nil, errors.New("permission denied") },
			lookupUser: func(string) (*user.User, error) { return nil, errors.New("unused") },
		}
		status, detail := probePublishedSocketAccess(env, svc)
		if status != statusFail || !strings.Contains(detail, "endpoint access unknown") || !strings.Contains(detail, "permission denied") {
			t.Fatalf("stat error: %s %s", status, detail)
		}
	})

	t.Run("lookupUser error", func(t *testing.T) {
		dir := shortSocketDir(t, "sock.sock")
		path := filepath.Join(dir, "sock.sock")
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		svc2 := svc
		svc2.HostSocket = path
		env := &probeEnv{
			stat:       os.Stat,
			lookupUser: func(string) (*user.User, error) { return nil, user.UnknownUserError("operator") },
		}
		status, detail := probePublishedSocketAccess(env, svc2)
		if status != statusFail || !strings.Contains(detail, "does not resolve") {
			t.Fatalf("lookup error: %s %s", status, detail)
		}
	})

	t.Run("owner uid unreadable", func(t *testing.T) {
		svc2 := svc
		svc2.HostSocket = "/fake/path"
		env := &probeEnv{
			stat:       func(string) (os.FileInfo, error) { return fakeFileInfo{mode: os.ModeSocket | 0o600}, nil },
			lookupUser: func(name string) (*user.User, error) { return &user.User{Uid: "1000", Username: name}, nil },
		}
		status, detail := probePublishedSocketAccess(env, svc2)
		if status != statusFail || !strings.Contains(detail, "owner of") || !strings.Contains(detail, "unreadable") {
			t.Fatalf("owner unreadable: %s %s", status, detail)
		}
	})
}

// TestCovPubAgentNamespaceListensIPv6HostMissingFile drives the ::1 host
// branch (which adds the IPv6-loopback want entry and narrows the scanned
// files to tcp6 only) and the per-file "tcp6 absent" continue that must not
// be reported as an error.
func TestCovPubAgentNamespaceListensIPv6HostMissingFile(t *testing.T) {
	env := &probeEnv{
		readFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
	}
	got, err := agentNamespaceListens(env, "/proc", 4242, "::1", 9000)
	if err != nil || got {
		t.Fatalf("got=%v err=%v, want false,nil when the tcp6 table is absent", got, err)
	}
}

// ---------------------------------------------------------------------------
// install.go
// ---------------------------------------------------------------------------

// TestCovPubDisplayBindPropertyInvalidDisplayNumber covers the branch where
// a display is enabled but its number cannot be turned into a socket path.
func TestCovPubDisplayBindPropertyInvalidDisplayNumber(t *testing.T) {
	env := &installEnv{displayEnabled: true, displayNumber: -1}
	if got := displayBindProperty(env); got != "" {
		t.Fatalf("invalid display number: got %q, want empty", got)
	}
	// Positive control: a valid display number does produce a bind property.
	env.displayNumber = 0
	if got := displayBindProperty(env); got == "" {
		t.Fatal("valid display number produced an empty bind property")
	}
}

// TestCovPubInstallPipelockBinaryManagedUnitsReadError covers the failure to
// read the loopback-forwarder inventory before a binary swap.
func TestCovPubInstallPipelockBinaryManagedUnitsReadError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.loopbackForwarderInvPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.loopbackForwarderInvPath, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := stepInstallPipelockBinary().apply(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "read managed namespace units before binary replacement") {
		t.Fatalf("err = %v, want managed units read failure", err)
	}
}

// TestCovPubInstallPipelockBinaryWriteError covers the binary-write failure,
// distinct from the quiesce failure covered below.
func TestCovPubInstallPipelockBinaryWriteError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.writeFile = func(path string, data []byte, mode os.FileMode) error {
		if path == filepath.Clean(env.pipelockTarget) {
			return errors.New("disk full")
		}
		return writeFileAtomic(path, data, mode)
	}
	_, err := stepInstallPipelockBinary().apply(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("err = %v, want write failure", err)
	}
}

// TestCovPubInstallPipelockBinaryRestoreManagedUnitsError covers the
// apply-time failure to clear systemd start limits and restore managed
// namespace runtime units after a successful binary write, distinct from the
// quiesce-time failure (which returns before the write ever happens).
func TestCovPubInstallPipelockBinaryRestoreManagedUnitsError(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	runner.on(argvFor("systemctl", "reset-failed", filepath.Base(env.proxyForwarderSocketPath)), "", 1, errors.New("reset denied"))
	_, err := stepInstallPipelockBinary().apply(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "restore managed namespace units after binary replacement") {
		t.Fatalf("err = %v, want restore-managed-units failure", err)
	}
}

// TestCovPubInstallPipelockBinaryQuiesceAndUndoErrors drives the apply-time
// quiesce failure and, by calling undo directly afterward against the same
// captured managed-unit state, every branch of its undo: the quiesce retry,
// the target restore, the deferred-service restart, and the managed-runtime
// restore.
func TestCovPubInstallPipelockBinaryQuiesceAndUndoErrors(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.installServiceStateKnown = true
	env.installServiceWasActive = true
	env.deferServiceRestart = false
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name != "systemctl" {
			return "", 0, nil
		}
		joined := strings.Join(args, " ")
		switch {
		case strings.HasPrefix(joined, "is-active"):
			return "active\n", 0, nil
		case strings.HasPrefix(joined, "stop "):
			return "", 1, errors.New("stop denied")
		case strings.HasPrefix(joined, "reset-failed "):
			return "", 1, errors.New("reset denied")
		case strings.HasPrefix(joined, "restart pipelock"):
			return "", 1, errors.New("restart denied")
		}
		return "", 0, nil
	}
	env.lstat = func(p string) (os.FileInfo, error) {
		if strings.HasSuffix(p, ".bak") {
			return nil, errors.New("lstat denied")
		}
		return os.Lstat(p)
	}

	s := stepInstallPipelockBinary()
	_, applyErr := s.apply(context.Background(), env)
	if applyErr == nil || !strings.Contains(applyErr.Error(), "stop denied") {
		t.Fatalf("apply err = %v, want quiesce failure", applyErr)
	}

	undoErr := s.undo(context.Background(), env)
	if undoErr == nil {
		t.Fatal("expected undo to report every injected failure")
	}
	for _, want := range []string{"stop denied", "lstat denied", "restart denied", "reset denied"} {
		if !strings.Contains(undoErr.Error(), want) {
			t.Fatalf("undo err = %v, missing %q", undoErr, want)
		}
	}
}

// TestCovPubReloadNFTManagedChainLegacyChainListErrors drives the two
// failure branches around the legacy receiver-chain live query: the command
// itself erroring, and a nonzero exit whose message is not the recognized
// "chain absent" diagnostic.
func TestCovPubReloadNFTManagedChainLegacyChainListErrors(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	const operatorUID, proxyUID, agentUID = 1000, 988, 987
	body := renderNFTRules(operatorUID, proxyUID, agentUID, env.proxyPort, defaultNFTTable, defaultNFTChain)

	t.Run("legacy chain list command errors", func(t *testing.T) {
		env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
			if name != testNFT {
				t.Fatalf("cmd = %s, want nft", name)
			}
			joined := strings.Join(args, " ")
			switch {
			case strings.HasPrefix(joined, "-n -a list chain"):
				return "table inet pipelock_containment {\n  chain output_filter { }\n}", 0, nil
			case strings.Contains(joined, legacyOwnedLoopbackInputChain):
				return "", 1, errors.New("dbus down")
			}
			return "", 0, nil
		}
		err := reloadNFTManagedChain(context.Background(), env, body, operatorUID, proxyUID, agentUID)
		if err == nil || !strings.Contains(err.Error(), "list legacy owned loopback receiver chain for reload") {
			t.Fatalf("err = %v, want legacy chain list command failure", err)
		}
	})

	t.Run("legacy chain list nonzero exit with unexpected message", func(t *testing.T) {
		env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.HasPrefix(joined, "-n -a list chain"):
				return "table inet pipelock_containment {\n  chain output_filter { }\n}", 0, nil
			case strings.Contains(joined, legacyOwnedLoopbackInputChain):
				return "permission denied", 1, nil
			}
			return "", 0, nil
		}
		err := reloadNFTManagedChain(context.Background(), env, body, operatorUID, proxyUID, agentUID)
		if err == nil || !strings.Contains(err.Error(), "list legacy owned loopback receiver chain exit=1") {
			t.Fatalf("err = %v, want legacy chain list exit failure", err)
		}
	})
}

// ---------------------------------------------------------------------------
// doctor.go
// ---------------------------------------------------------------------------

// TestCovPubDoctorDoorwaySocketReader drives doctorDoorwaySocketReader
// directly: an unhonorable declaration, a doorway socket that fails its
// live probe, and the healthy pass.
func TestCovPubDoctorDoorwaySocketReader(t *testing.T) {
	body := "containment:\n  loopback_services:\n  - host: 127.0.0.1\n    port: 9200\n    owner: x\n    reason: y\n    expires_at: \"" +
		futureExpiryForTest + "\"\n"

	t.Run("unusable declaration fails", func(t *testing.T) {
		base := makeProbeEnv(t, func(e *probeEnv) {
			e.configPath = "/etc/pipelock/pipelock.yaml"
			e.readFile = func(string) ([]byte, error) { return []byte("containment:\n  loopback_services: not-a-list\n"), nil }
		})
		doctor := &doctorEnv{port: base.port}
		reader := doctorDoorwaySocketReader(base, doctor)
		res := reader(context.Background())
		if res.status != statusFail || !strings.Contains(res.detail, "cannot be honored") {
			t.Fatalf("unusable declaration = (%q, %q)", res.status, res.detail)
		}
	})

	t.Run("socket not enabled fails", func(t *testing.T) {
		base := makeProbeEnv(t, func(e *probeEnv) {
			e.configPath = "/etc/pipelock/pipelock.yaml"
			e.proxyForwarderSocketPath = "/etc/systemd/system/pipelock-agent-proxy.socket"
			e.readFile = func(string) ([]byte, error) { return []byte(body), nil }
			e.runCmd = func(context.Context, string, ...string) (string, int, error) {
				return "disabled\n", 1, nil
			}
		})
		doctor := &doctorEnv{port: base.port}
		reader := doctorDoorwaySocketReader(base, doctor)
		res := reader(context.Background())
		if res.status != statusFail || !strings.Contains(res.detail, "not persistently enabled") {
			t.Fatalf("disabled socket = (%q, %q)", res.status, res.detail)
		}
	})

	t.Run("all sockets healthy passes", func(t *testing.T) {
		base := makeProbeEnv(t, func(e *probeEnv) {
			e.configPath = "/etc/pipelock/pipelock.yaml"
			e.proxyForwarderSocketPath = "/etc/systemd/system/pipelock-agent-proxy.socket"
			e.readFile = func(string) ([]byte, error) { return []byte(body), nil }
			e.runCmd = func(_ context.Context, _ string, args ...string) (string, int, error) {
				joined := strings.Join(args, " ")
				switch {
				case strings.Contains(joined, "is-enabled"):
					return systemctlEnabled + "\n", 0, nil
				case strings.Contains(joined, "is-active"):
					return systemctlActive + "\n", 0, nil
				}
				return "", 1, errors.New("unexpected " + joined)
			}
		})
		doctor := &doctorEnv{port: base.port}
		reader := doctorDoorwaySocketReader(base, doctor)
		res := reader(context.Background())
		if res.status != statusPass || !strings.Contains(res.detail, "all managed doorway sockets") {
			t.Fatalf("healthy sockets = (%q, %q)", res.status, res.detail)
		}
	})
}

// TestCovPubCheckManagedDoorwaySocketsNilReaderIsUnknown mirrors the existing
// nil-chainStructure-reader test for the sibling doorway-socket check.
func TestCovPubCheckManagedDoorwaySocketsNilReaderIsUnknown(t *testing.T) {
	env := newDoctorEnv(t, func([]string) (string, int, error) { return "", 0, nil })
	env.doorwaySockets = nil
	if res := checkManagedDoorwaySockets(context.Background(), env); res.status != statusUnknown || !strings.Contains(res.detail, "unavailable") {
		t.Fatalf("nil reader = (%q, %q), want unknown/unavailable", res.status, res.detail)
	}
}

// ---------------------------------------------------------------------------
// browser_ca.go
// ---------------------------------------------------------------------------

// TestCovPubForeignNicknameForCA drives every branch of foreignNicknameForCA
// directly: the initial listing command failing, the managed nickname being
// skipped, an entry whose export fails, an entry whose exported PEM does not
// parse, and the terminal "no match found" return.
func TestCovPubForeignNicknameForCA(t *testing.T) {
	t.Run("list command fails", func(t *testing.T) {
		run := func(context.Context, string, ...string) (string, int, error) {
			return "", 1, errors.New("certutil not available")
		}
		if _, err := foreignNicknameForCA(context.Background(), run, "linux", "/db", "fp"); err == nil {
			t.Fatal("expected the initial list error to propagate")
		}
	})

	t.Run("skips managed nickname, unreadable and unparseable entries, returns none on no match", func(t *testing.T) {
		list := "Certificate Nickname                                         Trust Attributes\n" +
			"                                                             SSL,S/MIME,JAR/XPI\n\n" +
			browserCANSSNickname + " C,C,C\n" +
			"export-fails C,C,C\n" +
			"bad-pem C,C,C\n"
		run := func(_ context.Context, _ string, args ...string) (string, int, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.HasSuffix(joined, " -L"):
				return list, 0, nil
			case strings.Contains(joined, "-n export-fails"):
				return "", 1, errors.New("boom")
			case strings.Contains(joined, "-n bad-pem"):
				return "not pem", 0, nil
			default:
				return "", 1, fmt.Errorf("unexpected certutil call %q", joined)
			}
		}
		name, err := foreignNicknameForCA(context.Background(), run, "linux", "/db", "wantfp")
		if err != nil || name != "" {
			t.Fatalf("name=%q err=%v, want no match found", name, err)
		}
	})
}

// TestCovPubEstablishAgentBrowserCATrustForeignLookupError covers the caller
// side of the same failure: when an existing NSS database's foreign-nickname
// scan itself fails, establishAgentBrowserCATrust must propagate it rather
// than silently treating the CA as untrusted.
func TestCovPubEstablishAgentBrowserCATrustForeignLookupError(t *testing.T) {
	env, nss := newBrowserCAEnv(t)
	if err := os.MkdirAll(nss.db, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nss.db, nssDatabaseFile), []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	var bareListCalls int
	base := nss.run
	env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		joined := strings.Join(args, " ")
		if name == browserCACertutilName && strings.HasSuffix(joined, " -L") {
			bareListCalls++
			// The first bare "-L" belongs to inspectBrowserCA's own presence
			// check; the second is foreignNicknameForCA's, reached only
			// because the database exists but declares no managed nickname.
			if bareListCalls == 2 {
				return "", 1, errors.New("second list boom")
			}
		}
		return base(ctx, name, args...)
	}
	changed, err := establishAgentBrowserCATrust(context.Background(), env)
	if changed || err == nil || !strings.Contains(err.Error(), "second list boom") {
		t.Fatalf("changed=%v err=%v, want the propagated foreign-nickname lookup failure", changed, err)
	}
}

// ---------------------------------------------------------------------------
// verify.go
// ---------------------------------------------------------------------------

// TestCovPubDiagnoseWorkspaceACLCause drives the getfacl-failure short
// circuit and the terminal "grants read but access still failed" branch,
// which none of the workspace-ACL tests reach because they stop at a more
// specific diagnosis first.
func TestCovPubDiagnoseWorkspaceACLCause(t *testing.T) {
	base := makeProbeEnv(t, func(e *probeEnv) { e.agentUserName = testAgentUser })

	t.Run("getfacl fails yields empty diagnosis", func(t *testing.T) {
		env := *base
		env.runCmd = func(context.Context, string, ...string) (string, int, error) { return "", 1, nil }
		if got := diagnoseWorkspaceACLCause(context.Background(), &env, "/w"); got != "" {
			t.Fatalf("got %q, want empty on getfacl failure", got)
		}
	})

	t.Run("acl grants read but access still failed", func(t *testing.T) {
		env := *base
		env.runCmd = func(context.Context, string, ...string) (string, int, error) {
			return "# file: /w\n# owner: root\nuser::rwx\nuser:" + testAgentUser + ":r-x\ngroup::r-x\nmask::r-x\nother::---\n", 0, nil
		}
		got := diagnoseWorkspaceACLCause(context.Background(), &env, "/w")
		want := fmt.Sprintf("ACL grants %s %q but access still failed", testAgentUser, "r-x")
		if got != want {
			t.Fatalf("got %q, want %q", got, want)
		}
	})
}

// TestCovPubCredentialGuardConfigRoots covers the operator-lookup failure and
// the empty-home-dir branch, distinct from the already-tested empty-
// operatorUser short circuit.
func TestCovPubCredentialGuardConfigRoots(t *testing.T) {
	t.Run("lookup error yields empty roots", func(t *testing.T) {
		env := &probeEnv{
			operatorUser: "operator",
			lookupUser:   func(string) (*user.User, error) { return nil, errors.New("no such user") },
		}
		if roots := credentialGuardConfigRoots(env); len(roots) != 0 {
			t.Fatalf("roots = %v, want empty on lookup error", roots)
		}
	})

	t.Run("empty home dir yields empty roots", func(t *testing.T) {
		env := &probeEnv{
			operatorUser: "operator",
			lookupUser:   func(name string) (*user.User, error) { return &user.User{Username: name, HomeDir: ""}, nil },
		}
		if roots := credentialGuardConfigRoots(env); len(roots) != 0 {
			t.Fatalf("roots = %v, want empty on empty home dir", roots)
		}
	})

	t.Run("resolved operator yields roots", func(t *testing.T) {
		env := &probeEnv{
			operatorUser: "operator",
			lookupUser: func(name string) (*user.User, error) {
				return &user.User{Username: name, HomeDir: "/home/operator"}, nil
			},
		}
		if roots := credentialGuardConfigRoots(env); len(roots) == 0 {
			t.Fatal("want non-empty roots for a resolved operator")
		}
	})
}
