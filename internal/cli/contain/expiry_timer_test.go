// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type expiryTimerReply struct {
	out  string
	code int
	err  error
}

func TestEnsureNFTExpiryUnitsFreshRerunAndRepair(t *testing.T) {
	env, _, _ := newFakeEnv(t)

	changed, err := ensureNFTExpiryUnits(env)
	if err != nil {
		t.Fatalf("fresh install: %v", err)
	}
	if !changed {
		t.Fatal("fresh install reported no change")
	}
	for _, unit := range []struct {
		path string
		want string
	}{
		{env.nftExpiryServicePath, renderNFTExpiryService(env)},
		{env.nftExpiryTimerPath, renderNFTExpiryTimer(env)},
	} {
		got, err := os.ReadFile(unit.path)
		if err != nil {
			t.Fatalf("read %s: %v", unit.path, err)
		}
		if string(got) != unit.want {
			t.Fatalf("%s:\n got %s\nwant %s", unit.path, got, unit.want)
		}
	}

	changed, err = ensureNFTExpiryUnits(env)
	if err != nil {
		t.Fatalf("rerun: %v", err)
	}
	if changed {
		t.Fatal("matching rerun rewrote expiry units")
	}

	altered := map[string]string{
		env.nftExpiryServicePath: "[Service]\nExecStart=/wrong/binary\n",
		env.nftExpiryTimerPath:   "[Timer]\nOnCalendar=never\n",
	}
	for path, body := range altered {
		if err := os.WriteFile(path, []byte(body), modeUnitFile); err != nil {
			t.Fatalf("alter %s: %v", path, err)
		}
	}
	changed, err = ensureNFTExpiryUnits(env)
	if err != nil {
		t.Fatalf("repair: %v", err)
	}
	if !changed {
		t.Fatal("repair reported no change")
	}
	for _, unit := range []struct {
		path string
		want string
	}{
		{env.nftExpiryServicePath, renderNFTExpiryService(env)},
		{env.nftExpiryTimerPath, renderNFTExpiryTimer(env)},
	} {
		got, err := os.ReadFile(unit.path)
		if err != nil {
			t.Fatalf("read repaired %s: %v", unit.path, err)
		}
		if string(got) != unit.want {
			t.Fatalf("repaired %s = %q, want %q", unit.path, got, unit.want)
		}
		backup, err := os.ReadFile(unit.path + ".bak")
		if err != nil {
			t.Fatalf("read repair backup for %s: %v", unit.path, err)
		}
		if string(backup) != altered[unit.path] {
			t.Fatalf("backup for %s = %q, want %q", unit.path, backup, altered[unit.path])
		}
	}
}

func TestEnsureNFTExpiryUnitsReportsServiceWriteFailure(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	writeFile := env.writeFile
	env.writeFile = func(path string, body []byte, mode os.FileMode) error {
		if path == env.nftExpiryServicePath {
			return errors.New("expiry service write denied")
		}
		return writeFile(path, body, mode)
	}

	changed, err := ensureNFTExpiryUnits(env)
	if err == nil || !strings.Contains(err.Error(), env.nftExpiryServicePath) || !strings.Contains(err.Error(), "write denied") {
		t.Fatalf("ensure expiry units error = %v, want named service write failure", err)
	}
	if changed {
		t.Fatal("failed first unit write reported a changed expiry-unit set")
	}
}

func TestEnsureContainmentUnitReportsFilesystemFailures(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(t *testing.T, env *installEnv, path, body string)
		wantPathDir bool
		want        string
	}{
		{
			name:        "mkdir",
			wantPathDir: true,
			mutate: func(_ *testing.T, env *installEnv, _ string, _ string) {
				env.mkdirAll = func(string, os.FileMode) error { return errors.New("mkdir denied") }
			},
			want: "mkdir",
		},
		{
			name:        "directory chmod",
			wantPathDir: true,
			mutate: func(_ *testing.T, env *installEnv, _ string, _ string) {
				env.chmod = func(string, os.FileMode) error { return errors.New("directory chmod denied") }
			},
			want: "chmod",
		},
		{
			name: "matching unit chmod",
			mutate: func(t *testing.T, env *installEnv, path, body string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), modeDirReadable); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), modeUnitFile); err != nil {
					t.Fatal(err)
				}
				chmod := env.chmod
				env.chmod = func(target string, mode os.FileMode) error {
					if target == path {
						return errors.New("unit chmod denied")
					}
					return chmod(target, mode)
				}
			},
			want: "unit chmod denied",
		},
		{
			name: "unexpected read",
			mutate: func(_ *testing.T, env *installEnv, _ string, _ string) {
				env.readFile = func(string) ([]byte, error) { return nil, errors.New("unit read denied") }
			},
			want: "unit read denied",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			path := filepath.Join(t.TempDir(), "system", "pipelock-containment-expiry.timer")
			const body = "[Timer]\nOnCalendar=hourly\n"
			tc.mutate(t, env, path, body)

			changed, err := ensureContainmentUnit(env, path, body)
			wantPath := path
			if tc.wantPathDir {
				wantPath = filepath.Dir(path)
			}
			if err == nil || !strings.Contains(err.Error(), wantPath) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ensure unit error = %v, want path %q and %q", err, wantPath, tc.want)
			}
			if changed {
				t.Fatal("failed unit operation reported a changed unit")
			}
		})
	}
}

func TestStepInstallNFTRulesReportsNewFailurePaths(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(env *installEnv, runner *fakeRunner)
		want   string
	}{
		{
			name: "expiry service write",
			mutate: func(env *installEnv, _ *fakeRunner) {
				writeFile := env.writeFile
				env.writeFile = func(path string, body []byte, mode os.FileMode) error {
					if path == env.nftExpiryServicePath {
						return errors.New("expiry service write denied")
					}
					return writeFile(path, body, mode)
				}
			},
			want: "expiry service write denied",
		},
		{
			name: "nft load",
			mutate: func(env *installEnv, runner *fakeRunner) {
				runner.on(argvFor(testNFT, "-f", env.nftRulesPath), "load denied", 1, nil)
			},
			want: "nft load failed",
		},
		{
			name: "systemd daemon reload",
			mutate: func(_ *installEnv, runner *fakeRunner) {
				runner.on(argvFor(testSystemctl, "daemon-reload"), "reload denied", 1, nil)
			},
			want: "systemctl daemon-reload",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), "", 1, errors.New("not loaded"))
			tc.mutate(env, runner)

			changed, err := stepInstallNFTRules().apply(context.Background(), env)
			if !changed {
				t.Fatal("failed install reported no changes despite writing containment artifacts")
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("install error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestStepInstallNFTRulesUndoReportsExpiryUnitRestoreFailures(t *testing.T) {
	for _, target := range []string{"timer", "service"} {
		t.Run(target, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			path := env.nftExpiryTimerPath
			if target == "service" {
				path = env.nftExpiryServicePath
			}
			removeFile := env.removeFile
			env.removeFile = func(candidate string) error {
				if candidate == path {
					return errors.New(target + " restore denied")
				}
				return removeFile(candidate)
			}

			err := stepInstallNFTRules().undo(context.Background(), env)
			if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), target+" restore denied") {
				t.Fatalf("undo error = %v, want failed restore for %s", err, path)
			}
		})
	}
}

func TestStepInstallNFTRulesUndoReportsDisabledExpiryTimerRestoreFailure(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	env.prevNFTExpiryTimerStateKnown = true
	env.prevNFTExpiryTimerEnabled = false
	timer := filepath.Base(env.nftExpiryTimerPath)
	runner.on(argvFor(testSystemctl, "disable", "--now", timer), "disable denied", 1, nil)

	err := stepInstallNFTRules().undo(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "stop "+timer+" for rollback") || !strings.Contains(err.Error(), "disable denied") {
		t.Fatalf("undo error = %v, want timer stop failure", err)
	}
}

func TestStepInstallNFTRulesUndoRestoresExpiryTimerState(t *testing.T) {
	states := []struct {
		name    string
		enabled bool
		active  bool
	}{
		{name: "disabled inactive"},
		{name: "disabled active", active: true},
		{name: "enabled inactive", enabled: true},
		{name: "enabled active", enabled: true, active: true},
	}

	for _, tc := range states {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			env.prevNFTExpiryTimerStateKnown = true
			env.prevNFTExpiryTimerEnabled = tc.enabled
			env.prevNFTExpiryTimerActive = tc.active
			originalTimer := "[Timer]\nOnCalendar=hourly\n"
			originalService := "[Service]\nExecStart=/bin/true\n"
			if err := os.WriteFile(env.nftExpiryTimerPath+".bak", []byte(originalTimer), modeUnitFile); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(env.nftExpiryServicePath+".bak", []byte(originalService), modeUnitFile); err != nil {
				t.Fatal(err)
			}

			if err := stepInstallNFTRules().undo(context.Background(), env); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"disable --now " + filepath.Base(env.nftExpiryTimerPath),
				"stop " + filepath.Base(env.nftExpiryServicePath),
			} {
				if !runnerCalled(runner, testSystemctl, want) {
					t.Fatalf("rollback did not run %q: %+v", want, runner.calls)
				}
			}
			timer := filepath.Base(env.nftExpiryTimerPath)
			if got := runnerCalled(runner, testSystemctl, "enable "+timer); got != tc.enabled {
				t.Errorf("enable restored = %v, want %v: %+v", got, tc.enabled, runner.calls)
			}
			if got := runnerCalled(runner, testSystemctl, "start "+timer); got != tc.active {
				t.Errorf("start restored = %v, want %v: %+v", got, tc.active, runner.calls)
			}
			got, err := os.ReadFile(env.nftExpiryTimerPath)
			if err != nil || string(got) != originalTimer {
				t.Fatalf("restored timer = %q, %v; want %q", got, err, originalTimer)
			}
		})
	}
}

func TestStepInstallNFTRulesReconcilesStoppedExpiryTimerOnMatchingRerun(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	body := renderNFTRules(1000, 988, 987, env.proxyPort, defaultNFTTable, defaultNFTChain)
	if err := os.MkdirAll(filepath.Dir(env.nftRulesPath), modeDirReadable); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.nftRulesPath, []byte(body), modeNFTFile); err != nil {
		t.Fatal(err)
	}
	writeNFTPersistUnitFixture(t, env)
	timerEnabled := false
	timerActive := false
	timer := filepath.Base(env.nftExpiryTimerPath)
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name == testNFT && strings.Join(args, " ") == "-n -a list chain inet "+defaultNFTTable+" "+defaultNFTChain {
			return body, 0, nil
		}
		if name != testSystemctl {
			return "", 0, nil
		}
		switch strings.Join(args, " ") {
		case "is-enabled " + filepath.Base(env.nftPersistUnitPath):
			return "enabled\n", 0, nil
		case "is-enabled " + timer:
			if timerEnabled {
				return "enabled\n", 0, nil
			}
			return "disabled\n", 1, nil
		case "is-active " + timer:
			if timerActive {
				return "active\n", 0, nil
			}
			return "inactive\n", 3, nil
		case "enable --now " + timer:
			timerEnabled = true
			timerActive = true
		}
		return "", 0, nil
	}

	applied, err := stepInstallNFTRules().apply(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !applied || !timerEnabled || !timerActive {
		t.Fatalf("matching rerun = applied:%v enabled:%v active:%v, want all true", applied, timerEnabled, timerActive)
	}
}

func runnerCalled(runner *fakeRunner, name, args string) bool {
	for _, call := range runner.calls {
		if call.name == name && strings.Join(call.args, " ") == args {
			return true
		}
	}
	return false
}

func TestActionRemoveNFTRulesReportsExpiryUnitRemovalFailures(t *testing.T) {
	for _, target := range []string{"timer", "service"} {
		t.Run(target, func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			env.nftMainPath = ""
			path := env.nftExpiryTimerPath
			if target == "service" {
				path = env.nftExpiryServicePath
			}
			removeFile := env.removeFile
			env.removeFile = func(candidate string) error {
				if candidate == path {
					return errors.New(target + " removal denied")
				}
				return removeFile(candidate)
			}

			err := actionRemoveNFTRules().undo(context.Background(), env)
			if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), target+" removal denied") {
				t.Fatalf("rollback error = %v, want failed removal for %s", err, path)
			}
		})
	}
}

func TestRenderNFTExpiryUnitsContract(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	service := renderNFTExpiryService(env)
	timer := renderNFTExpiryTimer(env)

	for _, want := range []string{
		"Type=oneshot",
		"TimeoutStartSec=" + containmentExpiryServiceTimeout,
		"ExecStart=" + env.pipelockTarget + " contain reload-nft-rules",
	} {
		if !strings.Contains(service, want) {
			t.Errorf("service missing %q:\n%s", want, service)
		}
	}
	for _, want := range []string{
		"OnCalendar=" + containmentExpiryTimerCalendar,
		"Persistent=true",
		"AccuracySec=" + containmentExpiryTimerAccuracy,
		"Unit=" + filepath.Base(env.nftExpiryServicePath),
		"WantedBy=timers.target",
	} {
		if !strings.Contains(timer, want) {
			t.Errorf("timer missing %q:\n%s", want, timer)
		}
	}
	if strings.Contains(timer, "RandomizedDelaySec") {
		t.Fatalf("timer widens the expiry window:\n%s", timer)
	}
}

func TestProbeContainmentExpiryTimer(t *testing.T) {
	tests := []struct {
		name         string
		mutate       func(t *testing.T, env *probeEnv)
		timerReply   expiryTimerReply
		timerActive  expiryTimerReply
		serviceReply expiryTimerReply
		wantStatus   string
		wantDetail   string
	}{
		{
			name:         "unconfigured persistence path skips",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{out: "static\n"},
			mutate: func(_ *testing.T, env *probeEnv) {
				env.nftPersistUnitPath = ""
			},
			wantStatus: statusSkip,
			wantDetail: "persistence unit path is not configured",
		},
		{
			name:         "persistence read failure fails",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{out: "static\n"},
			mutate: func(_ *testing.T, env *probeEnv) {
				readFile := env.readFile
				env.readFile = func(path string) ([]byte, error) {
					if path == env.nftPersistUnitPath {
						return nil, errors.New("persistence read denied")
					}
					return readFile(path)
				}
			},
			wantStatus: statusFail,
			wantDetail: "read nftables persistence unit",
		},
		{
			name:         "absent persistence unit skips as uninstalled",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{out: "static\n"},
			mutate: func(t *testing.T, env *probeEnv) {
				t.Helper()
				if err := os.Remove(env.nftPersistUnitPath); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: statusSkip,
			wantDetail: "containment is not installed",
		},
		{
			name:         "enabled timer and unmasked service pass",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{out: "static\n"},
			wantStatus:   statusPass,
		},
		{
			name:         "disabled timer fails",
			timerReply:   expiryTimerReply{out: "disabled\n", code: 1},
			serviceReply: expiryTimerReply{out: "static\n"},
			wantStatus:   statusFail,
			wantDetail:   "not enabled",
		},
		{
			name:         "runtime-only enabled timer fails",
			timerReply:   expiryTimerReply{out: "enabled-runtime\n"},
			serviceReply: expiryTimerReply{out: "static\n"},
			wantStatus:   statusFail,
			wantDetail:   "not enabled",
		},
		{
			name:         "inactive timer fails",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			timerActive:  expiryTimerReply{out: "inactive\n", code: 3},
			serviceReply: expiryTimerReply{out: "static\n"},
			wantStatus:   statusFail,
			wantDetail:   "not active",
		},
		{
			name:         "timer activity query failure does not skip",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			timerActive:  expiryTimerReply{err: errors.New("systemctl missing")},
			serviceReply: expiryTimerReply{out: "static\n"},
			wantStatus:   statusFail,
			wantDetail:   "systemctl unavailable",
		},
		{
			name:         "masked timer names unmask repair",
			timerReply:   expiryTimerReply{out: "masked\n", code: 1},
			serviceReply: expiryTimerReply{out: "static\n"},
			wantStatus:   statusFail,
			wantDetail:   "unmask the affected unit",
		},
		{
			name:         "masked service names unmask repair",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{out: "masked\n", code: 1},
			wantStatus:   statusFail,
			wantDetail:   "unmask the affected unit",
		},
		{
			name:         "timer missing schedule fails",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{out: "static\n"},
			mutate: func(t *testing.T, env *probeEnv) {
				t.Helper()
				body := "[Timer]\nUnit=" + filepath.Base(env.nftExpiryServicePath) + "\n"
				if err := os.WriteFile(env.nftExpiryTimerPath, []byte(body), modeUnitFile); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: statusFail,
			wantDetail: "does not contain the managed expiry schedule",
		},
		{
			name:         "expiry service read failure fails",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{out: "static\n"},
			mutate: func(_ *testing.T, env *probeEnv) {
				readFile := env.readFile
				env.readFile = func(path string) ([]byte, error) {
					if path == env.nftExpiryServicePath {
						return nil, errors.New("expiry service read denied")
					}
					return readFile(path)
				}
			},
			wantStatus: statusFail,
			wantDetail: "read containment expiry service",
		},
		{
			name:         "altered service command fails",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{out: "static\n"},
			mutate: func(t *testing.T, env *probeEnv) {
				t.Helper()
				if err := os.WriteFile(env.nftExpiryServicePath, []byte("[Service]\nExecStart=/wrong/binary\n"), modeUnitFile); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: statusFail,
			wantDetail: "missing exact ExecStart",
		},
		{
			name:         "appended timer calendar fails",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{out: "static\n"},
			mutate: func(t *testing.T, env *probeEnv) {
				t.Helper()
				body, err := os.ReadFile(env.nftExpiryTimerPath)
				if err != nil {
					t.Fatal(err)
				}
				body = []byte(strings.Replace(string(body), "Persistent=true", "Persistent=true\nOnCalendar=weekly", 1))
				if err := os.WriteFile(env.nftExpiryTimerPath, body, modeUnitFile); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: statusFail,
			wantDetail: "does not contain the managed expiry schedule",
		},
		{
			name:         "appended service exec start fails",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{out: "static\n"},
			mutate: func(t *testing.T, env *probeEnv) {
				t.Helper()
				body, err := os.ReadFile(env.nftExpiryServicePath)
				if err != nil {
					t.Fatal(err)
				}
				body = []byte(strings.Replace(string(body), "Type=oneshot", "Type=oneshot\nExecStart=/bin/true", 1))
				if err := os.WriteFile(env.nftExpiryServicePath, body, modeUnitFile); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: statusFail,
			wantDetail: "missing exact ExecStart",
		},
		{
			name:         "resetting timer calendar fails",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{out: "static\n"},
			mutate: func(t *testing.T, env *probeEnv) {
				t.Helper()
				body, err := os.ReadFile(env.nftExpiryTimerPath)
				if err != nil {
					t.Fatal(err)
				}
				body = []byte(strings.Replace(string(body), "Persistent=true", "Persistent=true\nOnCalendar=", 1))
				if err := os.WriteFile(env.nftExpiryTimerPath, body, modeUnitFile); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: statusFail,
			wantDetail: "does not contain the managed expiry schedule",
		},
		{
			name:         "timer linked to another service fails",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{out: "static\n"},
			mutate: func(t *testing.T, env *probeEnv) {
				t.Helper()
				if err := os.WriteFile(env.nftExpiryTimerPath, []byte("[Timer]\nUnit=other.service\n"), modeUnitFile); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: statusFail,
			wantDetail: "missing exact Unit linkage",
		},
		{
			name:         "missing timer file fails",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{out: "static\n"},
			mutate: func(t *testing.T, env *probeEnv) {
				t.Helper()
				if err := os.Remove(env.nftExpiryTimerPath); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: statusFail,
			wantDetail: "read containment expiry timer",
		},
		{
			name:         "systemctl failure does not skip",
			timerReply:   expiryTimerReply{err: errors.New("systemctl missing")},
			serviceReply: expiryTimerReply{out: "static\n"},
			wantStatus:   statusFail,
			wantDetail:   "systemctl unavailable",
		},
		{
			name:         "service systemctl failure does not skip",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{err: errors.New("systemctl missing")},
			wantStatus:   statusFail,
			wantDetail:   "systemctl unavailable",
		},
		{
			name:         "service not enabled fails",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{out: "disabled\n", code: 1},
			wantStatus:   statusFail,
			wantDetail:   "systemctl is-enabled",
		},
		{
			name:         "runtime-only enabled expiry service fails",
			timerReply:   expiryTimerReply{out: "enabled\n"},
			serviceReply: expiryTimerReply{out: "enabled-runtime\n"},
			wantStatus:   statusFail,
			wantDetail:   "systemctl is-enabled",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.timerActive.out == "" && tc.timerActive.err == nil {
				tc.timerActive.out = "active\n"
			}
			env := newExpiryProbeEnv(t, tc.timerReply, tc.timerActive, tc.serviceReply)
			if tc.mutate != nil {
				tc.mutate(t, env)
			}
			status, detail := probeContainmentExpiryTimer(context.Background(), env)
			if status != tc.wantStatus {
				t.Fatalf("status = %q, want %q (detail=%q)", status, tc.wantStatus, detail)
			}
			if !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("detail = %q, want %q", detail, tc.wantDetail)
			}
		})
	}
}

func TestStepInstallNFTRulesRollsBackExpiryUnitsAfterEnableFailure(t *testing.T) {
	for _, failedUnit := range []string{"persistence", "timer"} {
		t.Run(failedUnit, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			runner.on(argvFor(testNFT, "-n", "-a", "list", "chain", "inet", defaultNFTTable, defaultNFTChain), "", 1, errors.New("not loaded"))
			runner.on(argvFor(testSystemctl, "is-enabled", filepath.Base(env.nftPersistUnitPath)), "disabled\n", 1, nil)
			runner.on(argvFor(testSystemctl, "is-enabled", filepath.Base(env.nftExpiryTimerPath)), "disabled\n", 1, nil)
			unit := env.nftPersistUnitPath
			if failedUnit == "timer" {
				unit = env.nftExpiryTimerPath
			}
			if failedUnit == "timer" {
				runner.on(argvFor(testSystemctl, "enable", "--now", filepath.Base(unit)), "permission denied", 1, nil)
			} else {
				runner.on(argvFor(testSystemctl, "enable", filepath.Base(unit)), "permission denied", 1, nil)
			}

			s := stepInstallNFTRules()
			applied, err := s.apply(context.Background(), env)
			if err == nil || !applied {
				t.Fatalf("apply = (%t, %v), want changed failure", applied, err)
			}
			if err := s.undo(context.Background(), env); err != nil {
				t.Fatalf("undo: %v", err)
			}
			for _, path := range []string{env.nftExpiryServicePath, env.nftExpiryTimerPath} {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("%s survived failed install rollback: %v", path, err)
				}
			}
		})
	}
}

func TestProbeNFTContainmentRequiresEnabledExpiryTimer(t *testing.T) {
	tmp := t.TempDir()
	rulesPath := filepath.Join(tmp, "50-pipelock-containment.nft")
	persistPath := filepath.Join(tmp, "pipelock-containment-nft.service")
	servicePath := filepath.Join(tmp, "pipelock-containment-expiry.service")
	timerPath := filepath.Join(tmp, "pipelock-containment-expiry.timer")
	if err := os.WriteFile(rulesPath, []byte(renderNFTRules(1000, 988, 987, 8888, testTable, testChain)), modeUnitFile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(persistPath, []byte("[Unit]\nConditionPathExists="+rulesPath+"\n[Service]\nExecStart="+defaultPipelockTarget+" contain reload-nft-rules\n"), modeUnitFile); err != nil {
		t.Fatal(err)
	}
	installEnv := &installEnv{pipelockTarget: defaultPipelockTarget, nftExpiryServicePath: servicePath}
	if err := os.WriteFile(servicePath, []byte(renderNFTExpiryService(installEnv)), modeUnitFile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(timerPath, []byte(renderNFTExpiryTimer(installEnv)), modeUnitFile); err != nil {
		t.Fatal(err)
	}

	env := makeProbeEnv(t, func(env *probeEnv) {
		env.operatorUser = testOperatorUser
		env.lookupUser = containTestLookup
		env.nftRulesPath = rulesPath
		env.nftPersistUnitPath = persistPath
		env.nftExpiryServicePath = servicePath
		env.nftExpiryTimerPath = timerPath
		env.readFile = os.ReadFile
		env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
			if name == testNFT {
				return goodNFTContainmentOutput, 0, nil
			}
			if name == testSystemctl && len(args) == 2 && args[0] == "is-enabled" {
				switch args[1] {
				case filepath.Base(timerPath):
					return "disabled\n", 1, nil
				case filepath.Base(servicePath):
					return "static\n", 0, nil
				}
			}
			if name == testSystemctl && len(args) == 2 && args[0] == "is-active" && args[1] == filepath.Base(timerPath) {
				return "inactive\n", 3, nil
			}
			return "", -1, errors.New("unexpected command")
		}
	})
	status, detail := probeNFTContainment(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "not enabled") {
		t.Fatalf("status/detail = %q/%q, want expiry timer failure", status, detail)
	}
}

func TestActionRemoveNFTRulesStopsAndRemovesExpiryUnits(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	for _, path := range []string{env.nftExpiryServicePath, env.nftExpiryTimerPath} {
		if err := os.MkdirAll(filepath.Dir(path), modeDirReadable); err != nil {
			t.Fatalf("mkdir %s: %v", path, err)
		}
		if err := os.WriteFile(path, []byte("unit"), modeUnitFile); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	for _, path := range []string{env.nftExpiryServicePath, env.nftExpiryTimerPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s must exist before rollback: %v", path, err)
		}
	}
	for _, unit := range []string{filepath.Base(env.nftExpiryTimerPath), filepath.Base(env.nftExpiryServicePath)} {
		runner.on(argvFor(testSystemctl, "is-active", unit), "inactive\n", 3, nil)
	}
	if err := actionRemoveNFTRules().undo(context.Background(), env); err != nil {
		t.Fatalf("uninstall: %v", err)
	}
	for _, path := range []string{env.nftExpiryServicePath, env.nftExpiryTimerPath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s remains after uninstall: %v", path, err)
		}
	}
	for _, unit := range []string{filepath.Base(env.nftExpiryTimerPath), filepath.Base(env.nftExpiryServicePath)} {
		found := false
		for _, call := range runner.calls {
			if call.name == testSystemctl && strings.Join(call.args, " ") == "stop "+unit {
				found = true
			}
		}
		if !found {
			t.Errorf("uninstall did not stop %s: %+v", unit, runner.calls)
		}
	}
}

func newExpiryProbeEnv(t *testing.T, timerReply, timerActiveReply, serviceReply expiryTimerReply) *probeEnv {
	t.Helper()
	tmp := t.TempDir()
	env := makeProbeEnv(t)
	env.nftPersistUnitPath = filepath.Join(tmp, "pipelock-containment-nft.service")
	env.nftExpiryServicePath = filepath.Join(tmp, "pipelock-containment-expiry.service")
	env.nftExpiryTimerPath = filepath.Join(tmp, "pipelock-containment-expiry.timer")
	env.readFile = os.ReadFile
	if err := os.WriteFile(env.nftPersistUnitPath, []byte("[Service]\n"), modeUnitFile); err != nil {
		t.Fatal(err)
	}
	installEnv := &installEnv{pipelockTarget: env.pipelockTarget, nftExpiryServicePath: env.nftExpiryServicePath}
	if err := os.WriteFile(env.nftExpiryServicePath, []byte(renderNFTExpiryService(installEnv)), modeUnitFile); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.nftExpiryTimerPath, []byte(renderNFTExpiryTimer(installEnv)), modeUnitFile); err != nil {
		t.Fatal(err)
	}
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		if name != testSystemctl || len(args) != 2 {
			return "", -1, errors.New("unexpected command")
		}
		if args[0] == "is-active" && args[1] == filepath.Base(env.nftExpiryTimerPath) {
			return timerActiveReply.out, timerActiveReply.code, timerActiveReply.err
		}
		if args[0] != "is-enabled" {
			return "", -1, errors.New("unexpected command")
		}
		switch args[1] {
		case filepath.Base(env.nftExpiryTimerPath):
			return timerReply.out, timerReply.code, timerReply.err
		case filepath.Base(env.nftExpiryServicePath):
			return serviceReply.out, serviceReply.code, serviceReply.err
		default:
			return "", -1, errors.New("unexpected unit")
		}
	}
	return env
}
