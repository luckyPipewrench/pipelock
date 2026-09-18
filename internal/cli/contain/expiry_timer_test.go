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

	const altered = "[Service]\nExecStart=/wrong/binary\n"
	if err := os.WriteFile(env.nftExpiryServicePath, []byte(altered), modeUnitFile); err != nil {
		t.Fatalf("alter service: %v", err)
	}
	changed, err = ensureNFTExpiryUnits(env)
	if err != nil {
		t.Fatalf("repair: %v", err)
	}
	if !changed {
		t.Fatal("repair reported no change")
	}
	backup, err := os.ReadFile(env.nftExpiryServicePath + ".bak")
	if err != nil {
		t.Fatalf("read repair backup: %v", err)
	}
	if string(backup) != altered {
		t.Fatalf("backup = %q, want altered service", backup)
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
		serviceReply expiryTimerReply
		wantStatus   string
		wantDetail   string
	}{
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
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newExpiryProbeEnv(t, tc.timerReply, tc.serviceReply)
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
			runner.on(argvFor(testSystemctl, "enable", filepath.Base(unit)), "permission denied", 1, nil)

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
			if call.name == testSystemctl && strings.Join(call.args, " ") == "disable --now "+unit {
				found = true
			}
		}
		if !found {
			t.Errorf("uninstall did not stop %s: %+v", unit, runner.calls)
		}
	}
}

func newExpiryProbeEnv(t *testing.T, timerReply, serviceReply expiryTimerReply) *probeEnv {
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
		if name != testSystemctl || len(args) != 2 || args[0] != "is-enabled" {
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
