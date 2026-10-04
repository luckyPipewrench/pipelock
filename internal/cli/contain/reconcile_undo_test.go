// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// trackReconcileUnits models systemd runtime separately from the saved files.
// A failed enable can still start a socket before reporting a dependency error.
func trackReconcileUnits(env *installEnv, runner *fakeRunner, live []string, failing string) map[string]unitRuntimeState {
	states := make(map[string]unitRuntimeState)
	for _, unit := range live {
		// Socket-activated host relays are static units, not enabled services.
		enabled := strings.HasSuffix(unit, ".socket") || strings.HasSuffix(unit, "-netns.service") || unit == containedNetworkNamespaceUnit || unit == containedNamespaceForwarderUnit
		states[unit] = unitRuntimeState{enabled: enabled, active: true}
	}
	env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		out, code, err := runner.run(ctx, name, args...)
		if name != "systemctl" || len(args) < 2 {
			return out, code, err
		}
		unit := args[len(args)-1]
		state := states[unit]
		switch args[0] {
		case "is-enabled":
			if state.enabled {
				return "enabled\n", 0, nil
			}
			return "disabled\n", 1, nil
		case "is-active":
			if state.active {
				return "active\n", 0, nil
			}
			return "inactive\n", 3, nil
		case "enable":
			state.enabled = true
			if len(args) == 3 && args[1] == "--now" {
				state.active = true
				if unit == failing {
					states[unit] = state
					return "dependency failed", 1, errors.New("injected enable failure")
				}
			}
		case "disable":
			state.enabled = false
			if len(args) == 3 && args[1] == "--now" {
				state.active = false
			}
		case "stop":
			state.active = false
		case "start", "restart":
			state.active = true
		}
		states[unit] = state
		return out, code, err
	}
	return states
}

func assertReconcileUnitState(t *testing.T, states map[string]unitRuntimeState, units []string, want unitRuntimeState) {
	t.Helper()
	for _, unit := range units {
		if got := states[unit]; got != want {
			t.Errorf("runtime state of %s = %+v, want %+v", unit, got, want)
		}
	}
}

func TestPublishedReconcileUndoHonorsDeclarations(t *testing.T) {
	for _, removal := range []string{"expired", "removed"} {
		for _, tcp := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tcp=%t", removal, tcp), func(t *testing.T) {
				old := publishedTestService()
				if tcp {
					old.HostListen = "127.0.0.1:15900"
				}
				keep := publishedTestService()
				keep.Name, keep.AgentPort = "console", 5901
				fresh := publishedTestService()
				fresh.Name, fresh.AgentPort = "desktop", 5902
				env, runner := publishedInstallEnv(t, "mode: balanced\n")
				initial := []config.ContainmentPublishedService{old, keep}
				if _, err := stepInstallPublishedServices(&initial).apply(context.Background(), env); err != nil {
					t.Fatalf("initial install: %v", err)
				}
				body := "containment:\n  published_services:\n"
				if removal == "expired" {
					old.ExpiresAt = time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
					body += publishedReconcileConfigEntry(old)
				}
				body += publishedReconcileConfigEntry(keep) + publishedReconcileConfigEntry(fresh)
				if err := os.WriteFile(managedPipelockConfigPath(env), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				oldUnits := publishedRecordUnitNames(desiredPublishedServices([]config.ContainmentPublishedService{old}).Services[0])
				keepSocket := publishedServiceSockets(keep)[0]
				freshSocket := publishedServiceSockets(fresh)[0]
				states := trackReconcileUnits(env, runner, append(oldUnits, keepSocket), freshSocket)
				runner.calls = nil
				_, err := runSteps(context.Background(), env, env.out, []step{stepInstallPublishedServices(nil)})
				if err == nil || !strings.Contains(err.Error(), "injected enable failure") {
					t.Fatalf("reconcile error = %v, want injected enable failure", err)
				}
				assertReconcileUnitState(t, states, oldUnits, unitRuntimeState{})
				assertReconcileUnitState(t, states, []string{freshSocket}, unitRuntimeState{})
				assertReconcileUnitState(t, states, []string{keepSocket}, unitRuntimeState{enabled: true, active: true})
				if !runnerSaw(runner, "systemctl start "+keepSocket) {
					t.Fatal("undo did not restore the declared socket")
				}
			})
		}
	}
}

func publishedReconcileConfigEntry(service config.ContainmentPublishedService) string {
	return fmt.Sprintf("    - name: %s\n      agent_port: %d\n      operator_user: %s\n      owner: ops\n      reason: operator access\n      expires_at: %q\n      host_listen: %q\n", service.Name, service.AgentPort, service.OperatorUser, service.ExpiresAt, service.HostListen)
}

func TestLoopbackReconcileUndoHonorsDeclarations(t *testing.T) {
	for _, removal := range []string{"expired", "removed"} {
		for _, host := range []string{"127.0.0.1", "::1"} {
			t.Run(removal+"/"+host, func(t *testing.T) {
				env, runner, out := newFakeEnv(t)
				old, keep, fresh := loopbackTestService(9200), loopbackTestService(9201), loopbackTestService(9202)
				old.Host, keep.Host, fresh.Host = host, host, host
				initial := []config.ContainmentLoopbackService{old, keep}
				if _, err := stepInstallNetworkNamespaceWithServices(&initial).apply(context.Background(), env); err != nil {
					t.Fatalf("initial install: %v", err)
				}
				body := "containment:\n  loopback_services:\n"
				if removal == "expired" {
					old.ExpiresAt = time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
					body += loopbackReconcileConfigEntry(old)
				}
				body += loopbackReconcileConfigEntry(keep) + loopbackReconcileConfigEntry(fresh)
				if err := os.WriteFile(managedPipelockConfigPath(env), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				oldBase := loopbackForwarderUnitBase(old.Host, old.Port)
				keepBase := loopbackForwarderUnitBase(keep.Host, keep.Port)
				freshBase := loopbackForwarderUnitBase(fresh.Host, fresh.Port)
				oldUnits := []string{oldBase + ".socket", oldBase + ".service", oldBase + "-netns.service"}
				keptUnits := []string{keepBase + ".socket", keepBase + "-netns.service", containedProxyForwarderUnit + ".socket", containedNamespaceForwarderUnit, containedNetworkNamespaceUnit}
				states := trackReconcileUnits(env, runner, append(oldUnits, keptUnits...), freshBase+".socket")
				runner.calls = nil
				_, err := runSteps(context.Background(), env, out, []step{stepInstallNetworkNamespace()})
				if err == nil || !strings.Contains(err.Error(), "injected enable failure") {
					t.Fatalf("reconcile error = %v, want injected enable failure", err)
				}
				assertReconcileUnitState(t, states, oldUnits, unitRuntimeState{})
				assertReconcileUnitState(t, states, []string{freshBase + ".socket", freshBase + "-netns.service"}, unitRuntimeState{})
				assertReconcileUnitState(t, states, keptUnits, unitRuntimeState{enabled: true, active: true})
				for _, unit := range keptUnits {
					if !runnerSaw(runner, "systemctl start "+unit) {
						t.Errorf("undo did not restore declared unit %s", unit)
					}
				}
			})
		}
	}
}

func loopbackReconcileConfigEntry(service config.ContainmentLoopbackService) string {
	return fmt.Sprintf("    - host: %q\n      port: %d\n      owner: ops\n      reason: local service access\n      expires_at: %q\n", service.Host, service.Port, service.ExpiresAt)
}

func TestToolsListEntryRunnableUsesInjectedLookup(t *testing.T) {
	for _, runnable := range []bool{false, true} {
		t.Run(fmt.Sprintf("runnable=%t", runnable), func(t *testing.T) {
			const target = "/usr/local/bin/custom"
			env := &installEnv{toolCanExecute: func(path string) bool {
				if path != target {
					t.Fatalf("tool lookup path = %q, want %q", path, target)
				}
				return runnable
			}}
			if got := toolsListEntryRunnable(env, toolsListEntry{name: "custom", target: target}); got != runnable {
				t.Fatalf("runnable = %t, want %t", got, runnable)
			}
		})
	}
}

func TestDefaultToolFixtureDoesNotReadHostEligibility(t *testing.T) {
	for _, present := range []bool{false, true} {
		t.Run(fmt.Sprintf("present=%t", present), func(t *testing.T) {
			env, _, _ := newFakeEnv(t)
			var names []string
			if present {
				names = []string{"claude"}
			}
			plantResolvableDefaultTools(t, env, names...)
			env.lookupUser = nil
			env.lstat = func(path string) (os.FileInfo, error) {
				t.Fatalf("tool fixture consulted host metadata for %s", path)
				return nil, os.ErrNotExist
			}
			_, err := plannedToolsList(env)
			if present && err != nil {
				t.Fatalf("synthetic installed tool was refused: %v", err)
			}
			if !present && (err == nil || !strings.Contains(err.Error(), "no agent tools found")) {
				t.Fatalf("synthetic missing tool error = %v", err)
			}
		})
	}
}
