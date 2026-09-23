// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestContainedNetworkNamespaceUnits(t *testing.T) {
	namespace := renderContainedNetworkNamespaceUnit()
	for _, want := range []string{
		"PrivateNetwork=true",
		"ExecStart=/usr/bin/sleep infinity",
		"ExecStartPost=/bin/sh -c '/usr/bin/readlink /proc/self/ns/net > " + containedNamespaceIdentityPath + "'",
		"RuntimeDirectory=pipelock-contain",
		"NoNewPrivileges=true",
	} {
		if !strings.Contains(namespace, want) {
			t.Fatalf("namespace unit missing %q:\n%s", want, namespace)
		}
	}

	socket := renderContainedProxySocketUnit("pipelock-agent")
	for _, want := range []string{
		"ListenStream=" + containedDoorwaySocketPath,
		"SocketMode=0660",
		"SocketGroup=pipelock-agent",
		"RemoveOnStop=true",
		"WantedBy=sockets.target",
	} {
		if !strings.Contains(socket, want) {
			t.Fatalf("socket unit missing %q:\n%s", want, socket)
		}
	}
	// systemd.socket(5): every .socket listener is allocated in the HOST
	// network namespace. Asking for one inside the agent namespace is what
	// made an earlier revision fail at install, so these must stay absent.
	for _, forbidden := range []string{"PrivateNetwork=true", "JoinsNamespaceOf=", "ListenStream=127.0.0.1"} {
		if strings.Contains(socket, forbidden) {
			t.Fatalf("socket unit must not contain %q; a .socket listener is always host-namespace:\n%s", forbidden, socket)
		}
	}

	nsForward := renderContainedNamespaceForwarderUnit("/usr/local/bin/pipelock", "pipelock-agent", 8888)
	for _, want := range []string{
		"JoinsNamespaceOf=" + containedNetworkNamespaceUnit,
		"PrivateNetwork=true",
		"ExecStart=/usr/local/bin/pipelock contain netns-forward --listen 127.0.0.1:8888 --target " + containedDoorwaySocketPath,
		"User=pipelock-agent",
	} {
		if !strings.Contains(nsForward, want) {
			t.Fatalf("namespace forwarder unit missing %q:\n%s", want, nsForward)
		}
	}

	service := renderContainedProxyForwarderUnit("/usr/local/bin/pipelock", "pipelock-proxy", 8888)
	for _, want := range []string{
		"User=pipelock-proxy",
		"Group=pipelock-proxy",
		"ExecStart=/usr/local/bin/pipelock contain netns-forward --systemd-listener --target-tcp 127.0.0.1:8888",
		"Requires=pipelock.service",
	} {
		if !strings.Contains(service, want) {
			t.Fatalf("forwarder service missing %q:\n%s", want, service)
		}
	}
	if strings.Contains(service, "PrivateNetwork=true") {
		t.Fatal("forwarder service must stay in the host namespace so its outbound dial reaches the host proxy")
	}
}

func TestContainedNetworkNamespaceUnitsPassSystemdVerify(t *testing.T) {
	if _, err := exec.LookPath("systemd-analyze"); err != nil {
		t.Skip("systemd-analyze is unavailable")
	}
	dir := t.TempDir()
	units := map[string]string{
		containedNetworkNamespaceUnit:            renderContainedNetworkNamespaceUnit(),
		containedProxyForwarderUnit + ".socket":  renderContainedProxySocketUnit("pipelock-agent"),
		containedProxyForwarderUnit + ".service": renderContainedProxyForwarderUnit("/usr/local/bin/pipelock", "pipelock-proxy", 8888),
		containedNamespaceForwarderUnit:          renderContainedNamespaceForwarderUnit("/usr/local/bin/pipelock", "pipelock-agent", 8888),
		"pipelock.service":                       "[Service]\nType=simple\nExecStart=/usr/bin/sleep infinity\n",
	}
	// Every unit the installer writes belongs here, including the per-service
	// declared-loopback set. Leaving those out is what let a malformed socket
	// unit reach a real install twice: the proxy units were covered and the
	// declared ones were not.
	declared := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9200}
	declaredBase := loopbackForwarderUnitBase(declared.Host, declared.Port)
	units[declaredBase+".socket"] = renderDeclaredLoopbackSocketUnit("pipelock-agent", declared)
	units[declaredBase+".service"] = renderDeclaredLoopbackForwarderUnit("/usr/local/bin/pipelock", "pipelock-proxy", declared)
	units[declaredBase+"-netns.service"] = renderDeclaredLoopbackNamespaceForwarderUnit("/usr/local/bin/pipelock", "pipelock-agent", declared)
	paths := make([]string, 0, len(units))
	for name, body := range units {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	cmd := exec.CommandContext(context.Background(), "systemd-analyze", append([]string{"verify"}, paths...)...) //nolint:gosec // fixed executable and test-owned paths
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("systemd-analyze verify: %v\n%s", err, out)
	}
}

func TestInstallNetworkNamespaceWarnsWhenDeclaredHostListenerIsUnavailable(t *testing.T) {
	env, _, out := newFakeEnv(t)
	env.dialCtx = func(_ context.Context, network, address string, timeout time.Duration) (net.Conn, error) {
		if network != "tcp" || address != "127.0.0.1:9222" || timeout != loopbackHostProbeTimeout {
			t.Fatalf("dial = (%q, %q, %s)", network, address, timeout)
		}
		return nil, errors.New("connection refused")
	}
	configPath := filepath.Join(env.configDir, "pipelock.yaml")
	configBody := "containment:\n  loopback_services:\n    - host: 127.0.0.1\n      port: 9222\n" +
		"      owner: browser-team\n      reason: browser control\n      expires_at: " + futureExpiryForTest + "\n"
	if err := os.WriteFile(configPath, []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := stepInstallNetworkNamespace().apply(context.Background(), env); err != nil {
		t.Fatalf("install network namespace: %v", err)
	}
	warning := out.String()
	for _, want := range []string{
		"WARNING: containment.loopback_services entry 127.0.0.1:9222 has no reachable host TCP listener",
		"Pipelock will still reserve 127.0.0.1:9222 inside the agent namespace",
		"Remove this entry if the contained tool owns that port",
	} {
		if !strings.Contains(warning, want) {
			t.Fatalf("warning missing %q:\n%s", want, warning)
		}
	}
}

func TestHostListenerWarningSkipsUnavailableProbeAndCanceledContext(t *testing.T) {
	service := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9200}
	var warnings []string
	warn := func(message string) { warnings = append(warnings, message) }

	warnUnavailableHostLoopbackServices(context.Background(), []config.ContainmentLoopbackService{service}, nil, warn)
	warnUnavailableHostLoopbackServices(context.Background(), []config.ContainmentLoopbackService{service}, func(context.Context, string, string, time.Duration) (net.Conn, error) {
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}, warn)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	warnUnavailableHostLoopbackServices(ctx, []config.ContainmentLoopbackService{service}, func(context.Context, string, string, time.Duration) (net.Conn, error) {
		return nil, context.Canceled
	}, warn)

	if len(warnings) != 0 {
		t.Fatalf("warnings = %v, want none when probing is unavailable or canceled", warnings)
	}
}

func TestInstallNetworkNamespaceRollbackAfterStartFailure(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	socketUnit := filepath.Base(env.proxyForwarderSocketPath)
	runner.on(argvFor("systemctl", "enable", "--now", socketUnit), "dependency failed", 1, nil)

	steps := []step{stepInstallNetworkNamespace()}
	_, err := runSteps(context.Background(), env, out, steps)
	if err == nil || !strings.Contains(err.Error(), "enable contained namespace socket") {
		t.Fatalf("runSteps error = %v, want socket start failure", err)
	}
	for _, path := range []string{
		env.networkNamespaceUnitPath,
		env.proxyForwarderSocketPath,
		env.proxyForwarderServicePath,
	} {
		if _, statErr := os.Stat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s survived failed-install rollback: %v", path, statErr)
		}
	}
	if !strings.Contains(out.String(), "undo install-agent-network-namespace") {
		t.Fatalf("rollback output missing namespace undo:\n%s", out.String())
	}
}

func TestInstallNetworkNamespaceRestartsUpdatedNamespaceAndForwarders(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	service := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9222}
	unit := loopbackForwarderUnitBase(service.Host, service.Port)
	inv, err := json.Marshal(desiredLoopbackForwarders([]config.ContainmentLoopbackService{service}))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(env.loopbackForwarderInvPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.loopbackForwarderInvPath, inv, 0o600); err != nil {
		t.Fatal(err)
	}
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	oldBodies := map[string]string{
		env.networkNamespaceUnitPath:                  "old namespace unit\n",
		env.namespaceForwarderServicePath:             "old namespace forwarder\n",
		filepath.Join(unitDir, unit+"-netns.service"): "old declared namespace forwarder\n",
	}
	for path, body := range oldBodies {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Base(env.networkNamespaceUnitPath), containedNamespaceForwarderUnit, unit + "-netns.service"} {
		runner.on(argvFor(testSystemctl, "is-enabled", name), "enabled\n", 0, nil)
		runner.on(argvFor(testSystemctl, "is-active", name), "active\n", 0, nil)
	}
	laterFailure := step{
		name: "later-failure",
		desc: "force namespace rollback",
		apply: func(context.Context, *installEnv) (bool, error) {
			return false, errors.New("later install failed")
		},
	}
	services := []config.ContainmentLoopbackService{service}
	_, err = runSteps(context.Background(), env, out, []step{stepInstallNetworkNamespaceWithServices(&services), laterFailure})
	if err == nil || !strings.Contains(err.Error(), "later install failed") {
		t.Fatalf("runSteps error = %v", err)
	}
	for _, name := range []string{filepath.Base(env.networkNamespaceUnitPath), containedNamespaceForwarderUnit, unit + "-netns.service"} {
		if !fakeRunnerCalled(runner, "systemctl restart "+name) {
			t.Fatalf("updated active unit %s was not restarted: %v", name, runner.calls)
		}
		if !fakeRunnerCalled(runner, "systemctl start "+name) {
			t.Fatalf("rollback did not restore active unit %s: %v", name, runner.calls)
		}
	}
	for path, want := range oldBodies {
		got, readErr := os.ReadFile(filepath.Clean(path)) //nolint:gosec // test-owned unit path
		if readErr != nil || string(got) != want {
			t.Fatalf("rollback restored %s = %q, %v; want %q", path, got, readErr, want)
		}
	}
}

func TestInstallNetworkNamespaceRetiresAndRestoresLegacyAnchor(t *testing.T) {
	t.Run("successful replacement retires legacy anchor", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		legacyBody := "[Service]\nSlice=pipelock_contained.slice\n"
		if err := os.WriteFile(env.ownedLoopbackAnchorUnitPath, []byte(legacyBody), 0o600); err != nil {
			t.Fatal(err)
		}
		changed, err := stepInstallNetworkNamespace().apply(context.Background(), env)
		if err != nil || !changed {
			t.Fatalf("apply = (%t, %v), want changed", changed, err)
		}
		if _, err := os.Stat(env.ownedLoopbackAnchorUnitPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("legacy anchor survived successful replacement: %v", err)
		}
		if body, err := os.ReadFile(env.ownedLoopbackAnchorUnitPath + ".bak"); err != nil || string(body) != legacyBody {
			t.Fatalf("legacy rollback backup = %q, %v", body, err)
		}
		want := "systemctl disable --now " + filepath.Base(env.ownedLoopbackAnchorUnitPath)
		if !fakeRunnerCalled(runner, want) {
			t.Fatalf("legacy anchor was not disabled: %v", runner.calls)
		}
	})

	t.Run("later install failure restores legacy anchor state", func(t *testing.T) {
		env, runner, out := newFakeEnv(t)
		legacyBody := "[Service]\nSlice=pipelock_contained.slice\n"
		if err := os.WriteFile(env.ownedLoopbackAnchorUnitPath, []byte(legacyBody), 0o600); err != nil {
			t.Fatal(err)
		}
		legacyUnit := filepath.Base(env.ownedLoopbackAnchorUnitPath)
		runner.on(argvFor("systemctl", "is-enabled", legacyUnit), "enabled\n", 0, nil)
		runner.on(argvFor("systemctl", "is-active", legacyUnit), "active\n", 0, nil)
		laterFailure := step{
			name: "later-failure",
			desc: "fail after namespace replacement",
			apply: func(context.Context, *installEnv) (bool, error) {
				return false, errors.New("later install failed")
			},
		}
		_, err := runSteps(context.Background(), env, out, []step{stepInstallNetworkNamespace(), laterFailure})
		if err == nil || !strings.Contains(err.Error(), "later install failed") {
			t.Fatalf("runSteps error = %v", err)
		}
		body, readErr := os.ReadFile(env.ownedLoopbackAnchorUnitPath)
		if readErr != nil || string(body) != legacyBody {
			t.Fatalf("restored legacy anchor = %q, %v", body, readErr)
		}
		for _, call := range []string{"systemctl enable " + legacyUnit, "systemctl start " + legacyUnit} {
			if !fakeRunnerCalled(runner, call) {
				t.Fatalf("missing legacy state restoration %q: %v", call, runner.calls)
			}
		}
	})
}

func fakeRunnerCalled(runner *fakeRunner, want string) bool {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	for _, call := range runner.calls {
		if call.name+" "+strings.Join(call.args, " ") == want {
			return true
		}
	}
	return false
}

func TestContainedLaunchWrapperJoinsPrivateNetworkNamespace(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	body := renderContainedLaunchWrapper(env)
	for _, want := range []string{
		"--property=PrivateTmp=true",
		"--property=PrivateNetwork=true",
		"--property=JoinsNamespaceOf='" + containedNetworkNamespaceUnit + "'",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("contained launch wrapper missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "--slice=") {
		t.Fatal("contained launch wrapper still selects the superseded cgroup slice")
	}
}

// TestContainedLaunchWrapperBindsConfiguredDisplaySocket covers the other
// launch path the private /tmp change must protect: the sudoers-invoked plk-contained-launch
// wrapper. Isolation (PrivateTmp) and the display-socket bind must both be
// present together when a display is configured, and PrivateTmp must ship
// with NO bind when it is not - so a fresh install with display provisioning
// left off never carves an extra read path out of a supposedly private /tmp.
func TestContainedLaunchWrapperBindsConfiguredDisplaySocket(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.displayEnabled = true
	env.displayNumber = 99
	body := renderContainedLaunchWrapper(env)
	if !strings.Contains(body, "--property=PrivateTmp=true") {
		t.Fatalf("contained launch wrapper missing PrivateTmp isolation:\n%s", body)
	}
	if !strings.Contains(body, "--property=BindReadOnlyPaths=/tmp/.X11-unix/X99") {
		t.Fatalf("contained launch wrapper missing display socket bind:\n%s", body)
	}
}

func TestContainedLaunchWrapperNoDisplayNoBind(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	env.displayEnabled = false
	body := renderContainedLaunchWrapper(env)
	if !strings.Contains(body, "--property=PrivateTmp=true") {
		t.Fatalf("contained launch wrapper missing PrivateTmp isolation:\n%s", body)
	}
	if strings.Contains(body, "BindReadOnlyPaths") {
		t.Fatalf("contained launch wrapper bound a display socket with no display configured:\n%s", body)
	}
}

func TestProbeAgentNetworkNamespace(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		agentNamespace       string
		boundaryStatus       string
		missingNamespaceUnit bool
		doorwayState         string
		doorwayEnabled       string
		wantStatus           string
		wantDetail           string
	}{
		{
			name:           "private and boundary passes",
			agentNamespace: "net:[200]",
			boundaryStatus: statusPass,
			wantStatus:     statusPass,
			wantDetail:     "boundary passed",
		},
		{
			name:                 "namespace unit is missing",
			agentNamespace:       "net:[200]",
			boundaryStatus:       statusPass,
			missingNamespaceUnit: true,
			wantStatus:           statusFail,
			wantDetail:           "read contained network namespace unit",
		},
		{
			name:           "anchor still uses host namespace",
			agentNamespace: "net:[100]",
			boundaryStatus: statusPass,
			wantStatus:     statusFail,
			wantDetail:     "host network namespace",
		},
		{
			name:           "host loopback boundary fails",
			agentNamespace: "net:[200]",
			boundaryStatus: statusFail,
			wantStatus:     statusFail,
			wantDetail:     "host loopback reachable",
		},
		{
			name:           "failed doorway socket names the reset and start remedy",
			agentNamespace: "net:[200]",
			boundaryStatus: statusPass,
			doorwayState:   "failed",
			wantStatus:     statusFail,
			wantDetail:     "systemctl reset-failed pipelock-agent-proxy.socket && systemctl start pipelock-agent-proxy.socket",
		},
		{
			name:           "disabled doorway socket names the enable remedy",
			agentNamespace: "net:[200]",
			boundaryStatus: statusPass,
			doorwayEnabled: "disabled",
			wantStatus:     statusFail,
			wantDetail:     "systemctl enable --now pipelock-agent-proxy.socket",
		},
		{
			name:           "runtime-only enabled doorway socket is not persistent",
			agentNamespace: "net:[200]",
			boundaryStatus: statusPass,
			doorwayEnabled: "enabled-runtime",
			wantStatus:     statusFail,
			wantDetail:     "not persistently enabled",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			env := &probeEnv{
				port:                          8888,
				proxyUserName:                 "pipelock-proxy",
				agentUserName:                 "pipelock-agent",
				networkNamespaceUnitPath:      filepath.Join(root, containedNetworkNamespaceUnit),
				proxyForwarderSocketPath:      filepath.Join(root, containedProxyForwarderUnit+".socket"),
				proxyForwarderServicePath:     filepath.Join(root, containedProxyForwarderUnit+".service"),
				namespaceForwarderServicePath: filepath.Join(root, containedNamespaceForwarderUnit),
				loopbackForwarderInvPath:      filepath.Join(root, "loopback-forwarders.json"),
				readFile:                      os.ReadFile,
			}
			for path, body := range map[string]string{
				env.networkNamespaceUnitPath:      renderContainedNetworkNamespaceUnit(),
				env.proxyForwarderSocketPath:      renderContainedProxySocketUnit(env.agentUserName),
				env.proxyForwarderServicePath:     renderContainedProxyForwarderUnit(env.pipelockTarget, env.proxyUserName, env.port),
				env.namespaceForwarderServicePath: renderContainedNamespaceForwarderUnit(env.pipelockTarget, env.agentUserName, env.port),
			} {
				if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tt.missingNamespaceUnit {
				if err := os.Remove(env.networkNamespaceUnitPath); err != nil {
					t.Fatal(err)
				}
			}
			emptyInventory, err := json.MarshalIndent(desiredLoopbackForwarders(nil), "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			emptyInventory = append(emptyInventory, '\n')
			if err := os.WriteFile(env.loopbackForwarderInvPath, emptyInventory, 0o600); err != nil {
				t.Fatal(err)
			}
			env.runCmd = func(_ context.Context, _ string, args ...string) (string, int, error) {
				joined := strings.Join(args, " ")
				switch {
				case strings.HasPrefix(joined, "is-enabled "):
					if tt.doorwayEnabled != "" && strings.HasSuffix(joined, filepath.Base(env.proxyForwarderSocketPath)) {
						return tt.doorwayEnabled + "\n", 0, nil
					}
					return systemctlEnabled + "\n", 0, nil
				case strings.HasPrefix(joined, "is-active "):
					if tt.doorwayState != "" && strings.HasSuffix(joined, filepath.Base(env.proxyForwarderSocketPath)) {
						return tt.doorwayState + "\n", 3, nil
					}
					return systemctlActive + "\n", 0, nil
				case strings.HasPrefix(joined, "show "):
					return "4242\n", 0, nil
				default:
					return "", 1, nil
				}
			}
			env.readLink = func(path string) (string, error) {
				if path == "/proc/1/ns/net" {
					return "net:[100]", nil
				}
				return tt.agentNamespace, nil
			}
			env.networkNamespaceProbe = func(context.Context, *probeEnv) (string, string) {
				return tt.boundaryStatus, map[string]string{
					statusPass: "boundary passed",
					statusFail: "host loopback reachable",
				}[tt.boundaryStatus]
			}
			env.agentProcessNetnsProbe = func(context.Context, *probeEnv, string) (string, string) {
				return statusPass, "live agent processes use managed namespace"
			}

			status, detail := probeAgentNetworkNamespace(context.Background(), env)
			if status != tt.wantStatus || !strings.Contains(detail, tt.wantDetail) {
				t.Fatalf("probeAgentNetworkNamespace() = (%q, %q), want status %q detail containing %q", status, detail, tt.wantStatus, tt.wantDetail)
			}
		})
	}
}

func TestProbeNetworkNamespaceBoundary(t *testing.T) {
	for _, tt := range []struct {
		name        string
		codes       []int
		wantStatus  string
		wantDetail  string
		wantCmdRuns int
	}{
		{
			name:        "host loopback reachable fails",
			codes:       []int{0},
			wantStatus:  statusFail,
			wantDetail:  "reached host loopback canary",
			wantCmdRuns: 1,
		},
		{
			name:        "proxy unreachable fails",
			codes:       []int{7, 7},
			wantStatus:  statusFail,
			wantDetail:  "cannot reach the proxy socket",
			wantCmdRuns: 2,
		},
		{
			name:        "isolated namespace reaches proxy",
			codes:       []int{7, 0},
			wantStatus:  statusPass,
			wantDetail:  "cannot reach host loopback and can reach",
			wantCmdRuns: 2,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			env := &probeEnv{
				port:          8888,
				curlPath:      "/usr/bin/curl",
				agentUserName: "pipelock-agent",
				runCmd: func(_ context.Context, name string, args ...string) (string, int, error) {
					if name != systemdRunPath {
						t.Fatalf("command = %q, want %q", name, systemdRunPath)
					}
					joined := strings.Join(args, " ")
					for _, want := range []string{
						"--property=PrivateNetwork=true",
						"--property=JoinsNamespaceOf=" + containedNetworkNamespaceUnit,
						"--uid=pipelock-agent",
					} {
						if !strings.Contains(joined, want) {
							t.Fatalf("namespace probe command missing %q: %s", want, joined)
						}
					}
					if calls >= len(tt.codes) {
						t.Fatalf("unexpected command %d: %s", calls+1, joined)
					}
					code := tt.codes[calls]
					calls++
					return "probe output", code, nil
				},
			}

			status, detail := probeNetworkNamespaceBoundary(context.Background(), env)
			if status != tt.wantStatus || !strings.Contains(detail, tt.wantDetail) {
				t.Fatalf("probeNetworkNamespaceBoundary() = (%q, %q), want status %q detail containing %q", status, detail, tt.wantStatus, tt.wantDetail)
			}
			if calls != tt.wantCmdRuns {
				t.Fatalf("command runs = %d, want %d", calls, tt.wantCmdRuns)
			}
		})
	}
}

func TestProbeAgentProcessNamespaces(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		namespaces map[string]string
		cgroups    map[string]string
		unitBody   string
		wantStatus string
		wantDetail string
	}{
		{
			name:       "all agent processes use anchor",
			namespaces: map[string]string{"101": "net:[200]", "102": "net:[200]"},
			wantStatus: statusPass,
			wantDetail: "2 live pipelock-agent process(es)",
		},
		{
			name:       "one stale service uses host namespace",
			namespaces: map[string]string{"101": "net:[200]", "102": "net:[100]"},
			wantStatus: statusFail,
			wantDetail: "pid 102",
		},
		{
			name:       "managed display unit in host namespace is accounted for",
			namespaces: map[string]string{"101": "net:[200]", "103": "net:[100]"},
			cgroups:    map[string]string{"103": "0::/system.slice/pipelock-agent-display.service\n"},
			unitBody:   renderAgentDisplayUnit(&installEnv{agentUserName: "pipelock-agent", displayNumber: 99, xvfbPath: "/usr/bin/Xvfb"}),
			wantStatus: statusPass,
			wantDetail: "2 live pipelock-agent process(es)",
		},
		{
			name:       "display-named unit that is not the managed unit still fails",
			namespaces: map[string]string{"101": "net:[200]", "103": "net:[100]"},
			cgroups:    map[string]string{"103": "0::/system.slice/pipelock-agent-display.service\n"},
			unitBody:   "[Service]\nUser=pipelock-agent\nExecStart=/usr/bin/Xvfb :99\n",
			wantStatus: statusFail,
			wantDetail: "pid 103 (pipelock-agent-display.service)",
		},
		{
			name:       "managed display unit file does not cover another unit",
			namespaces: map[string]string{"101": "net:[200]", "104": "net:[100]"},
			cgroups:    map[string]string{"104": "0::/user.slice/user-987.slice/user@987.service/init.scope\n"},
			unitBody:   renderAgentDisplayUnit(&installEnv{agentUserName: "pipelock-agent", displayNumber: 99, xvfbPath: "/usr/bin/Xvfb"}),
			wantStatus: statusFail,
			wantDetail: "pid 104 (init.scope)",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			procRoot := t.TempDir()
			for pid, namespace := range tc.namespaces {
				pidRoot := filepath.Join(procRoot, pid)
				if err := os.MkdirAll(filepath.Join(pidRoot, "ns"), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(pidRoot, "status"), []byte("Name:\tagent\nUid:\t987\t987\t987\t987\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(pidRoot, "stat"), procStatFixture(pid, "12345"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(namespace, filepath.Join(pidRoot, "ns", "net")); err != nil {
					t.Fatal(err)
				}
				if cgroup, ok := tc.cgroups[pid]; ok {
					if err := os.WriteFile(filepath.Join(pidRoot, "cgroup"), []byte(cgroup), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			unitPath := filepath.Join(procRoot, "pipelock-agent-display.service")
			if tc.unitBody != "" {
				if err := os.WriteFile(unitPath, []byte(tc.unitBody), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			otherRoot := filepath.Join(procRoot, "201")
			if err := os.MkdirAll(otherRoot, 0o750); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(otherRoot, "status"), []byte("Uid:\t1000\t1000\t1000\t1000\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			env := &probeEnv{
				agentUserName:   "pipelock-agent",
				procRoot:        procRoot,
				displayUnitPath: unitPath,
				lookupUser: func(string) (*user.User, error) {
					return &user.User{Uid: "987", Username: "pipelock-agent"}, nil
				},
				readDir:  os.ReadDir,
				readFile: os.ReadFile,
				readLink: os.Readlink,
			}
			status, detail := probeAgentProcessNamespaces(context.Background(), env, "net:[200]")
			if status != tc.wantStatus || !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("probeAgentProcessNamespaces() = (%q, %q), want status %q detail containing %q", status, detail, tc.wantStatus, tc.wantDetail)
			}
		})
	}
}

func TestProbeAgentProcessNamespacesFailsClosed(t *testing.T) {
	t.Parallel()

	base := func() *probeEnv {
		return &probeEnv{
			agentUserName: "pipelock-agent",
			procRoot:      "/proc",
			lookupUser: func(string) (*user.User, error) {
				return &user.User{Uid: "987", Username: "pipelock-agent"}, nil
			},
			readDir: func(string) ([]os.DirEntry, error) { return nil, nil },
		}
	}

	for _, tc := range []struct {
		name    string
		mutate  func(*probeEnv)
		wantErr string
	}{
		{name: "user lookup", mutate: func(env *probeEnv) {
			env.lookupUser = func(string) (*user.User, error) { return nil, errors.New("lookup failed") }
		}, wantErr: "lookup failed"},
		{name: "invalid uid", mutate: func(env *probeEnv) {
			env.lookupUser = func(string) (*user.User, error) { return &user.User{Uid: "bad"}, nil }
		}, wantErr: "invalid uid"},
		{name: "process listing", mutate: func(env *probeEnv) {
			env.readDir = func(string) ([]os.DirEntry, error) { return nil, errors.New("listing failed") }
		}, wantErr: "listing failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := base()
			tc.mutate(env)
			status, detail := probeAgentProcessNamespaces(context.Background(), env, "net:[200]")
			if status != statusFail || !strings.Contains(detail, tc.wantErr) {
				t.Fatalf("probeAgentProcessNamespaces() = (%q, %q), want failure containing %q", status, detail, tc.wantErr)
			}
		})
	}
}

func TestProbeAgentProcessNamespacesSkipsRecycledPID(t *testing.T) {
	t.Parallel()

	procRoot := t.TempDir()
	pidRoot := filepath.Join(procRoot, "101")
	if err := os.MkdirAll(filepath.Join(pidRoot, "ns"), 0o750); err != nil {
		t.Fatal(err)
	}
	status := []byte("Name:\tagent\nUid:\t987\t987\t987\t987\n")
	if err := os.WriteFile(filepath.Join(pidRoot, "status"), status, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:[200]", filepath.Join(pidRoot, "ns", "net")); err != nil {
		t.Fatal(err)
	}
	statReads := 0
	env := &probeEnv{
		agentUserName: "pipelock-agent",
		procRoot:      procRoot,
		lookupUser: func(string) (*user.User, error) {
			return &user.User{Uid: "987", Username: "pipelock-agent"}, nil
		},
		readDir: os.ReadDir,
		readFile: func(path string) ([]byte, error) {
			if strings.HasSuffix(path, "/stat") {
				statReads++
				return procStatFixture("101", strconv.Itoa(100+statReads)), nil
			}
			return os.ReadFile(path) //nolint:gosec // fixture paths stay under t.TempDir
		},
		readLink: os.Readlink,
	}

	gotStatus, detail := probeAgentProcessNamespaces(context.Background(), env, "net:[200]")
	if gotStatus != statusPass || !strings.Contains(detail, "0 live pipelock-agent process(es)") {
		t.Fatalf("probeAgentProcessNamespaces() = (%q, %q), want recycled pid skipped", gotStatus, detail)
	}
}

func TestEffectiveUIDFromProcStatus(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		status  string
		want    int
		wantErr string
	}{
		{name: "valid", status: "Name:\tagent\nUid:\t987\t988\t989\t990\n", want: 988},
		{name: "missing", status: "Name:\tagent\n", wantErr: "missing Uid"},
		{name: "wrong field count", status: "Uid:\t987\t988\n", wantErr: "malformed Uid"},
		{name: "invalid effective uid", status: "Uid:\t987\tbad\t989\t990\n", wantErr: "malformed effective uid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := effectiveUIDFromProcStatus([]byte(tc.status))
			if tc.wantErr == "" {
				if err != nil || got != tc.want {
					t.Fatalf("effectiveUIDFromProcStatus() = (%d, %v), want (%d, nil)", got, err, tc.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("effectiveUIDFromProcStatus() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestProcessStartTimeFromProcStat(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		stat    []byte
		want    string
		wantErr string
	}{
		{name: "valid with spaces and parenthesis in command", stat: procStatFixture("101", "12345"), want: "12345"},
		{name: "missing command terminator", stat: []byte("101 agent"), wantErr: "missing command terminator"},
		{name: "missing start time", stat: []byte("101 (agent) S 0"), wantErr: "missing start time"},
		{name: "invalid start time", stat: procStatFixture("101", "invalid"), wantErr: "malformed stat start time"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := processStartTimeFromProcStat(tc.stat)
			if tc.wantErr == "" {
				if err != nil || got != tc.want {
					t.Fatalf("processStartTimeFromProcStat() = (%q, %v), want (%q, nil)", got, err, tc.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("processStartTimeFromProcStat() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func procStatFixture(pid, startTime string) []byte {
	return []byte(pid + " (agent worker)) S" + strings.Repeat(" 0", 18) + " " + startTime + "\n")
}

func TestDeclaredLoopbackForwardersInstallAndRevoke(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	configPath := filepath.Join(env.configDir, "pipelock.yaml")
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	operatorServicePath := filepath.Join(unitDir, loopbackForwarderUnitBase("127.0.0.1", 9200)+".service")
	operatorServiceBody := "[Service]\nExecStart=/usr/local/bin/operator-owned-listener\n"
	if err := os.WriteFile(operatorServicePath, []byte(operatorServiceBody), 0o600); err != nil {
		t.Fatal(err)
	}
	configured := `containment:
  loopback_services:
    - host: 127.0.0.1
      port: 9200
      owner: search-team
      reason: local retrieval
      expires_at: ` + futureExpiryForTest + `
    - host: ::1
      port: 9300
      owner: index-team
      reason: local index
      expires_at: ` + futureExpiryForTest + `
`
	if err := os.WriteFile(configPath, []byte(configured), 0o600); err != nil {
		t.Fatal(err)
	}
	install := stepInstallNetworkNamespace()
	changed, err := install.apply(context.Background(), env)
	if err != nil || !changed {
		t.Fatalf("install declared forwarders = (%t, %v), want changed", changed, err)
	}
	for _, name := range []string{
		loopbackForwarderUnitBase("127.0.0.1", 9200) + ".socket",
		loopbackForwarderUnitBase("127.0.0.1", 9200) + ".service",
		loopbackForwarderUnitBase("::1", 9300) + ".socket",
		loopbackForwarderUnitBase("::1", 9300) + ".service",
	} {
		if _, err := os.Stat(filepath.Join(unitDir, name)); err != nil {
			t.Fatalf("declared forwarder %s: %v", name, err)
		}
	}
	inv, err := readLoopbackForwarderInventory(env)
	if err != nil || len(inv.Services) != 2 {
		t.Fatalf("forwarder inventory = (%+v, %v), want two services", inv, err)
	}

	if err := os.WriteFile(configPath, []byte("containment:\n  loopback_services: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	revoke := stepInstallNetworkNamespace()
	changed, err = revoke.apply(context.Background(), env)
	if err != nil || !changed {
		t.Fatalf("revoke declared forwarders = (%t, %v), want changed", changed, err)
	}
	for _, name := range []string{
		loopbackForwarderUnitBase("127.0.0.1", 9200) + ".socket",
		loopbackForwarderUnitBase("127.0.0.1", 9200) + ".service",
		loopbackForwarderUnitBase("::1", 9300) + ".socket",
		loopbackForwarderUnitBase("::1", 9300) + ".service",
	} {
		if filepath.Join(unitDir, name) == operatorServicePath {
			continue
		}
		if _, err := os.Stat(filepath.Join(unitDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("revoked forwarder %s survived: %v", name, err)
		}
	}
	inv, err = readLoopbackForwarderInventory(env)
	if err != nil || len(inv.Services) != 0 {
		t.Fatalf("revoked inventory = (%+v, %v), want empty", inv, err)
	}
	if restored, err := os.ReadFile(filepath.Clean(operatorServicePath)); err != nil || string(restored) != operatorServiceBody { //nolint:gosec // test-owned temporary path
		t.Fatalf("operator-owned unit was not restored after revoke: body=%q err=%v", restored, err)
	}
}

func TestDeclaredLoopbackForwarderRevokeRollsBack(t *testing.T) {
	env, _, out := newFakeEnv(t)
	configPath := filepath.Join(env.configDir, "pipelock.yaml")
	service := config.ContainmentLoopbackService{
		Host:      "127.0.0.1",
		Port:      9200,
		Owner:     "search-team",
		Reason:    "local retrieval",
		ExpiresAt: futureExpiryForTest,
	}
	configured := `containment:
  loopback_services:
    - host: 127.0.0.1
      port: 9200
      owner: search-team
      reason: local retrieval
      expires_at: ` + futureExpiryForTest + `
`
	if err := os.WriteFile(configPath, []byte(configured), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stepInstallNetworkNamespace().apply(context.Background(), env); err != nil {
		t.Fatalf("install declared forwarder: %v", err)
	}
	if err := os.WriteFile(configPath, []byte("containment:\n  loopback_services: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	laterFailure := step{
		name: "later-failure",
		desc: "fail after revoking a forwarder",
		apply: func(context.Context, *installEnv) (bool, error) {
			return false, errors.New("later install failed")
		},
	}
	_, err := runSteps(context.Background(), env, out, []step{stepInstallNetworkNamespace(), laterFailure})
	if err == nil || !strings.Contains(err.Error(), "later install failed") {
		t.Fatalf("runSteps error = %v", err)
	}
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	servicePath := filepath.Join(unitDir, loopbackForwarderUnitBase(service.Host, service.Port)+".service")
	body, readErr := os.ReadFile(filepath.Clean(servicePath)) //nolint:gosec // test-owned temporary path
	if readErr != nil || string(body) != renderDeclaredLoopbackForwarderUnit(env.pipelockTarget, env.proxyUserName, service) {
		t.Fatalf("managed forwarder was not reconstructed after rollback: body=%q err=%v", body, readErr)
	}
	inv, invErr := readLoopbackForwarderInventory(env)
	if invErr != nil || len(inv.Services) != 1 || inv.Services[0].Port != service.Port {
		t.Fatalf("forwarder inventory was not restored after rollback: inv=%+v err=%v", inv, invErr)
	}
}

func TestDeclaredLoopbackForwarderUnits(t *testing.T) {
	for _, service := range []config.ContainmentLoopbackService{
		{Host: "127.0.0.1", Port: 9200},
		{Host: "::1", Port: 9300},
	} {
		socket := renderDeclaredLoopbackSocketUnit("pipelock-agent", service)
		forwarder := renderDeclaredLoopbackForwarderUnit("/usr/local/bin/pipelock", "pipelock-proxy", service)
		nsForwarder := renderDeclaredLoopbackNamespaceForwarderUnit("/usr/local/bin/pipelock", "pipelock-agent", service)
		address := systemdListenAddress(service.Host, service.Port)
		doorway := declaredLoopbackDoorwayPath(service.Host, service.Port)

		// The host doorway is a pathname unix socket. This test previously
		// required JoinsNamespaceOf= here and called that "binds inside
		// namespace", which systemd.socket(5) says is impossible: every
		// .socket listener is allocated in the host network namespace. The
		// install failed on exactly that.
		if !strings.Contains(socket, "ListenStream="+doorway) {
			t.Fatalf("declared socket for %+v does not open its host doorway:\n%s", service, socket)
		}
		for _, forbidden := range []string{"PrivateNetwork=true", "JoinsNamespaceOf=", "ListenStream=" + address} {
			if strings.Contains(socket, forbidden) {
				t.Fatalf("declared socket for %+v must not contain %q; a .socket listener is always host-namespace:\n%s", service, forbidden, socket)
			}
		}
		if !strings.Contains(forwarder, "--systemd-listener --target-tcp "+address) || strings.Contains(forwarder, "PrivateNetwork=true") {
			t.Fatalf("declared forwarder for %+v cannot bridge to host:\n%s", service, forwarder)
		}
		// The in-namespace listener is a service, which is the only unit type
		// whose processes JoinsNamespaceOf= actually moves.
		for _, want := range []string{
			"JoinsNamespaceOf=" + containedNetworkNamespaceUnit,
			"PrivateNetwork=true",
			"ExecStart=/usr/local/bin/pipelock contain netns-forward --listen " + address + " --target " + doorway,
		} {
			if !strings.Contains(nsForwarder, want) {
				t.Fatalf("declared namespace listener for %+v missing %q:\n%s", service, want, nsForwarder)
			}
		}
	}
}

// TestNoSocketUnitClaimsTheAgentNamespace enumerates every rendered unit that
// contains a [Socket] section and asserts none of them asks for the contained
// agent's network namespace.
//
// systemd.socket(5): "All network sockets allocated through .socket units are
// allocated in the host's network namespace." PrivateNetwork= and
// JoinsNamespaceOf= on a socket unit move the ACTIVATED SERVICE's processes,
// never the listener. Two separate renderers made this mistake, and the second
// survived a fix to the first because the sweep was scoped to the renderer in
// front of the author rather than to every ListenStream= in the package.
//
// If a new socket renderer is added, add it here. The list is the coverage.
func TestNoSocketUnitClaimsTheAgentNamespace(t *testing.T) {
	svc := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9222}
	socketUnits := map[string]string{
		"contained proxy doorway":   renderContainedProxySocketUnit("pipelock-agent"),
		"declared loopback doorway": renderDeclaredLoopbackSocketUnit("pipelock-agent", svc),
	}

	for name, body := range socketUnits {
		if !strings.Contains(body, "[Socket]") {
			t.Fatalf("%s is not a socket unit; this list must only hold socket units:\n%s", name, body)
		}
		for _, forbidden := range []string{"PrivateNetwork=", "JoinsNamespaceOf=", "NetworkNamespacePath="} {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s contains %q: a .socket listener is always allocated in the host network namespace, so this silently does not do what it reads as:\n%s",
					name, forbidden, body)
			}
		}
		// A doorway must be a pathname unix socket, which is what actually
		// crosses the boundary; network_namespaces(7) isolates only the
		// abstract unix namespace.
		if !strings.Contains(body, "ListenStream=/run/") {
			t.Errorf("%s does not listen on a pathname unix socket under /run:\n%s", name, body)
		}
	}
}

// TestContainedNetworkNamespaceUnitSharesPrivateTmp pins the holder half of
// the private /tmp contract: joined launches get a private /tmp only when the
// unit they join also enables PrivateTmp.
func TestContainedNetworkNamespaceUnitSharesPrivateTmp(t *testing.T) {
	t.Parallel()
	body := renderContainedNetworkNamespaceUnit()
	for _, want := range []string{"PrivateNetwork=true", "PrivateTmp=true"} {
		if !unitHasExactEntry(body, "Service", strings.SplitN(want, "=", 2)[0], strings.SplitN(want, "=", 2)[1]) {
			t.Fatalf("namespace holder unit missing %s:\n%s", want, body)
		}
	}
}
