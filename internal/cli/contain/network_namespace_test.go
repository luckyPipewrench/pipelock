// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestContainedNetworkNamespaceUnits(t *testing.T) {
	namespace := renderContainedNetworkNamespaceUnit()
	for _, want := range []string{
		"PrivateNetwork=true",
		"ExecStart=/usr/bin/sleep infinity",
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

	service := renderContainedProxyForwarderUnit("pipelock-proxy", 8888)
	for _, want := range []string{
		"User=pipelock-proxy",
		"Group=pipelock-proxy",
		"ExecStart=" + systemdSocketProxydPath + " 127.0.0.1:8888",
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
		containedProxyForwarderUnit + ".service": renderContainedProxyForwarderUnit("pipelock-proxy", 8888),
		containedNamespaceForwarderUnit:          renderContainedNamespaceForwarderUnit("/usr/local/bin/pipelock", "pipelock-agent", 8888),
		"pipelock.service":                       "[Service]\nType=simple\nExecStart=/usr/bin/sleep infinity\n",
	}
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

func TestProbeAgentNetworkNamespace(t *testing.T) {
	for _, tt := range []struct {
		name                 string
		agentNamespace       string
		boundaryStatus       string
		missingNamespaceUnit bool
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
				env.proxyForwarderServicePath:     renderContainedProxyForwarderUnit(env.proxyUserName, env.port),
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
					return systemctlEnabled + "\n", 0, nil
				case strings.HasPrefix(joined, "is-active "):
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
      expires_at: 2099-01-01T00:00:00Z
    - host: ::1
      port: 9300
      owner: index-team
      reason: local index
      expires_at: 2099-01-01T00:00:00Z
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
		ExpiresAt: "2099-01-01T00:00:00Z",
	}
	configured := `containment:
  loopback_services:
    - host: 127.0.0.1
      port: 9200
      owner: search-team
      reason: local retrieval
      expires_at: 2099-01-01T00:00:00Z
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
	if readErr != nil || string(body) != renderDeclaredLoopbackForwarderUnit(env.proxyUserName, service) {
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
		socket := renderDeclaredLoopbackSocketUnit(service)
		forwarder := renderDeclaredLoopbackForwarderUnit("pipelock-proxy", service)
		address := systemdListenAddress(service.Host, service.Port)
		if !strings.Contains(socket, "ListenStream="+address) || !strings.Contains(socket, "JoinsNamespaceOf="+containedNetworkNamespaceUnit) {
			t.Fatalf("declared socket for %+v does not bind inside namespace:\n%s", service, socket)
		}
		if !strings.Contains(forwarder, "ExecStart="+systemdSocketProxydPath+" "+address) || strings.Contains(forwarder, "PrivateNetwork=true") {
			t.Fatalf("declared forwarder for %+v cannot bridge to host:\n%s", service, forwarder)
		}
	}
}
