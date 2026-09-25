// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// futureExpiryForTest is an expiry that has not passed whenever the test runs,
// derived from the clock so no pinned calendar date can turn a passing test red.
var futureExpiryForTest = time.Now().UTC().AddDate(1, 0, 0).Format(time.RFC3339)

// expiredPublishedTestConfig is publishedTestConfig with an expiry that has
// already passed. It fails the test if the substitution does not apply, so a
// fixture change can never leave an "expired" case silently unexpired.
func expiredPublishedTestConfig(t *testing.T) string {
	t.Helper()
	past := time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)
	expired := strings.Replace(publishedTestConfig, futureExpiryForTest, past, 1)
	if expired == publishedTestConfig {
		t.Fatal("expired fixture did not change the expiry")
	}
	return expired
}

var publishedTestConfig = "containment:\n  published_services:\n" +
	"    - name: viewer\n      agent_port: 5900\n      operator_user: operator\n" +
	"      owner: ops\n      reason: watch the agent display\n      expires_at: \"" + futureExpiryForTest + "\"\n"

func publishedTestService() config.ContainmentPublishedService {
	return config.ContainmentPublishedService{
		Name: "viewer", AgentPort: 5900, OperatorUser: "operator",
		Owner: "ops", Reason: "watch the agent display", ExpiresAt: futureExpiryForTest,
	}
}

func TestRenderPublishedUnits(t *testing.T) {
	svc := publishedTestService()
	socket := renderPublishedSocketUnit(svc)
	for _, want := range []string{
		"ListenStream=/run/pipelock-contain-published/viewer.sock\n",
		"SocketUser=operator\n", "SocketGroup=root\n", "SocketMode=0600\n", "DirectoryMode=0755\n",
	} {
		if !strings.Contains(socket, want) {
			t.Fatalf("socket unit missing %q:\n%s", want, socket)
		}
	}
	relay := renderPublishedForwarderUnit("/usr/local/bin/pipelock", "pipelock-proxy", svc)
	for _, want := range []string{
		"JoinsNamespaceOf=" + containedNetworkNamespaceUnit + "\n",
		"PrivateNetwork=true\n",
		"User=pipelock-proxy\n",
		"ExecStart=/usr/local/bin/pipelock contain netns-forward --systemd-listener --target-tcp 127.0.0.1:5900\n",
	} {
		if !strings.Contains(relay, want) {
			t.Fatalf("relay unit missing %q:\n%s", want, relay)
		}
	}
	if strings.Contains(relay, "User=pipelock-agent") || strings.Contains(relay, "Group=pipelock-agent") {
		t.Fatalf("relay must never run as the agent account:\n%s", relay)
	}
	if files := publishedServiceFiles("/u", "/p", "proxy", svc); len(files) != 2 {
		t.Fatalf("unix-only publication renders %d files, want 2", len(files))
	}
	svc.AgentHost = "::1"
	svc.HostListen = "127.0.0.1:15900"
	files := publishedServiceFiles("/u", "/p", "proxy", svc)
	if len(files) != 4 || filepath.Base(files[2].path) != "pipelock-published-viewer-tcp.socket" {
		t.Fatalf("tcp opt-in files = %+v", files)
	}
	if !strings.Contains(files[2].body, "ListenStream=127.0.0.1:15900\n") || !strings.Contains(files[3].body, "--target-tcp [::1]:5900\n") {
		t.Fatalf("tcp opt-in bodies wrong:\n%s\n%s", files[2].body, files[3].body)
	}
}

func publishedInstallEnv(t *testing.T, configBody string) (*installEnv, *fakeRunner) {
	t.Helper()
	env, runner, _ := newFakeEnv(t)
	if err := os.MkdirAll(env.configDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(env.proxyForwarderSocketPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(managedPipelockConfigPath(env), []byte(configBody), 0o600); err != nil {
		t.Fatal(err)
	}
	return env, runner
}

func runnerSaw(runner *fakeRunner, argv string) bool {
	for _, call := range runner.calls {
		if call.name+" "+strings.Join(call.args, " ") == argv {
			return true
		}
	}
	return false
}

func TestInstallPublishedServicesLifecycle(t *testing.T) {
	env, runner := publishedInstallEnv(t, publishedTestConfig)
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	socketPath := filepath.Join(unitDir, "pipelock-published-viewer.socket")
	recordPath := publishedServiceRecordPath(env.loopbackForwarderInvPath)

	// Fresh install.
	if _, err := runSteps(context.Background(), env, env.out, []step{stepInstallPublishedServices(nil)}); err != nil {
		t.Fatalf("install: %v", err)
	}
	if body, err := os.ReadFile(filepath.Clean(socketPath)); err != nil || !strings.Contains(string(body), "SocketUser=operator") {
		t.Fatalf("socket unit not written: %v %q", err, body)
	}
	if !runnerSaw(runner, "systemctl enable --now pipelock-published-viewer.socket") {
		t.Fatalf("endpoint not started: %v", runner.calls)
	}
	records, err := readPublishedServiceRecords(env)
	if err != nil || len(records.Services) != 1 || records.Services[0].HostSocket != "/run/pipelock-contain-published/viewer.sock" {
		t.Fatalf("records = %+v, %v", records, err)
	}

	// Rerun with the endpoint live: nothing changes.
	runner.on(argvFor("systemctl", "is-enabled", "pipelock-published-viewer.socket"), "enabled\n", 0, nil)
	runner.on(argvFor("systemctl", "is-active", "pipelock-published-viewer.socket"), "active\n", 0, nil)
	changed, err := stepInstallPublishedServices(nil).apply(context.Background(), env)
	if err != nil || changed {
		t.Fatalf("idempotent rerun changed=%v err=%v", changed, err)
	}

	// Expiry after a prior successful install: reload hands the step an
	// empty set, and the doorway must close and its files go away.
	runner.calls = nil
	empty := []config.ContainmentPublishedService{}
	if _, err := runSteps(context.Background(), env, env.out, []step{stepInstallPublishedServices(&empty)}); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !runnerSaw(runner, "systemctl disable --now pipelock-published-viewer.socket") {
		t.Fatalf("expired endpoint not closed: %v", runner.calls)
	}
	if _, err := os.Stat(socketPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("revoked socket unit still present: %v", err)
	}
	records, err = readPublishedServiceRecords(env)
	if err != nil || len(records.Services) != 0 {
		t.Fatalf("records after revoke = %+v, %v", records, err)
	}
	if _, err := os.Stat(recordPath); err != nil {
		t.Fatalf("record file must remain as the empty set: %v", err)
	}
}

func TestPublishedReconcileKeepsRevokedUnitRecordedUntilDisabled(t *testing.T) {
	env, runner := publishedInstallEnv(t, publishedTestConfig)
	if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err != nil {
		t.Fatalf("positive control install: %v", err)
	}
	unit := "pipelock-published-viewer.socket"
	disable := argvFor("systemctl", "disable", "--now", unit)
	runner.on(disable, "", 1, errors.New("injected disable failure"))
	empty := []config.ContainmentPublishedService{}
	if _, err := stepInstallPublishedServices(&empty).apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "injected disable failure") {
		t.Fatalf("disable failure = %v", err)
	}
	if !runnerSaw(runner, "systemctl disable --now "+unit) {
		t.Fatal("disable mutation was not reached")
	}
	records, err := readPublishedServiceRecords(env)
	if err != nil || len(records.Services) != 1 || records.Services[0].Unit != "pipelock-published-viewer" {
		t.Fatalf("failed disable lost revoked unit: %+v, %v", records, err)
	}
	runner.on(disable, "", 0, nil)
	runner.calls = nil
	if _, err := stepInstallPublishedServices(&empty).apply(context.Background(), env); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if !runnerSaw(runner, "systemctl disable --now "+unit) {
		t.Fatal("retry did not disable recorded revoked unit")
	}
}

func TestInstallPublishedServicesRollbackOnLaterFailure(t *testing.T) {
	env, runner := publishedInstallEnv(t, publishedTestConfig)
	unitDir := filepath.Dir(env.proxyForwarderSocketPath)
	laterFailure := step{
		name:  "later-failure",
		apply: func(context.Context, *installEnv) (bool, error) { return false, errors.New("boom") },
	}
	if _, err := runSteps(context.Background(), env, env.out, []step{stepInstallPublishedServices(nil), laterFailure}); err == nil {
		t.Fatal("expected the later step to fail the install")
	}
	for _, name := range []string{"pipelock-published-viewer.socket", "pipelock-published-viewer.service"} {
		if _, err := os.Stat(filepath.Join(unitDir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s survived rollback: %v", name, err)
		}
	}
	if _, err := os.Stat(publishedServiceRecordPath(env.loopbackForwarderInvPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("record file survived rollback: %v", err)
	}
	if !runnerSaw(runner, "systemctl stop pipelock-published-viewer.socket") {
		t.Fatalf("rollback did not stop the endpoint it started: %v", runner.calls)
	}
}

func TestInstallPublishedServicesUnconfiguredLeavesNoState(t *testing.T) {
	env, runner := publishedInstallEnv(t, "mode: balanced\n")
	changed, err := stepInstallPublishedServices(nil).apply(context.Background(), env)
	if err != nil || changed || len(runner.calls) != 0 {
		t.Fatalf("unconfigured host: changed=%v err=%v calls=%v", changed, err, runner.calls)
	}
	if _, err := os.Stat(publishedServiceRecordPath(env.loopbackForwarderInvPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unconfigured host got a record file: %v", err)
	}
}

func TestInstallPublishedServicesRefusesBadOperators(t *testing.T) {
	for _, tc := range []struct{ user, want string }{
		{"pipelock-agent", "contained agent account"},
		{"nobody-here", "does not exist"},
	} {
		env, _ := publishedInstallEnv(t, strings.Replace(publishedTestConfig, "operator_user: operator", "operator_user: "+tc.user, 1))
		if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("operator %s: err=%v want %q", tc.user, err, tc.want)
		}
	}
}

func TestInstallPublishedServicesRefusesExpiredDeclaration(t *testing.T) {
	env, _ := publishedInstallEnv(t, expiredPublishedTestConfig(t))
	if _, err := stepInstallPublishedServices(nil).apply(context.Background(), env); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired declaration: err=%v", err)
	}
}

func TestReloadClosesPublicationsOnUnhonorableDeclaration(t *testing.T) {
	var warned []string
	env := &nftReloadEnv{
		configPath: "/etc/pipelock/pipelock.yaml",
		readFile:   func(string) ([]byte, error) { return []byte(publishedTestConfig), nil },
		now:        func() time.Time { return time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC) },
		warn:       func(m string) { warned = append(warned, m) },
	}
	if got := reconcileDeclaredContainmentPublishedServicesForReload(env, 8888); got != nil {
		t.Fatalf("expired publication must reconcile to none, got %+v", got)
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "closing every published service") {
		t.Fatalf("warnings = %v", warned)
	}
	env.now = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	if got := reconcileDeclaredContainmentPublishedServicesForReload(env, 8888); len(got) != 1 {
		t.Fatalf("current publication dropped: %+v", got)
	}
}

func TestReloadReconcilesPublicationsEvenWhenLoopbackFails(t *testing.T) {
	var published []config.ContainmentPublishedService
	called := false
	env := &nftReloadEnv{
		reconcileForwarders: func(context.Context, int, []config.ContainmentLoopbackService) error {
			return errors.New("forwarder failed")
		},
		reconcilePublished: func(_ context.Context, services []config.ContainmentPublishedService) error {
			called = true
			published = services
			return nil
		},
	}
	err := reconcileNamespaceDoorways(context.Background(), env, defaultProxyPort, nil, nil)
	if err == nil || !called || published != nil {
		t.Fatalf("err=%v called=%v published=%v", err, called, published)
	}
}

// publishedProbeFixture builds a probeEnv whose unit files and records are
// exactly what install renders, backed by a real listening unix socket for
// the owner/mode check and a /proc/net/tcp body in the kernel's format.
type publishedProbeFixture struct {
	env        *probeEnv
	files      map[string]string
	states     map[string]string
	socketPath string
	tcp        string
	relayNS    string
}

const (
	publishedTestHolderPID = 4242
	publishedTestRelayPID  = 4343
	publishedTestAgentNS   = "net:[4026532001]"
	publishedTestTCPHeader = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	publishedTestListen    = "   0: 0100007F:170C 00000000:0000 0A 00000000:00000000 00:00000000 00000000   987        0 41234 1 0000000000000000 100 0 0 10 0\n"
)

// shortSocketDir returns a directory whose socket paths fit the kernel's
// sun_path limit (108 bytes including the NUL). t.TempDir honors TMPDIR, and a
// deep TMPDIR plus a long subtest name makes bind fail with EINVAL, so fall
// back to a short directory under /tmp in that case.
func shortSocketDir(t *testing.T, name string) string {
	t.Helper()
	const sunPathBudget = 100
	dir := t.TempDir()
	if len(filepath.Join(dir, name)) <= sunPathBudget {
		return dir
	}
	short, err := os.MkdirTemp("/tmp", "plk-pub-")
	if err != nil {
		t.Fatalf("mkdir short socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(short) })
	return short
}

func newPublishedProbeFixture(t *testing.T) *publishedProbeFixture {
	t.Helper()
	socketPath := filepath.Join(shortSocketDir(t, "viewer.sock"), "viewer.sock")
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	if err := os.Chmod(socketPath, 0o600); err != nil {
		t.Fatal(err)
	}
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	fx := &publishedProbeFixture{
		files:      map[string]string{},
		states:     map[string]string{},
		socketPath: socketPath,
		tcp:        publishedTestTCPHeader + publishedTestListen,
		relayNS:    publishedTestAgentNS,
	}
	env := &probeEnv{
		configPath:               "/etc/pipelock/pipelock.yaml",
		loopbackForwarderInvPath: "/etc/pipelock/contain/loopback-forwarders.json",
		proxyForwarderSocketPath: "/etc/systemd/system/pipelock-agent-proxy.socket",
		pipelockTarget:           "/usr/local/bin/pipelock",
		proxyUserName:            "pipelock-proxy",
		port:                     8888,
		procRoot:                 "/proc",
	}
	fx.files[env.configPath] = publishedTestConfig
	svc := publishedTestService()
	records, err := encodePublishedServiceRecords(desiredPublishedServices([]config.ContainmentPublishedService{svc}))
	if err != nil {
		t.Fatal(err)
	}
	fx.files[publishedServiceRecordPath(env.loopbackForwarderInvPath)] = string(records)
	for _, item := range publishedServiceFiles(filepath.Dir(env.proxyForwarderSocketPath), env.pipelockTarget, env.proxyUserName, svc) {
		fx.files[item.path] = item.body
	}
	fx.states["is-enabled pipelock-published-viewer.socket"] = "enabled"
	fx.states["is-active pipelock-published-viewer.socket"] = "active"
	fx.states["is-active pipelock-published-viewer.service"] = "inactive"
	fx.states["show pipelock-published-viewer.service --property=MainPID --value"] = strconv.Itoa(publishedTestRelayPID)
	env.readFile = func(path string) ([]byte, error) {
		if path == "/proc/"+strconv.Itoa(publishedTestHolderPID)+"/net/tcp" {
			return []byte(fx.tcp), nil
		}
		if path == "/proc/"+strconv.Itoa(publishedTestHolderPID)+"/net/tcp6" {
			return []byte(publishedTestTCPHeader), nil
		}
		body, ok := fx.files[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(body), nil
	}
	env.runCmd = func(_ context.Context, _ string, args ...string) (string, int, error) {
		state, ok := fx.states[strings.Join(args, " ")]
		if !ok {
			return "", 1, errors.New("unexpected systemctl call " + strings.Join(args, " "))
		}
		code := 0
		if state != "active" && state != "enabled" && !strings.HasPrefix(args[0], "show") {
			code = 3
		}
		return state + "\n", code, nil
	}
	env.stat = func(path string) (os.FileInfo, error) {
		if path == svc.EffectiveHostSocket() {
			return os.Stat(fx.socketPath)
		}
		return nil, os.ErrNotExist
	}
	env.lookupUser = func(name string) (*user.User, error) {
		if name == "operator" {
			return &user.User{Uid: me.Uid, Gid: me.Gid, Username: name}, nil
		}
		return nil, user.UnknownUserError(name)
	}
	env.readLink = func(path string) (string, error) {
		if path == "/proc/"+strconv.Itoa(publishedTestRelayPID)+"/ns/net" {
			return fx.relayNS, nil
		}
		return "", os.ErrNotExist
	}
	fx.env = env
	return fx
}

func (fx *publishedProbeFixture) probe() (string, string) {
	return probePublishedServices(context.Background(), fx.env, publishedTestHolderPID, publishedTestAgentNS)
}

func TestProbePublishedServicesOutcomes(t *testing.T) {
	// Positive control: the untouched fixture passes.
	if status, detail := newPublishedProbeFixture(t).probe(); status != statusPass {
		t.Fatalf("healthy publication: %s %s", status, detail)
	}
	tests := []struct {
		name   string
		mutate func(*publishedProbeFixture)
		want   string
	}{
		{"absent listener", func(fx *publishedProbeFixture) { fx.tcp = publishedTestTCPHeader }, "absent listener"},
		{"listener on another port", func(fx *publishedProbeFixture) {
			fx.tcp = publishedTestTCPHeader + strings.Replace(publishedTestListen, ":170C", ":170D", 1)
		}, "absent listener"},
		{"connected but not listening", func(fx *publishedProbeFixture) {
			fx.tcp = publishedTestTCPHeader + strings.Replace(publishedTestListen, " 0A ", " 01 ", 1)
		}, "absent listener"},
		{"listener state unreadable", func(fx *publishedProbeFixture) {
			read := fx.env.readFile
			fx.env.readFile = func(path string) ([]byte, error) {
				if strings.HasSuffix(path, "/net/tcp") {
					return nil, errors.New("permission denied")
				}
				return read(path)
			}
		}, "agent listener state unknown"},
		{"endpoint inactive", func(fx *publishedProbeFixture) { fx.states["is-active pipelock-published-viewer.socket"] = "failed" }, "bridge failed: endpoint"},
		{"endpoint not enabled", func(fx *publishedProbeFixture) {
			fx.states["is-enabled pipelock-published-viewer.socket"] = "enabled-runtime"
		}, "not persistently enabled"},
		{"relay failed", func(fx *publishedProbeFixture) { fx.states["is-active pipelock-published-viewer.service"] = "failed" }, "bridge failed: relay"},
		{"relay unknown state", func(fx *publishedProbeFixture) {
			fx.states["is-active pipelock-published-viewer.service"] = "reloading"
		}, "unrecognized state"},
		{"endpoint missing", func(fx *publishedProbeFixture) {
			fx.env.stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
		}, "bridge failed: endpoint"},
		{"endpoint world connectable", func(fx *publishedProbeFixture) {
			if err := os.Chmod(fx.socketPath, 0o666); err != nil {
				t.Fatal(err)
			}
		}, "access denied"},
		{"endpoint owned by someone else", func(fx *publishedProbeFixture) {
			fx.env.lookupUser = func(name string) (*user.User, error) { return &user.User{Uid: "4000000", Username: name}, nil }
		}, "access denied"},
		{"endpoint is a regular file", func(fx *publishedProbeFixture) {
			plain := filepath.Join(t.TempDir(), "plain")
			if err := os.WriteFile(plain, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			fx.env.stat = func(string) (os.FileInfo, error) { return os.Stat(plain) }
		}, "access denied"},
		{"relay in the wrong namespace", func(fx *publishedProbeFixture) {
			fx.states["is-active pipelock-published-viewer.service"] = "active"
			fx.relayNS = "net:[4026531840]"
		}, "wrong namespace"},
		{"relay namespace unreadable", func(fx *publishedProbeFixture) {
			fx.states["is-active pipelock-published-viewer.service"] = "active"
			fx.env.readLink = func(string) (string, error) { return "", errors.New("gone") }
		}, "namespace unknown"},
		{"drifted relay unit", func(fx *publishedProbeFixture) {
			for path, body := range fx.files {
				if strings.HasSuffix(path, "pipelock-published-viewer.service") {
					fx.files[path] = strings.Replace(body, "User=pipelock-proxy", "User=pipelock-agent", 1)
				}
			}
		}, "missing or drifted"},
		{"records missing while declared", func(fx *publishedProbeFixture) {
			delete(fx.files, publishedServiceRecordPath(fx.env.loopbackForwarderInvPath))
		}, "published service records"},
		{"records stale after removal from config", func(fx *publishedProbeFixture) {
			fx.files[fx.env.configPath] = "mode: balanced\n"
		}, "do not match"},
		{"expired declaration", func(fx *publishedProbeFixture) {
			fx.files[fx.env.configPath] = expiredPublishedTestConfig(t)
		}, "cannot be honored"},
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

func TestProbePublishedServicesDescribesEndpointAccess(t *testing.T) {
	unix := newPublishedProbeFixture(t)
	if status, detail := unix.probe(); status != statusPass || !strings.Contains(detail, "admit only their operator") {
		t.Fatalf("Unix access detail: %s %q", status, detail)
	}
	tcp := newPublishedProbeFixture(t)
	svc := publishedTestService()
	svc.HostListen = "127.0.0.1:15900"
	tcp.files[tcp.env.configPath] = strings.Replace(publishedTestConfig, "      operator_user: operator\n", "      operator_user: operator\n      host_listen: 127.0.0.1:15900\n", 1)
	records, err := encodePublishedServiceRecords(desiredPublishedServices([]config.ContainmentPublishedService{svc}))
	if err != nil {
		t.Fatal(err)
	}
	tcp.files[publishedServiceRecordPath(tcp.env.loopbackForwarderInvPath)] = string(records)
	for _, item := range publishedServiceFiles(filepath.Dir(tcp.env.proxyForwarderSocketPath), tcp.env.pipelockTarget, tcp.env.proxyUserName, svc) {
		tcp.files[item.path] = item.body
	}
	tcp.states["is-enabled pipelock-published-viewer-tcp.socket"] = "enabled"
	tcp.states["is-active pipelock-published-viewer-tcp.socket"] = "active"
	if status, detail := tcp.probe(); status != statusPass || !strings.Contains(detail, "any local account on the host") {
		t.Fatalf("TCP access detail: %s %q", status, detail)
	}
}

func TestProbePublishedServicesUnconfiguredPasses(t *testing.T) {
	fx := newPublishedProbeFixture(t)
	fx.files = map[string]string{fx.env.configPath: "mode: balanced\n"}
	if status, detail := fx.probe(); status != statusPass || !strings.Contains(detail, "no published services") {
		t.Fatalf("unconfigured: %s %s", status, detail)
	}
}

// TestAgentNamespaceListensRealProcTable reads the kernel's own socket table
// for this process rather than a hand-written fixture, so the parser is
// checked against the real producer.
func TestAgentNamespaceListensRealProcTable(t *testing.T) {
	if _, err := os.Stat("/proc/self/net/tcp"); err != nil {
		t.Skip("no /proc socket table on this platform")
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	env := &probeEnv{readFile: os.ReadFile}
	got, err := agentNamespaceListens(env, "/proc", os.Getpid(), "127.0.0.1", port)
	if err != nil || !got {
		t.Fatalf("live listener on %d not found: %v %v", port, got, err)
	}
	_ = ln.Close()
	got, err = agentNamespaceListens(env, "/proc", os.Getpid(), "127.0.0.1", port)
	if err != nil || got {
		t.Fatalf("closed listener on %d still reported: %v %v", port, got, err)
	}
	if _, err := agentNamespaceListens(env, "/proc", 1, "127.0.0.1", port); err == nil {
		t.Fatal("pid 1 must be refused as a namespace holder")
	}
}

func TestAgentNamespaceListensIPv4WildcardFamilies(t *testing.T) {
	const port = 9000
	tcp6 := "  0: 00000000000000000000000000000000:2328 00000000000000000000000000000000:0000 0A\n"
	tcp := "  0: 00000000:2328 00000000:0000 0A\n"
	bindValue := "1"
	env := &probeEnv{readFile: func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "/bindv6only") {
			if bindValue == "unreadable" {
				return nil, os.ErrPermission
			}
			return []byte(bindValue), nil
		}
		if strings.HasSuffix(path, "/tcp6") {
			return []byte("header\n" + tcp6), nil
		}
		return []byte("header\n"), nil
	}}
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"0", true}, {"1", false}, {"unreadable", false},
	} {
		bindValue = tc.value
		got, err := agentNamespaceListens(env, "/proc", 4242, "127.0.0.1", port)
		if err != nil || got != tc.want {
			t.Fatalf("bindv6only %q = %v, %v; want %v, nil", tc.value, got, err, tc.want)
		}
	}
	env.readFile = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, "/tcp") {
			return []byte("header\n" + tcp), nil
		}
		return []byte("header\n"), nil
	}
	got, err := agentNamespaceListens(env, "/proc", 4242, "127.0.0.1", port)
	if err != nil || !got {
		t.Fatalf("IPv4 wildcard = %v, %v; want true, nil", got, err)
	}
}
