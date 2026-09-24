// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// This file adds unit-test coverage for lines identified as untested in
// internal/cli/contain/network_namespace.go, netns_assert.go, nft_reload.go,
// evidence_acl.go, and rollback.go. Every helper/type declared here is
// prefixed covNS to avoid clashing with other test files being written in
// the same package concurrently.

// ---------------------------------------------------------------------------
// network_namespace.go: readLoopbackForwarderInventory / decodeLoopbackForwarderInventory
// ---------------------------------------------------------------------------

func TestCovNSReadLoopbackForwarderInventoryReadError(t *testing.T) {
	env := &installEnv{
		loopbackForwarderInvPath: "/does/not/matter.json",
		readFile: func(string) ([]byte, error) {
			return nil, errors.New("disk offline")
		},
	}
	_, err := readLoopbackForwarderInventory(env)
	if err == nil || !strings.Contains(err.Error(), "read loopback forwarder inventory") || !strings.Contains(err.Error(), "disk offline") {
		t.Fatalf("readLoopbackForwarderInventory() error = %v, want wrapped read failure", err)
	}
}

func TestCovNSDecodeLoopbackForwarderInventoryMalformedJSON(t *testing.T) {
	_, err := decodeLoopbackForwarderInventory([]byte("not json"))
	if err == nil || !strings.Contains(err.Error(), "parse loopback forwarder inventory") {
		t.Fatalf("decodeLoopbackForwarderInventory() error = %v, want parse failure", err)
	}
}

func TestCovNSDecodeLoopbackForwarderInventoryNonCanonicalUnit(t *testing.T) {
	body, err := json.Marshal(loopbackForwarderInventory{Services: []loopbackForwarderRecord{
		{Unit: "totally-wrong-name", Host: "127.0.0.1", Port: 9200},
	}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = decodeLoopbackForwarderInventory(body)
	if err == nil || !strings.Contains(err.Error(), "non-canonical unit") {
		t.Fatalf("decodeLoopbackForwarderInventory() error = %v, want non-canonical unit failure", err)
	}
	// Positive control: the canonical unit name for the same host/port decodes
	// cleanly, proving the rejection above is about the unit name and nothing
	// else in the fixture.
	canonical, err := json.Marshal(loopbackForwarderInventory{Services: []loopbackForwarderRecord{
		{Unit: loopbackForwarderUnitBase("127.0.0.1", 9200), Host: "127.0.0.1", Port: 9200},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeLoopbackForwarderInventory(canonical); err != nil {
		t.Fatalf("decodeLoopbackForwarderInventory() with canonical unit name failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// network_namespace.go: probeAgentNetworkNamespace additional branches
// ---------------------------------------------------------------------------

// covNSProbeBase builds a probeEnv whose managed unit files and inventory are
// already exactly what a fresh install renders, with no declared loopback
// services, so each test below only has to mutate the one thing it is
// exercising.
func covNSProbeBase(t *testing.T) *probeEnv {
	t.Helper()
	root := t.TempDir()
	env := &probeEnv{
		port:                          8888,
		proxyUserName:                 "pipelock-proxy",
		agentUserName:                 testAgentUser,
		networkNamespaceUnitPath:      filepath.Join(root, containedNetworkNamespaceUnit),
		proxyForwarderSocketPath:      filepath.Join(root, containedProxyForwarderUnit+".socket"),
		proxyForwarderServicePath:     filepath.Join(root, containedProxyForwarderUnit+".service"),
		namespaceForwarderServicePath: filepath.Join(root, containedNamespaceForwarderUnit),
		loopbackForwarderInvPath:      filepath.Join(root, "loopback-forwarders.json"),
		configPath:                    filepath.Join(root, "pipelock.yaml"),
		procRoot:                      filepath.Join(root, "proc"),
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
		return "net:[200]", nil
	}
	env.networkNamespaceProbe = func(context.Context, *probeEnv) (string, string) {
		return statusPass, "boundary passed"
	}
	env.agentProcessNetnsProbe = func(context.Context, *probeEnv, string) (string, string) {
		return statusPass, "processes ok"
	}
	if err := os.MkdirAll(env.procRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	return env
}

func TestCovNSProbeAgentNetworkNamespaceUnitPathNotConfigured(t *testing.T) {
	env := covNSProbeBase(t)
	env.networkNamespaceUnitPath = ""
	status, detail := probeAgentNetworkNamespace(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "unit paths are not configured") {
		t.Fatalf("probeAgentNetworkNamespace() = (%q, %q), want unconfigured-path failure", status, detail)
	}
}

func TestCovNSProbeAgentNetworkNamespaceUnusableDeclaredServices(t *testing.T) {
	env := covNSProbeBase(t)
	body := "containment:\n  loopback_services:\n    - host: 127.0.0.1\n      port: " + strconv.Itoa(env.port) +
		"\n      owner: x\n      reason: y\n      expires_at: " + futureExpiryForTest + "\n"
	if err := os.WriteFile(env.configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	status, detail := probeAgentNetworkNamespace(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "cannot be forwarded into the private namespace") {
		t.Fatalf("probeAgentNetworkNamespace() = (%q, %q), want unusable declared services failure", status, detail)
	}
}

func TestCovNSProbeAgentNetworkNamespaceInventoryReadFails(t *testing.T) {
	env := covNSProbeBase(t)
	realReadFile := env.readFile
	env.readFile = func(path string) ([]byte, error) {
		if path == env.loopbackForwarderInvPath {
			return nil, errors.New("permission denied")
		}
		return realReadFile(path)
	}
	status, detail := probeAgentNetworkNamespace(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "read loopback forwarder inventory") {
		t.Fatalf("probeAgentNetworkNamespace() = (%q, %q), want inventory read failure", status, detail)
	}
}

func TestCovNSProbeAgentNetworkNamespaceInventoryDrifted(t *testing.T) {
	env := covNSProbeBase(t)
	service := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9200, Owner: "x", Reason: "y", ExpiresAt: futureExpiryForTest}
	body := "containment:\n  loopback_services:\n    - host: 127.0.0.1\n      port: 9200\n      owner: x\n      reason: y\n      expires_at: " + futureExpiryForTest + "\n"
	if err := os.WriteFile(env.configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = service
	// The baseline inventory on disk still describes zero declared services,
	// so it no longer matches the freshly declared one above.
	status, detail := probeAgentNetworkNamespace(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "loopback forwarder inventory does not match") {
		t.Fatalf("probeAgentNetworkNamespace() = (%q, %q), want inventory drift failure", status, detail)
	}
}

func TestCovNSProbeAgentNetworkNamespaceDeclaredUnitMissing(t *testing.T) {
	env := covNSProbeBase(t)
	service := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9200, Owner: "x", Reason: "y", ExpiresAt: futureExpiryForTest}
	body := "containment:\n  loopback_services:\n    - host: 127.0.0.1\n      port: 9200\n      owner: x\n      reason: y\n      expires_at: " + futureExpiryForTest + "\n"
	if err := os.WriteFile(env.configPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	inv, err := json.MarshalIndent(desiredLoopbackForwarders([]config.ContainmentLoopbackService{service}), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	inv = append(inv, '\n')
	if err := os.WriteFile(env.loopbackForwarderInvPath, inv, 0o600); err != nil {
		t.Fatal(err)
	}
	// Deliberately do not write the per-service socket/service/ns unit files.
	status, detail := probeAgentNetworkNamespace(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "is missing or drifted") {
		t.Fatalf("probeAgentNetworkNamespace() = (%q, %q), want missing declared unit failure", status, detail)
	}
}

func TestCovNSProbeAgentNetworkNamespaceNamespaceNotActive(t *testing.T) {
	env := covNSProbeBase(t)
	nsUnit := filepath.Base(env.networkNamespaceUnitPath)
	env.runCmd = func(_ context.Context, _ string, args ...string) (string, int, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.HasPrefix(joined, "is-enabled "):
			return systemctlEnabled + "\n", 0, nil
		case strings.HasPrefix(joined, "is-active "):
			if args[len(args)-1] == nsUnit {
				return "inactive\n", 3, nil
			}
			return systemctlActive + "\n", 0, nil
		default:
			return "", 1, nil
		}
	}
	status, detail := probeAgentNetworkNamespace(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "is not active") {
		t.Fatalf("probeAgentNetworkNamespace() = (%q, %q), want namespace-inactive failure", status, detail)
	}
}

func TestCovNSProbeAgentNetworkNamespacePIDFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		showOut string
		showErr error
		wantErr string
	}{
		{name: "show command errors", showErr: errors.New("systemctl unreachable"), wantErr: "read contained network namespace pid"},
		{name: "invalid pid text", showOut: "not-a-pid\n", wantErr: "invalid MainPID"},
		{name: "pid is 1", showOut: "1\n", wantErr: "invalid MainPID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := covNSProbeBase(t)
			env.runCmd = func(_ context.Context, _ string, args ...string) (string, int, error) {
				joined := strings.Join(args, " ")
				switch {
				case strings.HasPrefix(joined, "is-enabled "):
					return systemctlEnabled + "\n", 0, nil
				case strings.HasPrefix(joined, "is-active "):
					return systemctlActive + "\n", 0, nil
				case strings.HasPrefix(joined, "show "):
					if tc.showErr != nil {
						return "", 0, tc.showErr
					}
					return tc.showOut, 0, nil
				default:
					return "", 1, nil
				}
			}
			status, detail := probeAgentNetworkNamespace(context.Background(), env)
			if status != statusFail || !strings.Contains(detail, tc.wantErr) {
				t.Fatalf("probeAgentNetworkNamespace() = (%q, %q), want %q", status, detail, tc.wantErr)
			}
		})
	}
}

func TestCovNSProbeAgentNetworkNamespaceIdentityReadFailures(t *testing.T) {
	for _, tc := range []struct {
		name       string
		readLink   func(string) (string, error)
		wantErr    string
		wantStatus string
	}{
		{
			name: "agent namespace identity unreadable",
			readLink: func(path string) (string, error) {
				if strings.Contains(path, "/proc/4242/") {
					return "", errors.New("no such process")
				}
				return "net:[100]", nil
			},
			wantErr:    "read contained network namespace identity",
			wantStatus: statusFail,
		},
		{
			name: "host namespace identity unreadable",
			readLink: func(path string) (string, error) {
				if path == "/proc/1/ns/net" {
					return "", errors.New("permission denied")
				}
				return "net:[200]", nil
			},
			wantErr:    "read host network namespace identity",
			wantStatus: statusFail,
		},
		{
			name: "agent and host resolve to the same namespace",
			readLink: func(string) (string, error) {
				return "net:[100]", nil
			},
			wantErr:    "resolves to the host network namespace",
			wantStatus: statusFail,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := covNSProbeBase(t)
			env.readLink = tc.readLink
			status, detail := probeAgentNetworkNamespace(context.Background(), env)
			if status != tc.wantStatus || !strings.Contains(detail, tc.wantErr) {
				t.Fatalf("probeAgentNetworkNamespace() = (%q, %q), want %q", status, detail, tc.wantErr)
			}
		})
	}
}

// TestCovNSProbeAgentNetworkNamespaceDefaultBoundaryProbe drives
// probeAgentNetworkNamespace with env.networkNamespaceProbe left nil, so it
// must call the real probeNetworkNamespaceBoundary implementation.
func TestCovNSProbeAgentNetworkNamespaceDefaultBoundaryProbe(t *testing.T) {
	env := covNSProbeBase(t)
	env.networkNamespaceProbe = nil
	env.curlPath = "/usr/bin/curl"
	calls := 0
	env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
		joined := strings.Join(args, " ")
		switch {
		case name == systemdRunPath:
			calls++
			if calls == 1 {
				// Host loopback canary must be UNREACHABLE from inside the
				// namespace: non-zero exit is the pass condition here.
				return "", 1, nil
			}
			return "", 0, nil
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
	status, detail := probeAgentNetworkNamespace(context.Background(), env)
	if status != statusPass || !strings.Contains(detail, "cannot reach host loopback and can reach") {
		t.Fatalf("probeAgentNetworkNamespace() = (%q, %q), want the real boundary probe to pass", status, detail)
	}
	if calls != 2 {
		t.Fatalf("systemd-run canary calls = %d, want 2", calls)
	}
}

// TestCovNSProbeAgentNetworkNamespaceDefaultProcessProbe drives
// probeAgentNetworkNamespace with env.agentProcessNetnsProbe left nil, so it
// must call the real probeAgentProcessNamespaces implementation.
func TestCovNSProbeAgentNetworkNamespaceDefaultProcessProbe(t *testing.T) {
	env := covNSProbeBase(t)
	env.agentProcessNetnsProbe = nil
	env.lookupUser = func(string) (*user.User, error) {
		return &user.User{Uid: "987", Username: testAgentUser}, nil
	}
	env.readDir = os.ReadDir
	// procRoot is an empty directory: no live agent processes to audit.
	status, detail := probeAgentNetworkNamespace(context.Background(), env)
	if status != statusPass || !strings.Contains(detail, "0 live pipelock-agent process(es)") {
		t.Fatalf("probeAgentNetworkNamespace() = (%q, %q), want the real process probe to pass with none found", status, detail)
	}
}

func TestCovNSProbeAgentNetworkNamespaceProcessProbeFails(t *testing.T) {
	env := covNSProbeBase(t)
	env.agentProcessNetnsProbe = func(context.Context, *probeEnv, string) (string, string) {
		return statusFail, "a rogue process escaped the managed namespace"
	}
	status, detail := probeAgentNetworkNamespace(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "escaped the managed namespace") {
		t.Fatalf("probeAgentNetworkNamespace() = (%q, %q), want the process probe failure surfaced", status, detail)
	}
}

func TestCovNSProbeAgentNetworkNamespacePublishedProbeFails(t *testing.T) {
	env := covNSProbeBase(t)
	recordPath := publishedServiceRecordPath(env.loopbackForwarderInvPath)
	if err := os.WriteFile(recordPath, []byte("not the encoded record set"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, detail := probeAgentNetworkNamespace(context.Background(), env)
	if status != statusFail || !strings.Contains(detail, "published service records do not match") {
		t.Fatalf("probeAgentNetworkNamespace() = (%q, %q), want the published-services probe failure surfaced", status, detail)
	}
}

// ---------------------------------------------------------------------------
// network_namespace.go: probeAgentProcessNamespaces fine-grained branches
// ---------------------------------------------------------------------------

// covNSFault describes one scripted response for the Nth read of a
// particular basename ("status", "stat", or "net").
type covNSFault struct {
	occurrence int
	err        error
	body       []byte
}

func covNSFaultyReadFile(faults map[string][]covNSFault) func(string) ([]byte, error) {
	counts := map[string]int{}
	return func(p string) ([]byte, error) {
		suffix := filepath.Base(p)
		counts[suffix]++
		for _, f := range faults[suffix] {
			if f.occurrence == counts[suffix] {
				if f.err != nil {
					return nil, f.err
				}
				return f.body, nil
			}
		}
		return os.ReadFile(filepath.Clean(p))
	}
}

func covNSFaultyReadLink(faults map[string][]covNSFault) func(string) (string, error) {
	counts := map[string]int{}
	return func(p string) (string, error) {
		suffix := filepath.Base(p)
		counts[suffix]++
		for _, f := range faults[suffix] {
			if f.occurrence == counts[suffix] {
				if f.err != nil {
					return "", f.err
				}
				return string(f.body), nil
			}
		}
		return os.Readlink(p)
	}
}

// covNSValidProcFixture writes a single fully-valid pid directory: matching
// status/uid, a well-formed stat line, and an ns/net symlink matching
// agentNamespace. Individual test cases override reads through the fault
// ledger rather than corrupting the files on disk, so the same fixture is
// reusable for both first-read and re-read branches.
func covNSValidProcFixture(t *testing.T, procRoot string) {
	t.Helper()
	pidRoot := filepath.Join(procRoot, "101")
	if err := os.MkdirAll(filepath.Join(pidRoot, "ns"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidRoot, "status"), []byte("Name:\tagent\nUid:\t987\t987\t987\t987\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidRoot, "stat"), procStatFixture("101", "12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("net:[200]", filepath.Join(pidRoot, "ns", "net")); err != nil {
		t.Fatal(err)
	}
}

func TestCovNSProbeAgentProcessNamespacesFineGrainedBranches(t *testing.T) {
	for _, tc := range []struct {
		name         string
		buildFixture func(t *testing.T, procRoot string)
		readFaults   map[string][]covNSFault
		linkFaults   map[string][]covNSFault
		wantStatus   string
		wantDetail   string
	}{
		{
			name: "first status read missing pid dir is skipped",
			buildFixture: func(t *testing.T, procRoot string) {
				if err := os.MkdirAll(filepath.Join(procRoot, "101"), 0o750); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: statusPass,
			wantDetail: "0 live pipelock-agent process(es)",
		},
		{
			name:         "first status read errors",
			buildFixture: func(t *testing.T, procRoot string) { covNSValidProcFixture(t, procRoot) },
			readFaults:   map[string][]covNSFault{"status": {{occurrence: 1, err: errors.New("status unreadable")}}},
			wantStatus:   statusFail,
			wantDetail:   "read process 101 identity for namespace audit: status unreadable",
		},
		{
			name:         "first status read malformed",
			buildFixture: func(t *testing.T, procRoot string) { covNSValidProcFixture(t, procRoot) },
			readFaults:   map[string][]covNSFault{"status": {{occurrence: 1, body: []byte("no uid line here\n")}}},
			wantStatus:   statusFail,
			wantDetail:   "read process 101 identity for namespace audit: missing Uid field",
		},
		{
			name: "first stat read missing is skipped",
			buildFixture: func(t *testing.T, procRoot string) {
				pidRoot := filepath.Join(procRoot, "101")
				if err := os.MkdirAll(pidRoot, 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(pidRoot, "status"), []byte("Name:\tagent\nUid:\t987\t987\t987\t987\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: statusPass,
			wantDetail: "0 live pipelock-agent process(es)",
		},
		{
			name:         "first stat read errors",
			buildFixture: func(t *testing.T, procRoot string) { covNSValidProcFixture(t, procRoot) },
			readFaults:   map[string][]covNSFault{"stat": {{occurrence: 1, err: errors.New("stat unreadable")}}},
			wantStatus:   statusFail,
			wantDetail:   "read process 101 start time for namespace audit: stat unreadable",
		},
		{
			name:         "first stat read malformed",
			buildFixture: func(t *testing.T, procRoot string) { covNSValidProcFixture(t, procRoot) },
			readFaults:   map[string][]covNSFault{"stat": {{occurrence: 1, body: []byte("no terminator")}}},
			wantStatus:   statusFail,
			wantDetail:   "read process 101 start time for namespace audit: malformed stat: missing command terminator",
		},
		{
			name: "first ns/net read missing is skipped",
			buildFixture: func(t *testing.T, procRoot string) {
				pidRoot := filepath.Join(procRoot, "101")
				if err := os.MkdirAll(pidRoot, 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(pidRoot, "status"), []byte("Name:\tagent\nUid:\t987\t987\t987\t987\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(pidRoot, "stat"), procStatFixture("101", "12345"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantStatus: statusPass,
			wantDetail: "0 live pipelock-agent process(es)",
		},
		{
			name:         "first ns/net read errors",
			buildFixture: func(t *testing.T, procRoot string) { covNSValidProcFixture(t, procRoot) },
			linkFaults:   map[string][]covNSFault{"net": {{occurrence: 1, err: errors.New("namespace unreadable")}}},
			wantStatus:   statusFail,
			wantDetail:   "read process 101 network namespace: namespace unreadable",
		},
		{
			name:         "re-read status disappeared is skipped (recycled pid)",
			buildFixture: func(t *testing.T, procRoot string) { covNSValidProcFixture(t, procRoot) },
			readFaults:   map[string][]covNSFault{"status": {{occurrence: 2, err: os.ErrNotExist}}},
			wantStatus:   statusPass,
			wantDetail:   "0 live pipelock-agent process(es)",
		},
		{
			name:         "re-read status errors",
			buildFixture: func(t *testing.T, procRoot string) { covNSValidProcFixture(t, procRoot) },
			readFaults:   map[string][]covNSFault{"status": {{occurrence: 2, err: errors.New("re-read status unreadable")}}},
			wantStatus:   statusFail,
			wantDetail:   "re-read process 101 identity for namespace audit: re-read status unreadable",
		},
		{
			name:         "re-read status malformed",
			buildFixture: func(t *testing.T, procRoot string) { covNSValidProcFixture(t, procRoot) },
			readFaults:   map[string][]covNSFault{"status": {{occurrence: 2, body: []byte("garbage\n")}}},
			wantStatus:   statusFail,
			wantDetail:   "re-read process 101 identity for namespace audit: missing Uid field",
		},
		{
			name:         "re-read uid changed (recycled pid under a different account)",
			buildFixture: func(t *testing.T, procRoot string) { covNSValidProcFixture(t, procRoot) },
			readFaults:   map[string][]covNSFault{"status": {{occurrence: 2, body: []byte("Name:\tother\nUid:\t555\t555\t555\t555\n")}}},
			wantStatus:   statusPass,
			wantDetail:   "0 live pipelock-agent process(es)",
		},
		{
			name:         "re-read stat disappeared is skipped",
			buildFixture: func(t *testing.T, procRoot string) { covNSValidProcFixture(t, procRoot) },
			readFaults:   map[string][]covNSFault{"stat": {{occurrence: 2, err: os.ErrNotExist}}},
			wantStatus:   statusPass,
			wantDetail:   "0 live pipelock-agent process(es)",
		},
		{
			name:         "re-read stat errors",
			buildFixture: func(t *testing.T, procRoot string) { covNSValidProcFixture(t, procRoot) },
			readFaults:   map[string][]covNSFault{"stat": {{occurrence: 2, err: errors.New("re-read stat unreadable")}}},
			wantStatus:   statusFail,
			wantDetail:   "re-read process 101 start time for namespace audit: re-read stat unreadable",
		},
		{
			name:         "re-read stat malformed",
			buildFixture: func(t *testing.T, procRoot string) { covNSValidProcFixture(t, procRoot) },
			readFaults:   map[string][]covNSFault{"stat": {{occurrence: 2, body: []byte("still no terminator")}}},
			wantStatus:   statusFail,
			wantDetail:   "re-read process 101 start time for namespace audit: malformed stat: missing command terminator",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			procRoot := t.TempDir()
			tc.buildFixture(t, procRoot)
			env := &probeEnv{
				agentUserName: testAgentUser,
				procRoot:      procRoot,
				lookupUser: func(string) (*user.User, error) {
					return &user.User{Uid: "987", Username: testAgentUser}, nil
				},
				readDir:  os.ReadDir,
				readFile: covNSFaultyReadFile(tc.readFaults),
				readLink: covNSFaultyReadLink(tc.linkFaults),
			}
			status, detail := probeAgentProcessNamespaces(context.Background(), env, "net:[200]")
			if status != tc.wantStatus || !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("probeAgentProcessNamespaces() = (%q, %q), want status %q detail containing %q", status, detail, tc.wantStatus, tc.wantDetail)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// network_namespace.go: processSystemdUnit fallback
// ---------------------------------------------------------------------------

func TestCovNSProcessSystemdUnitNoUnifiedLine(t *testing.T) {
	readFile := func(string) ([]byte, error) {
		return []byte("1:name=systemd:/user.slice\n0::not-a-real-cgroup-format"), nil
	}
	// This cgroup body deliberately keeps a "0::" line that has no
	// meaningful terminal component so the loop still exercises the
	// CutPrefix branch; a body with NO "0::" prefix at all falls through the
	// loop entirely and returns "".
	got := processSystemdUnit(readFile, "/proc/999/cgroup")
	if got == "" {
		t.Fatal("processSystemdUnit() with a 0:: line returned empty, want the parsed base")
	}
	noPrefix := func(string) ([]byte, error) {
		return []byte("1:name=systemd:/user.slice\n4:pids:/user.slice\n"), nil
	}
	if got := processSystemdUnit(noPrefix, "/proc/999/cgroup"); got != "" {
		t.Fatalf("processSystemdUnit() with no 0:: line = %q, want empty fallback", got)
	}
}

// ---------------------------------------------------------------------------
// network_namespace.go: probeNetworkNamespaceBoundary command-error branches
// ---------------------------------------------------------------------------

func TestCovNSProbeNetworkNamespaceBoundaryCommandErrors(t *testing.T) {
	for _, tc := range []struct {
		name       string
		canaryErr  error
		proxyErr   error
		wantDetail string
	}{
		{name: "canary command fails to run", canaryErr: errors.New("systemd-run missing"), wantDetail: "run host-loopback namespace canary"},
		{name: "proxy reachability command fails to run", proxyErr: errors.New("systemd-run missing"), wantDetail: "run contained proxy reachability probe"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			env := &probeEnv{
				port:          8888,
				curlPath:      "/usr/bin/curl",
				agentUserName: testAgentUser,
				runCmd: func(_ context.Context, name string, _ ...string) (string, int, error) {
					if name != systemdRunPath {
						t.Fatalf("command = %q, want %q", name, systemdRunPath)
					}
					calls++
					if calls == 1 {
						if tc.canaryErr != nil {
							return "", 0, tc.canaryErr
						}
						return "", 7, nil
					}
					if tc.proxyErr != nil {
						return "", 0, tc.proxyErr
					}
					return "", 0, nil
				},
			}
			status, detail := probeNetworkNamespaceBoundary(context.Background(), env)
			if status != statusFail || !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("probeNetworkNamespaceBoundary() = (%q, %q), want %q", status, detail, tc.wantDetail)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// network_namespace.go: managedNamespaceRuntimeUnits / quiesce / restore
// ---------------------------------------------------------------------------

func TestCovNSManagedNamespaceRuntimeUnitsInventoryError(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.loopbackForwarderInvPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.loopbackForwarderInvPath, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := managedNamespaceRuntimeUnits(env)
	if err == nil || !strings.Contains(err.Error(), "parse loopback forwarder inventory") {
		t.Fatalf("managedNamespaceRuntimeUnits() error = %v, want inventory parse failure surfaced", err)
	}
}

func TestCovNSQuiesceManagedNamespaceRuntimeUnitsStopFailures(t *testing.T) {
	t.Run("non-socket stop failure", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		units := []managedNamespaceRuntimeUnit{{name: "covns-forwarder.service"}}
		states := map[string]unitRuntimeState{"covns-forwarder.service": {active: true}}
		runner.on(argvFor("systemctl", "stop", "covns-forwarder.service"), "denied", 1, nil)
		err := quiesceManagedNamespaceRuntimeUnits(context.Background(), env, units, states)
		if err == nil || !strings.Contains(err.Error(), "stop managed forwarder covns-forwarder.service before binary replacement") {
			t.Fatalf("quiesceManagedNamespaceRuntimeUnits() error = %v", err)
		}
	})
	t.Run("socket stop failure", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		units := []managedNamespaceRuntimeUnit{{name: "covns-doorway.socket", socket: true}}
		states := map[string]unitRuntimeState{"covns-doorway.socket": {active: true}}
		runner.on(argvFor("systemctl", "stop", "covns-doorway.socket"), "denied", 1, nil)
		err := quiesceManagedNamespaceRuntimeUnits(context.Background(), env, units, states)
		if err == nil || !strings.Contains(err.Error(), "stop managed doorway socket covns-doorway.socket before binary replacement") {
			t.Fatalf("quiesceManagedNamespaceRuntimeUnits() error = %v", err)
		}
	})
	t.Run("inactive units are never stopped (positive control)", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		units := []managedNamespaceRuntimeUnit{{name: "covns-forwarder.service"}, {name: "covns-doorway.socket", socket: true}}
		states := map[string]unitRuntimeState{}
		if err := quiesceManagedNamespaceRuntimeUnits(context.Background(), env, units, states); err != nil {
			t.Fatalf("quiesceManagedNamespaceRuntimeUnits() error = %v, want nil when nothing is active", err)
		}
		if len(runner.calls) != 0 {
			t.Fatalf("quiesceManagedNamespaceRuntimeUnits() issued %d commands for inactive units, want 0", len(runner.calls))
		}
	})
}

func TestCovNSRestoreManagedNamespaceRuntimeUnitsCombinesFailures(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	units := []managedNamespaceRuntimeUnit{
		{name: "covns-reset-fails.service"},
		{name: "covns-enable-fails.service"},
		{name: "covns-start-fails.service"},
	}
	states := map[string]unitRuntimeState{
		"covns-reset-fails.service":  {},
		"covns-enable-fails.service": {enabled: true},
		"covns-start-fails.service":  {active: true},
	}
	runner.on(argvFor("systemctl", "reset-failed", "covns-reset-fails.service"), "denied", 1, nil)
	runner.on(argvFor("systemctl", "enable", "covns-enable-fails.service"), "denied", 1, nil)
	runner.on(argvFor("systemctl", "start", "covns-start-fails.service"), "denied", 1, nil)

	err := restoreManagedNamespaceRuntimeUnits(context.Background(), env, units, states)
	if err == nil {
		t.Fatal("restoreManagedNamespaceRuntimeUnits() = nil, want combined failure")
	}
	for _, want := range []string{
		"reset failed managed unit covns-reset-fails.service",
		"enable managed unit covns-enable-fails.service",
		"start managed unit covns-start-fails.service",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("restoreManagedNamespaceRuntimeUnits() error = %v, missing %q", err, want)
		}
	}
}

// ---------------------------------------------------------------------------
// network_namespace.go: stepInstallNetworkNamespaceWithServices apply() error branches
// ---------------------------------------------------------------------------

func TestCovNSInstallNetworkNamespaceApplyFailureBranches(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(t *testing.T, env *installEnv, runner *fakeRunner)
		wantErr string
	}{
		{
			name: "declared loopback services collide with the proxy port",
			mutate: func(t *testing.T, env *installEnv, _ *fakeRunner) {
				cfgPath := filepath.Join(env.configDir, "pipelock.yaml")
				body := "containment:\n  loopback_services:\n    - host: 127.0.0.1\n      port: " + strconv.Itoa(env.proxyPort) +
					"\n      owner: x\n      reason: y\n      expires_at: " + futureExpiryForTest + "\n"
				if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "collides with the agent-accessible proxy port",
		},
		{
			name: "old loopback forwarder inventory is malformed",
			mutate: func(t *testing.T, env *installEnv, _ *fakeRunner) {
				if err := os.MkdirAll(filepath.Dir(env.loopbackForwarderInvPath), 0o750); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(env.loopbackForwarderInvPath, []byte("not json"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantErr: "parse loopback forwarder inventory",
		},
		{
			name: "loopback forwarder inventory directory cannot be created",
			mutate: func(_ *testing.T, env *installEnv, _ *fakeRunner) {
				env.mkdirAll = func(string, os.FileMode) error { return errors.New("mkdir denied") }
			},
			wantErr: "create loopback forwarder inventory directory",
		},
		{
			name: "unit path unconfigured",
			mutate: func(_ *testing.T, env *installEnv, _ *fakeRunner) {
				env.networkNamespaceUnitPath = ""
			},
			wantErr: "contained network namespace unit path is not configured",
		},
		{
			name: "chmod fails on an already-current managed file",
			mutate: func(t *testing.T, env *installEnv, _ *fakeRunner) {
				if err := os.WriteFile(env.networkNamespaceUnitPath, []byte(renderContainedNetworkNamespaceUnit()), 0o600); err != nil {
					t.Fatal(err)
				}
				env.chmod = func(string, os.FileMode) error { return errors.New("chmod denied") }
			},
			wantErr: "chmod",
		},
		{
			name: "writing a new managed file fails",
			mutate: func(_ *testing.T, env *installEnv, _ *fakeRunner) {
				env.writeFile = func(string, []byte, os.FileMode) error { return errors.New("disk full") }
			},
			wantErr: "write ",
		},
		{
			name: "daemon-reload after install fails",
			mutate: func(_ *testing.T, _ *installEnv, runner *fakeRunner) {
				runner.on(argvFor("systemctl", "daemon-reload"), "denied", 1, nil)
			},
			wantErr: "reload systemd after installing contained network namespace",
		},
		{
			name: "enabling the in-namespace proxy forwarder fails",
			mutate: func(_ *testing.T, _ *installEnv, runner *fakeRunner) {
				runner.on(argvFor("systemctl", "enable", "--now", containedNamespaceForwarderUnit), "denied", 1, nil)
			},
			wantErr: "enable contained namespace forwarder",
		},
		{
			name: "enabling a declared loopback in-namespace listener fails",
			mutate: func(t *testing.T, env *installEnv, runner *fakeRunner) {
				cfgPath := filepath.Join(env.configDir, "pipelock.yaml")
				body := "containment:\n  loopback_services:\n    - host: 127.0.0.1\n      port: 9200\n      owner: x\n      reason: y\n      expires_at: " + futureExpiryForTest + "\n"
				if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
				nsUnit := loopbackForwarderUnitBase("127.0.0.1", 9200) + "-netns.service"
				runner.on(argvFor("systemctl", "enable", "--now", nsUnit), "denied", 1, nil)
			},
			wantErr: "enable declared loopback namespace listener",
		},
		{
			name: "legacy owned-loopback anchor disable fails",
			mutate: func(t *testing.T, env *installEnv, runner *fakeRunner) {
				if err := os.WriteFile(env.ownedLoopbackAnchorUnitPath, []byte("[Service]\nSlice=pipelock_contained.slice\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				runner.on(argvFor("systemctl", "disable", "--now", filepath.Base(env.ownedLoopbackAnchorUnitPath)), "denied", 1, nil)
			},
			wantErr: "disable legacy owned-loopback anchor",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, runner, _ := newFakeEnv(t)
			tc.mutate(t, env, runner)
			_, err := stepInstallNetworkNamespace().apply(context.Background(), env)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("apply() error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestCovNSInstallNetworkNamespaceApplyRestartFailures exercises the restart
// branches, which require an already-active previous unit plus a definition
// change, so they get their own setup rather than sharing the table above.
func TestCovNSInstallNetworkNamespaceApplyRestartFailures(t *testing.T) {
	t.Run("restart of the changed namespace holder fails", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		if err := os.WriteFile(env.networkNamespaceUnitPath, []byte("old namespace unit\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		nsUnit := filepath.Base(env.networkNamespaceUnitPath)
		runner.on(argvFor(testSystemctl, "is-enabled", nsUnit), "enabled\n", 0, nil)
		runner.on(argvFor(testSystemctl, "is-active", nsUnit), "active\n", 0, nil)
		runner.on(argvFor(testSystemctl, "restart", nsUnit), "denied", 1, nil)
		_, err := stepInstallNetworkNamespace().apply(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "restart updated contained network namespace") {
			t.Fatalf("apply() error = %v", err)
		}
	})
	t.Run("restart of a changed namespace forwarder fails", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		if err := os.WriteFile(env.namespaceForwarderServicePath, []byte("old forwarder\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		runner.on(argvFor(testSystemctl, "is-enabled", containedNamespaceForwarderUnit), "enabled\n", 0, nil)
		runner.on(argvFor(testSystemctl, "is-active", containedNamespaceForwarderUnit), "active\n", 0, nil)
		runner.on(argvFor(testSystemctl, "restart", containedNamespaceForwarderUnit), "denied", 1, nil)
		_, err := stepInstallNetworkNamespace().apply(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "restart updated contained namespace forwarder") {
			t.Fatalf("apply() error = %v", err)
		}
	})
}

// TestCovNSInstallNetworkNamespaceApplyStaleForwarderFailures exercises the
// stale-declared-loopback-forwarder retirement branches: a service present
// in the OLD inventory but absent from the newly declared set.
func TestCovNSInstallNetworkNamespaceApplyStaleForwarderFailures(t *testing.T) {
	buildStaleInventory := func(t *testing.T, env *installEnv) string {
		t.Helper()
		stale := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9300, Owner: "x", Reason: "y", ExpiresAt: futureExpiryForTest}
		inv, err := json.Marshal(desiredLoopbackForwarders([]config.ContainmentLoopbackService{stale}))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(env.loopbackForwarderInvPath), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(env.loopbackForwarderInvPath, inv, 0o600); err != nil {
			t.Fatal(err)
		}
		cfgPath := filepath.Join(env.configDir, "pipelock.yaml")
		if err := os.WriteFile(cfgPath, []byte("containment:\n  loopback_services: []\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return loopbackForwarderUnitBase(stale.Host, stale.Port)
	}

	t.Run("disabling the stale in-namespace listener fails", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		unit := buildStaleInventory(t, env)
		runner.on(argvFor(testSystemctl, "disable", "--now", unit+"-netns.service"), "denied", 1, nil)
		_, err := stepInstallNetworkNamespace().apply(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "disable stale loopback forwarder") {
			t.Fatalf("apply() error = %v", err)
		}
	})

	t.Run("stat on a stale unit file fails for a reason other than absence", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		_ = runner
		unit := buildStaleInventory(t, env)
		unitDir := filepath.Dir(env.proxyForwarderSocketPath)
		staleSocket := filepath.Join(unitDir, unit+".socket")
		if err := os.WriteFile(staleSocket, []byte("stale socket unit\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env.stat = func(path string) (os.FileInfo, error) {
			if path == staleSocket {
				return nil, errors.New("stat denied")
			}
			return os.Stat(path)
		}
		_, err := stepInstallNetworkNamespace().apply(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "stat stale loopback forwarder") {
			t.Fatalf("apply() error = %v", err)
		}
	})

	t.Run("reading an existing stale unit file fails", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		unit := buildStaleInventory(t, env)
		unitDir := filepath.Dir(env.proxyForwarderSocketPath)
		staleSocket := filepath.Join(unitDir, unit+".socket")
		if err := os.WriteFile(staleSocket, []byte("stale socket unit\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		env.readFile = func(path string) ([]byte, error) {
			if path == staleSocket {
				return nil, errors.New("read denied")
			}
			return os.ReadFile(filepath.Clean(path))
		}
		_, err := stepInstallNetworkNamespace().apply(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "read stale loopback forwarder") {
			t.Fatalf("apply() error = %v", err)
		}
	})

	t.Run("restoring operator state behind a stale unit file fails", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		unit := buildStaleInventory(t, env)
		unitDir := filepath.Dir(env.proxyForwarderSocketPath)
		staleSocket := filepath.Join(unitDir, unit+".socket")
		if err := os.WriteFile(staleSocket, []byte("stale socket unit\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		// No .bak exists for staleSocket, so restoreBackup takes the
		// remove-current branch; make that removal fail.
		env.removeFile = func(path string) error {
			if path == staleSocket {
				return errors.New("remove denied")
			}
			return os.Remove(path)
		}
		_, err := stepInstallNetworkNamespace().apply(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "restore operator state behind stale loopback forwarder") {
			t.Fatalf("apply() error = %v", err)
		}
	})
}

// TestCovNSInstallNetworkNamespaceApplyLegacyAnchorRetirementFailures covers
// the remaining legacy owned-loopback anchor retirement branches: backing it
// up, removing it, reloading systemd after removal, and a stat failure that
// is not simple absence.
func TestCovNSInstallNetworkNamespaceApplyLegacyAnchorRetirementFailures(t *testing.T) {
	legacyBody := "[Service]\nSlice=pipelock_contained.slice\n"

	t.Run("backing up the legacy anchor fails", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		if err := os.WriteFile(env.ownedLoopbackAnchorUnitPath, []byte(legacyBody), 0o600); err != nil {
			t.Fatal(err)
		}
		env.rename = func(oldPath, newPath string) error {
			if oldPath == env.ownedLoopbackAnchorUnitPath {
				return errors.New("rename denied")
			}
			return os.Rename(oldPath, newPath)
		}
		_, err := stepInstallNetworkNamespace().apply(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "backup legacy owned-loopback anchor") {
			t.Fatalf("apply() error = %v", err)
		}
	})

	t.Run("removing the legacy anchor fails", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		if err := os.WriteFile(env.ownedLoopbackAnchorUnitPath, []byte(legacyBody), 0o600); err != nil {
			t.Fatal(err)
		}
		env.removeFile = func(path string) error {
			if path == env.ownedLoopbackAnchorUnitPath {
				return errors.New("remove denied")
			}
			return os.Remove(path)
		}
		_, err := stepInstallNetworkNamespace().apply(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "remove legacy owned-loopback anchor") {
			t.Fatalf("apply() error = %v", err)
		}
	})

	t.Run("daemon-reload after retiring the legacy anchor fails", func(t *testing.T) {
		env, runner, _ := newFakeEnv(t)
		if err := os.WriteFile(env.ownedLoopbackAnchorUnitPath, []byte(legacyBody), 0o600); err != nil {
			t.Fatal(err)
		}
		calls := 0
		env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
			if name == "systemctl" && len(args) == 1 && args[0] == "daemon-reload" {
				calls++
				if calls == 2 {
					return "denied", 1, nil
				}
				return "", 0, nil
			}
			return runner.run(ctx, name, args...)
		}
		_, err := stepInstallNetworkNamespace().apply(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "reload systemd after retiring legacy owned-loopback anchor") {
			t.Fatalf("apply() error = %v", err)
		}
	})

	t.Run("stat on the legacy anchor fails for a reason other than absence", func(t *testing.T) {
		env, _, _ := newFakeEnv(t)
		if err := os.WriteFile(env.ownedLoopbackAnchorUnitPath, []byte(legacyBody), 0o600); err != nil {
			t.Fatal(err)
		}
		env.stat = func(path string) (os.FileInfo, error) {
			if path == env.ownedLoopbackAnchorUnitPath {
				return nil, errors.New("stat denied")
			}
			return os.Stat(path)
		}
		_, err := stepInstallNetworkNamespace().apply(context.Background(), env)
		if err == nil || !strings.Contains(err.Error(), "stat legacy owned-loopback anchor") {
			t.Fatalf("apply() error = %v", err)
		}
	})
}

// TestCovNSInstallNetworkNamespaceApplySkipsRestartForRevokedForwarder proves
// a revoked declared-loopback forwarder is retired rather than restarted,
// even when the namespace holder's own definition changed in the same
// install (which is what makes the forwarder-restart loop consider it at
// all).
func TestCovNSInstallNetworkNamespaceApplySkipsRestartForRevokedForwarder(t *testing.T) {
	env, runner, _ := newFakeEnv(t)
	service := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9222, Owner: "x", Reason: "y", ExpiresAt: futureExpiryForTest}
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
	// An old namespace-holder body, different from the rendered one, forces
	// namespaceDefinitionChanged = true so the forwarder-restart loop below
	// considers every previously active forwarder, including this revoked one.
	if err := os.WriteFile(env.networkNamespaceUnitPath, []byte("old namespace unit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	nsUnit := filepath.Base(env.networkNamespaceUnitPath)
	revokedNS := unit + "-netns.service"
	for _, name := range []string{nsUnit, revokedNS} {
		runner.on(argvFor(testSystemctl, "is-enabled", name), "enabled\n", 0, nil)
		runner.on(argvFor(testSystemctl, "is-active", name), "active\n", 0, nil)
	}
	cfgPath := filepath.Join(env.configDir, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("containment:\n  loopback_services: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := stepInstallNetworkNamespace().apply(context.Background(), env); err != nil {
		t.Fatalf("apply() error = %v", err)
	}
	if fakeRunnerCalled(runner, "systemctl restart "+revokedNS) {
		t.Fatalf("apply() restarted a revoked forwarder %s instead of retiring it: %v", revokedNS, runner.calls)
	}
	// Positive control: the namespace holder itself, which IS still desired,
	// was restarted.
	if !fakeRunnerCalled(runner, "systemctl restart "+nsUnit) {
		t.Fatalf("apply() did not restart the changed namespace holder: %v", runner.calls)
	}
}

// TestCovNSInstallNetworkNamespaceUndoInactiveStateCleanupFailures forces
// every cleanup-before-restore command in undo() to fail while every
// previous unit was inactive/disabled -- the state newFakeEnv's fakeRunner
// reports by default for anything it wasn't told about.
func TestCovNSInstallNetworkNamespaceUndoInactiveStateCleanupFailures(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	service := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9222, Owner: "x", Reason: "y", ExpiresAt: futureExpiryForTest}
	unit := loopbackForwarderUnitBase(service.Host, service.Port)
	nsUnit := filepath.Base(env.networkNamespaceUnitPath)
	runner.on(argvFor(testSystemctl, "disable", "--now", containedNamespaceForwarderUnit), "denied", 1, nil)
	runner.on(argvFor(testSystemctl, "disable", "--now", unit+"-netns.service"), "denied", 1, nil)
	runner.on(argvFor(testSystemctl, "stop", unit+".socket"), "denied", 1, nil)
	runner.on(argvFor(testSystemctl, "disable", unit+".socket"), "denied", 1, nil)
	runner.on(argvFor(testSystemctl, "stop", nsUnit), "denied", 1, nil)

	services := []config.ContainmentLoopbackService{service}
	laterFailure := step{
		name: "later-failure",
		desc: "force namespace rollback",
		apply: func(context.Context, *installEnv) (bool, error) {
			return false, errors.New("later install failed")
		},
	}
	_, err := runSteps(context.Background(), env, out, []step{stepInstallNetworkNamespaceWithServices(&services), laterFailure})
	if err == nil || !strings.Contains(err.Error(), "later install failed") {
		t.Fatalf("runSteps error = %v", err)
	}
	// undo() errors are printed to the step-output writer, not joined into
	// the returned error (see rollbackApplied in step.go).
	if !strings.Contains(out.String(), "[FAIL] undo install-agent-network-namespace:") {
		t.Fatalf("output = %s, want the undo failure reported", out.String())
	}
	if !strings.Contains(out.String(), "systemctl disable --now "+containedNamespaceForwarderUnit+" exited 1: denied") {
		t.Fatalf("output = %s, want the cleanup failures joined in", out.String())
	}
	for _, want := range []string{
		argvFor(testSystemctl, "disable", "--now", containedNamespaceForwarderUnit),
		argvFor(testSystemctl, "disable", "--now", unit+"-netns.service"),
		argvFor(testSystemctl, "stop", unit+".socket"),
		argvFor(testSystemctl, "disable", unit+".socket"),
		argvFor(testSystemctl, "stop", nsUnit),
	} {
		if !fakeRunnerCalled(runner, want) {
			t.Fatalf("undo() did not attempt %q: %v", want, runner.calls)
		}
	}
}

// TestCovNSInstallNetworkNamespaceUndoActiveStateRestoreFailures forces every
// restore (enable/start) command in undo() to fail while every previous unit
// was active/enabled, so the cleanup-before-restore loops are no-ops and only
// the restore loops execute.
func TestCovNSInstallNetworkNamespaceUndoActiveStateRestoreFailures(t *testing.T) {
	env, runner, out := newFakeEnv(t)
	service := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9222, Owner: "x", Reason: "y", ExpiresAt: futureExpiryForTest}
	unit := loopbackForwarderUnitBase(service.Host, service.Port)
	legacyBody := "[Service]\nSlice=pipelock_contained.slice\n"
	if err := os.WriteFile(env.ownedLoopbackAnchorUnitPath, []byte(legacyBody), 0o600); err != nil {
		t.Fatal(err)
	}
	proxySocket := filepath.Base(env.proxyForwarderSocketPath)
	declaredSocket := unit + ".socket"
	nsUnit := filepath.Base(env.networkNamespaceUnitPath)
	legacyUnit := filepath.Base(env.ownedLoopbackAnchorUnitPath)
	declaredNS := unit + "-netns.service"
	for _, name := range []string{proxySocket, declaredSocket, nsUnit, containedNamespaceForwarderUnit, declaredNS, legacyUnit} {
		runner.on(argvFor(testSystemctl, "is-enabled", name), "enabled\n", 0, nil)
		runner.on(argvFor(testSystemctl, "is-active", name), "active\n", 0, nil)
	}
	for _, verb := range []string{"enable", "start"} {
		runner.on(argvFor(testSystemctl, verb, proxySocket), "denied", 1, nil)
		runner.on(argvFor(testSystemctl, verb, declaredSocket), "denied", 1, nil)
		runner.on(argvFor(testSystemctl, verb, containedNamespaceForwarderUnit), "denied", 1, nil)
		runner.on(argvFor(testSystemctl, verb, declaredNS), "denied", 1, nil)
		runner.on(argvFor(testSystemctl, verb, legacyUnit), "denied", 1, nil)
	}
	runner.on(argvFor(testSystemctl, "start", nsUnit), "denied", 1, nil)

	services := []config.ContainmentLoopbackService{service}
	laterFailure := step{
		name: "later-failure",
		desc: "force namespace rollback",
		apply: func(context.Context, *installEnv) (bool, error) {
			return false, errors.New("later install failed")
		},
	}
	_, err := runSteps(context.Background(), env, out, []step{stepInstallNetworkNamespaceWithServices(&services), laterFailure})
	if err == nil || !strings.Contains(err.Error(), "later install failed") {
		t.Fatalf("runSteps error = %v", err)
	}
	// undo() errors are printed to the step-output writer, not joined into
	// the returned error (see rollbackApplied in step.go).
	if !strings.Contains(out.String(), "[FAIL] undo install-agent-network-namespace:") {
		t.Fatalf("output = %s, want the undo failure reported", out.String())
	}
	if !strings.Contains(out.String(), "systemctl exited 1: denied") {
		t.Fatalf("output = %s, want the restore failures joined in", out.String())
	}
	for _, want := range []string{
		argvFor(testSystemctl, "enable", proxySocket), argvFor(testSystemctl, "start", proxySocket),
		argvFor(testSystemctl, "enable", declaredSocket), argvFor(testSystemctl, "start", declaredSocket),
		argvFor(testSystemctl, "enable", containedNamespaceForwarderUnit), argvFor(testSystemctl, "start", containedNamespaceForwarderUnit),
		argvFor(testSystemctl, "enable", declaredNS), argvFor(testSystemctl, "start", declaredNS),
		argvFor(testSystemctl, "start", nsUnit),
		argvFor(testSystemctl, "enable", legacyUnit), argvFor(testSystemctl, "start", legacyUnit),
	} {
		if !fakeRunnerCalled(runner, want) {
			t.Fatalf("undo() did not attempt to restore %q: %v", want, runner.calls)
		}
	}
}

// TestCovNSInstallNetworkNamespaceUndoFileAndReloadFailures exercises the
// remaining undo() branches: restoring a touched file that has no .bak (its
// remove fails), restoring a retired stale-forwarder body via backupAndWrite
// (its write fails), and undo's own daemon-reload call (distinct from
// apply's single daemon-reload call for the main install).
func TestCovNSInstallNetworkNamespaceUndoFileAndReloadFailures(t *testing.T) {
	env, _, out := newFakeEnv(t)
	stale := config.ContainmentLoopbackService{Host: "127.0.0.1", Port: 9300, Owner: "x", Reason: "y", ExpiresAt: futureExpiryForTest}
	staleUnit := loopbackForwarderUnitBase(stale.Host, stale.Port)
	inv, err := json.Marshal(desiredLoopbackForwarders([]config.ContainmentLoopbackService{stale}))
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
	staleSocketPath := filepath.Join(unitDir, staleUnit+".socket")
	if err := os.WriteFile(staleSocketPath, []byte("stale operator-owned socket unit\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(env.configDir, "pipelock.yaml")
	if err := os.WriteFile(cfgPath, []byte("containment:\n  loopback_services: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	reloadCalls := 0
	baseRunCmd := env.runCmd
	env.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		if name == "systemctl" && len(args) == 1 && args[0] == "daemon-reload" {
			reloadCalls++
			// Apply's own single daemon-reload call for the main install
			// must succeed; only undo's later call is made to fail.
			if reloadCalls >= 2 {
				return "denied", 1, nil
			}
		}
		return baseRunCmd(ctx, name, args...)
	}

	var denyFileOps bool
	baseRemove := env.removeFile
	env.removeFile = func(path string) error {
		if denyFileOps && path == env.networkNamespaceUnitPath {
			return errors.New("remove denied")
		}
		return baseRemove(path)
	}
	baseWrite := env.writeFile
	env.writeFile = func(path string, data []byte, mode os.FileMode) error {
		if denyFileOps && path == staleSocketPath {
			return errors.New("write denied")
		}
		return baseWrite(path, data, mode)
	}

	laterFailure := step{
		name: "later-failure",
		desc: "force namespace rollback",
		apply: func(context.Context, *installEnv) (bool, error) {
			// Apply must have already retired the stale forwarder and
			// written every managed file before this step turns the file
			// operations hostile for undo.
			denyFileOps = true
			return false, errors.New("later install failed")
		},
	}
	_, err = runSteps(context.Background(), env, out, []step{stepInstallNetworkNamespace(), laterFailure})
	if err == nil || !strings.Contains(err.Error(), "later install failed") {
		t.Fatalf("runSteps error = %v", err)
	}
	if !strings.Contains(out.String(), "[FAIL] undo install-agent-network-namespace:") {
		t.Fatalf("output = %s, want the undo failure reported", out.String())
	}
	for _, want := range []string{"remove denied", "restore retired managed forwarder " + staleSocketPath + ": write " + staleSocketPath + ": write denied", "systemctl exited 1: denied"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output = %s, missing %q", out.String(), want)
		}
	}
	if reloadCalls < 2 {
		t.Fatalf("daemon-reload calls = %d, want at least 2 (one from apply, one from undo)", reloadCalls)
	}
}

// TestCovNSContainedRelayTargetFallbacks covers the two configured-listener
// rejection branches: an unparsable host:port, and a parsed but non-loopback
// address.
func TestCovNSContainedRelayTargetFallbacks(t *testing.T) {
	dir := t.TempDir()
	shared := net.JoinHostPort("127.0.0.1", "8888")
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "unparsable host:port", body: "containment:\n  agent_listener: not-a-host-port\n"},
		{name: "non-loopback address", body: "containment:\n  agent_listener: 10.0.0.5:9999\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfgPath := filepath.Join(dir, tc.name+".yaml")
			if err := os.WriteFile(cfgPath, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := containedRelayTarget(cfgPath, 8888); got != shared {
				t.Fatalf("containedRelayTarget() = %q, want the shared proxy listener %q", got, shared)
			}
		})
	}
	// Positive control: a valid loopback listener is honored instead of
	// falling back.
	cfgPath := filepath.Join(dir, "valid.yaml")
	if err := os.WriteFile(cfgPath, []byte("containment:\n  agent_listener: 127.0.0.1:9321\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, want := containedRelayTarget(cfgPath, 8888), net.JoinHostPort("127.0.0.1", "9321"); got != want {
		t.Fatalf("containedRelayTarget() = %q, want the configured loopback listener %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// network_namespace.go: managedDoorwaySocketNames and probeAgentProcessNamespaces
// procRoot/readDir edge branches
// ---------------------------------------------------------------------------

func TestCovNSManagedDoorwaySocketNamesIncludesDeclaredServices(t *testing.T) {
	names := managedDoorwaySocketNames("/run/pipelock-agent-proxy.sock", []config.ContainmentLoopbackService{
		{Host: "127.0.0.1", Port: 9200},
		{Host: "::1", Port: 9300},
	})
	for _, want := range []string{
		"pipelock-agent-proxy.sock",
		loopbackForwarderUnitBase("127.0.0.1", 9200) + ".socket",
		loopbackForwarderUnitBase("::1", 9300) + ".socket",
	} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("managedDoorwaySocketNames() = %v, missing %q", names, want)
		}
	}
}

func TestCovNSProbeAgentProcessNamespacesDefaultProcRootAndNilReadDir(t *testing.T) {
	t.Run("empty procRoot falls back to /proc", func(t *testing.T) {
		called := false
		env := &probeEnv{
			agentUserName: testAgentUser,
			procRoot:      "",
			lookupUser: func(string) (*user.User, error) {
				return &user.User{Uid: "987"}, nil
			},
			readDir: func(path string) ([]os.DirEntry, error) {
				if path != "/proc" {
					t.Fatalf("readDir() path = %q, want the default /proc fallback", path)
				}
				called = true
				return nil, nil
			},
			readLink: func(string) (string, error) { return "", os.ErrNotExist },
		}
		status, detail := probeAgentProcessNamespaces(context.Background(), env, "net:[200]")
		if status != statusPass || !called {
			t.Fatalf("probeAgentProcessNamespaces() = (%q, %q), called=%t, want the default /proc path used", status, detail, called)
		}
	})
	t.Run("nil readDir is a closed failure", func(t *testing.T) {
		env := &probeEnv{
			agentUserName: testAgentUser,
			procRoot:      "/proc",
			lookupUser: func(string) (*user.User, error) {
				return &user.User{Uid: "987"}, nil
			},
			readDir: nil,
		}
		status, detail := probeAgentProcessNamespaces(context.Background(), env, "net:[200]")
		if status != statusFail || !strings.Contains(detail, "live agent process namespace audit is unavailable") {
			t.Fatalf("probeAgentProcessNamespaces() = (%q, %q), want the nil-readDir failure", status, detail)
		}
	})
}

// ---------------------------------------------------------------------------
// netns_assert.go
// ---------------------------------------------------------------------------

func TestCovNSNetnsAssertCmdRunE(t *testing.T) {
	t.Run("failure is wrapped as a config exit code", func(t *testing.T) {
		cmd := netnsAssertCmd()
		cmd.SetArgs([]string{"--agent-user", "covns-no-such-user"})
		var out strings.Builder
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		err := cmd.Execute()
		if err == nil {
			t.Fatal("Execute() = nil, want a lookup failure")
		}
		if cliExit := cliutil.ExitCodeOf(err); cliExit == 0 {
			t.Fatalf("Execute() error had exit code 0: %v", err)
		}
	})
}

func TestCovNSAssertManagedNetworkNamespaceMalformedIdentityPrefix(t *testing.T) {
	env := netnsAssertEnv{
		agentUser: testAgentUser,
		proxyPort: 8888,
		runCmd: func(context.Context, string, ...string) (string, int, error) {
			return "", 0, nil
		},
		readFile: func(string) ([]byte, error) { return []byte("garbage-without-brackets\n"), nil },
	}
	err := assertManagedNetworkNamespace(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "is malformed") {
		t.Fatalf("assertManagedNetworkNamespace() error = %v, want malformed-identity failure", err)
	}
}

func TestCovNSDirectContainedProxyHealthRedirectStopsAtFirstHop(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()
	port := redirector.Listener.Addr().(*net.TCPAddr).Port
	err := directContainedProxyHealth(context.Background(), port)
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("directContainedProxyHealth() error = %v, want the client to stop at the first redirect hop instead of following it", err)
	}
}

func TestCovNSDirectContainedProxyHealthConnectionFailure(t *testing.T) {
	// Bind, read back the ephemeral port, then close it immediately so the
	// health check dials a definitely-closed loopback port.
	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	err = directContainedProxyHealth(context.Background(), port)
	if err == nil {
		t.Fatal("directContainedProxyHealth() = nil, want a connection failure against a closed port")
	}
}

// ---------------------------------------------------------------------------
// nft_reload.go
// ---------------------------------------------------------------------------

func TestCovNSReloadNFTRulesDetectsLiveLegacyReceiver(t *testing.T) {
	rules := renderNFTRules(1000, 967, 966, 8888, defaultNFTTable, defaultNFTChain)
	liveOut := `meta skuid 966 oifname "lo" ip daddr 127.0.0.1 socket cgroupv2 level 1 "pipelock_contained.slice" ct state new ct mark set 0x504c4b01 accept # handle 5`
	var reported string
	err := reloadNFTRules(context.Background(), &nftReloadEnv{
		nftPath:    "nft",
		rulesPath:  "/managed/50-pipelock-containment.nft",
		table:      defaultNFTTable,
		chain:      defaultNFTChain,
		readFile:   func(string) ([]byte, error) { return []byte(rules), nil },
		writeFile:  func(string, []byte, os.FileMode) error { return nil },
		removeFile: func(string) error { return nil },
		report:     func(message string) { reported = message },
		runCmd: func(_ context.Context, _ string, args ...string) (string, int, error) {
			switch strings.Join(args, " ") {
			case "-n -a list chain inet " + defaultNFTTable + " " + defaultNFTChain:
				return liveOut, 0, nil
			case "-n list chain inet " + defaultNFTTable + " " + legacyOwnedLoopbackInputChain:
				return "some receiver chain content", 0, nil
			case "-c -f /managed/50-pipelock-containment.nft.reload":
				return "", 0, nil
			case "-f /managed/50-pipelock-containment.nft.reload":
				return "", 0, nil
			default:
				return "", -1, fmt.Errorf("unexpected nft command %q", strings.Join(args, " "))
			}
		},
	})
	if err != nil {
		t.Fatalf("reloadNFTRules() error = %v", err)
	}
	if reported == "" {
		t.Fatal("reloadNFTRules() did not report an outcome for the live-legacy-receiver reload")
	}
}

// TestCovNSLineHasLegacyOwnedLoopbackMarkRejectsTokenMismatch exercises the
// "want" token loop's failure branch: every fixed-position check before it
// passes, but one of the seven literal tokens in the middle of the line does
// not match.
func TestCovNSLineHasLegacyOwnedLoopbackMarkRejectsTokenMismatch(t *testing.T) {
	valid := `meta skuid 966 oifname "lo" ip daddr 127.0.0.1 socket cgroupv2 level 1 "pipelock_contained.slice" ct state new ct mark set 0x504c4b01 accept`
	if !lineHasLegacyOwnedLoopbackMark(valid, 966) {
		t.Fatalf("lineHasLegacyOwnedLoopbackMark() = false for a well-formed line, want true (positive control):\n%s", valid)
	}
	mismatched := `meta skuid 966 oifname "lo" ip daddr 127.0.0.1 socket cgroupv2 levelX 1 "pipelock_contained.slice" ct state new ct mark set 0x504c4b01 accept`
	if lineHasLegacyOwnedLoopbackMark(mismatched, 966) {
		t.Fatalf("lineHasLegacyOwnedLoopbackMark() = true for a line with \"levelX\" instead of \"level\", want false:\n%s", mismatched)
	}
}

func TestCovNSReconcileNamespaceDoorwaysPublishedFailureIsReported(t *testing.T) {
	var forwardersCalled, publishedCalled bool
	env := &nftReloadEnv{
		reconcileForwarders: func(context.Context, []config.ContainmentLoopbackService) error {
			forwardersCalled = true
			return nil
		},
		reconcilePublished: func(context.Context, []config.ContainmentPublishedService) error {
			publishedCalled = true
			return errors.New("published relay failed")
		},
	}
	err := reconcileNamespaceDoorways(context.Background(), env, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "published services failed to reconcile: published relay failed") {
		t.Fatalf("reconcileNamespaceDoorways() error = %v", err)
	}
	if !forwardersCalled || !publishedCalled {
		t.Fatalf("reconcileNamespaceDoorways() forwardersCalled=%t publishedCalled=%t, want both attempted", forwardersCalled, publishedCalled)
	}
}

// ---------------------------------------------------------------------------
// evidence_acl.go
// ---------------------------------------------------------------------------

func TestCovNSEvidenceACLInventoryCoversPartialGrant(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.evidenceACLInvPath), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := writeEvidenceACLInventory(env, evidenceACLInventory{
		Operator: "operator",
		Dirs:     []string{"/var/lib/pipelock/logs"},
	}); err != nil {
		t.Fatal(err)
	}
	// The recorded inventory covers the logs dir but not the recorder dir:
	// evidenceACLInventoryCovers must report false, forcing a re-grant.
	covers := evidenceACLInventoryCovers(env, "operator", []string{"/var/lib/pipelock/logs", "/var/lib/pipelock/recorder"})
	if covers {
		t.Fatal("evidenceACLInventoryCovers() = true, want false when a declared dir is missing from the recorded grant")
	}
	// Positive control: a request for only the already-recorded dir is
	// covered.
	if !evidenceACLInventoryCovers(env, "operator", []string{"/var/lib/pipelock/logs"}) {
		t.Fatal("evidenceACLInventoryCovers() = false for a subset of the recorded grant, want true")
	}
}

// ---------------------------------------------------------------------------
// rollback.go
// ---------------------------------------------------------------------------

func TestCovNSActionRemoveNetworkNamespaceUndoCombinesBothReadFailures(t *testing.T) {
	env, _, _ := newFakeEnv(t)
	if err := os.MkdirAll(filepath.Dir(env.loopbackForwarderInvPath), 0o750); err != nil {
		t.Fatal(err)
	}
	recordPath := publishedServiceRecordPath(env.loopbackForwarderInvPath)
	if err := os.WriteFile(recordPath, []byte("not the encoded record set"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.loopbackForwarderInvPath, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := actionRemoveNetworkNamespace().undo(context.Background(), env)
	if err == nil {
		t.Fatal("undo() = nil, want the two malformed records surfaced")
	}
	for _, want := range []string{"parse published service records", "parse loopback forwarder inventory"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("undo() error = %v, missing %q", err, want)
		}
	}
}
