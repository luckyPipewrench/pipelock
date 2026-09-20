// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os/user"
	"strings"
	"testing"
)

func TestAssertAgentNetworkNamespace(t *testing.T) {
	t.Parallel()

	base := func() netnsAssertEnv {
		return netnsAssertEnv{
			agentUser: testAgentUser,
			proxyPort: 8888,
			euid:      func() int { return 987 },
			lookup: func(string) (*user.User, error) {
				return &user.User{Uid: "987", Username: testAgentUser}, nil
			},
			runCmd: func(_ context.Context, name string, args ...string) (string, int, error) {
				if name != containSystemctlPath || !containsArg(args, containedNetworkNamespaceUnit) || !containsArg(args, "is-active") {
					t.Fatalf("unexpected command: %s %v", name, args)
				}
				return "", 0, nil
			},
			readFile: func(string) ([]byte, error) { return []byte("net:[200]\n"), nil },
			readLink: func(string) (string, error) { return "net:[200]", nil },
			interfaces: func() ([]net.Interface, error) {
				return []net.Interface{{Name: "lo", Flags: net.FlagLoopback | net.FlagUp}}, nil
			},
			proxyHealth: func(context.Context, int) error { return nil },
		}
	}

	for _, tc := range []struct {
		name    string
		mutate  func(*netnsAssertEnv)
		wantErr string
	}{
		{name: "managed namespace"},
		{name: "wrong effective user", mutate: func(env *netnsAssertEnv) {
			env.euid = func() int { return 1000 }
		}, wantErr: "effective uid"},
		{name: "agent lookup failure", mutate: func(env *netnsAssertEnv) {
			env.lookup = func(string) (*user.User, error) { return nil, errors.New("lookup failed") }
		}, wantErr: "lookup failed"},
		{name: "invalid agent uid", mutate: func(env *netnsAssertEnv) {
			env.lookup = func(string) (*user.User, error) { return &user.User{Uid: "invalid"}, nil }
		}, wantErr: "invalid uid"},
		{name: "different private namespace", mutate: func(env *netnsAssertEnv) {
			env.readLink = func(string) (string, error) { return "net:[300]", nil }
		}, wantErr: "does not match managed namespace"},
		{name: "published identity unavailable", mutate: func(env *netnsAssertEnv) {
			env.readFile = func(string) ([]byte, error) { return nil, errors.New("permission denied") }
		}, wantErr: "permission denied"},
		{name: "malformed published identity", mutate: func(env *netnsAssertEnv) {
			env.readFile = func(string) ([]byte, error) { return []byte("net:[not-a-number]\n"), nil }
		}, wantErr: "is malformed"},
		{name: "self namespace unavailable", mutate: func(env *netnsAssertEnv) {
			env.readLink = func(string) (string, error) { return "", errors.New("namespace unavailable") }
		}, wantErr: "namespace unavailable"},
		{name: "host interfaces", mutate: func(env *netnsAssertEnv) {
			env.interfaces = func() ([]net.Interface, error) {
				return []net.Interface{
					{Name: "lo", Flags: net.FlagLoopback | net.FlagUp},
					{Name: "eth0", Flags: net.FlagUp},
				}, nil
			}
		}, wantErr: "want only loopback"},
		{name: "interface listing unavailable", mutate: func(env *netnsAssertEnv) {
			env.interfaces = func() ([]net.Interface, error) { return nil, errors.New("interface failure") }
		}, wantErr: "interface failure"},
		{name: "inactive anchor", mutate: func(env *netnsAssertEnv) {
			env.runCmd = func(context.Context, string, ...string) (string, int, error) {
				return "inactive\n", 3, nil
			}
		}, wantErr: "not active"},
		{name: "proxy doorway unavailable", mutate: func(env *netnsAssertEnv) {
			env.proxyHealth = func(context.Context, int) error { return errors.New("connection refused") }
		}, wantErr: "connection refused"},
		{name: "systemctl unavailable", mutate: func(env *netnsAssertEnv) {
			env.runCmd = func(context.Context, string, ...string) (string, int, error) {
				return "", 0, errors.New("unavailable")
			}
		}, wantErr: "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := base()
			if tc.mutate != nil {
				tc.mutate(&env)
			}
			err := assertAgentNetworkNamespace(context.Background(), env)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("assertAgentNetworkNamespace() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("assertAgentNetworkNamespace() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestDirectContainedProxyHealth(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		status  int
		wantErr string
	}{
		{name: "healthy", status: http.StatusOK},
		{name: "redirect is not health", status: http.StatusFound, wantErr: "HTTP 302"},
		{name: "unhealthy", status: http.StatusServiceUnavailable, wantErr: "HTTP 503"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			port := server.Listener.Addr().(*net.TCPAddr).Port
			err := directContainedProxyHealth(context.Background(), port)
			if tc.wantErr == "" && err != nil {
				t.Fatalf("directContainedProxyHealth() error = %v", err)
			}
			if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("directContainedProxyHealth() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}
