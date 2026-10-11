// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"strings"
	"testing"
	"testing/fstest"
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
			readFile: managedRuntimeFixtureReadFile,
			readDir:  managedRuntimeFixtureReadDir,
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
		{name: "proxy doorway unavailable", mutate: func(env *netnsAssertEnv) {
			env.proxyHealth = func(context.Context, int) error { return errors.New("connection refused") }
		}, wantErr: "connection refused"},
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

const (
	managedRuntimeMountFixture = "20 1 0:200 / /run ro - tmpfs tmpfs ro\n21 1 0:201 / /dev/shm rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n22 20 0:50 /pipelock-contain/agent-netns.id /run/pipelock-contain/agent-netns.id ro - tmpfs tmpfs rw\n"
	hostRuntimeMountFixture    = "10 1 0:50 / /run rw - tmpfs tmpfs rw\n11 1 0:51 / /dev/shm rw,nosuid,nodev,noexec - tmpfs tmpfs rw\n"
)

func managedRuntimeFixtureReadFile(path string) ([]byte, error) {
	switch path {
	case "/proc/self/mountinfo":
		return []byte(managedRuntimeMountFixture), nil
	case "/proc/1/mountinfo":
		return []byte(hostRuntimeMountFixture), nil
	case containedNamespaceIdentityPath:
		return []byte("net:[200]\n"), nil
	default:
		return nil, os.ErrNotExist
	}
}

func managedRuntimeFixtureReadDir(path string) ([]os.DirEntry, error) {
	tree := fstest.MapFS{"pipelock-contain/agent-netns.id": &fstest.MapFile{Data: []byte("net:[200]\n"), Mode: 0o600}}
	name := strings.TrimPrefix(strings.TrimPrefix(path, "/run"), "/")
	if name == "" {
		name = "."
	}
	return tree.ReadDir(name)
}

func TestManagedNamespaceRefusesMissingRuntimeMounts(t *testing.T) {
	for _, tc := range []struct{ name, mounts string }{
		{"host runtime", hostRuntimeMountFixture},
		{"writable run", strings.Replace(managedRuntimeMountFixture, "/run ro", "/run rw", 1)},
		{"missing shm mask", strings.Replace(managedRuntimeMountFixture, "0:201", "0:51", 1)},
		{"missing identity bind", strings.Join(strings.Split(managedRuntimeMountFixture, "\n")[:2], "\n")},
		{"not tmpfs", strings.Replace(managedRuntimeMountFixture, "tmpfs", "ext4", 1)},
		{"malformed mountinfo", "unparseable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := defaultNetnsAssertEnv()
			env.readFile = func(path string) ([]byte, error) {
				if path == "/proc/self/mountinfo" {
					return []byte(tc.mounts), nil
				}
				return managedRuntimeFixtureReadFile(path)
			}
			env.readDir = managedRuntimeFixtureReadDir
			env.readLink = func(string) (string, error) { return "net:[200]", nil }
			env.interfaces = func() ([]net.Interface, error) { return []net.Interface{{Name: "lo", Flags: net.FlagLoopback}}, nil }
			env.proxyHealth = func(context.Context, int) error {
				t.Fatal("runtime mount refusal must precede proxy health")
				return nil
			}
			err := assertManagedNetworkNamespace(t.Context(), env)
			if err == nil {
				t.Fatal("namespace admitted without runtime isolation")
			}
			for _, property := range []string{"TemporaryFileSystem=/run:ro", "TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,noexec", "BindReadOnlyPaths=" + containedNamespaceIdentityPath} {
				if !strings.Contains(err.Error(), property) {
					t.Errorf("refusal must name %s: %v", property, err)
				}
			}
		})
	}
}

func TestRuntimeMountEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, mounts, want string
		mutate             func(*netnsAssertEnv)
	}{
		{name: "valid"},
		{name: "shadowed host mounts", mounts: "10 1 0:50 / /run rw - tmpfs tmpfs rw\n11 1 0:51 / /dev/shm rw - tmpfs tmpfs rw\n" + strings.ReplaceAll(strings.ReplaceAll(managedRuntimeMountFixture, "20 1", "20 10"), "21 1", "21 11")},
		{name: "unordered shadow stack", mounts: strings.ReplaceAll(strings.ReplaceAll(managedRuntimeMountFixture, "20 1", "20 10"), "21 1", "21 11") + "11 1 0:51 / /dev/shm rw - tmpfs tmpfs rw\n10 1 0:50 / /run rw - tmpfs tmpfs rw\n"},
		{name: "missing run", mounts: strings.Join(strings.Split(managedRuntimeMountFixture, "\n")[1:], "\n"), want: "private tmpfs"},
		{name: "host run", mounts: strings.Replace(managedRuntimeMountFixture, "0:200", "0:50", 1), want: "private filesystem identity"},
		{name: "subtree run", mounts: strings.Replace(managedRuntimeMountFixture, "0:200 /", "0:200 /subtree", 1), want: "private tmpfs"},
		{name: "readonly shm", mounts: strings.Replace(managedRuntimeMountFixture, "/dev/shm rw", "/dev/shm ro", 1), want: "lacks rw"},
		{name: "executable shm", mounts: strings.Replace(managedRuntimeMountFixture, ",noexec", "", 1), want: "lacks noexec"},
		{name: "writable identity", mounts: strings.Replace(managedRuntimeMountFixture, "agent-netns.id ro", "agent-netns.id rw", 1), want: "read-only bind"},
		{name: "duplicate mount", mounts: managedRuntimeMountFixture + "23 1 0:202 / /run ro - tmpfs tmpfs ro\n", want: "ambiguous"},
		{name: "duplicate mount id", mounts: managedRuntimeMountFixture + "20 1 0:202 / /run ro - tmpfs tmpfs ro\n", want: "duplicate runtime mount identity"},
		{name: "mount cycle", mounts: strings.Replace(managedRuntimeMountFixture, "20 1", "20 20", 1), want: "ambiguous"},
		{name: "missing reader", want: "readers are unavailable", mutate: func(env *netnsAssertEnv) { env.readDir = nil }},
		{name: "self unreadable", want: "permission denied", mutate: func(env *netnsAssertEnv) {
			env.readFile = func(string) ([]byte, error) { return nil, os.ErrPermission }
		}},
		{name: "host unreadable", want: "permission denied", mutate: func(env *netnsAssertEnv) {
			env.readFile = func(path string) ([]byte, error) {
				if path == "/proc/1/mountinfo" {
					return nil, os.ErrPermission
				}
				return managedRuntimeFixtureReadFile(path)
			}
		}},
		{name: "host missing shm", want: "private filesystem identity", mutate: func(env *netnsAssertEnv) {
			env.readFile = func(path string) ([]byte, error) {
				if path == "/proc/1/mountinfo" {
					return []byte(strings.Split(hostRuntimeMountFixture, "\n")[0]), nil
				}
				return managedRuntimeFixtureReadFile(path)
			}
		}},
		{name: "directory unreadable", want: "inspect isolated runtime", mutate: func(env *netnsAssertEnv) {
			env.readDir = func(string) ([]os.DirEntry, error) { return nil, os.ErrPermission }
		}},
		{name: "extra host directory", want: "contain only", mutate: func(env *netnsAssertEnv) {
			env.readDir = func(path string) ([]os.DirEntry, error) {
				tree := fstest.MapFS{"pipelock-contain/agent-netns.id": &fstest.MapFile{}, "user/bus": &fstest.MapFile{}}
				if path == "/run" {
					return tree.ReadDir(".")
				}
				return tree.ReadDir("pipelock-contain")
			}
		}},
		{name: "extra identity sibling", want: "contain only", mutate: func(env *netnsAssertEnv) {
			env.readDir = func(path string) ([]os.DirEntry, error) {
				if path == "/run" {
					return managedRuntimeFixtureReadDir(path)
				}
				return (fstest.MapFS{"agent-netns.id": &fstest.MapFile{}, "socket": &fstest.MapFile{}}).ReadDir(".")
			}
		}},
		{name: "symlink identity", want: "contain only", mutate: func(env *netnsAssertEnv) {
			env.readDir = func(path string) ([]os.DirEntry, error) {
				if path == "/run" {
					return managedRuntimeFixtureReadDir(path)
				}
				return (fstest.MapFS{"agent-netns.id": &fstest.MapFile{Mode: os.ModeSymlink}}).ReadDir(".")
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := defaultNetnsAssertEnv()
			env.readFile, env.readDir = managedRuntimeFixtureReadFile, managedRuntimeFixtureReadDir
			if tc.mounts != "" {
				env.readFile = func(path string) ([]byte, error) {
					if path == "/proc/self/mountinfo" {
						return []byte(tc.mounts), nil
					}
					return managedRuntimeFixtureReadFile(path)
				}
			}
			if tc.mutate != nil {
				tc.mutate(&env)
			}
			err := assertManagedRuntimeMounts(env)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("mount refusal = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRuntimeMountReaderRefusalNamesEvidenceAccess(t *testing.T) {
	for _, path := range []string{"/proc/self/mountinfo", "/proc/1/mountinfo", "/run"} {
		t.Run(path, func(t *testing.T) {
			env := defaultNetnsAssertEnv()
			env.readFile = func(name string) ([]byte, error) {
				if name == path {
					return nil, os.ErrPermission
				}
				return managedRuntimeFixtureReadFile(name)
			}
			env.readDir = func(name string) ([]os.DirEntry, error) {
				if name == path {
					return nil, os.ErrPermission
				}
				return managedRuntimeFixtureReadDir(name)
			}
			err := assertManagedRuntimeMounts(env)
			if !errors.Is(err, os.ErrPermission) || !strings.Contains(err.Error(), "cannot be verified") || strings.Contains(err.Error(), "TemporaryFileSystem=") {
				t.Fatalf("reader refusal should name evidence access without mount remediation: %v", err)
			}
		})
	}
}

func TestRuntimeMountEvidenceSeparateVarRun(t *testing.T) {
	env := defaultNetnsAssertEnv()
	env.readDir = managedRuntimeFixtureReadDir
	for _, tc := range []struct {
		name, extra string
		denied      bool
	}{
		{"private", "24 1 0:202 / /var/run ro - tmpfs tmpfs ro\n", false},
		{"missing", "", true},
		{"host bind", "24 1 0:1 /var/run /var/run ro - ext4 root ro\n", true},
		{"writable", "24 1 0:202 / /var/run rw - tmpfs tmpfs rw\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env.readFile = func(path string) ([]byte, error) {
				if path == "/proc/self/mountinfo" {
					return []byte(managedRuntimeMountFixture + tc.extra), nil
				}
				if path == "/proc/1/mountinfo" {
					return []byte(hostRuntimeMountFixture + "1 0 0:1 / / rw - ext4 root rw\n"), nil
				}
				return managedRuntimeFixtureReadFile(path)
			}
			err := checkRuntimeMountsForProperties(env, []string{"/run:ro", "/dev/shm:rw,nosuid,nodev,noexec", "/var/run:ro"})
			if (err != nil) != tc.denied {
				t.Fatalf("separate /var/run %s: %v", tc.name, err)
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

func TestRequireHostNetworkNamespace(t *testing.T) {
	link := func(self, host string, selfErr, hostErr error) func(string) (string, error) {
		return func(path string) (string, error) {
			switch path {
			case "/proc/self/ns/net":
				return self, selfErr
			case "/proc/1/ns/net":
				return host, hostErr
			case "/proc/self/ns/mnt", "/proc/1/ns/mnt":
				return "mnt:[1]", nil
			}
			return "", os.ErrNotExist
		}
	}
	// mountLink is a host network namespace with the given mount identities.
	mountLink := func(self, host string, selfErr, hostErr error) func(string) (string, error) {
		return func(path string) (string, error) {
			switch path {
			case "/proc/self/ns/net", "/proc/1/ns/net":
				return "net:[1]", nil
			case "/proc/self/ns/mnt":
				return self, selfErr
			case "/proc/1/ns/mnt":
				return host, hostErr
			}
			return "", os.ErrNotExist
		}
	}
	tests := []struct {
		name     string
		readLink func(string) (string, error)
		wantErr  string
	}{
		{"host namespace passes", link("net:[1]", "net:[1]", nil, nil), ""},
		{"agent namespace refused", link("net:[2]", "net:[1]", nil, nil), "not the host network namespace"},
		{"empty identity refused", link("", "", nil, nil), "not the host network namespace"},
		{"unreadable self refused", link("", "net:[1]", os.ErrPermission, nil), "read own network namespace"},
		{"unreadable host refused", link("net:[1]", "", nil, os.ErrPermission), "read host network namespace"},
		{"missing reader refused", nil, "unavailable"},
		// A unit that joins the agent namespace shares its private /tmp: host
		// network alone is not enough for host-side probes.
		{"agent mount namespace refused", mountLink("mnt:[2]", "mnt:[1]", nil, nil), "not the host mount namespace"},
		{"unreadable mount namespace refused", mountLink("", "mnt:[1]", os.ErrPermission, nil), "read own mount namespace"},
		{"unreadable host mount namespace refused", mountLink("mnt:[1]", "", nil, os.ErrPermission), "read host mount namespace"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := requireHostNetworkNamespace(tc.readLink)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestHostNamespaceCommandArgs(t *testing.T) {
	got := strings.Join(hostNamespaceCommandArgs("/usr/local/bin/pipelock", []string{"contain", "service-posture", "--", "tool"}), " ")
	want := "--net=/proc/1/ns/net --mount=/proc/1/ns/mnt -- /usr/local/bin/pipelock contain service-posture -- tool"
	if got != want {
		t.Fatalf("args = %q, want %q", got, want)
	}
}

func TestRunInHostNetworkNamespaceFailsForUnprivilegedCaller(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can join namespaces; the failure path needs an unprivileged caller")
	}
	if err := runInHostNetworkNamespace(context.Background(), io.Discard, io.Discard, []string{"version"}); err == nil {
		t.Fatal("expected the host-namespace re-exec to fail for an unprivileged caller")
	}
}
