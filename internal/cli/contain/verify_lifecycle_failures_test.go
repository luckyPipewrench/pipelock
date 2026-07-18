// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

func TestProbeWorkspaceAccessSurfacesUnsafeStates(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "workspace.txt")
	mustWriteFile(t, file, "data\n")

	tests := []struct {
		name       string
		paths      []string
		stat       func(string) (os.FileInfo, error)
		run        runCommand
		wantStatus string
		wantDetail string
	}{
		{
			name:       "stat failure",
			paths:      []string{file},
			stat:       func(string) (os.FileInfo, error) { return nil, os.ErrPermission },
			run:        rejectAllRun,
			wantStatus: statusFail,
			wantDetail: "stat: permission denied",
		},
		{
			name:  "process failure",
			paths: []string{file},
			stat:  os.Stat,
			run: func(context.Context, string, ...string) (string, int, error) {
				return "", -1, errors.New("sudo unavailable")
			},
			wantStatus: statusFail,
			wantDetail: "check failed: sudo unavailable",
		},
		{
			name:  "agent missing",
			paths: []string{dir},
			stat:  os.Stat,
			run: func(context.Context, string, ...string) (string, int, error) {
				return "sudo: unknown user pipelock-agent", 1, nil
			},
			wantStatus: statusSkip,
			wantDetail: "user missing",
		},
		{
			name:  "sudo refusal",
			paths: []string{dir},
			stat:  os.Stat,
			run: func(context.Context, string, ...string) (string, int, error) {
				return "sudo: a password is required", 1, nil
			},
			wantStatus: statusSkip,
			wantDetail: "sudo -n refused",
		},
		{
			name:  "unreadable",
			paths: []string{dir},
			stat:  os.Stat,
			run: func(context.Context, string, ...string) (string, int, error) {
				return "denied\nwith detail", 1, nil
			},
			wantStatus: statusFail,
			wantDetail: "not readable/traversable",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := makeProbeEnv(t, func(env *probeEnv) {
				env.workspacePaths = tc.paths
				env.stat = tc.stat
				env.runCmd = tc.run
			})
			status, detail := probeWorkspaceAccess(context.Background(), env)
			if status != tc.wantStatus || !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("probe = (%q, %q), want status %q containing %q", status, detail, tc.wantStatus, tc.wantDetail)
			}
		})
	}
}

func TestContainmentUIDResolutionFailsClosed(t *testing.T) {
	rulesPath := filepath.Join(t.TempDir(), "containment.nft")
	tests := []struct {
		name   string
		lookup lookupUserFunc
		read   func(string) ([]byte, error)
		want   string
	}{
		{
			name: "proxy lookup",
			lookup: func(name string) (*user.User, error) {
				return nil, user.UnknownUserError(name)
			},
			read: os.ReadFile,
			want: "lookup proxy uid",
		},
		{
			name:   "proxy root",
			lookup: uidLookup("0", "987"),
			read:   os.ReadFile,
			want:   "proxy user must be non-root",
		},
		{
			name: "agent lookup",
			lookup: func(name string) (*user.User, error) {
				if name == testProxyUser {
					return &user.User{Uid: "988"}, nil
				}
				return nil, user.UnknownUserError(name)
			},
			read: os.ReadFile,
			want: "lookup agent uid",
		},
		{
			name:   "agent root",
			lookup: uidLookup("988", "0"),
			read:   os.ReadFile,
			want:   "agent user must be non-root",
		},
		{
			name:   "same uid",
			lookup: uidLookup("988", "988"),
			read:   os.ReadFile,
			want:   "must be distinct",
		},
		{
			name:   "rules unreadable",
			lookup: uidLookup("988", "987"),
			read:   func(string) ([]byte, error) { return nil, os.ErrPermission },
			want:   "read nftables rules file",
		},
		{
			name:   "malformed header",
			lookup: uidLookup("988", "987"),
			read: func(string) ([]byte, error) {
				return []byte("# operator=1000 pipelock-proxy=nope pipelock-agent=987\n"), nil
			},
			want: "parse nftables rules file",
		},
		{
			name:   "missing header uid",
			lookup: uidLookup("988", "987"),
			read: func(string) ([]byte, error) {
				return []byte("# operator=1000 pipelock-proxy=988 unrelated=1\n"), nil
			},
			want: "missing operator",
		},
		{
			name:   "proxy drift",
			lookup: uidLookup("988", "987"),
			read: func(string) ([]byte, error) {
				return []byte("# operator=1000 pipelock-proxy=986 pipelock-agent=987\n"), nil
			},
			want: "proxy uid 986 does not match",
		},
		{
			name:   "agent drift",
			lookup: uidLookup("988", "987"),
			read: func(string) ([]byte, error) {
				return []byte("# operator=1000 pipelock-proxy=988 pipelock-agent=986\n"), nil
			},
			want: "agent uid 986 does not match",
		},
		{
			name:   "agent allow listed",
			lookup: uidLookup("988", "987"),
			read: func(string) ([]byte, error) {
				return []byte("# ignored operator=1000 badfield pipelock-proxy=988 pipelock-agent=987 operator=987\n"), nil
			},
			want: "contained agent must not be allow-listed",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := makeProbeEnv(t, func(env *probeEnv) {
				env.lookupUser = tc.lookup
				env.nftRulesPath = rulesPath
				env.readFile = tc.read
			})
			_, err := containmentUIDsFromProbeEnv(env)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func uidLookup(proxyUID, agentUID string) lookupUserFunc {
	return func(name string) (*user.User, error) {
		switch name {
		case testProxyUser:
			return &user.User{Uid: proxyUID}, nil
		case testAgentUser:
			return &user.User{Uid: agentUID}, nil
		default:
			return nil, user.UnknownUserError(name)
		}
	}
}

func TestListedToolTargetsRejectMalformedOrUnsafeState(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "tool")
	mustWriteFile(t, executable, "#!/bin/sh\n")
	if err := os.Chmod(executable, 0o755); err != nil { // #nosec G302 -- executable test fixture.
		t.Fatalf("chmod executable: %v", err)
	}
	directory := t.TempDir()
	nonExecutable := filepath.Join(t.TempDir(), "plain")
	mustWriteFile(t, nonExecutable, "plain\n")

	tests := []struct {
		name   string
		body   string
		stat   func(string) (os.FileInfo, error)
		detail string
	}{
		{name: "relative target", body: "tool\trelative/tool\n", stat: os.Stat, detail: "not absolute"},
		{name: "missing path target", body: "tool\t\n", stat: func(string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		}, detail: "not found"},
		{name: "stat denied", body: "tool\t" + executable + "\n", stat: func(string) (os.FileInfo, error) {
			return nil, os.ErrPermission
		}, detail: "permission denied"},
		{name: "directory target", body: "tool\t" + directory + "\n", stat: os.Stat, detail: "is a directory"},
		{name: "not executable", body: "tool\t" + nonExecutable + "\n", stat: os.Stat, detail: "not executable"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := makeProbeEnv(t, func(env *probeEnv) {
				env.readFile = func(string) ([]byte, error) { return []byte(tc.body), nil }
				env.stat = tc.stat
			})
			status, detail := probeListedToolTargets(context.Background(), env)
			if status != statusFail || !strings.Contains(detail, tc.detail) {
				t.Fatalf("probe = (%q, %q), want fail containing %q", status, detail, tc.detail)
			}
		})
	}
}

func TestVerificationMetadataFailuresAreVisible(t *testing.T) {
	t.Run("binary self path", func(t *testing.T) {
		env := makeProbeEnv(t, func(env *probeEnv) {
			env.readFile = func(string) ([]byte, error) { return []byte(strings.Repeat("a", sha256HexLen)), nil }
			env.selfPath = func() (string, error) { return "", os.ErrPermission }
		})
		status, detail := probeBinaryIntegrity(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "resolve self path") {
			t.Fatalf("probe = (%q, %q)", status, detail)
		}
	})

	t.Run("binary hash", func(t *testing.T) {
		env := makeProbeEnv(t, func(env *probeEnv) {
			env.readFile = func(string) ([]byte, error) { return []byte(strings.Repeat("a", sha256HexLen)), nil }
			env.selfPath = func() (string, error) { return "/bin/pipelock", nil }
			env.hashFile = func(string) (string, error) { return "", os.ErrPermission }
		})
		status, detail := probeBinaryIntegrity(context.Background(), env)
		if status != statusFail || !strings.Contains(detail, "hash /bin/pipelock") {
			t.Fatalf("probe = (%q, %q)", status, detail)
		}
	})

	for _, tc := range []struct {
		name string
		data []byte
		err  error
		want string
	}{
		{name: "inventory unreadable", err: os.ErrPermission, want: "read wrapper inventory"},
		{name: "inventory malformed", data: []byte("{"), want: "parse wrapper inventory"},
		{name: "inventory empty", data: []byte(`{"wrappers":[]}`), want: "is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := makeProbeEnv(t, func(env *probeEnv) {
				env.wrapperInvPath = filepath.Join(t.TempDir(), "wrappers.json")
				env.readFile = func(string) ([]byte, error) { return tc.data, tc.err }
			})
			_, err := wrappersForVerify(env)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}
}

func TestVerificationParsersRejectIncompleteSafetyEvidence(t *testing.T) {
	t.Run("workspace probe registration", func(t *testing.T) {
		env := makeProbeEnv(t, func(env *probeEnv) {
			env.workspacePaths = []string{"/workspace"}
		})
		probes := probesForEnv(env)
		if len(probes) != len(allProbes())+1 || probes[len(probes)-1].name != "workspace_access" {
			t.Fatalf("probes = %v", probes)
		}
	})

	t.Run("short digest remains readable", func(t *testing.T) {
		if got := shortHash("short"); got != "short" {
			t.Fatalf("short hash = %q", got)
		}
	})

	t.Run("systemd noise ignored", func(t *testing.T) {
		fields := parseSystemdShow("noise without separator\nActiveState=active\n")
		if len(fields) != 1 || fields["ActiveState"] != "active" {
			t.Fatalf("fields = %v", fields)
		}
	})

	t.Run("malformed uid", func(t *testing.T) {
		_, err := lookupUID(func(string) (*user.User, error) {
			return &user.User{Uid: "not-numeric"}, nil
		}, "pipelock-agent")
		if err == nil || !strings.Contains(err.Error(), "parse uid") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("managed header absent", func(t *testing.T) {
		_, ok, err := parseNFTRulesHeaderUIDs([]byte("table inet unrelated {}\n"))
		if err != nil || ok {
			t.Fatalf("ok = %v, error = %v", ok, err)
		}
	})

	t.Run("persistence unit unreadable", func(t *testing.T) {
		env := makeProbeEnv(t, func(env *probeEnv) {
			env.nftPersistUnitPath = "/managed/pipelock-nft.service"
			env.readFile = func(string) ([]byte, error) { return nil, os.ErrPermission }
		})
		err := verifyNFTPersistence(env)
		if err == nil || !strings.Contains(err.Error(), "read nftables persistence unit") {
			t.Fatalf("error = %v", err)
		}
	})

	t.Run("nft executable fallback", func(t *testing.T) {
		if got := probeNFTExecutable(nil); got != "nft" {
			t.Fatalf("executable = %q", got)
		}
	})

	t.Run("closed chain has no evidence", func(t *testing.T) {
		rules := "chain output_filter {\n  type filter hook output priority filter; policy accept;\n}\n"
		if chainHasLineBeforeAgentDrop(rules, "output_filter", 987, func(string) bool { return false }) {
			t.Fatal("closed chain unexpectedly matched")
		}
	})

	t.Run("non certificate pem ignored", func(t *testing.T) {
		count, commonName, err := scanPipelockCertCN([]byte("-----BEGIN OTHER-----\nYWJj\n-----END OTHER-----\n"))
		if err != nil || count != 0 || commonName != "" {
			t.Fatalf("count = %d, common name = %q, error = %v", count, commonName, err)
		}
	})

	t.Run("real command success", func(t *testing.T) {
		output, code, err := realRunCommand(context.Background(), "true")
		if err != nil || code != 0 || output != "" {
			t.Fatalf("output = %q, code = %d, error = %v", output, code, err)
		}
	})
}
