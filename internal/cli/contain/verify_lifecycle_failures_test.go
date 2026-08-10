// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"fmt"
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
	for _, tc := range []struct {
		name       string
		selfPath   func() (string, error)
		hashFile   func(string) (string, error)
		wantStatus string
		wantDetail string
	}{
		{
			name:       "invoking binary path unavailable does not prevent deployed binary verification",
			selfPath:   func() (string, error) { return "", os.ErrPermission },
			hashFile:   func(string) (string, error) { return strings.Repeat("a", sha256HexLen), nil },
			wantStatus: statusPass,
			wantDetail: "matches pin",
		},
		{
			name:       "deployed binary unreadable",
			selfPath:   func() (string, error) { return "/bin/pipelock", nil },
			hashFile:   func(string) (string, error) { return "", os.ErrPermission },
			wantStatus: statusFail,
			wantDetail: "hash deployed binary",
		},
		{
			name:       "deployed binary absent",
			selfPath:   func() (string, error) { return "/bin/pipelock", nil },
			hashFile:   func(string) (string, error) { return "", os.ErrNotExist },
			wantStatus: statusFail,
			wantDetail: "hash deployed binary",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := makeProbeEnv(t, func(env *probeEnv) {
				env.readFile = func(string) ([]byte, error) { return []byte(strings.Repeat("a", sha256HexLen)), nil }
				env.selfPath = tc.selfPath
				env.hashFile = tc.hashFile
			})
			if tc.wantStatus == statusPass {
				target := filepath.Join(t.TempDir(), "pipelock")
				mustWriteFile(t, target, "deployed binary")
				env.pipelockTarget = target
				configureMatchingServiceBinary(t, env)
			}
			status, detail := probeBinaryIntegrity(context.Background(), env)
			if status != tc.wantStatus || !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("probe = (%q, %q), want (%q, containing %q)", status, detail, tc.wantStatus, tc.wantDetail)
			}
		})
	}

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

func TestProbeBinaryIntegrityVerifiesDeployedBinary(t *testing.T) {
	const deployedContents = "deployed binary before mutation"

	tests := []struct {
		name           string
		mutateDeployed bool
		invokingBody   string
		wantStatus     string
		wantDetail     string
	}{
		{
			name:           "mutated deployed binary fails even when invoking binary still matches pin",
			mutateDeployed: true,
			invokingBody:   deployedContents,
			wantStatus:     statusFail,
			wantDetail:     "mismatch",
		},
		{
			name:         "different invoking binary notes but does not fail when deployed binary matches pin",
			invokingBody: "separate operator binary",
			wantStatus:   statusPass,
			wantDetail:   "note: invoking binary",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			deployed := filepath.Join(dir, "deployed-pipelock")
			invoking := filepath.Join(dir, "invoking-pipelock")
			pinPath := filepath.Join(dir, "binary-pin.sha256")
			mustWriteFile(t, deployed, deployedContents)
			pinned, err := sha256HexOfFile(deployed)
			if err != nil {
				t.Fatalf("hash deployed binary before mutation: %v", err)
			}
			mustWriteFile(t, pinPath, pinned+"\n")
			if tc.mutateDeployed {
				mustWriteFile(t, deployed, "deployed binary after mutation")
			}
			mustWriteFile(t, invoking, tc.invokingBody)

			env := makeProbeEnv(t, func(env *probeEnv) {
				env.pinPath = pinPath
				env.pipelockTarget = deployed
				env.readFile = os.ReadFile
				env.selfPath = func() (string, error) { return invoking, nil }
				env.hashFile = sha256HexOfFile
			})
			configureMatchingServiceBinary(t, env)
			status, detail := probeBinaryIntegrity(context.Background(), env)
			if status != tc.wantStatus || !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("probe = (%q, %q), want (%q, containing %q)", status, detail, tc.wantStatus, tc.wantDetail)
			}
		})
	}
}

func TestProbeBinaryIntegrity_DoesNotMisreportAliasedInvokingBinary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alias func(t *testing.T, target, invoking string)
	}{
		{
			name: "symlink",
			alias: func(t *testing.T, target, invoking string) {
				t.Helper()
				if err := os.Symlink(target, invoking); err != nil {
					t.Fatalf("symlink invoking binary: %v", err)
				}
			},
		},
		{
			name: "hardlink",
			alias: func(t *testing.T, target, invoking string) {
				t.Helper()
				if err := os.Link(target, invoking); err != nil {
					t.Fatalf("hardlink invoking binary: %v", err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "deployed-pipelock")
			invoking := filepath.Join(dir, "invoking-pipelock")
			pinPath := filepath.Join(dir, "binary-pin.sha256")
			mustWriteFile(t, target, "installed binary")
			pinned, err := sha256HexOfFile(target)
			if err != nil {
				t.Fatalf("hash deployed binary: %v", err)
			}
			mustWriteFile(t, pinPath, pinned+"\n")
			tc.alias(t, target, invoking)

			env := makeProbeEnv(t, func(env *probeEnv) {
				env.pinPath = pinPath
				env.pipelockTarget = target
				env.readFile = os.ReadFile
				env.selfPath = func() (string, error) { return invoking, nil }
				env.hashFile = sha256HexOfFile
			})
			configureMatchingServiceBinary(t, env)
			status, detail := probeBinaryIntegrity(context.Background(), env)
			if status != statusPass {
				t.Fatalf("status = %q, want pass: %s", status, detail)
			}
			if strings.Contains(detail, "note: invoking binary") {
				t.Fatalf("detail = %q, must not report a path alias as a different binary", detail)
			}
		})
	}
}

func TestProbeBinaryIntegrity_VerifiesEffectiveServiceCommandAndRunningImage(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, target, pinPath string) (execPath, mainPID, runningImage string, readLinkErr error)
		wantStatus string
		wantDetail string
	}{
		{
			name: "clean deployed command and running image match",
			setup: func(t *testing.T, target, pinPath string) (string, string, string, error) {
				t.Helper()
				return target, "4242", target, nil
			},
			wantStatus: statusPass,
			wantDetail: "deployed and running service binary hash",
		},
		{
			name: "effective ExecStart points at a different binary",
			setup: func(t *testing.T, target, pinPath string) (string, string, string, error) {
				t.Helper()
				other := filepath.Join(t.TempDir(), "other-pipelock")
				mustWriteFile(t, other, "other executable")
				return other, "4242", target, nil
			},
			wantStatus: statusFail,
			wantDetail: "effective ExecStart path",
		},
		{
			name: "deployed file was atomically replaced but service still maps the old image",
			setup: func(t *testing.T, target, pinPath string) (string, string, string, error) {
				t.Helper()
				oldImage := target + ".old"
				if err := os.Rename(target, oldImage); err != nil {
					t.Fatalf("preserve running image: %v", err)
				}
				mustWriteFile(t, target+".new", "new deployed executable")
				if err := os.Rename(target+".new", target); err != nil {
					t.Fatalf("atomically replace deployed image: %v", err)
				}
				pinned, err := sha256HexOfFile(target)
				if err != nil {
					t.Fatalf("hash replacement: %v", err)
				}
				mustWriteFile(t, pinPath, pinned+"\n")
				return target, "4242", oldImage, nil
			},
			wantStatus: statusFail,
			wantDetail: "running service image",
		},
		{
			name: "systemd reports no main process",
			setup: func(t *testing.T, target, pinPath string) (string, string, string, error) {
				t.Helper()
				return target, "0", target, nil
			},
			wantStatus: statusFail,
			wantDetail: "invalid MainPID",
		},
		{
			name: "MainPID is stale",
			setup: func(t *testing.T, target, pinPath string) (string, string, string, error) {
				t.Helper()
				return target, "4242", "", os.ErrNotExist
			},
			wantStatus: statusFail,
			wantDetail: "read running service image",
		},
		{
			name: "running image is not visible without root",
			setup: func(t *testing.T, target, pinPath string) (string, string, string, error) {
				t.Helper()
				return target, "4242", "", os.ErrPermission
			},
			wantStatus: statusSkip,
			wantDetail: "rerun as root",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "pipelock")
			pinPath := filepath.Join(dir, "binary-pin.sha256")
			mustWriteFile(t, target, "original executable")
			pinned, err := sha256HexOfFile(target)
			if err != nil {
				t.Fatalf("hash deployed image: %v", err)
			}
			mustWriteFile(t, pinPath, pinned+"\n")

			execPath, mainPID, runningImage, readLinkErr := tc.setup(t, target, pinPath)
			procExe := serviceProcessExePath(testServicePID)
			env := makeProbeEnv(t, func(env *probeEnv) {
				env.pipelockTarget = target
				env.pinPath = pinPath
				env.readFile = os.ReadFile
				env.selfPath = func() (string, error) { return target, nil }
				env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
					if name != testSystemctl || !containsArg(args, "--value") {
						return "", -1, fmt.Errorf("unexpected command %s %v", name, args)
					}
					switch {
					case containsArg(args, "--property=ExecStart"):
						return fmt.Sprintf("{ path=%s ; argv[]=%s run ; }\n", execPath, execPath), 0, nil
					case containsArg(args, "--property=MainPID"):
						return mainPID + "\n", 0, nil
					default:
						return "", -1, fmt.Errorf("unexpected systemctl property %v", args)
					}
				}
				env.readLink = func(path string) (string, error) {
					if path != procExe {
						return "", fmt.Errorf("unexpected readLink %s", path)
					}
					if readLinkErr != nil {
						return "", readLinkErr
					}
					return runningImage, nil
				}
				env.stat = func(path string) (os.FileInfo, error) {
					if path == procExe {
						return os.Stat(runningImage)
					}
					return os.Stat(path)
				}
				env.hashFile = func(path string) (string, error) {
					if path == procExe {
						return sha256HexOfFile(runningImage)
					}
					return sha256HexOfFile(path)
				}
			})

			status, detail := probeBinaryIntegrity(context.Background(), env)
			if status != tc.wantStatus || !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("probe = (%q, %q), want (%q, containing %q)", status, detail, tc.wantStatus, tc.wantDetail)
			}
		})
	}
}

func TestProbeBinaryIntegrity_RunningImageVerificationFailures(t *testing.T) {
	tests := []struct {
		name       string
		configure  func(env *probeEnv, target, procExe string)
		wantStatus string
		wantDetail string
	}{
		{
			name: "systemctl reports a failed show command",
			configure: func(env *probeEnv, _, _ string) {
				env.runCmd = func(context.Context, string, ...string) (string, int, error) {
					return "unit not loaded\nextra detail", 5, nil
				}
			},
			wantStatus: statusFail,
			wantDetail: "systemctl exit=5",
		},
		{
			name: "systemctl reports a malformed effective command",
			configure: func(env *probeEnv, _, _ string) {
				env.runCmd = func(context.Context, string, ...string) (string, int, error) {
					return "MainPID=4242\nExecStart={ path=pipelock ; argv[]=pipelock run ; }\n", 0, nil
				}
			},
			wantStatus: statusFail,
			wantDetail: "parse effective ExecStart",
		},
		{
			name: "running image stat permission denied",
			configure: func(env *probeEnv, _, procExe string) {
				originalStat := env.stat
				env.stat = func(path string) (os.FileInfo, error) {
					if path == procExe {
						return nil, os.ErrPermission
					}
					return originalStat(path)
				}
			},
			wantStatus: statusSkip,
			wantDetail: "stat running service image",
		},
		{
			name: "running image stat stale process",
			configure: func(env *probeEnv, _, procExe string) {
				originalStat := env.stat
				env.stat = func(path string) (os.FileInfo, error) {
					if path == procExe {
						return nil, os.ErrNotExist
					}
					return originalStat(path)
				}
			},
			wantStatus: statusFail,
			wantDetail: "stat running service image",
		},
		{
			name: "running image hash permission denied",
			configure: func(env *probeEnv, _, procExe string) {
				originalHash := env.hashFile
				env.hashFile = func(path string) (string, error) {
					if path == procExe {
						return "", os.ErrPermission
					}
					return originalHash(path)
				}
			},
			wantStatus: statusSkip,
			wantDetail: "hash running service image",
		},
		{
			name: "running image hash stale process",
			configure: func(env *probeEnv, _, procExe string) {
				originalHash := env.hashFile
				env.hashFile = func(path string) (string, error) {
					if path == procExe {
						return "", os.ErrNotExist
					}
					return originalHash(path)
				}
			},
			wantStatus: statusFail,
			wantDetail: "hash running service image",
		},
		{
			name: "running image hash differs from pin",
			configure: func(env *probeEnv, _, procExe string) {
				originalHash := env.hashFile
				env.hashFile = func(path string) (string, error) {
					if path == procExe {
						return strings.Repeat("b", sha256HexLen), nil
					}
					return originalHash(path)
				}
			},
			wantStatus: statusFail,
			wantDetail: "running service image hash mismatch",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "pipelock")
			pinPath := filepath.Join(dir, "binary-pin.sha256")
			mustWriteFile(t, target, "service image")
			pinned, err := sha256HexOfFile(target)
			if err != nil {
				t.Fatalf("hash target: %v", err)
			}
			mustWriteFile(t, pinPath, pinned+"\n")
			procExe := serviceProcessExePath(testServicePID)
			env := makeProbeEnv(t, func(env *probeEnv) {
				env.pipelockTarget = target
				env.pinPath = pinPath
				env.readFile = os.ReadFile
				env.selfPath = func() (string, error) { return target, nil }
				env.hashFile = sha256HexOfFile
				configureMatchingServiceBinary(t, env)
			})
			tc.configure(env, target, procExe)
			status, detail := probeBinaryIntegrity(context.Background(), env)
			if status != tc.wantStatus || !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("probe = (%q, %q), want (%q, containing %q)", status, detail, tc.wantStatus, tc.wantDetail)
			}
		})
	}
}

func TestProbeBinaryIntegrity_EnforcementOnlySkipsRunningImage(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "pipelock")
	pinPath := filepath.Join(dir, "binary-pin.sha256")
	mustWriteFile(t, target, "service image")
	pinned, err := sha256HexOfFile(target)
	if err != nil {
		t.Fatalf("hash target: %v", err)
	}
	mustWriteFile(t, pinPath, pinned+"\n")

	env := makeProbeEnv(t, func(env *probeEnv) {
		env.pipelockTarget = target
		env.pinPath = pinPath
		env.readFile = os.ReadFile
		env.selfPath = func() (string, error) { return target, nil }
		env.hashFile = sha256HexOfFile
		env.verifyRunningImage = false
	})

	status, detail := probeBinaryIntegrity(context.Background(), env)
	if status != statusPass || !strings.Contains(detail, "binary hash") {
		t.Fatalf("probe = (%q, %q), want deployed-pin pass", status, detail)
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

	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{name: "relative ExecStart path", raw: "{ path=pipelock ; argv[]=pipelock run ; }", want: "invalid executable path"},
		{name: "missing ExecStart path", raw: "{ argv[]=/usr/local/bin/pipelock run ; }", want: "no executable path"},
		{name: "multiple ExecStart paths", raw: "{ path=/usr/local/bin/pipelock ; }; { path=/usr/bin/other ; }", want: "expected one executable path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := systemdExecStartPath(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want containing %q", err, tc.want)
			}
		})
	}

	t.Run("missing systemd MainPID", func(t *testing.T) {
		_, err := systemdMainPID("")
		if err == nil || !strings.Contains(err.Error(), "missing MainPID") {
			t.Fatalf("error = %v", err)
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
