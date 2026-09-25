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

func TestDisplayProvisionAuthorityFailures(t *testing.T) {
	for _, tc := range []struct {
		name               string
		enabled, priorUnit bool
		fault              string
		wantApplied        bool
		want               string
	}{
		{"disabled no unit read", false, false, "read", false, "read Xauthority file"},
		{"disabled managed read", false, true, "read", false, "read Xauthority file"},
		{"disabled managed removal", false, true, "remove", true, "remove Xauthority file"},
		{"enabled prior read", true, false, "read", false, "read Xauthority file"},
		{"enabled cookie write", true, false, "write", false, "write Xauthority file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := covDispPrepareDisplayEnv(t)
			if tc.enabled {
				covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: true\n    number: 5\n")
			} else {
				covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: false\n")
			}
			if tc.priorUnit {
				body := renderAgentDisplayUnit(&installEnv{agentUserName: env.agentUserName, displayNumber: 5, xvfbPath: env.xvfbPath})
				if err := os.WriteFile(env.displayUnitPath, []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			switch tc.fault {
			case "read":
				prior := env.readFile
				env.readFile = func(path string) ([]byte, error) {
					if path == env.displayAuthorityPath {
						return nil, os.ErrPermission
					}
					return prior(path)
				}
			case "remove":
				prior := env.removeFile
				env.removeFile = func(path string) error {
					if path == env.displayAuthorityPath {
						return os.ErrPermission
					}
					return prior(path)
				}
			case "write":
				prior := env.writeFile
				env.writeFile = func(path string, data []byte, mode os.FileMode) error {
					if path == env.displayAuthorityPath {
						return os.ErrPermission
					}
					return prior(path, data, mode)
				}
			}
			applied, err := stepProvisionAgentDisplay().apply(context.Background(), env)
			if applied != tc.wantApplied || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("apply = %v, %v; want applied=%v and %q", applied, err, tc.wantApplied, tc.want)
			}
		})
	}
}

func TestDisplayProvisionUndoAuthorityFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		changed func(*installEnv)
		want    string
	}{
		{"restore existing authority", func(env *installEnv) {
			env.writeFile = func(string, []byte, os.FileMode) error { return os.ErrPermission }
		}, "restore Xauthority file"},
		{"remove new authority", func(env *installEnv) {
			prior := env.removeFile
			env.removeFile = func(path string) error {
				if path == env.displayAuthorityPath {
					return os.ErrPermission
				}
				return prior(path)
			}
		}, "remove Xauthority file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := covDispPrepareDisplayEnv(t)
			covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: true\n    number: 5\n")
			if tc.name == "restore existing authority" {
				if err := os.WriteFile(env.displayAuthorityPath, []byte("old"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			s := stepProvisionAgentDisplay()
			if applied, err := s.apply(context.Background(), env); !applied || err != nil {
				t.Fatalf("apply = %v, %v", applied, err)
			}
			tc.changed(env)
			if err := s.undo(context.Background(), env); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("undo error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestDisplayActionReportsAuthorityRemoveFailure(t *testing.T) {
	env, _ := covDispPrepareDisplayEnv(t)
	env.removeFile = func(path string) error {
		if path == filepath.Clean(env.displayAuthorityPath) {
			return os.ErrPermission
		}
		return os.Remove(path)
	}
	if err := actionRemoveAgentDisplay().undo(context.Background(), env); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("remove action: %v", err)
	}
}

func TestDisplayProvisionUndoReportsSystemAndAuthorityFailures(t *testing.T) {
	t.Run("restore prior authority", func(t *testing.T) {
		env, _ := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: false\n")
		body := renderAgentDisplayUnit(&installEnv{agentUserName: env.agentUserName, displayNumber: 5, xvfbPath: env.xvfbPath})
		if err := os.WriteFile(env.displayUnitPath, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(env.displayAuthorityPath, []byte("prior"), 0o600); err != nil {
			t.Fatal(err)
		}
		s := stepProvisionAgentDisplay()
		if applied, err := s.apply(context.Background(), env); !applied || err != nil {
			t.Fatalf("apply = %v, %v", applied, err)
		}
		env.chown = func(string, int, int) error { return os.ErrPermission }
		if err := s.undo(context.Background(), env); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("restore authority: %v", err)
		}
	})
	t.Run("restore display unit", func(t *testing.T) {
		env, runner := covDispPrepareDisplayEnv(t)
		covDispWriteManagedConfig(t, env, "containment:\n  display:\n    enabled: true\n    number: 5\n")
		s := stepProvisionAgentDisplay()
		if applied, err := s.apply(context.Background(), env); !applied || err != nil {
			t.Fatalf("apply = %v, %v", applied, err)
		}
		runner.on(argvFor(testSystemctl, "disable", "--now", filepath.Base(env.displayUnitPath)), "denied", 1, nil)
		if err := s.undo(context.Background(), env); err == nil || !strings.Contains(err.Error(), "denied") {
			t.Fatalf("restore display: %v", err)
		}
	})
}

func TestDisplayActionReportsUnitRestoreFailure(t *testing.T) {
	env, runner := covDispPrepareDisplayEnv(t)
	runner.on(argvFor(testSystemctl, "disable", "--now", filepath.Base(env.displayUnitPath)), "denied", 1, nil)
	if err := actionRemoveAgentDisplay().undo(context.Background(), env); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("remove action: %v", err)
	}
}

func TestWriteDisplayAuthorityRejectsRelativeDirectory(t *testing.T) {
	env, _ := covDispPrepareDisplayEnv(t)
	env.displayAuthorityPath = filepath.Join("relative", "Xauthority")
	if err := writeDisplayAuthority(env, strings.NewReader(strings.Repeat("x", displayAuthorityCookieSize))); err == nil || !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("write relative authority: %v", err)
	}
}
