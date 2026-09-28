// Copyright 2026 Pipelock contributors
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

func TestRunStepsRetriesFailedWriteCleanup(t *testing.T) {
	for _, tc := range []struct {
		name      string
		prior     bool
		applied   bool
		wantFile  bool
		failAgain bool
	}{
		{name: "prior file and applied step", prior: true, applied: true, wantFile: true},
		{name: "prior file and unapplied step", prior: true, wantFile: true},
		{name: "fresh file with stale backup", wantFile: false},
		{name: "persistent restore error remains incomplete", prior: true, failAgain: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _, out := newFakeEnv(t)
			path := filepath.Join(t.TempDir(), "managed")
			if tc.prior {
				if err := os.WriteFile(path, []byte("previous"), 0o600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(path+".bak", []byte("stale backup"), 0o600); err != nil {
				t.Fatal(err)
			}
			write := env.writeFile
			env.writeFile = func(p string, _ []byte, mode os.FileMode) error {
				if p == path {
					if err := write(p, []byte("partial replacement"), mode); err != nil {
						return err
					}
					return errors.New("write interrupted")
				}
				return write(p, nil, mode)
			}
			cleanupFailures := 0
			if tc.prior {
				rename := env.rename
				env.rename = func(from, to string) error {
					if from == path+".bak" && to == path && (cleanupFailures == 0 || tc.failAgain) {
						cleanupFailures++
						return errors.New("restore denied once")
					}
					return rename(from, to)
				}
			} else {
				remove := env.removeFile
				env.removeFile = func(p string) error {
					if p == path && cleanupFailures == 0 {
						cleanupFailures++
						return errors.New("remove denied once")
					}
					return remove(p)
				}
			}
			writeStep := step{
				name: "write-managed-file",
				apply: func(_ context.Context, env *installEnv) (bool, error) {
					return tc.applied, backupAndWrite(env, path, []byte("replacement"), 0o600)
				},
				undo: func(context.Context, *installEnv) error { return nil },
			}
			_, err := runSteps(context.Background(), env, out, []step{writeStep})
			if err == nil || !strings.Contains(err.Error(), "write interrupted") || strings.Contains(err.Error(), "rollback incomplete") != tc.failAgain {
				t.Fatalf("runSteps error = %v, want incomplete=%t\n%s", err, tc.failAgain, out.String())
			}
			if cleanupFailures == 0 {
				t.Fatal("positive control: immediate cleanup did not fail")
			}
			if (len(env.failedWriteRestores) > 0) != tc.failAgain {
				t.Fatalf("pending restores after rollback = %v, want incomplete=%t", env.failedWriteRestores, tc.failAgain)
			}
			if tc.failAgain {
				return
			}
			got, readErr := os.ReadFile(filepath.Clean(path))
			if tc.wantFile {
				if readErr != nil || string(got) != "previous" {
					t.Fatalf("restored file = %q, %v; want previous", got, readErr)
				}
			} else if !errors.Is(readErr, os.ErrNotExist) {
				t.Fatalf("fresh file after rollback = %q, %v; want absent", got, readErr)
			}
			if !tc.prior {
				backup, err := os.ReadFile(filepath.Clean(path + ".bak"))
				if err != nil || string(backup) != "stale backup" {
					t.Fatalf("stale backup = %q, %v; want unchanged", backup, err)
				}
			}
		})
	}
}
