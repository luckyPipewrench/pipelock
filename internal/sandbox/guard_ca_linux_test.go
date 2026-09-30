// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/guard"
)

func TestGuardSymlinkedCAFiles(t *testing.T) {
	if mode := os.Getenv("PIPELOCK_TEST_CA_MODE"); mode != "" {
		runGuardCAChild(t, mode, os.Getenv("PIPELOCK_TEST_CA_ROOT"))
		// Restrictions are irreversible; parent owns fixture cleanup.
		os.Exit(0)
	}
	abi, err := llsys.LandlockGetABIVersion()
	if err != nil || abi < guard.ThreadSyncABI {
		t.Skipf("requires Landlock ABI %d: ABI=%d err=%v", guard.ThreadSyncABI, abi, err)
	}
	for _, mode := range []string{"direct", "relative", "duplicates", "absolute", "outer-missing"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			for _, dir := range []string{"ssl/certs", "extracted"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0o750); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"extracted/bundle.pem", "extracted/neighbor", "runtime"} {
				if err := os.WriteFile(filepath.Join(root, name), []byte("fixture"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for name, target := range map[string]string{
				"ssl/cert.pem":     "../extracted/bundle.pem",
				"ssl/certs/ca.crt": "../../extracted/bundle.pem",
				"ssl/absolute.pem": filepath.Join(root, "extracted/bundle.pem"),
			} {
				if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
					t.Fatal(err)
				}
			}
			// Re-exec this test binary: the restriction under test is irreversible.
			helper, err := os.Executable()
			if err != nil {
				t.Fatalf("resolve test helper: %v", err)
			}
			cmd := exec.CommandContext(t.Context(), helper, "-test.run=^TestGuardSymlinkedCAFiles$", "-test.v") // #nosec G204 -- re-exec of this test binary with a fixed run filter.
			cmd.Env = append(os.Environ(), "PIPELOCK_TEST_CA_MODE="+mode, "PIPELOCK_TEST_CA_ROOT="+root)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child %s: %v\n%s", mode, err, out)
			}
			t.Logf("%s", out)
		})
	}
}

func runGuardCAChild(t *testing.T, mode, root string) {
	t.Helper()
	bundle := filepath.Join(root, "extracted/bundle.pem")
	files := []string{filepath.Join(root, "ssl/cert.pem")}
	switch mode {
	case "direct":
		files = []string{bundle}
	case "duplicates":
		files = append(files, filepath.Join(root, "ssl/certs/ca.crt"))
	case "absolute":
		files = []string{filepath.Join(root, "ssl/absolute.pem")}
	}
	cfg := config.Defaults()
	cfg.Guard = config.Guard{
		Profiles:  []config.GuardProfile{{Name: "test", Manifests: []string{"ca"}}},
		Manifests: []config.GuardManifest{{Name: "ca", ReadOnly: files}},
	}
	p, err := guard.Prepare(cfg, "test", os.Getuid())
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	defer func() { _ = p.Close() }()
	if !p.Complete() {
		t.Fatalf("incomplete: %+v", p.Outcomes())
	}
	for _, outcome := range p.Outcomes() {
		if outcome.ResolvedPath != bundle {
			t.Fatalf("resolved %q, want %q", outcome.ResolvedPath, bundle)
		}
	}
	if mode != "direct" {
		policy := Policy{AllowReadDirs: []string{filepath.Join(root, "ssl")}}
		if mode != "outer-missing" {
			policy = guardRuntimeFilePolicy(policy, filepath.Join(root, "runtime"), files)
		}
		policy, err = ResolvePolicyPaths(policy)
		if err != nil {
			t.Fatal(err)
		}
		if err := landlock.V8.RestrictPaths(buildRules(policy)...); err != nil {
			t.Fatal(err)
		}
	}
	record, err := p.Apply()
	if mode == "outer-missing" {
		if !errors.Is(err, guard.ErrPolicyNarrowed) || record.Enforced() {
			t.Fatalf("missing outer grant: err=%v record=%+v", err, record)
		}
		t.Log("missing outer CA grant: REFUSED")
		return
	}
	if err != nil || !record.Enforced() {
		t.Fatalf("apply: %v; %s", err, record.Describe())
	}
	for _, path := range append(files, bundle) {
		if content, err := os.ReadFile(filepath.Clean(path)); err != nil || string(content) != "fixture" {
			t.Fatalf("bundle read %q: %q %v", path, content, err)
		}
	}
	if _, err := os.ReadFile(filepath.Clean(filepath.Join(root, "extracted/neighbor"))); !errors.Is(err, unix.EACCES) {
		t.Fatalf("neighbor read = %v, want EACCES", err)
	}
	if err := os.WriteFile(bundle, []byte("changed"), 0o600); !errors.Is(err, unix.EACCES) {
		t.Fatalf("bundle write = %v, want EACCES", err)
	}
	t.Log("bundle readable; neighbor and bundle write DENIED")
}
