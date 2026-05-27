// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build hermes_e2e

// This file is behind the `hermes_e2e` build tag so it never runs in the normal
// `go test ./...` lane (which has no Python/Hermes). Run it with:
//
//	make hermes-e2e
//
// or directly:
//
//	go test -tags hermes_e2e -run TestHermesLiveE2E -count=1 -v ./internal/cli/hermes/...
//
// It installs a PINNED hermes-agent into a throwaway venv, does a real
// `pipelock hermes install --mode full` into a temp HOME, and drives Hermes'
// OWN plugin machinery (testdata/hermes_e2e_driver.py) to prove the plugin
// loads, enables, and blocks an adversarial tool call through the real binary.
// This is the durable guard the unit tests can't be: it exercises Hermes'
// discover -> enable -> invoke_hook(cb(**kwargs)) path, not our assumption of it.
//
// Why a build-tagged make target and not a default CI job: running it pulls
// hermes-agent plus its full transitive dependency tree from PyPI, unpinned by
// hash. This repo's supply-chain policy (scripts/check-python-pins.sh,
// CONTRIBUTING.md) requires ==-pinned + --hash for any committed requirements,
// and Hermes ships ~weekly, so a hashed lockfile would be high-churn. The
// always-on CI guard is instead the hermetic signature regression test
// (plugin_signature_test.go), which needs no network and proves our hooks
// accept Hermes' kwarg contract. This e2e is the release/version-bump gate:
// run `make hermes-e2e` before claiming full mode works against a new Hermes.

package hermes_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// hermesE2EVersion is the Hermes version this e2e validates against. Bumping it
// triggers re-verification of the loader/dispatch/manifest contract; Hermes
// ships roughly weekly and the hook/enable/manifest contract can drift. See
// docs/guides/hermes.md.
const hermesE2EVersion = "0.14.0"

// TestHermesLiveE2E is the keystone proof that `--mode full` actually works
// end-to-end against a real Hermes, not just in pipelock-side unit tests.
func TestHermesLiveE2E(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("python3 required for the live-Hermes e2e: %v", err)
	}

	work := t.TempDir()
	venv := filepath.Join(work, "venv")
	venvPython := filepath.Join(venv, "bin", "python")
	venvPip := filepath.Join(venv, "bin", "pip")
	bin := filepath.Join(work, "pipelock")
	home := filepath.Join(work, "home")
	if err := os.MkdirAll(home, 0o750); err != nil {
		t.Fatalf("mkdir home: %v", err)
	}

	// Generous ceiling: the pip install dominates and needs network.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	run := func(name string, env []string, args ...string) {
		t.Helper()
		//nolint:gosec // G204: name is a test-controlled interpreter/binary path; args are fixed test literals.
		cmd := exec.CommandContext(ctx, name, args...)
		if env != nil {
			cmd.Env = env
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
		}
	}

	// 1. Throwaway venv with the pinned Hermes.
	run(python, nil, "-m", "venv", venv)
	run(venvPip, nil, "install", "--quiet", "--disable-pip-version-check", "hermes-agent=="+hermesE2EVersion)

	// 2. Build the real pipelock binary the plugin shells out to.
	run("go", nil, "build", "-o", bin, "github.com/luckyPipewrench/pipelock/cmd/pipelock")

	// 3. Real full install into the temp HOME.
	installEnv := append(os.Environ(), "HOME="+home)
	run(bin, installEnv, "hermes", "install", "--mode", "full")

	// 4. Drive Hermes' own machinery via the committed driver.
	driver, err := filepath.Abs(filepath.Join("testdata", "hermes_e2e_driver.py"))
	if err != nil {
		t.Fatalf("resolve driver path: %v", err)
	}
	driverEnv := append(os.Environ(),
		"HERMES_HOME="+filepath.Join(home, ".hermes"),
		"PIPELOCK_BIN="+bin,
	)
	//nolint:gosec // G204: venvPython and driver are test-controlled paths.
	cmd := exec.CommandContext(ctx, venvPython, driver)
	cmd.Env = driverEnv
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("live-Hermes driver failed (full mode is NOT production-ready):\n%s\nerror: %v", out, err)
	}
	if !strings.Contains(string(out), "E2E PASS") {
		t.Fatalf("driver did not report E2E PASS:\n%s", out)
	}
	t.Logf("live-Hermes e2e (hermes-agent==%s):\n%s", hermesE2EVersion, out)
}
